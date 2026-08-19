/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/containerof.h>
#include "ice.h"

/*
 * Transmitting packets works largely identical to the 700-series (i40e) NICs.
 * The 800-series (ice) does have some additional features (e.g. completion
 * queues) that aren't currently utilized. Like any other nic, the mblk_t we're
 * transmitting consists of an arbitrary number of fragments of arbitrary size
 * (linked by the b_cont field). Transmitting the packet is a matter of
 * assembling a list of physical address and lengths for all of these fragments
 * and writing them out to the TX ring.
 *
 * The transmit control blocks (ice_tx_control_block_t aka tcb) are used to
 * track these (paddr, len) pairs. For each fragment, we either DMA bind the
 * fragment (if the fragment is sufficiently large), or we copy the contents
 * of the fragment into a pre-DMA mapped buffer. We will also attempt to copy
 * the contents of a larger fragment if the DMA mapping operation fails
 * as well as if the packet exceeds the DMA engine's per packet descriptor
 * limit (more on this below). To increase the utilization of the preallocated
 * DMA buffers, consecutive small mblk fragments will be concatenated into a
 * single pre-allocated DMA buffer. Each DMA bound mblk fragment as well as
 * each pre-allocated DMA buffer consume a tcb.
 *
 * Once we've processed every fragment, we write the physical addresses,
 * lengths, and other metadata (e.g. hw checksum offload information, etc)
 * onto the TX descriptor ring and tell the hardware to transmit the packet.
 * At the same time, the TCBs consumed by this packet are saved on another
 * ring at the same index as the last descriptor written on the TX descriptor
 * ring. Since the number of tcbs is always <= the number of TX descriptors
 * used, if there is enough free slots for the TX descriptors, we'll always
 * have enough free slots on the tcb ring to hold the corresponding tcbs.
 *
 * When the NIC has finished sending the NIC, it will generate a completion
 * interrupt, and we use ice_tx_recycle_ring() to go through the TX descriptor
 * and tcb descriptor rings and release the tcbs so they can be reused.
 *
 * Like the i40e NICs, the ice nics have a limit of 8 descriptors per packet.
 * More correctly, for every packet sent over the wire, the NIC will do at
 * most 8 DMA transfers to gather the packet contents from RAM. In the
 * non-LSO case, this distinction isn't significant -- the number of TX
 * descriptors written to the ring is equal to the number of DMA transfers
 * that will occur.
 *
 * For the LSO case however, things get more complex. The description from
 * the Intel I210 datasheet is helpful here. It is obviously not the same
 * model as the E810, however, the explanation there is more clarifying than
 * what is found in the E810 (or 710) datasheets yet (based on painful
 * experiences) appears to describe the same behavior (examination of the
 * structures of things like TX/RX descriptors and such also shows a rather
 * obvious evolution for the various models over time). From the I210
 * datasheet (Section 6.2.4.8):
 *
 * The flow used by the I210-CS/CL to do TCP segmentation is as follows:
 *
 *    1. Get a descriptor with a request for a TSO off-load of a TCP packet.
 *    2. First Segment processing:
 *        a. Fetch all the buffers containing the header as calculated by the
 *           MACLEN, IPLEN and L4LEN fields. Save the addresses and lengths of
 *           the buffers containing the header (up to 4 buffers). The
 *           header content is not saved.
 *        b. Fetch data up to the MSS from subsequent buffers & calculate the
 *           adequate checksum(s).
 *        c. Update the Header accordingly and update internal state of the
 *           packet (next data to fetch and TCP SN).
 *        d. Send the packet to the network.
 *        e. If total packet was sent, go to step 4. else continue.
 *    3. Next segments
 *        a. Wait for next arbitration of this queue.
 *        b. Fetch all the buffers containing the header from the saved
 *           addresses. Subsequent reads of the header might be done with a no
 *           snoop attribute.
 *        c. Fetch data up to the MSS or end of packet from subsequent
 *           buffers & calculate the adequate checksum(s).
 *        d. Update the Header accordingly and update internal state of the
 *           packet (next data to fetch and TCP SN).
 *        e. If total packet was sent, request is done, else restart from step 3.
 *    4. Release all buffers (update head pointer).
 *
 * From the above explanation, two key observations become apparent:
 *
 *    1. The header is always copied as a separate DMA transfer from the
 *       data.
 *    2. The header is re-read for every packet the NIC generates when doing
 *       LSO.
 *
 * The implications in conjunction with the hard 8 DMA transfer limit is
 * that the LSO case comes a lot more complicated. For example, if the
 * first descriptor of a packet contains both the header and data, this
 * will result in 2 DMA transfers, leaving 6 DMA transfers to 'fill up'
 * the packet before sending. Likewise, assuming the header is contained
 * in a single descriptor (the E810 NIC allows up to 3, but as described
 * below, for us it will always be in 1 descriptor), the 2nd packet will
 * only have 7 DMA transfers to tranfer enough data to 'fill' the packet
 * (similarly for any subsequent packets generated from the same original
 * 'large' LSO packet passed down stack.
 *
 * This matches _exactly_ the behavior seen (as well as the 710 NICs).
 * The E810 datasheet implies, but does not explicitly state that it really
 * wants the headers in their own descriptors from data. This is further
 * strengthened when looking at how the Linux ice driver handles things
 * based on the comments in the __ice_chk_linearize() function in it.
 *
 * To tackle this complexity, we attempt to do the following:
 *
 * - For LSO, we always copy the headers into their own pre-allocated DMA
 *   buffer and add that to the head of the list of TCBs for this packet.
 *   Since we have a pool of 'small' (512) byte DMA buffers for small
 *   packets, we can do this without being too wasteful.
 *
 * - For each segment (dblk_t) of the packet, we will either attempt to
 *   DMA bind the buffer or copy the contents into a preallocated DMA
 *   buffer. We allocate a tcb to track/manage this.
 *
 * - When a tcb is added to the list of tcbs for the packet, we iterate
 *   through the DMA cookies (ddi_dma_cookie_ts) for the data tracked by
 *   the tcb. We keep a count of the number of descriptors used for the
 *   current MSS segment (And the total size).
 *
 * - If the addition of a tcb will cross an MSS boundary, we reset the
 *   segment and size counters. Additionally, we checkpoint the state.
 *
 * - If the addition of a tcb will cause us to exceed the DMA transfer
 *   limit, we rollback the state to the last checkpoint (including releasing
 *   any tcbs that were allocated for the current mss segment). We then
 *   will retry the current MSS segment by copying all of the data for
 *   the current MSS segment into preallocated DMA buffers. Since the
 *   the preallocated DMA buffers are MIN(sdu, pagesize), even in the
 *   case of jumbo frames, should need at most 3 buffers to hold a whole
 *   MSS-sized segment of data. Once we cross the next mss boundary, we
 *   revert back to attempting DMA binding as normal.
 *
 * - If for some reason the retry also fails, we take the max power approach,
 *   release all of the tcbs allocated for the packet, and copy the entire
 *   packet into preallocated buffers. This should always succeed as long
 *   as buffers are available (if not, this is no different than the usual
 *   'out of buffers case).
 *
 * For all of this, the ice_tx_pkt_t is used to track the state. It could
 * probably all be done with local variables, but this is arguably cleaner
 * and certainly makes observability into the state much easier.
 *
 * For eack packet, an ice_tx_pkt_t is allocated (if we have multiple
 * packets to send in once mc_tx(9E) call, we'll reuse it). We then setup
 * the initial state using ice_tx_pkt_init().
 *
 * ice_tx_{bind, copy{_fragment() are called as appropriate to copy/bind
 * the packet data to a tcb.
 *
 * ice_tx_pkt_add_tcb() is then used to add the tcb and update our
 * state tracking. If we fail, ice_tx_pkt_retry_mss_seg() is used to
 * rollback the state to retry the MSS segment by copying.
 *
 */

/* Note these are defined in the order we attempt each method */
typedef enum ice_tx_pkt_method {
	ITPM_NORMAL,		/* Try binding and copying based on frag size */
	ITPM_COPY_MSS,		/* Try to copy the current mss segment */
	ITPM_COPY_ALL,		/* Copy the entire packet */
} ice_tx_pkt_method_t;

typedef struct ice_tx_pkt_state {
	ice_tx_ctrl_block_t	*itps_tail;

	mblk_t			*itps_mp;
	uint16_t		itps_off;

	uint16_t		itps_ntcbs;
	uint16_t		itps_ndesc;

	uint32_t		itps_copy_bytes;
	uint32_t		itps_bind_bytes;

	uint16_t		itps_copy_segs;
	uint16_t		itps_bind_segs;
	uint16_t		itps_bind_fails;

	uint16_t		itps_seglen;
	uint8_t			itps_segcnt;
} ice_tx_pkt_state_t;

enum {
	ITXP_INIT = 0,
	ITXP_PREV = 1,
	ITXP_CURR = 2,
};

typedef enum ice_tx_pkt_flags {
	ITPF_NONE =	0,
	ITPF_DONE =	(1 << 0),
	ITPF_LSO =	(1 << 1),
} ice_tx_pkt_flags_t;

typedef struct ice_tx_pkt {
	ice_tx_ring_t		*itxp_ring;
	mblk_t			*itxp_mp;
	ice_tx_ctrl_block_t	*itxp_head;
	mac_ether_offload_info_t itxp_meo;

	uint16_t		itxp_dma_min;
	uint16_t		itxp_mss_retries;

	uint16_t		itxp_hdrlen;	/* Size of L2+L3+L4 headers */
	uint16_t		itxp_mss;

	ice_tx_pkt_flags_t	itxp_flags;
	ice_tx_pkt_method_t	itxp_method;

	ice_tx_pkt_state_t	itxp_state[3];
} __aligned(64) ice_tx_pkt_t;

typedef struct ice_tx_pkt_iter {
	ice_tx_ctrl_block_t	*itpi_tcb;
	ddi_dma_handle_t	itpi_dmah;
	const ddi_dma_cookie_t	*itpi_ic;
	ddi_dma_cookie_t	itpi_cookie;
} ice_tx_pkt_iter_t;

static kmem_cache_t *ice_tx_pkt_cache;

static void ice_tx_recycle_ring(ice_tx_ring_t *);

static inline uintptr_t
ice_qtx_index(const ice_tx_ring_t *txr)
{
	return (txr->itxr_index + txr->itxr_ice->ice_first_txq);
}

static inline uintptr_t
ice_qtx_tail(const ice_tx_ring_t *txr)
{
	return (ICE_QTX_TAIL(ice_qtx_index(txr)));
}

static inline uintptr_t
ice_qint_tqctl(const ice_tx_ring_t *txr)
{
	return (ICE_REG_QINT_TQCTL(ice_qtx_index(txr)));
}

static inline ice_tx_ring_t *
ice_ih_to_txr(const ice_intr_handler_t *h)
{
	return (__containerof(h, ice_tx_ring_t, itxr_intr));
}

static inline uint16_t
ice_tx_next(const ice_tx_ring_t *txr, uint16_t idx, uint16_t amt)
{
	/* Use a larger size to hold intermediate results to avoid overflow */
	uint32_t val;

	ASSERT3U(idx, <, txr->itxr_size);

	val = idx + amt;
	if (val >= txr->itxr_size)
		val -= txr->itxr_size;

	ASSERT3U(val, <, txr->itxr_size);
	return (val);
}

static inline uint16_t
ice_tx_prev(const ice_tx_ring_t *txr, uint16_t idx)
{
	ASSERT3U(idx, <, txr->itxr_size);

	return ((idx > 0) ? idx - 1 : txr->itxr_size - 1);
}

static ice_tx_ctrl_block_t *
ice_tcb_alloc(ice_tx_ring_t *txr)
{
	ice_tx_ctrl_block_t *tcb;

	mutex_enter(&txr->itxr_tcb_lock);

	if (txr->itxr_tcb_nfree == 0) {
		mutex_exit(&txr->itxr_tcb_lock);
		return (NULL);
	}

	--txr->itxr_tcb_nfree;
	tcb = txr->itxr_tcb_free_list[txr->itxr_tcb_nfree];
	txr->itxr_tcb_free_list[txr->itxr_tcb_nfree] = NULL;

	mutex_exit(&txr->itxr_tcb_lock);

	ASSERT3P(tcb->itcb_next, ==, NULL);
	tcb->itcb_ring = txr;

	return (tcb);
}

static void
ice_tcb_free(ice_tx_ctrl_block_t *tcb)
{
	ice_t		*ice;
	ice_tx_ring_t	*txr;

	if (tcb == NULL)
		return;

	ASSERT3P(tcb->itcb_ring, !=, NULL);
	ASSERT3P(tcb->itcb_next, ==, NULL);

	txr = tcb->itcb_ring;
	ice = txr->itxr_ice;

	switch (tcb->itcb_type) {
	case ITCB_NOT_USED:
		break;
	case ITCB_SMALL_COPY:
		ice_buf_pool_free(&ice->ice_small_bufs, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_COPY:
		ice_buf_pool_free(&ice->ice_bufs, tcb->itcb_buf);
		tcb->itcb_buf = NULL;
		break;
	case ITCB_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_dmah);
		break;
	case ITCB_LSO_BIND:
		(void) ddi_dma_unbind_handle(tcb->itcb_lso_dmah);
		break;
	}

	tcb->itcb_type = ITCB_NOT_USED;
	tcb->itcb_len = 0;
	if (tcb->itcb_mp != NULL) {
		freemsg(tcb->itcb_mp);
		tcb->itcb_mp = NULL;
	}

	tcb->itcb_tx_time = 0;

	mutex_enter(&txr->itxr_tcb_lock);

	ASSERT3U(txr->itxr_tcb_nfree, <, txr->itxr_size);
	txr->itxr_tcb_free_list[txr->itxr_tcb_nfree] = tcb;
	txr->itxr_tcb_nfree++;

	mutex_exit(&txr->itxr_tcb_lock);
}

/* Allocates a tcb + dma buffer */
static ice_tx_ctrl_block_t *
ice_tcb_alloc_buf(ice_tx_ring_t *txr, bool small)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_ctrl_block_t	*tcb;

	tcb = ice_tcb_alloc(txr);
	if (tcb == NULL)
		return (NULL);

	ASSERT3P(tcb->itcb_buf, ==, NULL);

	/*
	 * If a small buffer is requested, we try, but will fallback
	 * to a full sized buffer if that fails.
	 */
	if (small) {
		tcb->itcb_buf = ice_buf_pool_alloc(&ice->ice_small_bufs);
		tcb->itcb_type = ITCB_SMALL_COPY;
	}

	if (tcb->itcb_buf == NULL) {
		tcb->itcb_buf = ice_buf_pool_alloc(&ice->ice_bufs);
		tcb->itcb_type = ITCB_COPY;
	}

	if (tcb->itcb_buf == NULL) {
		tcb->itcb_type = ITCB_NOT_USED;
		ice_tcb_free(tcb);
		return (NULL);
	}

	return (tcb);
}

static inline bool
ice_tcb_is_copy(const ice_tx_ctrl_block_t *tcb)
{
	if (tcb == NULL)
		return (false);

	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		return (true);
	default:
		return (false);
	}
}

/* How many bytes remain for copying in the given tcb */
static inline uint32_t
ice_tcb_remaining(const ice_tx_ctrl_block_t *tcb)
{
	if (tcb == NULL)
		return (0);

	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		ASSERT3U(tcb->itcb_len, <=, tcb->itcb_buf->idb_len);
		return (tcb->itcb_buf->idb_len - tcb->itcb_len);
	default:
		/* All others can't be used for copying */
		return (0);
	}
}

static inline ddi_dma_handle_t
ice_tcb_dma_handle(const ice_tx_ctrl_block_t *tcb)
{
	switch (tcb->itcb_type) {
	case ITCB_SMALL_COPY:
	case ITCB_COPY:
		return (tcb->itcb_buf->idb_dma_handle);
	case ITCB_BIND:
		return (tcb->itcb_dmah);
	case ITCB_LSO_BIND:
		return (tcb->itcb_lso_dmah);
	default:
		return (NULL);
	}
}

static inline uint_t
ice_tcb_ncookies(const ice_tx_ctrl_block_t *tcb)
{
	ddi_dma_handle_t h = ice_tcb_dma_handle(tcb);
	return ((h != NULL) ? ddi_dma_ncookies(h) : 0);
}

static inline const ddi_dma_cookie_t *
ice_tcb_cookie_iter(const ice_tx_ctrl_block_t *tcb, const ddi_dma_cookie_t *c)
{
	ddi_dma_handle_t h = ice_tcb_dma_handle(tcb);
	return ((h != NULL) ? ddi_dma_cookie_iter(h, c) : NULL);
}

static bool
ice_tx_enter(ice_tx_ring_t *txr)
{
	bool allow;

	mutex_enter(&txr->itxr_lock);
	allow = !txr->itxr_quiesce;
	if (allow)
		txr->itxr_active++;
	mutex_exit(&txr->itxr_lock);

	return (allow);
}

static void
ice_tx_exit_nolock(ice_tx_ring_t *txr)
{
	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	ASSERT3U(txr->itxr_active, >, 0);
	txr->itxr_active--;
	if (txr->itxr_quiesce)
		cv_signal(&txr->itxr_cv);
}

static void
ice_tx_exit(ice_tx_ring_t *txr)
{
	mutex_enter(&txr->itxr_lock);
	ice_tx_exit_nolock(txr);
	mutex_exit(&txr->itxr_lock);
}

/*
 * Wait for all TX activity to quiesce. Returns true if already quiesced,
 * false otherwise.
 */
bool
ice_tx_quiesce(ice_tx_ring_t *txr)
{
	mutex_enter(&txr->itxr_lock);
	if (txr->itxr_quiesce) {
		/* Ring is already shutdown */
		mutex_exit(&txr->itxr_lock);
		return (true);
	}

	/* Wait for any threads in the TX path to exit */
	txr->itxr_quiesce = true;
	while (txr->itxr_active > 0)
		cv_wait(&txr->itxr_cv, &txr->itxr_lock);

	mutex_exit(&txr->itxr_lock);

	return (false);
}

/*
 * Checkpoint the current relevant packet state needed to rollback to
 * the start of an mss segment.
 */
static inline void
ice_tx_pkt_checkpoint(ice_tx_pkt_t *pkt)
{
	ice_tx_pkt_state_t *cur = &pkt->itxp_state[ITXP_CURR];
	ice_tx_pkt_state_t *prev = &pkt->itxp_state[ITXP_PREV];

	bcopy(cur, prev, sizeof (*cur));
}

static inline size_t
ice_tx_pkt_msglen(const ice_tx_pkt_t *pkt)
{
	return (pkt->itxp_meo.meoi_len);
}

static inline bool
ice_tx_pkt_lso(const ice_tx_pkt_t *pkt)
{
	return (pkt->itxp_flags & ITPF_LSO);
}

static inline bool
ice_tx_pkt_done(const ice_tx_pkt_t *pkt)
{
	return (pkt->itxp_flags & ITPF_DONE);
}

static inline uint16_t
ice_tx_pkt_desc_needed(const ice_tx_pkt_t *pkt)
{
	const ice_tx_pkt_state_t	*st = &pkt->itxp_state[ITXP_CURR];
	uint16_t			n = st->itps_ndesc;

	/*
	 * LSO requires an additional descriptor to hold the TX
	 * context
	 */
	if (ice_tx_pkt_lso(pkt))
		n++;

	return (n);
}


/*
 * Add a `tcb `to `pkt` .`mp` and `off` reflect the location in the packet
 * data just after the data in `tcb`. If we can add this tcb without
 * violating the hardware's segmentation rules, we return true. Otherwise
 * we return false.
 *
 * If the tcb is added successfully, if it also crosses the current mss
 * segment boundary, it 'checkpoints'. That is, The value of `mp` and `off`
 * are saved (along with some other internal bookkeeping information) so
 * we are able to undo things and rollback the state of pkt as it is when
 * we return now -- basically the start of a new mss segment boundary (that
 * way we can retry by copying the entire mss segment).
 *
 */
static bool
ice_tx_pkt_add_tcb(ice_tx_pkt_t *pkt, ice_tx_ctrl_block_t *tcb, mblk_t *mp,
    uint16_t off)
{
	const ddi_dma_cookie_t	*c;
	ddi_dma_handle_t	h;
	ice_tx_pkt_state_t	*st = &pkt->itxp_state[ITXP_CURR];
	uint16_t		ndesc;
	uint16_t		seglen;
	uint8_t			segcnt;
	bool			need_checkpoint = false;

	if (tcb == NULL)
		return (true);

	/* Once done, we should not be asked to add more tcbs */
	ASSERT(!ice_tx_pkt_done(pkt));

	IMPLY(mp == NULL, off == 0);

	h = ice_tcb_dma_handle(tcb);

	const uint_t n = ice_tcb_ncookies(tcb);
	ASSERT3U(n, >, 0);

	/*
	 * The non-LSO case is simple -- just add the tcb if don't
	 * exceed the single-packet max cookie.
	 */
	if (!ice_tx_pkt_lso(pkt)) {
		if (st->itps_ndesc + n > ICE_TX_MAX_COOKIE)
			return (false);

		st->itps_ndesc += n;
		st->itps_segcnt += n;
		st->itps_seglen += tcb->itcb_len;

		/*
		 * When pkt was inited, we should have verified the
		 * packet will fit.
		 */
		ASSERT3U(st->itps_seglen, <, pkt->itxp_mss);

		if (ice_tcb_is_copy(tcb)) {
			st->itps_copy_bytes += tcb->itcb_len;
			st->itps_copy_segs++;
		} else {
			st->itps_bind_bytes += tcb->itcb_len;
			st->itps_bind_segs += n;
		}

		goto done;
	}

	ndesc = st->itps_ndesc;
	seglen = st->itps_seglen;
	segcnt = st->itps_segcnt;

	/*
	 * A copy TCB uses a preallocated DMA buffer constructed so that
	 * it should only ever use 1 cookie.
	 */
	IMPLY(ice_tcb_is_copy(tcb), n == 1);

	/*
	 * Gather up all of the physical addresses and lengths for this
	 * tcb (for DMA mapped data, there may be more than one cookie)
	 */
	for (c = ddi_dma_cookie_iter(h, NULL); c != NULL;
	    c = ddi_dma_cookie_iter(h, c)) {
		uint16_t len;

		/*
		 * Whenever we accumulate enough bytes to cross an mss
		 * boundary (pkt->itxp_seglen >= mss), we reset itxp_seglen
		 * and itxp_segcnt. If we are at the maximum (it's one less
		 * than the actual maximum to account for the header)
		 * and start the loop again, we've failed (and need to resort
		 * to some amount of copying).
		 */
		if (segcnt == ICE_TX_MAX_COOKIE - 1)
			return (false);

		/*
		 * itcb_len is the total amount of data represented by this
		 * tcb. As noted above, a copy TCB uses a preallocated DMA
		 * buffer. This buffer may be larger than the amount of
		 * data present. However since it also only contains 1
		 * cookie, itcb_len _is_ the size of the segment's data.
		 *
		 * For a bound TCB, there may be multiple cookies, so
		 * itcb_len may not match this cookie's dmac_size
		 */
		IMPLY(ice_tcb_is_copy(tcb), tcb->itcb_len <= c->dmac_size);
		len = ice_tcb_is_copy(tcb) ? tcb->itcb_len : c->dmac_size;

		/*
		 * Track the total number of TX descriptor entries that
		 * will be needed for this packet. This is equivalent to
		 * the total number of DMA cookies we use.
		 */
		ndesc++;

		/* Update our mss frame accounting */
		segcnt++;
		seglen += len;

		if (seglen >= pkt->itxp_mss) {
			/*
			 * If this descriptor straddles an mss boundary,
			 * the NIC will DMA the remaining data in the
			 * descriptor when it starts the next packet, so
			 * we must reflect that in our accounting
			 */
			seglen %= pkt->itxp_mss;
			segcnt = (seglen == 0) ? 0 : 1;

			/*
			 * But we also need create a new checkpoint once
			 * we've finished adding this tcb
			 */
			need_checkpoint = true;
		}
	}

	st->itps_ndesc = ndesc;
	st->itps_seglen = seglen;
	st->itps_segcnt = segcnt;

done:
	if (st->itps_tail != NULL) {
		st->itps_tail->itcb_next = tcb;
		st->itps_tail = tcb;
	} else {
		ASSERT3P(pkt->itxp_head, ==, NULL);

		pkt->itxp_head = tcb;
		st->itps_tail = tcb;
	}
	st->itps_ntcbs++;

	st->itps_mp = mp;
	st->itps_off = off;

	if (need_checkpoint) {
		ice_tx_pkt_checkpoint(pkt);

		/*
		 * Since we've finished with this mss segment, we can
		 * revert to our default behavior of binding larger fragments.
		 *
		 * If we're desperate enough to resort to copying the
		 * entire packet (ITPM_COPY_ALL), we never switch back to
		 * either prior behavior for this packet.
		 */
		if (pkt->itxp_method == ITPM_COPY_MSS)
			pkt->itxp_method = ITPM_NORMAL;
	}

	if (mp == NULL)
		pkt->itxp_flags |= ITPF_DONE;

	return (true);
}

static bool
ice_tx_pkt_sync(ice_tx_pkt_t *pkt)
{
	ice_tx_ctrl_block_t *tcb = pkt->itxp_head;

	while (tcb != NULL) {
		ddi_dma_handle_t h = ice_tcb_dma_handle(tcb);

		/*
		 * Since we're syncing the entire range, this should
		 * always succeed.
		 */
		VERIFY0(ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORDEV));

		if (ice_check_dma_handle(h) != DDI_FM_OK) {
			ice_t *ice = pkt->itxp_ring->itxr_ice;

			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_DEGRADED);
			atomic_or_32(&ice->ice_state, ICE_ERROR);

			return (false);
		}

		tcb = tcb->itcb_next;
	}

	return (true);
}

/*
 * Restore the packet state to the start of the current mss segment
 * and switch to force copy mode.
 */
static void
ice_tx_pkt_retry_mss_seg(ice_tx_pkt_t *pkt, mblk_t **mpp, uint16_t *offp)
{
	ice_tx_ctrl_block_t	*tcb;
	ice_tx_ctrl_block_t	*next;
	ice_tx_pkt_state_t	*to;
	ice_tx_pkt_state_t	*from = NULL;

	/* We should never retry once we're copying the whole packet */
	VERIFY3S(pkt->itxp_method, !=, ITPM_COPY_ALL);

	pkt->itxp_mss_retries++;

	to = &pkt->itxp_state[ITXP_CURR];

	/*
	 * Advance to the next method and determine which state
	 * we restore from.
	 */
	pkt->itxp_method++;

	switch (pkt->itxp_method) {
	case ITPM_NORMAL:
	default:
		dev_err(pkt->itxp_ring->itxr_ice->ice_dip, CE_PANIC,
		    "%s: invalid packet rollback state %d", __func__,
		    pkt->itxp_method);
		break;

	case ITPM_COPY_MSS:
		from = &pkt->itxp_state[ITXP_PREV];
		break;
	case ITPM_COPY_ALL:
		/*
		 * If we've hit full-on desperation, it should only
		 * every possibly happen for LSO. All non-LSO packets
		 * should be able to be handled using ITPM_COPY_MSS
		 */
		VERIFY(ice_tx_pkt_lso(pkt));
		from = &pkt->itxp_state[ITXP_INIT];
		break;
	}

#ifdef	DEBUG
	/*
	 * Cross check our descriptor and tcb accounting on debug builds.
	 * After we've freed all of the tcbs to roll back to the checkpoint,
	 * the number of tcbs and the number of descriptors we've removed
	 * should match what was saved in the checkpoint.
	 */
	uint_t ndesc = to->itps_ndesc;
	uint_t ntcb = to->itps_ntcbs;
#endif

	bcopy(from, to, sizeof (*from));

	/*
	 * If the checkpoint doesn't have a tail, it has to be
	 * the start of the packet.
	 */
	if (to->itps_tail != NULL) {
		tcb = to->itps_tail->itcb_next;
	} else {
		ASSERT(!ice_tx_pkt_lso(pkt));
		tcb = pkt->itxp_head;
		pkt->itxp_head = NULL;
	}

	while (tcb != NULL) {
		next = tcb->itcb_next;

		tcb->itcb_next = NULL;
#ifdef	DEBUG
		ASSERT(!__builtin_usub_overflow(ndesc, ice_tcb_ncookies(tcb),
		    &ndesc));
		ASSERT(!__builtin_usub_overflow(ntcb, 1, &ntcb));
#endif

		ice_tcb_free(tcb);
		tcb = next;
	}
	ASSERT3U(ndesc, ==, from->itps_ndesc);
	ASSERT3U(ntcb, ==, from->itps_ntcbs);

	*mpp = to->itps_mp;
	*offp = to->itps_off;
}

/*
 * This copies up to `len` bytes into tcb. `len` may be larger
 * than the size of this fragment (MBKL(*mpp)) in which case the
 * remainder of the fragment is copied.
 *
 * This advances *mpp and *offp by the amount copied and returns
 * the number of bytes copied.
 *
 * Note that it is legitimate (if not unforunate) we could be called
 * due to a 0-byte mblk_t span. In such a case we just advance past it.
 */
static uint16_t
ice_tx_copy_fragment(ice_tx_ctrl_block_t *tcb, mblk_t **mpp, uint16_t *offp,
    uint16_t len)
{
	const void	*src = (*mpp)->b_rptr + *offp;
	void		*dest = tcb->itcb_buf->idb_va + tcb->itcb_len;
	uint16_t	amt;

	ASSERT3U(tcb->itcb_type, !=, ITCB_BIND);
	ASSERT3U(tcb->itcb_type, !=, ITCB_LSO_BIND);

	amt = MIN(len, MBLKL(*mpp) - *offp);
	amt = MIN(amt, ice_tcb_remaining(tcb));

	ASSERT3P(src, >=, (*mpp)->b_rptr);
	ASSERT3P(src, <, (*mpp)->b_wptr);
	ASSERT3U(amt, <=, MBLKL(*mpp));
	ASSERT3U((uintptr_t)src + amt, <=, (uintptr_t)((*mpp)->b_wptr));
	ASSERT3U(tcb->itcb_len + amt, <=, tcb->itcb_buf->idb_len);

	bcopy(src, dest, amt);
	tcb->itcb_len += amt;

	*offp += amt;
	if (*offp == MBLKL(*mpp)) {
		*mpp = (*mpp)->b_cont;
		*offp = 0;
	}

	return (amt);
}

/*
 * This tries to DMA bind the remainder of the fragment in `*mpp
 * starting at offset `*offp`. On success *mpp and *offp are advanced to
 * the next fragment (if any).
 */
static bool
ice_tx_bind_fragment(ice_tx_pkt_t *pkt, ice_tx_ctrl_block_t *tcb, mblk_t **mpp,
    uint16_t *offp)
{
	const void		*src = (*mpp)->b_rptr + *offp;
	const size_t		amt = MBLKL(*mpp) - *offp;
	ddi_dma_handle_t	h;
	int			ret;

	/* We should be handed an empty tcb */
	ASSERT3S(tcb->itcb_type, ==, ITCB_NOT_USED);
	ASSERT0(tcb->itcb_len);

	ASSERT3P(src, >=, (*mpp)->b_rptr);
	ASSERT3P(src, <, (*mpp)->b_wptr);
	ASSERT3U(amt, <=, MBLKL(*mpp));
	ASSERT3U((uintptr_t)src + amt, <=, (uintptr_t)((*mpp)->b_wptr));
	ASSERT3U(amt, <=, UINT16_MAX);

	/*
	 * We need to set this now so we can obtain the correct DMA
	 * handle.
	 */
	tcb->itcb_type = ice_tx_pkt_lso(pkt) ? ITCB_LSO_BIND : ITCB_BIND;

	h = ice_tcb_dma_handle(tcb);
	ret = ddi_dma_addr_bind_handle(h, NULL, (caddr_t)src, amt,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, NULL,
	    NULL);
	if (ret != DDI_DMA_MAPPED) {
		/* Reset the type so we don't try to unbind in ice_tcb_free() */
		tcb->itcb_type = ITCB_NOT_USED;
		pkt->itxp_state[ITXP_CURR].itps_bind_fails++;
		return (false);
	}

	tcb->itcb_len = amt;

	/*
	 * We always bind the remainder of this segment, so we always
	 * advance to the next segment (if any).
	 */
	*mpp = (*mpp)->b_cont;
	*offp = 0;

	return (true);
}

/*
 * Initialize pkt to transmit mp. Sets initial values in preparation for
 * copying & mapping mblk segments. Returns true on success. Returns false
 * if mp is malformed (and should be dropped).
 */
static bool
ice_tx_pkt_init(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt, mblk_t *mp)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_pkt_state_t	*st = &pkt->itxp_state[ITXP_INIT];
	uint32_t		lsoflags;
	uint32_t		mss = 0;
	uint16_t		off = 0;

	/* We do all of this work _before_ we take the TX ring lock. */
	ASSERT(!MUTEX_HELD(&txr->itxr_lock));

	bzero(pkt, sizeof (*pkt));

	mac_ether_offload_info(mp, &pkt->itxp_meo);

	pkt->itxp_ring = txr;
	pkt->itxp_hdrlen = pkt->itxp_meo.meoi_l2hlen +
	    pkt->itxp_meo.meoi_l3hlen + pkt->itxp_meo.meoi_l4hlen;

	/* XXX log this? make it an ASSERT or VERIFY()?, dtrace probe ? */
	if (pkt->itxp_meo.meoi_len < pkt->itxp_hdrlen)
		return (false);

	/*
	 * While the hardware supports doing LSO with packets > 64KiB,
	 * upstack does not. We assume all of our sizes are <= UINT16_MAX and
	 * won't receive a packet > UINT16_MAX in size.
	 */
	VERIFY3U(pkt->itxp_meo.meoi_len, <=, UINT16_MAX);

	pkt->itxp_mp = mp;

	membar_consumer();
	pkt->itxp_dma_min = ice->ice_tx_dma_min;

	/*
	 * This is arguably a bit of abuse of terms, but we start off
	 * assuming the maximum chunk of data that can be added is
	 * the frame size since the header isn't treated separately.
	 * For the LSO case, this will reflect the maximum amount of data that
	 * can be added per LSO 'chunk' that gets sent over the wire at a
	 * time (i.e. the real MSS).
	 */
	pkt->itxp_mss = txr->itxr_ice->ice_frame_size;

	mac_lso_get(mp, &mss, &lsoflags);
	VERIFY3U(mss, <=, UINT16_MAX);

	/*
	 * If we're not doing LSO or can't do LSO because it's either
	 * been disabled in the driver or the packet is too small, we
	 * proceed as a normal packet.
	 */
	if ((lsoflags & HW_LSO) == 0 || !ice->ice_tx_lso_enable ||
	    pkt->itxp_meo.meoi_len < ICE_TX_LSO_MIN_MSS) {

		/* A non-LSO packet has to respect the packet limits */
		if (pkt->itxp_meo.meoi_len > ice->ice_frame_size) {
			mutex_enter(&txr->itxr_lock);
			txr->itxr_stats.ictxs_toobig.value.ui64++;
			mutex_exit(&txr->itxr_lock);

			return (false);
		}

		/*
		 * We'll still try to send, but want to note that
		 * we were given a bad mss value from upstack.
		 *
		 * XXX: dtrace probe?
		 */
		if ((lsoflags & HW_LSO) != 0 &&
		    pkt->itxp_meo.meoi_len < ICE_TX_LSO_MIN_MSS) {
			mutex_enter(&txr->itxr_lock);
			txr->itxr_stats.ictxs_badmss.value.ui64++;
			mutex_exit(&txr->itxr_lock);
		}

		st->itps_mp = mp;
		st->itps_off = off;

		/* Copy the initial state to the current state */
		bcopy(st, &pkt->itxp_state[ITXP_CURR], sizeof (*st));

		return (true);
	}


	/*
	 * For LSO, we need to copy the header into its own buffer
	 * and add the resulting tcb. This will serve as the
	 * ultimate rollback point for the packet (we never need to
	 * recopy the header in the LSO case).
	 */
	ice_tx_ctrl_block_t	*tcb = NULL;
	uint16_t		remaining = pkt->itxp_hdrlen;

	/* Use a small buffer if possible */
	tcb = ice_tcb_alloc_buf(txr, (pkt->itxp_hdrlen <= ICE_TX_SMALL_PKT));
	if (tcb == NULL)
		return (false);

	/* It's a copy tcb, so there better only be 1 cookie */
	ASSERT3U(ice_tcb_ncookies(tcb), ==, 1);

	/* There should be enough room in the tcb for the header */
	ASSERT3U(ice_tcb_remaining(tcb), >=, pkt->itxp_hdrlen);

	while (remaining > 0) {
		uint16_t n;

		n = ice_tx_copy_fragment(tcb, &mp, &off, remaining);
		ASSERT3U(n, >, 0);

		remaining -= n;
	}

	pkt->itxp_head = tcb;

	/*
	 * Note that itps_seglen and itps_segcnt are left initialized to zero.
	 * The MSS value already accounts for the size of the header, so
	 * it's not included in tracking the current segment size. Similarly,
	 * when adding a tcb, we already account there for the descriptor
	 * used for the header
	 */
	st->itps_mp = mp;
	st->itps_off = off;
	st->itps_ndesc = 1;
	st->itps_copy_bytes = pkt->itxp_hdrlen;
	st->itps_copy_segs = 1;
	st->itps_tail = tcb;

	/*
	 * Since we are beginning, the current state represents both
	 * the initial rollback point and the 'desperation' rollback
	 * point. It's also the initial current state, so it's copied
	 * from ITXP_INIT to both ITXP_PREV and ITXP_CURR.
	 */
	bcopy(st, &pkt->itxp_state[ITXP_CURR], sizeof (*st));
	bcopy(st, &pkt->itxp_state[ITXP_PREV], sizeof (*st));

	pkt->itxp_flags |= ITPF_LSO;

	return (true);
}

static void
ice_tx_pkt_fini(ice_tx_pkt_t *pkt)
{
	ice_tx_ctrl_block_t	*tcb, *next;

	tcb = pkt->itxp_head;
	while (tcb != NULL) {
		next = tcb->itcb_next;

		tcb->itcb_next = NULL;
		ice_tcb_free(tcb);

		tcb = next;
	}

	bzero(pkt, sizeof (*pkt));
}

static inline const ddi_dma_cookie_t *
ice_tx_pkt_iter_cookie(ice_tx_pkt_iter_t *iter)
{
	if (iter->itpi_ic == NULL)
		return (NULL);

	iter->itpi_cookie = *iter->itpi_ic;

	/*
	 * itcb_len is the total length of data managed by the tcb.
	 * When we are copying data into a preallocated DMA buffer
	 * (ITCB_SMALL_COPY or ITCB_COPY), it's possible the destination
	 * DMA buffer (and thus it's cookie size) will be larger than
	 * the actual amount of valid data in it.
	 *
	 * When we're doing DMA binding though, we expect each
	 * cookie for the DMA handle to reflect the actual amount of
	 * data present.
	 */
	if (iter->itpi_ic->dmac_size > iter->itpi_tcb->itcb_len) {
		ASSERT3S(iter->itpi_tcb->itcb_type, !=, ITCB_BIND);
		ASSERT3S(iter->itpi_tcb->itcb_type, !=, ITCB_LSO_BIND);
		iter->itpi_cookie.dmac_size = iter->itpi_tcb->itcb_len;
	}

	return (&iter->itpi_cookie);
}

static void
ice_tx_pkt_iter_init(ice_tx_pkt_t *pkt, ice_tx_pkt_iter_t *iter)
{
	iter->itpi_tcb = pkt->itxp_head;
	iter->itpi_dmah = ice_tcb_dma_handle(iter->itpi_tcb);
	iter->itpi_ic = NULL;
}

static const ddi_dma_cookie_t *
ice_tx_pkt_iter(ice_tx_pkt_iter_t *iter)
{
	if (iter->itpi_tcb == NULL)
		return (NULL);

	ASSERT3P(iter->itpi_dmah, !=, NULL);
	ASSERT3U(iter->itpi_tcb->itcb_len, >, 0);

	iter->itpi_ic = ddi_dma_cookie_iter(iter->itpi_dmah, iter->itpi_ic);
	if (iter->itpi_ic == NULL) {
		iter->itpi_tcb = iter->itpi_tcb->itcb_next;
		if (iter->itpi_tcb == NULL)
			return (NULL);

		iter->itpi_dmah = ice_tcb_dma_handle(iter->itpi_tcb);
		iter->itpi_ic = ddi_dma_cookie_iter(iter->itpi_dmah, NULL);

		/* If we have a tcb, we should have at least 1 cookie */
		ASSERT3P(iter->itpi_ic, !=, NULL);
	}

	/*
	 * For a BIND or LSO_BIND tcb, the dma cookies will reflect
	 * the exact amount of data present. However for a copy or
	 * small copy tcb, the DMA cookie size (dmac_size) is the
	 * size of the allocated buffer. This can be larger than the
	 * amount of valid data in the buffer. For those tcbs, the
	 * total size of of data managed by the tcb (itcb_size) is
	 * the amount of data present in the first cookie (all
	 * copy buffers are explicitly allocated to only have 1
	 * cookie).
	 */
	iter->itpi_cookie = *iter->itpi_ic;
	if (iter->itpi_ic->dmac_size > iter->itpi_tcb->itcb_len) {
		ASSERT3S(iter->itpi_tcb->itcb_type, !=, ITCB_BIND);
		ASSERT3S(iter->itpi_tcb->itcb_type, !=, ITCB_LSO_BIND);
		ASSERT3U(ddi_dma_ncookies(iter->itpi_dmah), ==, 1);

		iter->itpi_cookie.dmac_size = iter->itpi_tcb->itcb_len;
	}

	return (&iter->itpi_cookie);
}

static inline bool
ice_tx_try_bind(ice_tx_pkt_t *pkt, size_t len)
{
	if (pkt->itxp_method == ITPM_NORMAL &&
	    len >= pkt->itxp_dma_min) {
		return (true);
	}

	return (false);
}

/*
 * Prepares the pkt for transmission. Copy and/or DMA map each mblk segment.
 * Returns true on success, false if insufficient resources are available
 * and the caller should retry/reschedule sending the packet.
 */
static bool
ice_tx_prepare_pkt(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt)
{
	ice_tx_ctrl_block_t		*copy_tcb = NULL;
	ice_tx_ctrl_block_t		*bind_tcb = NULL;
	mblk_t				*mp;
	uint16_t			off;
	size_t				mlen;
	bool				copy = false;

	mp = pkt->itxp_state[ITXP_CURR].itps_mp;
	off = pkt->itxp_state[ITXP_CURR].itps_off;

	if (mp == NULL) {
		/*
		 * A bit of an odd case -- we're asked to to LSO on
		 * a header-only packet (i.e. no TCP data).
		 * in this case there's nothing to do -- we've already
		 * copied the header into the initial tcb.
		 *
		 * XXX: Stat for this? dtrace probe?
		 */
		ASSERT(ice_tx_pkt_lso(pkt));
		ASSERT3U(pkt->itxp_state[ITXP_CURR].itps_ndesc, ==, 1);
		ASSERT3U(pkt->itxp_head, !=, NULL);
		ASSERT3U(pkt->itxp_hdrlen, ==, ice_tx_pkt_msglen(pkt));

		pkt->itxp_flags |= ITPF_DONE;
		return (true);
	}

	if (ice_tx_pkt_msglen(pkt) <= ICE_TX_SMALL_PKT &&
	    ice_tx_pkt_msglen(pkt) < pkt->itxp_dma_min) {
		copy_tcb = ice_tcb_alloc_buf(txr, true);
		if (copy_tcb == NULL)
			return (false);

		copy = true;
	}

	/*
	 * As we work through the data in the packet, we deal in contiguous
	 * spans of data in the packet at a time. In other words, the range
	 * [mp->b_rptr + off, bp->b_wptr). As such, `mp` + `off` track our
	 * current position in the packet. For each span, we either DMA bind
	 * or copy the contents to a tcb. In either case, `mp` and `off`
	 * are advanced past the data associated with the tcb. When we
	 * add a tcb to the list for this packet, we call
	 * ice_tx_pkt_add_tcb() with the tcb and the value of mp and off after
	 * they've been advanced so that potentially be a checkpoint for
	 * rollback if necessary (see big theory statement at the top).
	 *
	 * The general approach is to DMA bind larger spans and copy smaller
	 * spans. If the DMA binding fails, we fall back and attempt to
	 * copy instead. If there are several consecutive small spans in
	 * the packet, we also will copy the contents into a single tcb.
	 */
	while (mp != NULL) {
		mlen = MBLKL(mp) - off;

		/*
		 * As nonsensical as this might seem, it is unfortunately
		 * completely legitimate to have an arbitrary number of
		 * 0-byte (MBLKL) mblk_ts linked via b_cont. We just
		 * skip to the copy case which will advance mp for us
		 * while preserving the ability to coalesce consecutive
		 * spans into a single copy buffer.
		 */
		if (mlen == 0)
			goto try_copy;

		/* Try to bind if we can */
		if (!copy && pkt->itxp_method == ITPM_NORMAL &&
		    pkt->itxp_dma_min <= mlen) {
			/*
			 * Even if we're out of tcbs, we might be able to
			 * copy the fragment into the copy tcb.
			 */
			bind_tcb = ice_tcb_alloc(txr);
			if (bind_tcb == NULL)
				goto try_copy;

			/*
			 * If the previous loop iteration did a copy, we
			 * want to hold off adding copy_tcb until the
			 * current span of packet data has been successfully
			 * bound to bind_tcb. Since copying or binding data
			 * advances the packet position (mp + off), we need
			 * to save the mp position of copy_tcb until after
			 * we've successfully bound.
			 */
			mblk_t			*cpy_mp = mp;
			uint16_t		cpy_off = off;

			if (!ice_tx_bind_fragment(pkt, bind_tcb, &mp, &off)) {
				ice_tcb_free(bind_tcb);
				bind_tcb = NULL;
				goto try_copy;
			}

			/*
			 * Note we have to add copy_tcb first. It has the data
			 * from the previous iteration of the loop. If tcb is
			 * NULL, ice_tx_pkg_add_tcb() ignores it and
			 * returns success.
			 */
			if (!ice_tx_pkt_add_tcb(pkt, copy_tcb, cpy_mp,
			    cpy_off)) {
				ice_tcb_free(copy_tcb);
				ice_tcb_free(bind_tcb);
				copy_tcb = NULL;
				bind_tcb = NULL;
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}
			/*
			 * Now that copy_tcb has been added, no further data
			 * can be appened to it. copy_tcb is set to NULL
			 * so we're forced to allocate a new tcb for
			 * any subsequent copying (in a future iteration
			 * of the loop).
			 */
			copy_tcb = NULL;

			/* Now add the bound tcb */
			if (!ice_tx_pkt_add_tcb(pkt, bind_tcb, mp, off)) {
				ice_tcb_free(bind_tcb);
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}

			bind_tcb = NULL;
			continue;
		}

try_copy:
		IMPLY(copy_tcb != NULL, ice_tcb_is_copy(copy_tcb));

		if (copy_tcb == NULL) {
			copy_tcb = ice_tcb_alloc_buf(txr, false);
			if (copy_tcb == NULL)
				return (false);
		}

		(void) ice_tx_copy_fragment(copy_tcb, &mp, &off, mlen);

		/*
		 * If the tcb is full or this is the last mblk_t fragment,
		 * then add it to pkt.
		 */
		if (ice_tcb_remaining(copy_tcb) == 0 || mp == NULL) {
			IMPLY(mp == NULL, off == 0);

			if (!ice_tx_pkt_add_tcb(pkt, copy_tcb, mp, off)) {
				ice_tcb_free(copy_tcb);
				copy_tcb = NULL;
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}

			/* Need to start a new tcb next time around */
			copy_tcb = NULL;
		}
	}

	return (true);
}

/*
 * Initialize the necessary descriptor values for HW checksum offload.
 * Returns true on success, false if the checksum data was malformed and
 * the packet should be dropped.
 *
 * On success, the TX context descriptor in tx_ctx is set with the necessary
 * values for LSO (if LSO is used, otherwise it's ignored) and the qword1
 * data descriptor hw checksum fields are set in *qw1p. This is bitwise-ORed
 * with the descriptor specific fields (e.g. data descriptor length) to
 * form the final qword1 value to write to the descriptor.
 *
 * NOTE all values of the TX context descriptor and *qw1p are all in
 * local byte order.
 */
static bool
ice_tx_hcksum_init(ice_tx_pkt_t *pkt, ice_tx_desc_t *tx_ctx, uint64_t *qw1p)
{
	const mac_ether_offload_info_t	*meo = &pkt->itxp_meo;
	ice_txq_stat_t			*stats = &pkt->itxp_ring->itxr_stats;
	uint64_t			cmd = 0;
	uint64_t			offset = 0;
	uint32_t			start, chkflags;

	mac_hcksum_get(pkt->itxp_mp, &start, NULL, NULL, NULL, &chkflags);

	if (chkflags & HCK_IPV4_HDRCKSUM) {
		if ((meo->meoi_flags & MEOI_L2INFO_SET) == 0) {
			stats->ictxs_hck_nol2info.value.ui64++;
			return (false);
		}
		if ((meo->meoi_flags & MEOI_L3INFO_SET) == 0) {
			stats->ictxs_hck_nol3info.value.ui64++;
			return (false);
		}
		if (meo->meoi_l3proto != ETHERTYPE_IP) {
			stats->ictxs_hck_badl3.value.ui64++;
			return (false);
		}

		cmd = ICE_TX_DESC_CMD_SET_IIPT(cmd,
		    ICE_TX_DESC_CMD_IIPT_IPV4_CKSUM);

		/* This is in units of words (uint16_t's) */
		offset = ICE_TX_DESC_OFFSET_SET_MACLEN(offset,
		    meo->meoi_l2hlen >> 1);

		/* While this is in units of dwords (uint32_t's) */
		offset = ICE_TX_DESC_OFFSET_SET_IPLEN(offset,
		    meo->meoi_l3hlen >> 2);
	}

	if (chkflags & HCK_PARTIALCKSUM) {
		if ((meo->meoi_flags & MEOI_L4INFO_SET) == 0) {
			stats->ictxs_hck_nol4info.value.ui64++;
			return (false);
		}

		if ((chkflags & HCK_IPV4_HDRCKSUM) == 0) {
			if ((meo->meoi_flags & MEOI_L2INFO_SET) == 0) {
				stats->ictxs_hck_nol2info.value.ui64++;
				return (false);
			}
			if ((meo->meoi_flags & MEOI_L3INFO_SET) == 0) {
				stats->ictxs_hck_nol3info.value.ui64++;
				return (false);
			}

			switch (meo->meoi_l3proto) {
			case ETHERTYPE_IP:
				cmd = ICE_TX_DESC_CMD_SET_IIPT(cmd,
				    ICE_TX_DESC_CMD_IIPT_IPV4_NOCKSUM);
				break;
			case ETHERTYPE_IPV6:
				cmd = ICE_TX_DESC_CMD_SET_IIPT(cmd,
				    ICE_TX_DESC_CMD_IIPT_IPV6);
				break;
			default:
				stats->ictxs_hck_badl3.value.ui64++;
				return (false);
			}

			/* This is in units of words (uint16_t's) */
			offset = ICE_TX_DESC_OFFSET_SET_MACLEN(offset,
			    meo->meoi_l2hlen >> 1);

			/* This is in units of dwords (uint32_t's) */
			offset = ICE_TX_DESC_OFFSET_SET_IPLEN(offset,
			    meo->meoi_l3hlen >> 2);
		}

		switch (meo->meoi_l4proto) {
		case IPPROTO_TCP:
			cmd = ICE_TX_DESC_CMD_SET_L4T(cmd,
			    ICE_TX_DESC_CMD_L4T_TCP);
			break;
		case IPPROTO_UDP:
			cmd = ICE_TX_DESC_CMD_SET_L4T(cmd,
			    ICE_TX_DESC_CMD_L4T_UDP);
			break;
		case IPPROTO_SCTP:
			cmd = ICE_TX_DESC_CMD_SET_L4T(cmd,
			    ICE_TX_DESC_CMD_L4T_SCTP);
			break;
		default:
			stats->ictxs_hck_badl4.value.ui64++;
			return (false);
		}

		/* This is in units of dwords (uint32_t's) */
		offset = ICE_TX_DESC_OFFSET_SET_L4LEN(offset,
		    meo->meoi_l4hlen >> 2);
	}

	/*
	 * 10.5.3.1.1 - For TSO (aka LSO), if IPV4, the L4T must be 0b11
	 * (aka ICE_TX_DESC_CMD_IIPT_IPV4_CKSUM)
	 */
	IMPLY(ice_tx_pkt_lso(pkt),
	    (ICE_TX_DESC_CMD_IIPT(cmd) == ICE_TX_DESC_CMD_IIPT_IPV4_CKSUM) ||
	    (ICE_TX_DESC_CMD_IIPT(cmd) == ICE_TX_DESC_CMD_IIPT_IPV6));

	/* Also if L4T != 0, L4LEN must be set */
	IMPLY(ICE_TX_DESC_CMD_L4T(cmd) != 0,
	    ICE_TX_DESC_OFFSET_L4LEN(offset) != 0);

	*qw1p = ICE_TX_DESC_SET_CMD(*qw1p, cmd);
	*qw1p = ICE_TX_DESC_SET_OFFSET(*qw1p, offset);

	/* If IL2TAG1 is not set, L2TAG1 should be set to zero */
	IMPLY((*qw1p & ICE_TX_DESC_CMD_IL2TAG1) == 0,
	    ICE_TX_DESC_L2TAG1(*qw1p) == 0);

	if (!ice_tx_pkt_lso(pkt))
		return (true);

	tx_ctx->itxd_qw0 = 0;

	tx_ctx->itxd_qw1 = ICE_TX_DESC_SET_DTYPE(0, ICE_TX_DESC_DTYPE_TCTX);
	tx_ctx->itxd_qw1 = ICE_TX_CTXD_SET_CMD(tx_ctx->itxd_qw1,
	    ICE_TX_CTXD_CMD_TSO);
	tx_ctx->itxd_qw1 = ICE_TX_CTXD_SET_MSS(tx_ctx->itxd_qw1, pkt->itxp_mss);
	tx_ctx->itxd_qw1 = ICE_TX_CTXD_SET_TLEN(tx_ctx->itxd_qw1,
	    ice_tx_pkt_msglen(pkt) - pkt->itxp_hdrlen);

	return (true);
}

/*
 * Attempt to write the descriptors out to the TX ring. Returns:
 *	>0	The number of descriptors consumed on the ring
 *	0	Insufficient space on the ring, reschedule.
 *	-1	Error with packet, caller should drop.
 */
static int
ice_tx_send_pkt(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_pkt_state_t	*st = &pkt->itxp_state[ITXP_CURR];
	ice_tx_desc_t		*desc = NULL;
	ice_tx_desc_t		tx_ctx_desc;
	uint64_t		init_qw1;
	uint16_t		tail;
	uint16_t		desc_needed;
	uint16_t		desc_used;
	ice_tx_pkt_iter_t	iter;
	const ddi_dma_cookie_t	*c;

	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	ASSERT((pkt->itxp_flags & ITPF_DONE) != 0);

	desc_needed = ice_tx_pkt_desc_needed(pkt);

	ASSERT3U(desc_needed, >, 0);
	ASSERT3U(desc_needed, <=, txr->itxr_avail);

	(void) ice_tx_pkt_sync(pkt);

	tx_ctx_desc.itxd_qw0 = 0;
	tx_ctx_desc.itxd_qw1 = 0;

	init_qw1 = ICE_TX_DESC_SET_CMD(0, ICE_TX_DESC_CMD_RESV);

	if (ice->ice_tx_hcksum_enable &&
	    !ice_tx_hcksum_init(pkt, &tx_ctx_desc, &init_qw1)) {
		return (-1);
	}

	desc_used = 0;

	tail = txr->itxr_tail;

	if (ice_tx_pkt_lso(pkt)) {
		desc = &txr->itxr_descs[tail];

		/* Write out the TX context descriptor to the ring */
		desc->itxd_qw0 = LE_64(tx_ctx_desc.itxd_qw0);
		desc->itxd_qw1 = LE_64(tx_ctx_desc.itxd_qw1);

		txr->itxr_tcbs[tail] = NULL;

		tail = ice_tx_next(txr, tail, 1);
		desc_used++;
	}

	ice_tx_pkt_iter_init(pkt, &iter);
	while ((c = ice_tx_pkt_iter(&iter)) != NULL) {
		uint64_t qw1;

		desc = &txr->itxr_descs[tail];

		qw1 = ICE_TX_DESC_SET_DTYPE(init_qw1, ICE_TX_DESC_DTYPE_DATA);
		qw1 = ICE_TX_DESC_SET_BSIZE(qw1, c->dmac_size);

		desc->itxd_qw0 = LE_64(c->dmac_laddress);
		desc->itxd_qw1 = LE_64(qw1);

		tail = ice_tx_next(txr, tail, 1);
		desc_used++;
	}
	ASSERT3U(desc_used, ==, desc_needed);

	/*
	 * desc is now the last descriptor, set the EOP and RS (report
	 * status) bits. Note since the existing value is already
	 * little endian (from the above loop), we just bitwise-OR
	 * the flags in instead of converting to native, setting the bits
	 * and converting back. It's all a nop for x86 and arm, but
	 * we want to correct.
	 */
	desc->itxd_qw1 |= LE_64(ICE_TX_DESC_SET_CMD(0,
	    ICE_TX_DESC_CMD_EOP|ICE_TX_DESC_CMD_RS));

	/* Done updating descriptors, so sync the ring to the device */
	if (!ice_dma_sync(txr->itxr_ice, &txr->itxr_dma, DDI_DMA_SYNC_FORDEV)) {
		uint64_t start = txr->itxr_tail;

		/*
		 * If we hit a fatal error, it likely stops the entire
		 * device, but to be nice, clear out everything we wrote.
		 */
		while (start != tail) {
			txr->itxr_descs[start].itxd_qw0 = 0;
			txr->itxr_descs[start].itxd_qw1 = 0;
			txr->itxr_tcbs[start] = NULL;
			start = ice_tx_next(txr, start, 1);
		}

		return (-1);
	}

	txr->itxr_tail = tail;
	txr->itxr_avail -= desc_used;

	ice_reg_write(ice, ice_qtx_tail(txr), txr->itxr_tail);

	/*
	 * Save mp in the last tcb we used so we can free it when we
	 * recycle these tcbs after TX is complete. We choose the last
	 * tcb so as we recycle the tcbs, we don't free the mblk until
	 * all of the descriptors for the packet have been processed.
	 */
	ASSERT3U(st->itps_ntcbs, >, 0);
	st->itps_tail->itcb_mp = pkt->itxp_mp;

	pkt->itxp_mp = NULL;

	txr->itxr_stats.ictxs_bind_fails.value.ui64 += st->itps_bind_fails;
	txr->itxr_stats.ictxs_copy_bytes.value.ui64 += st->itps_copy_bytes;
	txr->itxr_stats.ictxs_copy_frags.value.ui64 += st->itps_copy_segs;
	txr->itxr_stats.ictxs_bind_bytes.value.ui64 += st->itps_bind_bytes;
	txr->itxr_stats.ictxs_bind_frags.value.ui64 += st->itps_bind_segs;

	if (ice_tx_pkt_lso(pkt)) {
		txr->itxr_stats.ictxs_lso_packets.value.ui64++;
		txr->itxr_stats.ictxs_lso_bytes.value.ui64 +=
		    ice_tx_pkt_msglen(pkt);
	}

	txr->itxr_stats.ictxs_packets.value.ui64++;
	txr->itxr_stats.ictxs_bytes.value.ui64 +=
	    ice_tx_pkt_msglen(pkt);

	return (desc_used);
}

mblk_t *
ice_ring_tx(void *arg, mblk_t *mp)
{
	ice_tx_ring_t	*txr = arg;
	ice_t		*ice = txr->itxr_ice;
	ice_tx_pkt_t	*pkt;

	if (!ice_is_running(txr->itxr_ice) || !ice_tx_enter(txr)) {
		freemsgchain(mp);
		return (NULL);
	}

	pkt = kmem_cache_alloc(ice_tx_pkt_cache, KM_NOSLEEP);
	if (pkt == NULL) {
		txr->itxr_stats.ictxs_no_pkt_cache.value.ui64++;
		ice_tx_exit(txr);
		return (mp);
	}

	while (mp != NULL) {
		mblk_t		*mp_next = mp->b_next;
		int		n;
		uint16_t	desc_needed;

		mp->b_next = NULL;

		if (!ice_tx_pkt_init(txr, pkt, mp)) {
			/* mp was malformed in some way, drop and continue */
			txr->itxr_stats.ictxs_drops.value.ui64++;
			bzero(pkt, sizeof (*pkt));
			mp = mp_next;
			continue;
		}

		if (!ice_tx_prepare_pkt(txr, pkt)) {
			/* No resources right now, reschedule */
			ice_tx_pkt_fini(pkt);
			mp->b_next = mp_next;
			break;
		}

		mutex_enter(&txr->itxr_lock);

		desc_needed = ice_tx_pkt_desc_needed(pkt);
		if (txr->itxr_avail < desc_needed) {
			/*
			 * Try to recycle and re-check if we can
			 * send
			 */
			ice_tx_recycle_ring(txr);
			if (txr->itxr_avail < desc_needed) {
				txr->itxr_blocked = true;
				txr->itxr_stats.ictxs_blocked.value.ui64++;

				mutex_exit(&txr->itxr_lock);

				ice_tx_pkt_fini(pkt);
				mp->b_next = mp_next;
				break;
			}
		}

		n = ice_tx_send_pkt(txr, pkt);
		if (n < 0) {
			/* Asked to drop packet */
			mutex_exit(&txr->itxr_lock);

			freemsg(mp);

			if ((ice->ice_state & ICE_ERROR) != 0) {
				freemsgchain(mp_next);
				mp = NULL;
				break;
			}

			/*
			 * If we failed for some reason other than the NIC
			 * being in an error state, we'll just move on to
			 * the next packet.
			 */
			ice_tx_pkt_fini(pkt);
			mp = mp_next;
			continue;
		}

		ASSERT(MUTEX_HELD(&txr->itxr_lock));

		ASSERT3U(n, ==, desc_needed);

		/*
		 * Move used tcbs in pkt onto the tcb ring. These will get
		 * freed when we recycle.
		 *
		 * Note that we attach the tcb to the index of the last
		 * descriptor of the packet so that we can use this
		 * to tell when a full packet is ready to be recycled.
		 */
		pkt->itxp_head->itcb_tx_time = gethrtime();
		txr->itxr_tcbs[ice_tx_prev(txr, txr->itxr_tail)] =
		    pkt->itxp_head;
		pkt->itxp_head = NULL;

		mutex_exit(&txr->itxr_lock);

		/*
		 * We've moved the TCBs from pkt onto the TX ring, so we
		 * don't want pkt to access them anymore.
		 */
		pkt->itxp_mp = NULL;

		ice_tx_pkt_fini(pkt);

		mp = mp_next;
	}

	ice_tx_pkt_fini(pkt);
	kmem_cache_free(ice_tx_pkt_cache, pkt);

	ice_tx_exit(txr);

	return (mp);
}

static inline bool
ice_tx_desc_done(const ice_tx_desc_t *desc)
{
	uint64_t dtype = ICE_TX_DESC_DTYPE(LE_64(desc->itxd_qw1));
	return (dtype == ICE_TX_DESC_DTYPE_DONE);
}

void
ice_tx_recycle_ring(ice_tx_ring_t *txr)
{
	ice_t			*ice = txr->itxr_ice;
	ice_tx_ctrl_block_t	*tcb, *next;
	uint32_t		n, head, tail;

	ASSERT(MUTEX_HELD(&txr->itxr_lock));
	ASSERT3U(txr->itxr_avail, <=, txr->itxr_size);

	if (txr->itxr_avail == txr->itxr_size) {
		if (txr->itxr_blocked) {
			txr->itxr_blocked = false;

			mutex_exit(&txr->itxr_lock);

			mac_tx_ring_update(ice->ice_mac_hdl,
			    txr->itxr_mactxring);

			mutex_enter(&txr->itxr_lock);
		}

		return;
	}

	if (!ice_dma_sync(ice, &txr->itxr_dma, DDI_DMA_SYNC_FORKERNEL)) {
		return;
	}

	/*
	 * Earlier models had a pre-tx ring register that gave you the
	 * index of the last descriptor of the most recently processed, packet.
	 * The ice NICs do not have this (technically it does, but all bits
	 * in it are marked reserved in the datasheet, though apparently
	 * Linux's ice driver uses this for watchdog purposes).
	 *
	 * We only want to recycle a packet once it has been completely
	 * transmitted. As such, we use the fact the tcb for the packet
	 * is saved on the index of the last descriptor of the packet.
	 * If the corresponding descriptor has completed, we know we
	 * can recycle that packet.
	 */
	n = 0;
	head = tail = txr->itxr_head;
	while (head != ice_tx_prev(txr, txr->itxr_head)) {
		tcb = txr->itxr_tcbs[head];
		if (tcb == NULL) {
			head = ice_tx_next(txr, head, 1);
			continue;
		}

		if (!ice_tx_desc_done(&txr->itxr_descs[head])) {
			break;
		}

		txr->itxr_tcbs[head] = NULL;
		head = ice_tx_next(txr, head, 1);

		do {
			/* Zero out used descriptors for sanity */
			txr->itxr_descs[tail].itxd_qw0 = 0;
			txr->itxr_descs[tail].itxd_qw1 = 0;

			while (tcb != NULL) {
				next = tcb->itcb_next;
				tcb->itcb_next = NULL;
				ice_tcb_free(tcb);
				tcb = next;
			}

			n++;

			tail = ice_tx_next(txr, tail, 1);
		} while (tail != head);
	}

	txr->itxr_head = tail;
	txr->itxr_avail += n;

	// XXX add tx update threshold?

	if (txr->itxr_blocked && txr->itxr_avail > 0) {
		txr->itxr_blocked = false;

		mutex_exit(&txr->itxr_lock);

		mac_tx_ring_update(ice->ice_mac_hdl,
		    txr->itxr_mactxring);

		mutex_enter(&txr->itxr_lock);
	}
}

static bool
ice_tx_setup_bufs(ice_tx_ring_t *txr)
{
	ice_t			*ice = txr->itxr_ice;
	ddi_dma_attr_t		desc_attr;
	ddi_dma_attr_t		bind_attr;
	ddi_dma_attr_t		lso_bind_attr;
	ddi_device_acc_attr_t	dev_attr;
	size_t			len;
	int			ret;

	ice_dma_ring_attr(ice, &desc_attr);
	ice_pkt_txbind_attr(ice, &bind_attr);
	ice_pkt_txbind_lso_attr(ice, &lso_bind_attr);
	ice_dma_acc_attr(ice, &dev_attr);

	len = txr->itxr_size * sizeof (ice_tx_desc_t);
	if (!ice_dma_alloc(ice, &txr->itxr_dma, &desc_attr, &dev_attr,
	    true, len, true)) {
		ice_error(ice, "failed to alloc TX descriptor ring");
		return (false);
	}
	txr->itxr_descs = (ice_tx_desc_t *)txr->itxr_dma.idb_va;

	len = txr->itxr_size * sizeof (ice_tx_ctrl_block_t *);

	txr->itxr_tcbs = kmem_zalloc(len, KM_SLEEP);
	txr->itxr_avail = txr->itxr_size;

	txr->itxr_tcb_free_list = kmem_zalloc(len, KM_SLEEP);

	for (uint_t i = 0; i < txr->itxr_size; i++) {
		ice_tx_ctrl_block_t *tcb;

		tcb = kmem_zalloc(sizeof (*tcb), KM_SLEEP);

		ret = ddi_dma_alloc_handle(ice->ice_dip, &bind_attr,
		    DDI_DMA_SLEEP, 0, &tcb->itcb_dmah);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to alloc TX DMA handle");
			kmem_free(tcb, sizeof (*tcb));
			return (false);
		}

		ret = ddi_dma_alloc_handle(ice->ice_dip, &lso_bind_attr,
		    DDI_DMA_SLEEP, 0, &tcb->itcb_lso_dmah);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to alloc TX LSO DMA handle");
			ddi_dma_free_handle(&tcb->itcb_dmah);
			kmem_free(tcb, sizeof (*tcb));
			return (false);
		}

		txr->itxr_tcb_free_list[txr->itxr_tcb_nfree++] = tcb;
	}

	return (true);
}

static void
ice_tx_teardown_bufs(ice_tx_ring_t *txr)
{
	ice_tx_ctrl_block_t *tcb;
	size_t ringlen;

	ringlen = txr->itxr_size * sizeof (ice_tx_ctrl_block_t *);

	IMPLY(txr->itxr_tcb_nfree > 0, txr->itxr_tcb_free_list != NULL);

	/*
	 * There might have been packets in flight that haven't been
	 * recycled. Put those back on the free list now.
	 */
	while (txr->itxr_avail < txr->itxr_size) {
		tcb = txr->itxr_tcbs[txr->itxr_head];
		ASSERT3P(tcb, !=, NULL);

		ice_tcb_free(tcb);
		txr->itxr_tcbs[txr->itxr_head] = NULL;
		txr->itxr_avail++;

		txr->itxr_head = ice_tx_next(txr, txr->itxr_head, 1);
	}

	if (txr->itxr_tcbs != NULL) {
		kmem_free(txr->itxr_tcbs, ringlen);
		txr->itxr_tcbs = NULL;
	}

	while (txr->itxr_tcb_nfree > 0) {
		tcb = txr->itxr_tcb_free_list[--txr->itxr_tcb_nfree];
		txr->itxr_tcb_free_list[txr->itxr_tcb_nfree] = NULL;

		ddi_dma_free_handle(&tcb->itcb_dmah);
		ddi_dma_free_handle(&tcb->itcb_lso_dmah);
		kmem_free(tcb, sizeof (*tcb));
	}

	if (txr->itxr_tcb_free_list != NULL) {
		kmem_free(txr->itxr_tcb_free_list, ringlen);
		txr->itxr_tcb_free_list = NULL;
	}

	if (txr->itxr_descs != NULL) {
		ice_dma_free(&txr->itxr_dma);
		txr->itxr_descs = NULL;
	}
}

int
ice_ring_tx_start(mac_ring_driver_t mri, uint64_t gen)
{
	ice_tx_ring_t		*txr = (ice_tx_ring_t *)mri;
	ice_t			*ice = txr->itxr_ice;
	ice_vsi_t		*vsi = list_head(&ice->ice_vsi);
	uint64_t		ring_pa;
	ice_hw_txq_context_t	ctx;

	ASSERT3P(vsi, !=, NULL);

	mutex_enter(&txr->itxr_lock);

	if (!ice_tx_setup_bufs(txr)) {
		ice_tx_teardown_bufs(txr);
		mutex_exit(&txr->itxr_lock);
		return (-1);
	}

	ring_pa = txr->itxr_dma.idb_cookie.dmac_laddress;

	/* Double check the ring's physical address is properly aligned */
	ASSERT(IS_P2ALIGNED(ring_pa, (1ULL << ICE_HW_TXQ_CTX_BASE_SHIFT)));

	bzero(&ctx, sizeof (ctx));

	ASSERT3U(vsi->ivsi_id, <=, ICE_VSI_MAX);

	ctx.ihtc_base = ring_pa >> ICE_HW_TXQ_CTX_BASE_SHIFT;
	ctx.ihtc_vmvf_type = ICE_HW_TXQ_CTX_VMVF_TYPE_PF;
	ctx.ihtc_vsi_id = vsi->ivsi_id;
	ctx.ihtc_qlen = txr->itxr_size;
	ctx.ihtc_port = ice->ice_port_id;
	ctx.ihtc_legacy = 1;
	ctx.ihtc_tso = 1;
	/*
	 * If we support multiple VSIs or RDMA, this will need to be
	 * the mapped TX queue id. We probably would also need to be
	 * mindful of the lower limit (2K vs. 16K) for TSO queues when
	 * allocating/assigning TX queues to a mac NIC.
	 *
	 * Note that this value is in PF space, so we don't need to
	 * adjust it.
	 */
	ctx.ihtc_tso_queue = txr->itxr_index;

	if (!ice_cmd_add_txq_grp(ice, vsi, txr, &ctx)) {
		ice_tx_teardown_bufs(txr);
		mutex_exit(&txr->itxr_lock);
		return (-1);
	}

	// TODO anything else?

	txr->itxr_head = txr->itxr_tail = 0;
	txr->itxr_avail = txr->itxr_size;
	txr->itxr_quiesce = false;

	mutex_exit(&txr->itxr_lock);

	return (0);
}

void
ice_ring_tx_stop(mac_ring_driver_t mri)
{
	ice_tx_ring_t		*txr = (ice_tx_ring_t *)mri;
	ice_t			*ice = txr->itxr_ice;

	(void) ice_tx_quiesce(txr);

	if (!ice_cmd_disable_queue(ice, txr)) {
		ice_error(ice, "failed to disable TX queue %u",
		    txr->itxr_index);
	}

	mutex_enter(&txr->itxr_lock);

	ice_tx_teardown_bufs(txr);

	mutex_exit(&txr->itxr_lock);
}

int
ice_ring_tx_intr_enable(mac_intr_handle_t intrh)
{
	ice_tx_ring_t	*txr = (ice_tx_ring_t *)intrh;
	ice_t		*ice = txr->itxr_ice;
	uint32_t	val;

	val = ice_reg_read(ice, ice_qint_tqctl(txr));
	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 1);
	ice_reg_write(ice, ice_qint_tqctl(txr), val);

	return (0);
}

int
ice_ring_tx_intr_disable(mac_intr_handle_t intrh)
{
	ice_tx_ring_t	*txr = (ice_tx_ring_t *)intrh;
	ice_t		*ice = txr->itxr_ice;
	uint32_t	val;

	val = ice_reg_read(ice, ice_qint_tqctl(txr));
	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 0);
	ice_reg_write(ice, ice_qint_tqctl(txr), val);

	return (0);
}

void
ice_tx_interrupt(ice_t *ice, ice_intr_handler_t *h)
{

	ice_tx_ring_t	*txr = ice_ih_to_txr(h);

	if (!ice_tx_enter(txr))
		return;

	mutex_enter(&txr->itxr_lock);

	ice_tx_recycle_ring(txr);
	ice_tx_exit_nolock(txr);

	mutex_exit(&txr->itxr_lock);
}

int
ice_ring_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ice_tx_ring_t *txr = (ice_tx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = txr->itxr_stats.ictxs_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = txr->itxr_stats.ictxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

void
ice_tx_start(ice_t *ice)
{
	ddi_dma_attr_t	attr;
	size_t		n, bufsz;

	bufsz = MIN(ice->ice_frame_size, ICE_MAX_PKT_DMA_BUFSZ);
	/* Arbitrary for now */
	n = 20000;

	ice_pkt_dma_attr(ice, &attr);
	ice_buf_pool_init(ice, &ice->ice_bufs, n, bufsz, &attr);
	ice_buf_pool_init(ice, &ice->ice_small_bufs, n / 3, ICE_TX_SMALL_PKT,
	    &attr);
}

void
ice_tx_stop(ice_t *ice)
{
	ice_buf_pool_fini(&ice->ice_small_bufs);
	ice_buf_pool_fini(&ice->ice_bufs);
}

static int
ice_tx_pkt_ctor(void *buf, void *arg __unused, int kmflags)
{
	bzero(buf, sizeof (ice_tx_pkt_t));
	return (0);
}

void
ice_tx_init(void)
{
	ice_tx_pkt_cache = kmem_cache_create("ice_tx_pkt_t",
	    sizeof (ice_tx_pkt_t), 64, ice_tx_pkt_ctor, NULL, NULL, NULL,
	    NULL, 0);
}

void
ice_tx_fini(void)
{
	kmem_cache_destroy(ice_tx_pkt_cache);

	ice_tx_pkt_cache = NULL;
}
