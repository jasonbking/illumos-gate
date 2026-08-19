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

typedef struct ice_tx_pkt {
	ice_tx_ring_t		*itxp_ring;
	mblk_t			*itxp_mp;
	mac_ether_offload_info_t itxp_meo;
	size_t			itxp_hdrlen;	/* Size of L2+L3+L4 headers */

	ice_tx_ctrl_block_t	*itxp_tcbs;
	ice_tx_ctrl_block_t	*itxp_tcb_tail;
	size_t			itxp_ntcbs;
	size_t			itxp_ndesc;

	bool			itxp_done;
	bool			itxp_lso;
	ice_tx_pkt_method_t	itxp_method;
	uint32_t		itxp_mss;

	uint32_t		itxp_dma_min;

	/* mss frame tracking */
	uint16_t		itxp_seglen;
	uint8_t			itxp_segcnt;
	uint8_t			itxp_segmax;

	/* Stats for this packet */
	uint32_t		itxp_bind_fails;

	uint32_t		itxp_mss_retries;
	uint32_t		itxp_mss_full_copies;

	uint32_t		itxp_copy_bytes;
	uint32_t		itxp_copy_segs;
	uint32_t		itxp_bind_bytes;
	uint32_t		itxp_bind_segs;

	/* rollback state */
	mblk_t			*itxp_prev_mp_seg;
	size_t			itxp_prev_off;

	ice_tx_ctrl_block_t	*itxp_prev_tcb_tail;
	uint16_t		itxp_prev_ndesc;
	uint16_t		itxp_prev_seglen;
	uint8_t			itxp_prev_segcnt;
	uint8_t			itxp_prev_ntcbs;

	uint32_t		itxp_prev_copy_bytes;
	uint32_t		itxp_prev_copy_segs;
	uint32_t		itxp_prev_bind_bytes;
	uint32_t		itxp_prev_bind_segs;

	/* initial state for rolling back to start of packet */
	mblk_t			*itxp_init_mp_seg;
	size_t			itxp_init_off;
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
ice_tx_pkt_checkpoint(ice_tx_pkt_t *pkt, mblk_t *mp, size_t off)
{
	pkt->itxp_prev_seglen = pkt->itxp_seglen;
	pkt->itxp_prev_segcnt = pkt->itxp_segcnt;

	pkt->itxp_prev_tcb_tail = pkt->itxp_tcb_tail;
	pkt->itxp_prev_ntcbs = pkt->itxp_ntcbs;
	pkt->itxp_prev_ndesc = pkt->itxp_ndesc;
	pkt->itxp_prev_mp_seg = mp;
	pkt->itxp_prev_off = off;

	pkt->itxp_prev_copy_bytes = pkt->itxp_copy_bytes;
	pkt->itxp_prev_copy_segs = pkt->itxp_copy_segs;
	pkt->itxp_prev_bind_bytes = pkt->itxp_bind_bytes;
	pkt->itxp_prev_bind_segs = pkt->itxp_bind_segs;
}

static inline size_t
ice_tx_pkt_msglen(const ice_tx_pkt_t *pkt)
{
	return (pkt->itxp_meo.meoi_len);
}

static inline uint16_t
ice_tx_pkt_desc_needed(const ice_tx_pkt_t *pkt)
{
	uint16_t n = pkt->itxp_ndesc;

	/*
	 * LSO requires an additional descriptor to hold the TX
	 * context
	 */
	if (pkt->itxp_lso)
		n++;

	return (n);
}


/*
 * Add a `tcb `to `pkt` . `mp` and `off` reflect the location in the packet
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
    size_t off)
{
	const ddi_dma_cookie_t	*c;
	ddi_dma_handle_t	h;
	size_t			init_ndesc;
	uint16_t		init_seglen;
	uint8_t			init_segcnt;
	bool			need_checkpoint;

	if (tcb == NULL)
		return (true);

	ASSERT(!pkt->itxp_done);

	IMPLY(mp == NULL, off == 0);

	h = ice_tcb_dma_handle(tcb);

	/*
	 * For non-LSO, we're limited to ICE_TX_MAX_COOKIE (8) cookies
	 * total. We fail saving so we can fall back to copying.
	 */
	if (!pkt->itxp_lso &&
	    pkt->itxp_segcnt + ice_tcb_ncookies(tcb) > ICE_TX_MAX_COOKIE) {
		return (false);
	}

	init_ndesc = pkt->itxp_ndesc;
	init_seglen = pkt->itxp_seglen;
	init_segcnt = pkt->itxp_segcnt;
	need_checkpoint = false;

	/*
	 * A copy TCB uses a preallocated DMA buffer constructed so that
	 * it should only ever use 1 cookie.
	 */
	IMPLY(ice_tcb_is_copy(tcb), ddi_dma_ncookies(h) == 1);

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
		 * and itxp_segcnt. If we are at the maximum and start
		 * the loop again, we've failed (and need to resort to
		 * some amount of copying).
		 */
		if (pkt->itxp_segcnt == pkt->itxp_segmax)
			goto fail;

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
		pkt->itxp_ndesc++;

		/* Update our mss frame accounting */
		pkt->itxp_segcnt++;
		pkt->itxp_seglen += len;

		if (pkt->itxp_seglen >= pkt->itxp_mss) {
			/*
			 * We've cross an mss boundary. If we're not doing
			 * LSO, that means we've got a packet larger than
			 * our MTU. If we are doing LSO, we need to reset
			 * the counters for the current mss segment.
			 */
			if (!pkt->itxp_lso)
				goto fail;

			/*
			 * If this descriptor straddles an mss boundary,
			 * the NIC will DMA the remaining data in the
			 * descriptor when it starts the next packet, so
			 * we must reflect that in our accounting
			 */
			pkt->itxp_seglen %= pkt->itxp_mss;
			pkt->itxp_segcnt = (pkt->itxp_seglen == 0) ? 0 : 1;

			/*
			 * But we also need create a new checkpoint once
			 * we've finished adding this tcb
			 */
			need_checkpoint = true;
		}
	}

	/* Append this tcb onto the end of the list */
	if (pkt->itxp_tcb_tail != NULL) {
		pkt->itxp_tcb_tail->itcb_next = tcb;
	} else {
		pkt->itxp_tcbs = tcb;
	}
	pkt->itxp_tcb_tail = tcb;
	pkt->itxp_ntcbs++;

	if (need_checkpoint) {
		ASSERT(pkt->itxp_lso);
		ice_tx_pkt_checkpoint(pkt, mp, off);

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
		pkt->itxp_done = true;

	return (true);

fail:
	pkt->itxp_ndesc = init_ndesc;
	pkt->itxp_segcnt = init_segcnt;
	pkt->itxp_seglen = init_seglen;

	return (false);
}

static bool
ice_tx_pkt_sync(ice_tx_pkt_t *pkt)
{
	ice_tx_ctrl_block_t *tcb = pkt->itxp_tcbs;

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
ice_tx_pkt_retry_mss_seg(ice_tx_pkt_t *pkt, mblk_t **mpp, size_t *offp)
{
	ice_tx_ctrl_block_t *tcb;
	ice_tx_ctrl_block_t *next;

	/* We should never retry once we're copying the whole packet */
	VERIFY3S(pkt->itxp_method, !=, ITPM_COPY_ALL);

	pkt->itxp_mss_retries++;

	if (pkt->itxp_method == ITPM_COPY_MSS) {
		/*
		 * We need to rollback to the initial packet state. This
		 * should only ever happen with LSO packets -- since a non
		 * LSO packet only ever results in a single frame on the
		 * wire, the initial rewind of the current mss segment IS
		 * the start of the packet and there is no possible
		 * spillover from a previous frame as there is with LSO, so
		 * we should only ever have to attempt this once.
		 */
		VERIFY(pkt->itxp_lso);

		pkt->itxp_prev_mp_seg = pkt->itxp_init_mp_seg;
		pkt->itxp_prev_off = pkt->itxp_init_off;
		pkt->itxp_prev_tcb_tail = pkt->itxp_tcbs;
		pkt->itxp_prev_seglen = 0;
		pkt->itxp_prev_segcnt = 0;
		pkt->itxp_prev_ntcbs = 1;
		pkt->itxp_prev_ndesc = 1;
		pkt->itxp_mss_full_copies++;

		// XXX dtrace probe?
	}

	pkt->itxp_tcb_tail = pkt->itxp_prev_tcb_tail;

	/*
	 * Release all of the entries _after_ the previous tail so it
	 * becomes the new tail.
	 *
	 * If there is no previous tail, this can only happen for a non-LSO
	 * packet as we always have the initial tcb for the header (which
	 * always stays)
	 */
	if (pkt->itxp_prev_tcb_tail == NULL) {
		ASSERT(!pkt->itxp_lso);

		tcb = pkt->itxp_tcbs;
		pkt->itxp_tcbs = NULL;
	} else {
		/*
		 * Release all of the entries _after_ the previous tail so it
		 * becomes the new tail.
		 */
		tcb = pkt->itxp_tcb_tail->itcb_next;
		pkt->itxp_tcb_tail->itcb_next = NULL;
	}

#ifdef	DEBUG
	uint32_t ndesc = 0;
#endif

	while (tcb != NULL) {
		next = tcb->itcb_next;

		tcb->itcb_next = NULL;
#ifdef	DEBUG
		ndesc += ddi_dma_ncookies(ice_tcb_dma_handle(tcb));
#endif

		ice_tcb_free(tcb);
		tcb = next;

		pkt->itxp_ntcbs--;
	}
	ASSERT3U(pkt->itxp_ntcbs, ==, pkt->itxp_prev_ntcbs);

	/* Adjust our statistics */
	pkt->itxp_copy_bytes = pkt->itxp_prev_copy_bytes;
	pkt->itxp_copy_segs = pkt->itxp_prev_copy_segs;
	pkt->itxp_bind_bytes = pkt->itxp_prev_bind_bytes;
	pkt->itxp_bind_segs = pkt->itxp_prev_bind_segs;

	/*
	 * Since we're able to crosscheck this, verify the number of
	 * DMA cookies (thus the number of descriptors needed) we
	 * rollback leaves us with what we checkpointed.
	 */
	ASSERT3U(pkt->itxp_ndesc, >=, ndesc);
	ASSERT3U(pkt->itxp_ndesc - ndesc, ==, pkt->itxp_prev_ndesc);
	pkt->itxp_ndesc = pkt->itxp_prev_ndesc;

	pkt->itxp_seglen = pkt->itxp_prev_seglen;
	pkt->itxp_segcnt = pkt->itxp_prev_segcnt;

	*mpp = pkt->itxp_prev_mp_seg;
	*offp = pkt->itxp_prev_off;

	/* Advance to the next method */
	pkt->itxp_method++;
}

static uint_t
ice_tx_copy_fragment(ice_tx_pkt_t *pkt, ice_tx_ctrl_block_t *tcb,
    const mblk_t *mp, size_t off, size_t len)
{
	const void	*src = mp->b_rptr + off;
	void		*dest = tcb->itcb_buf->idb_va + tcb->itcb_len;
	size_t		to_copy = MIN(ice_tcb_remaining(tcb), len);

	ASSERT3U(tcb->itcb_type, !=, ITCB_BIND);
	ASSERT3U(tcb->itcb_type, !=, ITCB_LSO_BIND);
	ASSERT3U(to_copy, >, 0);

	ASSERT3P(src, >=, mp->b_rptr);
	ASSERT3P(src, <, mp->b_wptr);
	ASSERT3U(to_copy, <=, MBLKL(mp));
	ASSERT3U((uintptr_t)src + to_copy, <=, (uintptr_t)mp->b_wptr);
	ASSERT3U(tcb->itcb_len + to_copy, <=, tcb->itcb_buf->idb_len);

	bcopy(src, dest, to_copy);
	tcb->itcb_len += to_copy;

	pkt->itxp_copy_bytes += to_copy;
	pkt->itxp_copy_segs++;

	return (to_copy);
}

static ice_tx_ctrl_block_t *
ice_tx_bind_fragment(ice_tx_pkt_t *pkt, const mblk_t *mp, size_t off,
    size_t len)
{
	ice_tx_ctrl_block_t	*tcb;
	ddi_dma_handle_t	h;
	int			ret;

	tcb = ice_tcb_alloc(pkt->itxp_ring);
	if (tcb == NULL)
		return (NULL);

	/*
	 * We need to set this now so we can obtain the correct DMA
	 * handle.
	 */
	tcb->itcb_type = pkt->itxp_lso ? ITCB_LSO_BIND : ITCB_BIND;

	h = ice_tcb_dma_handle(tcb);
	ret = ddi_dma_addr_bind_handle(h, NULL, (caddr_t)(mp->b_rptr + off),
	    MBLKL(mp) - off, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, NULL, NULL);
	if (ret != DDI_DMA_MAPPED) {
		/* Reset the type so we don't try to unbind in ice_tcb_free() */
		tcb->itcb_type = ITCB_NOT_USED;
		ice_tcb_free(tcb);
		pkt->itxp_bind_fails++;
		return (NULL);
	}

	tcb->itcb_len = len;
	pkt->itxp_bind_bytes += len;
	pkt->itxp_bind_segs++;

	return (tcb);
}

/*
 * Initialize pkt to transmit mp. Sets initial values in preparation for
 * copying & mapping mblk segments. Returns true on success. Returns false
 * if mp is malformed (and should be dropped).
 */
static bool
ice_tx_pkt_init(ice_tx_ring_t *txr, ice_tx_pkt_t *pkt, mblk_t *mp)
{
	ice_t		*ice = txr->itxr_ice;
	uint32_t	lsoflags;

	ASSERT(!MUTEX_HELD(&txr->itxr_lock));

	bzero(pkt, sizeof (*pkt));

	mac_ether_offload_info(mp, &pkt->itxp_meo);

	pkt->itxp_ring = txr;
	pkt->itxp_hdrlen = pkt->itxp_meo.meoi_l2hlen +
	    pkt->itxp_meo.meoi_l3hlen + pkt->itxp_meo.meoi_l4hlen;

	/* XXX probably should log this, maybe even a dtrace probe */
	if (pkt->itxp_meo.meoi_len < pkt->itxp_hdrlen)
		return (false);

	pkt->itxp_mp = mp;
	pkt->itxp_segmax = ICE_TX_MAX_COOKIE;

	membar_consumer();
	pkt->itxp_dma_min = ice->ice_tx_dma_min;

	pkt->itxp_init_mp_seg = mp;
	pkt->itxp_init_off = 0;

	mac_lso_get(mp, &pkt->itxp_mss, &lsoflags);
	if ((lsoflags & HW_LSO) != 0) {
		/*
		 * Since we're doing LSO, each packet that goes out the
		 * wire consists of pkt->itxp_hdrlen bytes (the header) +
		 * up to pkt->itxp_mss bytes of data (the final packet
		 * that gets sent may have less).
		 *
		 * XXX Since this is coming from mac_ether_offload_info(),
		 * can we rely on sanity and turn this into an ASSERT()?
		 */
		if (pkt->itxp_hdrlen + pkt->itxp_mss >
		    pkt->itxp_meo.meoi_len) {
			/*
			 * XXX: If we don't turn this into an assert,
			 * should we add a stat for this? dtrace probe?
			 */
			return (false);
		}

		/*
		 * Upstack requested LSO and the packet meets the
		 * hardware's LSO requirements. If LSO support is turned on
		 * and the packet meets the minimum size, we will attempt
		 * to send using LSO.
		 *
		 * XXX: Might we want to also skip LSO if the packet size
		 * is < MTU but larger than the minimum MSS (i.e. we
		 * can just send as 1 packet over the wire)?
		 */
		if (ice->ice_tx_lso_enable &&
		    pkt->itxp_mss >= ICE_TX_LSO_MIN_MSS) {
			pkt->itxp_lso = true;

			/*
			 * Reserve 1 segment in each over the wire
			 * segment for the header.
			 */
			pkt->itxp_segmax--;
			return (true);
		}

		/*
		 * Packet was too small for the NIC to do LSO. We'll
		 * fallback and send as a non-LSO packet, but note
		 * the event.
		 *
		 * XXX: Might it be better to turn it into an atomic inc?
		 */
		mutex_enter(&txr->itxr_lock);
		txr->itxr_stats.ictxs_badmss.value.ui64++;
		mutex_exit(&txr->itxr_lock);

		/* Fall through to non-LSO case */
	} else {
		/*
		 * For a non-LSO packet, it better be small enough for
		 * us to send.
		 */
		if (pkt->itxp_meo.meoi_len > ice->ice_frame_size) {
			mutex_enter(&txr->itxr_lock);
			txr->itxr_stats.ictxs_toobig.value.ui64++;
			mutex_exit(&txr->itxr_lock);

			return (false);
		}
	}

	/*
	 * For the non-LSO case, we treat the MTU as the MSS.
	 * This is arguably stretching terminology to potential
	 * abuse, but itxp_mss is used to determine how much
	 * data can fit in an OTW packet. For LSO, this is
	 * after accounting for headers (and is reflected in
	 * the value set by mac_lso_get() since we're letting the
	 * NIC take care of the headers for each OTW packet.
	 *
	 * For non-LSO though, we supply everything including the
	 * header, so using the frame size serves as a check against
	 * receiving an oversized packet from up stack.
	 */
	pkt->itxp_mss = txr->itxr_ice->ice_frame_size;
	pkt->itxp_lso = false;

	return (true);
}

static void
ice_tx_pkt_fini(ice_tx_pkt_t *pkt)
{
	ice_tx_ctrl_block_t	*tcb, *next;

	tcb = pkt->itxp_tcbs;
	while (tcb != NULL) {
		next = tcb->itcb_next;

		tcb->itcb_next = NULL;
		ice_tcb_free(tcb);

		tcb = next;
	}

	bzero(pkt, sizeof (*pkt));
}

/*
 * To simplify writing the descriptors, there are a few helper functions
 * defined that will iterate through all of the ddi_dma_cookie_ts for
 * the packet. Specifically, the intended (simplified) flow is:
 *
 * ice_tx_pkt_init
 * ice_tx_pkt_prepare
 * while ((c = ice_tx_pkt_iter(pkt, iter)) != NULL
 *     <write descriptor using c>
 *     c = ice_tx_pkt_iter_next(iter)
 *
 */
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

static inline const ddi_dma_cookie_t *
ice_tx_pkt_iter_next_tcb(ice_tx_pkt_iter_t *iter, ice_tx_ctrl_block_t *tcb)
{
	if (tcb == NULL)
		return (NULL);

	iter->itpi_tcb = tcb;
	iter->itpi_dmah = ice_tcb_dma_handle(iter->itpi_tcb);
	return (ddi_dma_cookie_iter(iter->itpi_dmah, NULL));
}

static const ddi_dma_cookie_t *
ice_tx_pkt_iter(ice_tx_pkt_t *pkt, ice_tx_pkt_iter_t *iter)
{
	const ddi_dma_cookie_t *c;

	c = ice_tx_pkt_iter_next_tcb(iter, pkt->itxp_tcbs);
	if (c == NULL) {
		ASSERT3U(pkt->itxp_ntcbs, ==, 0);
		return (NULL);
	}
	iter->itpi_ic = c;

	return (ice_tx_pkt_iter_cookie(iter));
}

static const ddi_dma_cookie_t *
ice_tx_pkt_iter_next(ice_tx_pkt_iter_t *iter)
{
	const ddi_dma_cookie_t *c;

	if (iter->itpi_ic == NULL)
		return (NULL);

	c = ddi_dma_cookie_iter(iter->itpi_dmah, iter->itpi_ic);
	if (c == NULL)
		c = ice_tx_pkt_iter_next_tcb(iter, iter->itpi_tcb->itcb_next);

	iter->itpi_ic = c;
	return (ice_tx_pkt_iter_cookie(iter));
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
	ice_t				*ice = txr->itxr_ice;
	mblk_t				*mp = pkt->itxp_mp;
	ice_tx_ctrl_block_t		*tcb = NULL;
	size_t				off = 0;
	size_t				to_copy;
	size_t				mlen;

	/*
	 * For LSO, we want a small buffer for the header (if possible)
	 * For non-LSO packets, we want to copy into a small buffer if
	 * the packet is sufficiently small.
	 */
	if (pkt->itxp_lso ||
	    (ice_tx_pkt_msglen(pkt) < ICE_TX_SMALL_PKT &&
	    ice_tx_pkt_msglen(pkt) < pkt->itxp_dma_min)) {
		size_t remaining;

		remaining = pkt->itxp_lso ?
		    pkt->itxp_hdrlen : ice_tx_pkt_msglen(pkt);
		ASSERT3U(remaining, >, 0);

		tcb = ice_tcb_alloc(txr);
		if (tcb == NULL)
			return (false);

		/*
		 * Try to use a small buf, but fallback to a full sized one
		 * if none are available.
		 */
		tcb->itcb_buf = ice_buf_pool_alloc(&ice->ice_small_bufs);
		tcb->itcb_type = ITCB_SMALL_COPY;
		if (tcb->itcb_buf == NULL) {
			tcb->itcb_buf =
			    ice_buf_pool_alloc(&ice->ice_bufs);
			tcb->itcb_type = ITCB_COPY;
		}

		/* If neither are availble, we fail */
		if (tcb->itcb_buf == NULL) {
			ice_tcb_free(tcb);
			return (false);
		}

		ASSERT3U(ice_tcb_remaining(tcb), >=, remaining);
		while (remaining > 0) {
			uint_t n;

			/*
			 * remaining is initialized to either the size of the
			 * L2,L3,L4 headers (when using LSO) or the total size
			 * of the packet. Either way, we cannot get this
			 * far unless we can copy remaining bytes from
			 * the packet, so this should never fail.
			 */
			ASSERT3P(mp, !=, NULL);

			mlen = MBLKL(mp);
			to_copy = MIN(mlen, remaining);

			n = ice_tx_copy_fragment(pkt, tcb, mp, off, to_copy);
			ASSERT3U(n, ==, to_copy);

			remaining -= n;
			off += n;

			if (off == mlen) {
				mp = mp->b_cont;
				off = 0;
			} else {
				/*
				 * There is trailing bytes in the current
				 * mblk segment that is not being copied.
				 * The tcb we're copying into should be
				 * large enough to contain all of the header
				 * or the entire packet if it's a 'small'
				 * packet. Therefore, this should only
				 * happen when we're copying just the
				 * header and the trailing bytes are the
				 * packet data (and thus we should have
				 * completed copying the header).
				 */
				ASSERT(pkt->itxp_lso);
				ASSERT3U(remaining, ==, 0);
			}
		}

		/* If we have a 'small' packet, we should be done */
		IMPLY(ice_tx_pkt_msglen(pkt) < ICE_TX_SMALL_PKT, mp == NULL);

		/*
		 * If a small packet, we can go ahead and add the TCB
		 * (note that mp is used to 'checkpoint' the packet
		 * state for LSO, so can be NULL in the non-LSO case).
		 * If this is an LSO packet, we want to save off the
		 * header in its own TCB to simplify the accounting
		 * we have to do to comply with the DMA requirements
		 * of the NIC for each segment it offloads for us.
		 */
		VERIFY(ice_tx_pkt_add_tcb(pkt, tcb, mp, off));
		tcb = NULL;

		if (pkt->itxp_lso) {
			/*
			 * Reset the mss segment counters since the header
			 * doesn't count against the limits.
			 */
			pkt->itxp_seglen = 0;
			pkt->itxp_segcnt = 0;

			/*
			 * Also set the initial state (if we have to do
			 * a full copy) to start after the header.
			 */
			pkt->itxp_init_mp_seg = mp;
			pkt->itxp_init_off = off;

			/*
			 * We never want to rollback past the end of the
			 * header with LSO, so reset the rollback point to now.
			 */
			ice_tx_pkt_checkpoint(pkt, mp, off);
		}
	}

	/*
	 * The general idea is bind large fragments, copy small fragments.
	 * If a bind fails, we want to fall back to try to copy.
	 * If we have a bunch of consecutive small segments linked together, we
	 * want to copy them all into one contiguous buffer.
	 *
	 * This latter desire adds a bit of subtlety to the implementation.
	 * `tcb` holds the last buffer we copied into or NULL if the
	 * previous tcb was bound (or we're just starting). We cannot
	 * add `tcb` until we've either successfully bound the next bit
	 * of data, or we've filled tcb up. At the same time, any time we
	 * attempt to add a tcb to the packet, we may fail the mss segment
	 * limitations and have to roll back to the start of the mss-sized
	 * segment.
	 */
	while (mp != NULL) {
		mlen = MBLKL(mp) - off;

		if (ice_tx_try_bind(pkt, mlen)) {
			ice_tx_ctrl_block_t *btcb;

			btcb = ice_tx_bind_fragment(pkt, mp, off, mlen);
			if (btcb == NULL)
				goto try_copy;

			/*
			 * Note we have to add tcb first. It has the data
			 * from the previous iteration of the loop. If tcb is
			 * NULL, ice_tx_pkg_add_tcb() ignores it and
			 * returns success.
			 */
			if (!ice_tx_pkt_add_tcb(pkt, tcb, mp, off)) {
				ice_tcb_free(tcb);
				ice_tcb_free(btcb);
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}
			/*
			 * Now that it's been added, we need to set it
			 * to NULL so we don't try to add more to it
			 * and instead allocate a new tcb if we need
			 * to copy.
			 */
			tcb = NULL;

			/*
			 * If we successfully bound, then we've added
			 * the remainder of this mp. Update mp and off
			 * to reflect the start of the next mblk_t segment
			 * (if any).
			 */
			mp = mp->b_cont;
			off = 0;

			/* And then add the bound tcb */
			if (!ice_tx_pkt_add_tcb(pkt, btcb, mp, off)) {
				ice_tcb_free(btcb);
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}

			continue;
		}

try_copy:
		IMPLY(tcb != NULL, ice_tcb_is_copy(tcb));

		if (tcb == NULL) {
			tcb = ice_tcb_alloc(txr);
			if (tcb == NULL)
				return (false);

			tcb->itcb_type = ITCB_COPY;
			tcb->itcb_buf = ice_buf_pool_alloc(&ice->ice_bufs);
			if (tcb->itcb_buf == NULL) {
				ice_tcb_free(tcb);
				return (false);
			}
		}

		off += ice_tx_copy_fragment(pkt, tcb, mp, off, mlen);
		if (off == mlen) {
			off = 0;
			mp = mp->b_cont;
		}

		/*
		 * If the tcb is full or this is the last mblk_t fragment,
		 * then add it to pkt.
		 */
		if (ice_tcb_remaining(tcb) == 0 || mp == NULL) {
			IMPLY(mp == NULL, off == 0);

			if (!ice_tx_pkt_add_tcb(pkt, tcb, mp, off)) {
				ice_tcb_free(tcb);
				tcb = NULL;
				ice_tx_pkt_retry_mss_seg(pkt, &mp, &off);
				continue;
			}

			/* Need to start a new tcb next time around */
			tcb = NULL;
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
	IMPLY(pkt->itxp_lso,
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

	if (!pkt->itxp_lso)
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
	ice_tx_desc_t		*desc = NULL;
	ice_tx_desc_t		tx_ctx_desc;
	uint64_t		init_qw1;
	uint16_t		tail;
	uint16_t		desc_needed;
	uint16_t		desc_used;
	ice_tx_pkt_iter_t	iter;
	const ddi_dma_cookie_t	*c;

	ASSERT(MUTEX_HELD(&txr->itxr_lock));

	ASSERT(pkt->itxp_done);

	desc_needed = ice_tx_pkt_desc_needed(pkt);

	ASSERT3U(desc_needed, >, 0);
	ASSERT3U(desc_needed, <=, txr->itxr_avail);

	(void) ice_tx_pkt_sync(pkt);

	tx_ctx_desc.itxd_qw0 = 0;
	tx_ctx_desc.itxd_qw1 = 0;

	init_qw1 = ICE_TX_DESC_CMD_RESV;

	if (txr->itxr_ice->ice_tx_hcksum_enable &&
	    !ice_tx_hcksum_init(pkt, &tx_ctx_desc, &init_qw1)) {
		return (-1);
	}

	desc_used = 0;

	tail = txr->itxr_tail;

	if (pkt->itxp_lso) {
		desc = &txr->itxr_descs[tail];

		/* Write out the TX context descriptor to the ring */
		desc->itxd_qw0 = LE_64(tx_ctx_desc.itxd_qw0);
		desc->itxd_qw1 = LE_64(tx_ctx_desc.itxd_qw1);

		txr->itxr_tcbs[tail] = NULL;

		tail = ice_tx_next(txr, tail, 1);
		desc_used++;
	}

	for (c = ice_tx_pkt_iter(pkt, &iter); c != NULL;
	    c = ice_tx_pkt_iter_next(&iter)) {
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
	 * status) bits.
	 */
	desc->itxd_qw1 |= LE_64(ICE_TX_DESC_CMD_EOP|ICE_TX_DESC_CMD_RS);

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
	ASSERT3U(pkt->itxp_ntcbs, >, 0);
	pkt->itxp_tcb_tail->itcb_mp = pkt->itxp_mp;

	pkt->itxp_mp = NULL;

	txr->itxr_stats.ictxs_bind_fails.value.ui64 += pkt->itxp_bind_fails;
	txr->itxr_stats.ictxs_copy_bytes.value.ui64 += pkt->itxp_copy_bytes;
	txr->itxr_stats.ictxs_copy_frags.value.ui64 += pkt->itxp_copy_segs;
	txr->itxr_stats.ictxs_bind_bytes.value.ui64 += pkt->itxp_bind_bytes;
	txr->itxr_stats.ictxs_bind_frags.value.ui64 += pkt->itxp_bind_segs;

	if (pkt->itxp_lso) {
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
		ASSERT3U(pkt->itxp_ntcbs, <=, n);

		/*
		 * Move used tcbs in pkt onto the tcb ring. These will get
		 * freed when we recycle.
		 *
		 * Note that we attach the tcb to the index of the last
		 * descriptor of the packet so that we can use this
		 * to tell when a full packet is ready to be recycled.
		 */
		pkt->itxp_tcbs->itcb_tx_time = gethrtime();
		txr->itxr_tcbs[ice_tx_prev(txr, txr->itxr_tail)] =
		    pkt->itxp_tcbs;
		pkt->itxp_tcbs = pkt->itxp_tcb_tail = NULL;

		mutex_exit(&txr->itxr_lock);

		/*
		 * We've moved the TCBs from pkt onto the TX ring, so we
		 * don't want pkt to access them anymore.
		 */
		pkt->itxp_ntcbs = 0;
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

	bufsz = MIN(ice->ice_mtu, ICE_MAX_PKT_DMA_BUFSZ);
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
