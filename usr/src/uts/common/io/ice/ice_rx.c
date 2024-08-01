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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2017 Tegile Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 * Copyright 2020 Ryan Zezeski
 * Copyright 2021 Oxide Computer Company
 *
 * NOTE: While not an exact copy, this borrows heavily from i40e_transciever.c
 * as both NICs have very similar interfaces (in general, the E810 hardware is
 * a superset of the E710). As such, the copyright notices from that file at
 * the time of this file's creation have been imported here, though they
 * should not need to be kept in sync (unless both files are being modified
 * at the same time).
 *
 * Aside from the Intel E810 Data Sheet, the i40e driver source can also be
 * of assistance in answering an questions about the behavior. The main
 * differences are that the E810 driver may use multiple DMA buffers for a
 * packet when the MTU is larger than the system's page size. This is to avoid
 * lengthy allocation times for packet memory.
 *
 * Allocating single cookie DMA buffers larger than the system's page size
 * implies that the resulting memory is physically contiguous. As a result,
 * when kernel memory is fragmented (even if large amounts are free), the VM
 * may have to work hard to satisify the thousands of requests per ring needed
 * for DMA buffers for packet memory (for the ring descriptor memory, this
 * is less of an issue since there is only one per ring).
 *
 * When we scan the RX ring (either due to an interrupt or when asked to
 * via ice_rx_poll()), we first 'peek' at the descriptors (looking at their
 * state as well as their length) to determine how many entries should be
 * processed. In the case of being invoked by the interrupt, we process
 * up to ice->ice_rx_limit_per_intr packets and in the case of polling, we
 * limit ourselves to the number of packets less than or equal to the
 * limit given to us by mac.
 *
 * Once we determine how many packets to process, we then will either
 * copy or loan the buffers from the ring (depending on the size of the
 * segment and the amount of buffers available to loan).
 */

#include <sys/types.h>
#include "ice.h"

#define	ICE_RCTX_MAP(_f, _w, _l)				\
{								\
	.icm_offset = offsetof(ice_hw_rxq_context_t, _f),	\
	.icm_size = sizeof (((ice_hw_rxq_context_t *)0)->_f),	\
	.icm_width = _w,					\
	.icm_lsb = _l,						\
}

static const ice_ctx_map_t ice_rctx_map[] = {
	ICE_RCTX_MAP(ihrc_head,		13, 0),
	ICE_RCTX_MAP(ihrc_base,		57, 32),
	ICE_RCTX_MAP(ihrc_qlen,		13, 89),
	ICE_RCTX_MAP(ihrc_dbuff,	7, 102),
	ICE_RCTX_MAP(ihrc_hbuff,	5, 109),
	ICE_RCTX_MAP(ihrc_dtype,	2, 114),
	ICE_RCTX_MAP(ihrc_dsize,	1, 116),
	ICE_RCTX_MAP(ihrc_crcstrip,	1, 117),
	ICE_RCTX_MAP(ihrc_l2tsel,	1, 119),
	ICE_RCTX_MAP(ihrc_hsplit0,	4, 120),
	ICE_RCTX_MAP(ihrc_hsplit1,	2, 124),
	ICE_RCTX_MAP(ihrc_showiv,	1, 127),
ICE_RCTX_MAP(ihrc_rxmax,	14, 128),
	ICE_RCTX_MAP(ihrc_tphrdesc,	1, 193),
	ICE_RCTX_MAP(ihrc_tphwdesc,	1, 194),
	ICE_RCTX_MAP(ihrc_tphdata,	1, 195),
	ICE_RCTX_MAP(ihrc_tphhead,	1, 196),
	ICE_RCTX_MAP(ihrc_lrxqthresh,	3, 198),
	{ 0 }
};

static inline bool
ice_rx_desc_done(const ice_rx_desc_t *desc)
{
	return (LE_64(desc->irxd_qw1) & ICE_RXD_DONE);
}

static inline bool
ice_rx_eop(const ice_rx_desc_t *desc)
{
	return (LE_64(desc->irxd_qw1) & ICE_RXD_EOP);
}

static inline uint64_t
ice_rx_errval(const ice_rx_desc_t *desc)
{
	return (LE_64(desc->irxd_qw1) >> ICE_RXD_ERR_SHIFT);
}

static inline bool
ice_rx_error(const ice_rx_desc_t *desc)
{
	return (ice_rx_errval(desc) & ICE_RXD_ERR);
}

static inline uint32_t
ice_rx_lenval(const ice_rx_desc_t *desc)
{
	return (LE_64(desc->irxd_qw1) >> ICE_RXD_LEN_SHIFT);
}

static inline uint16_t
ice_rx_data_len(const ice_rx_desc_t *desc)
{
	return (ice_rx_lenval(desc) & ICE_RXD_LEN_MASK);
}

static inline bool
ice_rx_l3l4p(const ice_rx_desc_t *desc)
{
	return (LE_64(desc->irxd_qw1 & ICE_RXD_L3L4P));
}

#ifdef DEBUG
static inline bool
ice_rx_split(const ice_rx_desc_t *desc)
{
	return (ice_rx_lenval(desc) & ICE_RXD_SPLIT);
}
#endif

static inline uint16_t
ice_rx_next(const ice_rx_ring_t *rxr, uint16_t idx, uint16_t amt)
{
	/* Use a larger size to hold intermediate results to avoid overflow */
	uint32_t val;

	ASSERT3U(idx, <, rxr->irxr_size);

	val = (uint32_t)idx + amt;
	if (idx > rxr->irxr_size)
		val -= rxr->irxr_size;

	ASSERT3U(val, <, rxr->irxr_size);
	return (val);
}

static inline void
ice_rx_reset_desc(ice_rx_ring_t *rxr, uint16_t idx)
{
	ASSERT3U(idx, <, rxr->irxr_size);

	ice_rx_desc_t		*desc = &rxr->irxr_descs[idx];
	ice_rx_ctrl_block_t	*rcb = rxr->irxr_rcbs[idx];

	ASSERT3P(rcb, !=, NULL);
	ASSERT3U(rcb->ircb_dma.idb_ncookies, ==, 1);

	desc->irxd_qw0 = LE_64(rcb->ircb_dma.idb_cookie.dmac_laddress);
	desc->irxd_qw1 = 0;
	desc->irxd_qw2 = 0;
	desc->irxd_qw3 = 0;
}

/*
 * If rcb doesn't have an mblk_t associted with it, attempt to alloc an
 * mblk_t and associate it with the buffer in rcb.
*
 * Returns true if rcb has an mblk_t associated with it, false if not.
 */
static inline bool
ice_rx_alloc_mp(ice_rx_ctrl_block_t *rcb)
{
	ASSERT3P(rcb->ircb_mp, ==, NULL);

	if (rcb->ircb_mp != NULL)
		return (true);

	rcb->ircb_mp = desballoc((unsigned char *)rcb->ircb_dma.idb_va,
	    rcb->ircb_dma.idb_len, 0, &rcb->ircb_free_rtn);
	if (rcb->ircb_mp == NULL)
		return (false);

	return (true);
}

static ice_rx_ctrl_block_t *
ice_rcb_alloc(ice_rx_ring_t *rxr, bool loan_replacement)
{
	ice_t			*ice = rxr->irxr_ice;
	ice_rx_ctrl_block_t	*rcb = NULL;

	mutex_enter(&ice->ice_rxbuf_lock);
	if (loan_replacement) {
		if (ice->ice_rxbuf_onloan == ice->ice_rx_maxloan) {
			mutex_exit(&ice->ice_rxbuf_lock);
			return (NULL);
		}
		ice->ice_rxbuf_onloan++;
	}

	rcb = NULL; // TODO get from pool
	mutex_exit(&ice->ice_rxbuf_lock);

	ASSERT3S(rcb->ircb_state, ==, IRXB_FREE);
	ASSERT3P(rcb->ircb_ring, ==, NULL);
	rcb->ircb_state = IRXB_ONRING;
	rcb->ircb_ring = rxr;
	return (rcb);
}

static void
ice_rcb_free(ice_rx_ctrl_block_t *rcb)
{
	ice_t *ice;

	if (rcb == NULL)
		return;

	ASSERT3S(rcb->ircb_state, !=, IRXB_FREE);
	ASSERT3P(rcb->ircb_ring, !=, NULL);

	ice = rcb->ircb_ring->irxr_ice;

	rcb->ircb_state = IRXB_FREE;
	rcb->ircb_ring = NULL;

	mutex_enter(&ice->ice_rxbuf_lock);
	if (rcb->ircb_state == IRXB_ONLOAN)
		ice->ice_rxbuf_onloan--;

	// TODO: put back in pool
	mutex_exit(&ice->ice_rxbuf_lock);
}

/*
 * This is called by freemsg(9F).
 */
void
ice_rx_recycle(caddr_t arg)
{
	ice_t			*ice;
	ice_rx_ctrl_block_t	*rcb = (ice_rx_ctrl_block_t *)arg;

	/*
	 * If we were anywhere but the free pool, we should be associated
	 * with a ring.
	 */
	IMPLY(rcb->ircb_state != IRXB_FREE, rcb->ircb_ring != NULL);

	/*
	 * If we've been called by freemsg(9F), our mblk_t is no longer
	 * valid, so set it to NULL to avoid any confusion.
	 */
	rcb->ircb_mp = NULL;

	switch (rcb->ircb_state) {
	case IRXB_FREE:
	case IRXB_ONRING:
		/*
		 * If we're already on the free list or assigned to a ring and
		 * freemsg(9F) has been called on our rcb's mblk_t, that means
		 * we're shutting down, and don't need to do anything else.
		 */
		return;
	case IRXB_ONLOAN:
		break;
	}

	ice = rcb->ircb_ring->irxr_ice;

	rcb->ircb_state = IRXB_FREE;
	rcb->ircb_ring = NULL;

	/*
	 * If we're not shutting down, try to attach a new mblk_t. If it
	 * fails, we'll do one final attempt during RX, so failure here
	 * is not fatal.
	 */
	if (!ice->ice_shutdown)
		(void) ice_rx_alloc_mp(rcb);

	// TODO -- put back in the pool
}

static mblk_t *
ice_rx_bind(ice_rx_ring_t *rxr, uint16_t idx, uint_t len)
{
	ice_t			*ice = rxr->irxr_ice;
	ice_rx_ctrl_block_t	*rcb, *replacement;
	mblk_t			*mp;

	ASSERT3U(idx, <, rxr->irxr_size);

	replacement = ice_rcb_alloc(rxr, true);
	if (replacement == NULL) {
		rxr->irxr_stats.icrxs_bind_no_rcb.value.ui64++;
		return (NULL);
	}

	rcb = rxr->irxr_rcbs[idx];
	ASSERT3S(rcb->ircb_state, ==, IRXB_ONRING);

	/*
	 * Make sure we have an mblk_t for this data. If not, fall back
	 * to copying
	 */
	if (!ice_rx_alloc_mp(rcb)) {
		rxr->irxr_stats.icrxs_bind_no_mp.value.ui64++;
		ice_rcb_free(replacement);
		return (NULL);
	}

	ice_rx_reset_desc(rxr, idx);

	if (!ice_dma_sync(ice, &rcb->ircb_dma, DDI_DMA_SYNC_FORKERNEL)) {
		ice_rcb_free(replacement);
		return (NULL);
	}

	rcb->ircb_state = IRXB_ONLOAN;
	rcb->ircb_ring = rxr;

	mp = rcb->ircb_mp;
	mp->b_cont = mp->b_next = NULL;
	mp->b_wptr = mp->b_rptr + len;

	rxr->irxr_rcbs[idx] = replacement;

	rxr->irxr_stats.icrxs_bind_bytes.value.ui64 += len;
	rxr->irxr_stats.icrxs_bind_segs.value.ui64++;
	return (mp);
}

static mblk_t *
ice_rx_copy(ice_rx_ring_t *rxr, uint16_t idx, uint_t len)
{
	ice_t			*ice = rxr->irxr_ice;
	ice_rx_ctrl_block_t	*rcb;
	mblk_t			*mp;

	ASSERT3U(idx, <, rxr->irxr_size);

	rcb = rxr->irxr_rcbs[idx];
	if (!ice_dma_sync(ice, &rcb->ircb_dma, DDI_DMA_SYNC_FORKERNEL))
		return (NULL);

	mp = allocb(len, 0);
	if (mp == NULL) {
		rxr->irxr_stats.icrxs_copy_nomem.value.ui64++;
		return (NULL);
	}

	bcopy(rcb->ircb_dma.idb_va, mp->b_rptr, len);
	mp->b_wptr = mp->b_rptr + len;

	rxr->irxr_stats.icrxs_copy_bytes.value.ui64 += len;
	rxr->irxr_stats.icrxs_copy_segs.value.ui64++;
	return (mp);
}

static void
ice_rx_hwcksum(ice_rx_ring_t *rxr, const ice_rx_desc_t *desc, mblk_t *mp)
{
	int pinfo = 0;
	uint32_t cksum;

	cksum = 0;

	// TODO
	if (pinfo == 0) {
		rxr->irxr_stats.icrxs_hck_unknown.value.ui64++;
		return;
	}

	/*
	 * Descriptor must have the L3L4P bit set if the NIC has done
	 * any HW checksum validation.
	 */
	if (!ice_rx_l3l4p(desc)) {
		rxr->irxr_stats.icrxs_hck_nol3l4p.value.ui64++;
		return;
	}

	// TODO

	if (cksum != 0) {
		rxr->irxr_stats.icrxs_hck_set.value.ui64++;
		mac_hcksum_set(mp, 0, 0, 0, 0, cksum);
	} else {
		rxr->irxr_stats.icrxs_hck_miss.value.ui64++;
	}
}

static mblk_t *
ice_ring_rx_frame(ice_rx_ring_t *rxr, uint_t max_size, uint_t *lenp)
{
	ice_t			*ice = rxr->irxr_ice;
	ice_rx_desc_t		*desc;
	mblk_t			*mp_head, *mp_tail;
	uint_t			len;
	uint16_t		head, seg_count;

	mp_head = NULL;
	len = 0;
	seg_count = 0;

	/*
	 * Determine the size of this packet. Also verify that a complete
	 * packet is available.
	 */
	head = rxr->irxr_head;
	do {
		desc = &rxr->irxr_descs[head];

		/*
		 * If we encounter a descriptor without the DD (descriptor
		 * done) flag set, we don't have a full packet ready.
		 */
		if (!ice_rx_desc_done(desc))
			return (NULL);

		/*
		 * Currently, we don't support header splitting, so we can
		 * just examine the data length.
		 */
		ASSERT(!ice_rx_split(desc));

		seg_count++;
		len += ice_rx_data_len(desc);

		head = ice_rx_next(rxr, head, 1);
	} while (!ice_rx_eop(desc) && (seg_count < ICE_RX_MAX_DESC) &&
	    (max_size == 0 || len <= max_size));

	if (!ice_rx_eop(desc)) {
		/*
		 * If we didn't encounter an EOP (end of packet) flag,
		 * the only permissible reason is because the packet size
		 * exceeds what we're polling for (max_size). Anything
		 * else is a hardware error
		 */
		if (len > max_size)
			return (NULL);

		// TODO: improve this error message. FMA degrade?
		// we probably would need to reset the ring at this point
		ice_error(rxr->irxr_ice, "received packet with excessive "
		    "segments");
		return (NULL);
	}

	if (ice_rx_error(desc)) {
		rxr->irxr_stats.icrxs_desc_error.value.ui64++;
		goto discard;
	}

	/* Asemble a (possibly segmented) mblk_t from the packet */
	head = rxr->irxr_head;
	len = 0;
	do {
		mblk_t *mp = NULL;

		desc = &rxr->irxr_descs[head];
		len = ice_rx_data_len(desc);

		/*
		 * If segment is large enough, try to bind it. If we're
		 * unable to for any reason, we will fall back to copying
		 * it.
		 */
		if (len >= ice->ice_rx_dma_min)
			mp = ice_rx_bind(rxr, head, len);
		if (mp == NULL)
			mp = ice_rx_copy(rxr, head, len);

		/*
		 * Couldn't bind or copy the packet, discard any assembled
		 * segments, and discard the packet.
		 */
		if (mp == NULL) {
			if (mp_head != NULL) {
				freemsg(mp_head);
				mp_head = NULL;
			}
			goto discard;
		}

		if (mp_head == NULL) {
			mp_head = mp_tail = mp;
		} else {
			mp_tail->b_cont = mp;
			mp_tail = mp;
		}

		head = ice_rx_next(rxr, head, 1);
	} while (!ice_rx_eop(desc));

	if (ice->ice_rx_hcksum_enable)
		ice_rx_hwcksum(rxr, desc, mp_head);

	*lenp = len;

discard:
	head = rxr->irxr_head;

	for (uint_t i = 0; i < seg_count; i++) {
		ice_rx_reset_desc(rxr, head);
		head = ice_rx_next(rxr, head, 1);
	}

	rxr->irxr_head = head;
	return (mp_head);
}

/*
 * Receive packets from ring. If poll_bytes > 0, it represents the maximum
 * amount of data we can receive. If poll_bytes == 0, there is no byte limit.
 * Returns an mblk_t chain of received packets, or NULL if none are
 * available (subject to poll_bytes).
 */
mblk_t *
ice_ring_rx(ice_rx_ring_t *rxr, int poll_bytes)
{
	ice_t *ice = rxr->irxr_ice;
	mblk_t *mp_head, *mp_tail;
	uint_t bytes, npkts;

	ASSERT(MUTEX_HELD(&rxr->irxr_lock));

	if (!ice_is_running(ice))
		return (NULL);

	mp_head = mp_tail = NULL;
	bytes = 0;
	npkts = 0;

	if (!ice_dma_sync(ice, &rxr->irxr_desc_dma, DDI_DMA_SYNC_FORKERNEL))
		return (NULL);

	do {
		mblk_t *mp;
		uint_t len;

		ASSERT3S(poll_bytes, >=, 0);
		mp = ice_ring_rx_frame(rxr, poll_bytes, &len);
		if (mp == NULL)
			break;

		if (mp_tail != NULL) {
			mp_tail->b_next = mp;
			mp_tail = mp;
		} else {
			ASSERT3P(mp_head, ==, NULL);
			mp_head = mp_tail = mp;
		}

		npkts++;
		bytes += len;

		if (poll_bytes > 0) {
			ASSERT3S(poll_bytes, >=, len);
			poll_bytes -= len;
			if (poll_bytes == 0)
				break;
		}
	} while (poll_bytes > 0 || npkts < ice->ice_rx_limit_per_intr);

	if (npkts == ice->ice_rx_limit_per_intr)
		rxr->irxr_stats.icrxs_intr_limit.value.ui64++;

	/*
	 * We've modified the ring, and now need to sync it so the hardware
	 * sees the changes.
	 *
	 * If this fails, we don't have any recovery at this point, just
	 * let ice_dma_sync do the FMA updates and finish whatever we
	 * managed to get.
	 */
	(void) ice_dma_sync(ice, &rxr->irxr_desc_dma, DDI_DMA_SYNC_FORDEV);

	if (npkts > 0) {
		uint16_t tail;

		if (rxr->irxr_head > 0)
			tail = rxr->irxr_head - 1;
		else
			tail = rxr->irxr_size - 1;

		ice_reg_write(ice, ICE_QRX_TAIL(rxr->irxr_index), tail);
		if (ice_regs_check(ice) != DDI_FM_OK) {
			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_DEGRADED);
			atomic_or_32(&ice->ice_state, ICE_ERROR);
		}
	
		rxr->irxr_stats.icrxs_bytes.value.ui64 += bytes;
		rxr->irxr_stats.icrxs_packets.value.ui64 += npkts;
	}

	EQUIV(bytes == 0, npkts == 0);

	return (mp_head);
}

mblk_t *
ice_ring_rx_poll(void *arg, int poll_bytes)
{
	ice_rx_ring_t *rxr = arg;
	mblk_t *mp;

	ASSERT3S(poll_bytes, >, 0);

	mutex_enter(&rxr->irxr_lock);
	mp = ice_ring_rx(rxr, poll_bytes);
	mutex_exit(&rxr->irxr_lock);

	return (mp);
}

static bool
ice_rx_setup_bufs(ice_rx_ring_t *rxr)
{
	ice_t			*ice = rxr->irxr_ice;
	ddi_dma_attr_t		attr;
	ddi_device_acc_attr_t	dev_attr;
	size_t			len;

	ASSERT(MUTEX_HELD(&rxr->irxr_lock));

	ice_dma_ring_attr(ice, &attr);
	ice_dma_acc_attr(ice, &dev_attr);

	len = rxr->irxr_size * sizeof (ice_rx_desc_t);
	if (!ice_dma_alloc(ice, &rxr->irxr_desc_dma, &attr, &dev_attr, true,
	    len, true)) {
		ice_error(ice, "failed to alloc RX descriptor ring");
		return (false);
	}
	rxr->irxr_descs = (ice_rx_desc_t *)rxr->irxr_desc_dma.idb_va;

	len = rxr->irxr_size * sizeof (ice_tx_ctrl_block_t *);
	rxr->irxr_rcbs = kmem_zalloc(len, KM_SLEEP);

	for (uint_t i = 0; i < rxr->irxr_size; i++) {
		ice_rx_ctrl_block_t *rcb = NULL;

		rcb = ice_rcb_alloc(rxr, false);
		VERIFY3P(rcb, !=, NULL);

		rxr->irxr_rcbs[i] = rcb;
		ice_rx_reset_desc(rxr, i);
	}

	if (!ice_dma_sync(ice, &rxr->irxr_desc_dma, DDI_DMA_SYNC_FORDEV)) {
		ice_error(ice, "failed to sync rx ring");
		return (false);
	}

	return (true);
}

static void
ice_rx_teardown_bufs(ice_rx_ring_t *rxr)
{
	size_t len;

	for (uint_t i = 0; i < rxr->irxr_size; i++) {
		ice_rcb_free(rxr->irxr_rcbs[i]);
		rxr->irxr_rcbs[i] = NULL;
	}

	len = rxr->irxr_size * sizeof (ice_tx_ctrl_block_t *);
	kmem_free(rxr->irxr_rcbs, len);
	rxr->irxr_rcbs = NULL;

	ice_dma_free(&rxr->irxr_desc_dma);
	rxr->irxr_size = 0;
}

static bool
ice_rx_setup_ctx(ice_rx_ring_t *rxr)
{
	ice_t			*ice = rxr->irxr_ice;
	uint32_t		regs[ICE_RXQ_CONTEXT_REG_SIZE] = { 0 };
	ice_hw_rxq_context_t	rctx = {
		.ihrc_head = 0,
		.ihrc_base = rxr->irxr_desc_dma.idb_cookie.dmac_laddress >>
		    ICE_HW_RXQ_CTX_BASE_SHIFT,
		.ihrc_qlen = rxr->irxr_size,
		.ihrc_dbuff = ice->ice_rx_bufsize >> ICE_HW_RXQ_CTX_DBUFF_SHIFT,
		.ihrc_hbuff = 0 >> ICE_HW_RXQ_CTX_HBUFF_SHIFT,
		.ihrc_dtype = ICE_HW_RXQ_CTX_DTYPE_NOSPLIT,
		.ihrc_dsize = ICE_HW_RXQ_CTX_DSIZE_32B,
		.ihrc_crcstrip = 1,
		.ihrc_l2tsel = 0,
		.ihrc_hsplit0 = 0,
		.ihrc_hsplit1 = 0,
		.ihrc_showiv = 0,
		.ihrc_rxmax = ice->ice_frame_size, // XXX
		.ihrc_tphrdesc = 1,
		.ihrc_tphwdesc = 1,
		.ihrc_tphdata = 1,
		.ihrc_tphhead = 0,
		.ihrc_lrxqthresh = 0, // XXX
		.ihrc_req = 0,
	};

	ice_ctx_xlate(ice_rctx_map, &rctx, regs, true);

	for (uint_t i = 0; i < ICE_RXQ_CONTEXT_REG_SIZE; i++) {
		uintptr_t addr = ICE_REG_RXQ_CONTEXT(i, rxr->irxr_index);

		ice_reg_write(ice, addr, regs[i]);
	}

	if (ice_regs_check(ice) != 0) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ice->ice_state, ICE_ERROR);
		return (false);
	}

	return (true);
}


int
ice_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ice_rx_ring_t	*rxr = (ice_rx_ring_t *)rh;
	ice_t		*ice = rxr->irxr_ice;
	uint32_t	reg;

	mutex_enter(&rxr->irxr_lock);

	rxr->irxr_rxgen = gen_num;
	rxr->irxr_size = ice->ice_rx_rsize;
	rxr->irxr_head = rxr->irxr_tail = 0;

	/*
	 * 10.4.3.1.1 Receive Queue Enable Flow.
	 *
	 * 1. Allocate memory for receive ring and program receive
	 * descriptors.
	 */
	if (!ice_rx_setup_bufs(rxr)) {
		ice_rx_teardown_bufs(rxr);
		mutex_exit(&rxr->irxr_lock);
		return (-1);
	}

	/* 2. Program the Rx-Queue context parameters */
	if (!ice_rx_setup_ctx(rxr)) {
		ice_rx_teardown_bufs(rxr);
		mutex_exit(&rxr->irxr_lock);
		return (-1);
	}

	/*
	 * 3. Clear queue tail pointer and set tail to end of descriptor
	 * ring
	 */
	ice_reg_write(ice, ICE_QRX_TAIL(rxr->irxr_index), 0);
	ice_reg_write(ice, ICE_QRX_TAIL(rxr->irxr_index), rxr->irxr_size - 1);


	/* 4. Set QENA_REQ flag in QRX_CTRL[n] */
	reg = ice_reg_read(ice, ICE_QRX_CTRL(rxr->irxr_index));
	VERIFY3U((reg & ICE_QRX_CTRL_ENABLED), !=, ICE_QRX_CTRL_ENABLED);

	reg |= ICE_QRX_CTRL_QENA_REQ;
	ice_reg_write(ice, ICE_QRX_CTRL(rxr->irxr_index), reg);

	/* Note we don't support no-drop TCs, so step 5 omitted */

	/*
	 * 6. Wait for QENA_STAT flag to be set in QRX_CTRL[n]. Note that
	 * QENA_REQ should remain set. While this should happen within 10us,
	 * other drivers (e.g. FreeBSD's ice driver) will retry a few
	 * times with a 10us delay.
	 */
	for (uint_t i = 0; i < ICE_RING_WAIT_NTRIES; i++) {
		reg = ice_reg_read(ice, ICE_QRX_CTRL(rxr->irxr_index));
		if ((reg & ICE_QRX_CTRL_ENABLED) != ICE_QRX_CTRL_ENABLED)
			break;

		drv_usecwait(10);
	}

	if ((reg & ICE_QRX_CTRL_ENABLED) != ICE_QRX_CTRL_ENABLED) {
		ice_error(rxr->irxr_ice, "!failed to enable rx queue %u, "
		    "timed out", rxr->irxr_index);

		ice_rx_teardown_bufs(rxr);
		mutex_exit(&rxr->irxr_lock);
		return (-1);
	}

	/* We currently don't support VFs, so step 7 ommitted */
	rxr->irxr_shutdown = false;
	mutex_exit(&rxr->irxr_lock);

	return (0);
}

void
ice_ring_rx_stop(mac_ring_driver_t rh)
{
	ice_rx_ring_t	*rxr = (ice_rx_ring_t *)rh;
	ice_t		*ice = rxr->irxr_ice;
	uint32_t	reg;

	mutex_enter(&rxr->irxr_lock);
	rxr->irxr_shutdown = true;

	// XXX Should we release the lock and disable the queue outside
	// of holding the lock?

	reg = ice_reg_read(ice, ICE_QRX_CTRL(rxr->irxr_index));

	reg &= ~ICE_QRX_CTRL_QENA_REQ;
	ice_reg_write(ice, ICE_QRX_CTRL(rxr->irxr_index), reg);

	for (uint_t i = 0; i < ICE_RING_WAIT_NTRIES; i++) {
		reg = ice_reg_read(ice, ICE_QRX_CTRL(rxr->irxr_index));
		if ((reg & ICE_QRX_CTRL_QENA_STAT) == 0)
			break;

		drv_usecwait(10);
	}

	if ((reg & ICE_QRX_CTRL_QENA_STAT) != 0) {
		ice_error(rxr->irxr_ice, "!failed to stop queue %u, timed out",
		    rxr->irxr_index);
	}

	ice_rx_teardown_bufs(rxr);
	mutex_exit(&rxr->irxr_lock);
}

int
ice_ring_rx_intr_enable(mac_intr_handle_t intrh)
{
	return (0);
}

int 
ice_ring_rx_intr_disable(mac_intr_handle_t intrh)
{
	return (0);
}
