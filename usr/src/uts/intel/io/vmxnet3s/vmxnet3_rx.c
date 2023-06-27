/*
 * Copyright (C) 2007 VMware, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common
 * Development and Distribution License (the "License") version 1.0
 * and no later version.  You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 *         http://www.opensource.org/licenses/cddl1.php
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */
/*
 * Copyright (c) 2013, 2016 by Delphix. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <vmxnet3.h>

static int vmxnet3_rxbuf_ctor(void *, void *);
static void vmxnet3_rxbuf_reset(void *, void *);
static void vmxnet3_rxbuf_dtor(void *, void *);

static inline mblk_t *
vmxnet3_rx_alloc_mblk(vmxnet3_rxbuf_t *rxb)
{
	if (rxb->mblk == NULL) {
		rxb->mblk = desballoc((void *)rxb->dma->buf, rxb->dma->bufLen,
		    0, &rxb->freeCB);
	} else {
		ASSERT3U(MBLKSIZE(rxb->mblk), ==, rxb->dma->bufLen);
	}

	return (rxb->mblk);
}

static inline vmxnet3_rxbuf_t *
vmxnet3_rx_assign(vmxnet3_rxqueue_t *rxq, vmxnet3_rxbuf_t *rxb, uint16_t idx)
{
	vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
	Vmxnet3_RxDesc		*rxd = &VMXNET3_GET_DESC(cmdRing, idx)->rxd;
	vmxnet3_rxbuf_t		*old;

	ASSERT(MUTEX_HELD(&rxq->rxLock));

	/*
	 * We don't care right now if this fails or not. If it fails, we'll
	 * do a final attempt during rx and drop the packet if it fails.
	 */
	(void) vmxnet3_rx_alloc_mblk(rxb);

	ASSERT3S(rxb->state, ==, VMXNET3_RX_FREE);

	old = rxq->bufRing[idx];
	rxq->bufRing[idx] = rxb;
	rxd->addr = rxb->dma->bufPA;
	rxd->len = rxb->dma->bufLen;
	/*
	 * Without a separate ring for body descriptors (not yet implemented),
	 * this doesn't cause header splitting.
	 */
	rxd->btype = VMXNET3_RXD_BTYPE_HEAD;

	membar_producer();

	rxd->gen = cmdRing->gen;
	rxb->state = VMXNET3_RX_ONRING;

	return (old);
}

int
vmxnet3_rx_start(mac_ring_driver_t mrh, uint64_t gen_num)
{
	vmxnet3_rxqueue_t	*rxq = (vmxnet3_rxqueue_t *)mrh;
	vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
	vmxnet3_softc_t		*dp = rxq->sc;
	uint_t			idx;

	idx = vmxnet3_rqidx(rxq);
	VMXNET3_DEBUG(rxq->sc, 1, "rx %u start", idx);

	mutex_enter(&rxq->rxLock);

	vmxnet3_init_cmdring(&rxq->cmdRing, dp->rxRingSize);
	vmxnet3_init_compring(&rxq->compRing, dp->rxRingSize);

	ASSERT0(cmdRing->next2fill);
	do {
		vmxnet3_rxbuf_t *rxb;

		rxb = vmxnet3_bufcache_alloc(dp->rxBufCache);
		/*
		 * If we successfully initialized rxBufCache, we should
		 * always have enough rxbs to initially populate the ring.
		 */
		VERIFY3P(rxb, !=, NULL);

		VERIFY3P(vmxnet3_rx_assign(rxq, rxb, cmdRing->next2fill), ==,
		    NULL);
		VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
	} while (cmdRing->next2fill != 0);

	rxq->gen_num = gen_num;

	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_RXPROD(idx),
	    rxq->cmdRing.size - 1);

	rxq->started = B_TRUE;
	mutex_exit(&rxq->rxLock);

	return (0);
}

void
vmxnet3_rx_stop(mac_ring_driver_t mrh)
{
	vmxnet3_rxqueue_t	*rxq = (vmxnet3_rxqueue_t *)mrh;
	vmxnet3_rxbuf_t		*rxBuf;
	uint_t			idx __maybe_unused;

	idx = vmxnet3_rqidx(rxq);
	VMXNET3_DEBUG(rxq->sc, 1, "rx %u stop", idx);

	mutex_enter(&rxq->rxLock);
	rxq->started = B_FALSE;

	for (uint_t i = 0; i < rxq->cmdRing.size; i++) {
		rxBuf = rxq->bufRing[i];

		ASSERT(rxBuf != NULL);

		rxq->bufRing[i] = NULL;

		vmxnet3_bufcache_free(rxq->sc->rxBufCache, rxBuf);
	}

	bzero(rxq->cmdRing.dma.buf, rxq->cmdRing.dma.bufLen);
	bzero(rxq->compRing.dma.buf, rxq->compRing.dma.bufLen);
	bzero(rxq->bufRing,
	    VMXNET3_RX_RING_MAX_SIZE * sizeof (vmxnet3_rxbuf_t *));

	mutex_exit(&rxq->rxLock);
}

int
vmxnet3_rx_intr_enable(mac_intr_handle_t mih)
{
	vmxnet3_rxqueue_t *rxq = (vmxnet3_rxqueue_t *)mih;

	ASSERT(!vmxnet3_intr_legacy(rxq->sc));

	mutex_enter(&rxq->rxLock);
	vmxnet3_intr_enable(rxq->sc, rxq->intr_num);
	mutex_exit(&rxq->rxLock);

	return (0);
}

int
vmxnet3_rx_intr_disable(mac_intr_handle_t mih)
{
	vmxnet3_rxqueue_t *rxq = (vmxnet3_rxqueue_t *)mih;

	ASSERT(!vmxnet3_intr_legacy(rxq->sc));

	mutex_enter(&rxq->rxLock);
	vmxnet3_intr_disable(rxq->sc, rxq->intr_num);
	mutex_exit(&rxq->rxLock);

	return (0);
}

/*
 * Determine if a received packet was checksummed by the Vmxnet3
 * device and tag the mp appropriately.
 */
static void
vmxnet3_rx_hwcksum(vmxnet3_softc_t *dp, mblk_t *mp,
    Vmxnet3_GenericDesc *compDesc)
{
	uint32_t flags = 0;

	if (!compDesc->rcd.cnc) {
		if (compDesc->rcd.v4 && compDesc->rcd.ipc) {
			flags |= HCK_IPV4_HDRCKSUM;
			if ((compDesc->rcd.tcp || compDesc->rcd.udp) &&
			    compDesc->rcd.tuc) {
				flags |= HCK_FULLCKSUM | HCK_FULLCKSUM_OK;
			}
		}

		VMXNET3_DEBUG(dp, 3, "rx cksum flags = 0x%x\n", flags);

		mac_hcksum_set(mp, 0, 0, 0, 0, flags);
	}
}

static inline mblk_t *
vmxnet3_rx_loan(vmxnet3_rxqueue_t *rxq, vmxnet3_rxbuf_t *rxb, uint16_t idx,
    uint16_t len)
{
	mblk_t		*mp;
	vmxnet3_rxbuf_t	*new_rxb = NULL;
	vmxnet3_rxbuf_t	*old;
	vmxnet3_dmabuf_t *newdma = NULL;

	ASSERT(MUTEX_HELD(&rxq->rxLock));

	if (len <= rxq->sc->rxCopyThreshold)
		return (NULL);
	if (rxq->rx_onloan >= rxq->sc->rxMaxLoan)
		return (NULL);

	/* Last chance to allocate an mblk */
	mp = vmxnet3_rx_alloc_mblk(rxb);
	if (mp == NULL) {
		rxq->rx_nomblk++;
		return (NULL);
	}

	newdma = vmxnet3_bufcache_alloc(rxq->sc->bufCache);
	if (newdma == NULL) {
		/*
		 * vmxnet3_rx_alloc_mblk() sets rxb->mblk to mp. If we fail
		 * here, we leave the mblk_t in place since we'll likely
		 * use it later.
		 */
		rxq->rx_nodma++;
		return (NULL);
	}

	/*
	 * Try to get an rxbuf to replace the one we want to loan out and
	 * assign it to the rx ring.
	 */
	new_rxb = vmxnet3_bufcache_alloc(rxq->sc->rxBufCache);
	if (new_rxb == NULL) {
		rxq->rx_nobuf++;
		return (NULL);
	}
	new_rxb->dma = newdma;

	old = vmxnet3_rx_assign(rxq, new_rxb, idx);
	ASSERT3P(old, ==, rxb);

	rxb->rxq = rxq;
	rxb->state = VMXNET3_RX_ONLOAN;
	mp->b_wptr += len;

	rxq->rx_loaned++;
	rxq->rx_loaned_bytes += len;
	rxq->rx_onloan++;
	return (mp);
}

static inline mblk_t *
vmxnet3_rx_copy(vmxnet3_rxqueue_t *rxq, vmxnet3_rxbuf_t *rxb, uint16_t len)
{
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&rxq->rxLock));

	mp = allocb(len, 0);
	if (mp == NULL) {
		rxq->rx_nomblk++;
		return (NULL);
	}

	bcopy(rxb->dma->buf, mp->b_rptr, len);
	mp->b_wptr += len;

	bzero(rxb->dma->buf, rxb->dma->bufLen);

	rxq->rx_copied++;
	rxq->rx_copied_bytes += len;
	return (mp);
}

/*
 * Receive one (possibly segmented) packet. If we could not receive it
 * for any reason, we return NULL, otherwise the mblk_t is returned.
 */
static mblk_t *
vmxnet3_rx_one(vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_compring_t	*compRing = &rxq->compRing;
	vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
	Vmxnet3_GenericDesc	*compDesc, *rxDesc;
	vmxnet3_rxbuf_t		*rxb;
	mblk_t			*mp_head, *mp_tail, *mp;
	boolean_t		eop;
	boolean_t		drop;
	uint16_t		idx;

	ASSERT(MUTEX_HELD(&rxq->rxLock));

	mp_head = mp_tail = NULL;
	eop = B_FALSE;
	drop = B_FALSE;

	compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
	ASSERT(compDesc->rcd.sop);

	do {
		idx = compDesc->rcd.rxdIdx;

		/*
		 * HW may still be in the middle of generating this entry,
		 * so hold until the gen bit is flipped.
		 */
		while (compDesc->rcd.gen != compRing->gen)
			membar_consumer();

		rxb = rxq->bufRing[idx];
		rxDesc = VMXNET3_GET_DESC(cmdRing, cmdRing->next2fill);

		/* Some RX descriptors may have been skipped */
		while (cmdRing->next2fill != idx) {
			rxDesc->rcd.gen = cmdRing->gen;
			VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
			rxDesc = VMXNET3_GET_DESC(cmdRing, cmdRing->next2fill);
		}

		eop = compDesc->rcd.eop;

		/*
		 * Try to loan, if that fails (returns NULL), we
		 * fall back to copying instead.
		 */
		mp = vmxnet3_rx_loan(rxq, rxb, idx, compDesc->rcd.len);
		if (mp == NULL)
			mp = vmxnet3_rx_copy(rxq, rxb, compDesc->rcd.len);

		/*
		 * Either we've loaned out and replaced the rxbuf for
		 * this descriptor, we've copied the packet into a
		 * new mblk, or we failed. No matter what, we now need to
		 * flip the gen bit to indicate the descriptor is ready
		 * to be used.
		 */
		rxDesc->rxd.gen = cmdRing->gen;

		if (mp == NULL) {
			drop = B_TRUE;
		} else {
			mp->b_next = mp->b_cont = NULL;
			if (mp_head == NULL) {
				mp_head = mp_tail = mp;
			} else {
				mp_tail->b_cont = mp;
				mp_tail = mp;
			}
		}

		VMXNET3_INC_RING_IDX(compRing, compRing->next2comp);
		VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
		compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
	} while (!eop);

	if (compDesc->rcd.err)
		drop = B_TRUE;

	if (drop) {
		rxq->rx_dropped++;
		if (mp_head != NULL)
			freemsg(mp_head);
		return (NULL);
	}

	vmxnet3_rx_hwcksum(rxq->sc, mp_head, compDesc);
	return (mp_head);
}

/*
 * Attempt to receive packets from rxq. If no packets are available (or
 * an error occurred resulting in no usable packets) NULL is returned.
 * Otherwise a chained (via b_next) list of mblks is returned.
 */
mblk_t *
vmxnet3_rx_intr(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_compring_t	*compRing = &rxq->compRing;
	Vmxnet3_RxQueueCtrl	*rxqCtrl = rxq->sharedCtrl;
	Vmxnet3_GenericDesc	*compDesc;
	mblk_t			*mp_head, *mp_tail, *mp;

	mp_head = mp_tail = NULL;

	mutex_enter(&rxq->rxLock);

	for (;;) {
		compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
		if (compDesc->rcd.gen != compRing->gen)
			break;

		/*
		 * If the ring hasn't been started, we're not ready to
		 * process any packets, so just silently drop them.
		 */
		if (!rxq->started) {
			vmxnet3_cmdring_t	*cmdRing;
			Vmxnet3_GenericDesc	*rxd;

			cmdRing = &rxq->cmdRing;
			rxd = VMXNET3_GET_DESC(cmdRing, cmdRing->next2fill);

			rxd->rxd.gen = cmdRing->gen;
			VMXNET3_INC_RING_IDX(compRing, compRing->next2comp);
			VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
			continue;
		}

		/* vmxnet3_rx_one() increments compRing and cmdRing */
		mp = vmxnet3_rx_one(rxq);

		if (mp == NULL)
			continue;

		if (mp_head == NULL) {
			mp_head = mp_tail = mp;
		} else {
			mp_tail->b_next = mp;
			mp_tail = mp;
		}
	}

	if (rxqCtrl->updateRxProd) {
		vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
		uint32_t		rxprod;
		uint_t			idx = vmxnet3_rqidx(rxq);

		if (cmdRing->next2fill != 0) {
			rxprod = cmdRing->next2fill - 1;
		} else {
			/*
			 * All buffers are actually available, but we can't
			 * tell that to the device because it may interpret that
			 * as an empty ring. So skip one buffer.
			 */
			rxprod = cmdRing->size - 1;
		}
		VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_RXPROD(idx), rxprod);
	}

	mutex_exit(&rxq->rxLock);
	return (mp_head);
}

/*
 * Peek at the size of the next packet available on the ring.
 * Returns 0 if no packet or only a partial packet is available, otherwise
 * returns the size of the next packet.
 */
static uint32_t
vmxnet3_rx_check_poll(vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_compring_t	*compRing = &rxq->compRing;
	Vmxnet3_GenericDesc	*compDesc;
	boolean_t		eop;
	uint32_t		len;
	uint16_t		idx;
	uint8_t			gen;

	len = 0;
	eop = B_FALSE;
	gen = compRing->gen;
	idx = compRing->next2comp;

	compDesc = VMXNET3_GET_DESC(compRing, idx);
	if (!compDesc->rcd.sop)
		return (0);

	while (!eop) {
		if (compDesc->rcd.gen != gen)
			return (0);

		len += compDesc->rcd.len;
		eop = compDesc->rcd.eop;

		/*
		 * We're peeking ahead, so don't want to change the gen
		 * on compRing.
		 */
		idx++;
		if (idx == compRing->size) {
			idx = 0;
			gen ^= 1;
		}

		compDesc = VMXNET3_GET_DESC(compRing, idx);
	}

	return (len);
}

mblk_t *
vmxnet3_rx_poll(void *driver, int poll_bytes)
{
	vmxnet3_rxqueue_t	*rxq = driver;
	mblk_t			*mp_head, *mp_tail;
	uint32_t		len;

	mp_head = mp_tail = NULL;
	while (poll_bytes > 0) {
		mblk_t *mp;

		len = vmxnet3_rx_check_poll(rxq);
		if (len == 0 || len > poll_bytes)
			break;

		mp = vmxnet3_rx_one(rxq);
		if (mp_head == NULL) {
			mp_head = mp_tail = mp;
		} else {
			mp_tail->b_next = mp;
			mp_tail = mp;
		}
		ASSERT3U(msgsize(mp), ==, len);

		poll_bytes -= len;
	}

	return (mp_head);
}

static int
vmxnet3_rx_kstat_update(kstat_t *ksp, int rw)
{
	vmxnet3_rxqueue_t	*rxq = ksp->ks_private;
	vmxnet3_rx_kstats_t	*rxs = ksp->ks_data;
	UPT1_RxStats		*rxStats;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	mutex_enter(&rxq->sc->genLock);
	vmxnet3_get_stats(rxq->sc);
	mutex_exit(&rxq->sc->genLock);

	rxStats = &vmxnet3_rqdesc(rxq)->stats;

	mutex_enter(&rxq->rxLock);

	rxs->rx_nomblk.value.ui64 = rxq->rx_nomblk;
	rxs->rx_nobuf.value.ui64 = rxq->rx_nobuf;
	rxs->rx_nodma.value.ui64 = rxq->rx_nodma;
	rxs->rx_loaned.value.ui64 = rxq->rx_loaned;
	rxs->rx_loaned_bytes.value.ui64 = rxq->rx_loaned_bytes;
	rxs->rx_copied.value.ui64 = rxq->rx_copied;
	rxs->rx_copied_bytes.value.ui64 = rxq->rx_copied_bytes;
	rxs->rx_dropped.value.ui64 = rxq->rx_dropped;

	rxs->rx_hw_lro_pkts.value.ui64 = rxStats->LROPktsRxOK;
	rxs->rx_hw_lro_bytes.value.ui64 = rxStats->LROBytesRxOK;
	rxs->rx_hw_ucast_pkts.value.ui64 = rxStats->ucastPktsRxOK;
	rxs->rx_hw_ucast_bytes.value.ui64 = rxStats->ucastBytesRxOK;
	rxs->rx_hw_mcast_pkts.value.ui64 = rxStats->mcastPktsRxOK;
	rxs->rx_hw_mcast_bytes.value.ui64 = rxStats->mcastBytesRxOK;
	rxs->rx_hw_bcast_pkts.value.ui64 = rxStats->bcastPktsRxOK;
	rxs->rx_hw_bcast_bytes.value.ui64 = rxStats->bcastBytesRxOK;
	rxs->rx_hw_nobuf.value.ui64 = rxStats->pktsRxOutOfBuf;
	rxs->rx_hw_error.value.ui64 = rxStats->pktsRxError;

	mutex_exit(&rxq->rxLock);
	return (0);
}

int
vmxnet3_rx_kstat_init(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_rx_kstats_t	*rxs;
	char			buf[32];
	uint_t			rxq_num = vmxnet3_rqidx(rxq);

	(void) snprintf(buf, sizeof (buf), "rx_ring%u", rxq_num);

	rxq->rxRingStats = kstat_create(VMXNET3_MODNAME, dp->instance, buf,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (vmxnet3_rx_kstats_t) / sizeof (kstat_named_t), 0);
	if (rxq->rxRingStats == NULL)
		return (DDI_FAILURE);

	rxq->rxRingStats->ks_update = vmxnet3_rx_kstat_update;
	rxq->rxRingStats->ks_private = rxq;

	rxs = rxq->rxRingStats->ks_data;
	kstat_named_init(&rxs->rx_nomblk, "no_mblk", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_nobuf, "no_buf", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_nodma, "no_dmabuf", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_loaned, "loaned", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_loaned_bytes, "loaned_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_copied, "copied", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_copied_bytes, "copied_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_dropped, "dropped", KSTAT_DATA_UINT64);

	kstat_named_init(&rxs->rx_hw_lro_pkts, "hw_lro_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_lro_bytes, "hw_lro_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_ucast_pkts, "hw_ucast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_ucast_bytes, "hw_ucast_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_mcast_pkts, "hw_mcast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_mcast_bytes, "hw_mcast_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_bcast_pkts, "hw_bcast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_bcast_bytes, "hw_bcast_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_nobuf, "hw_nobuf", KSTAT_DATA_UINT64);
	kstat_named_init(&rxs->rx_hw_error, "hw_error", KSTAT_DATA_UINT64);
	kstat_install(rxq->rxRingStats);
	return (DDI_SUCCESS);
}

int
vmxnet3_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *valp)
{
	vmxnet3_rxqueue_t	*rxq = (vmxnet3_rxqueue_t *)rh;
	vmxnet3_softc_t		*dp = rxq->sc;
	UPT1_RxStats		*rxStats;

	rxStats = &vmxnet3_rqdesc(rxq)->stats;

	switch (stat) {
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
		break;
	default:
		return (ENOTSUP);
	}

	mutex_enter(&dp->genLock);
	vmxnet3_get_stats(dp);
	mutex_exit(&dp->genLock);

	mutex_enter(&rxq->rxLock);
	switch (stat) {
	case MAC_STAT_RBYTES:
		*valp = rxStats->ucastBytesRxOK + rxStats->mcastBytesRxOK +
		    rxStats->bcastBytesRxOK;
		break;
	case MAC_STAT_IPACKETS:
		*valp = rxStats->ucastPktsRxOK + rxStats->mcastPktsRxOK +
		    rxStats->bcastPktsRxOK;
		break;
	}
	mutex_exit(&rxq->rxLock);

	return (0);
}

/* desballoc() free callback */
static void
vmxnet3_rxbuf_mfree(void *arg)
{
	vmxnet3_rxbuf_t *rxb = arg;

	/*
	 * We should only be called as a result of msgfree(), which means
	 * we had an allocated mblk but now has been freed.
	 */
	ASSERT3P(rxb->mblk, !=, NULL);

	/*
	 * Reflect that the we no longer have a valid mblk because we're
	 * called by freeb().
	 */
	rxb->mblk = NULL;

	switch (rxb->state) {
	case VMXNET3_RX_FREE:
	case VMXNET3_RX_TEARDOWN:
		/*
		 * If we're already freed (and in the cache) or are
		 * tearing down, we have nothing to do.
		 */
		break;

	case VMXNET3_RX_ONLOAN:
		ASSERT3P(rxb->rxq, !=, NULL);

		/* Update loan accounting */
		mutex_enter(&rxb->rxq->rxLock);
		rxb->rxq->rx_onloan--;
		mutex_exit(&rxb->rxq->rxLock);

		/*FALLTHRU*/
	default:
		/* Return buffer to pool for recycling */
		vmxnet3_bufcache_free(rxb->sc->rxBufCache, rxb);
		break;
	}
}

static int
vmxnet3_rxbuf_ctor(void *el, void *arg)
{
	vmxnet3_rxbuf_t		*rxb = el;
	vmxnet3_softc_t		*sc = arg;

	rxb->sc = sc;
	rxb->rxq = NULL;
	rxb->state = VMXNET3_RX_FREE;
	rxb->freeCB.free_func = vmxnet3_rxbuf_mfree;
	rxb->freeCB.free_arg = (caddr_t)rxb;

	/* We always should have enough free bufs to populate the ring */
	rxb->dma = vmxnet3_bufcache_alloc(sc->bufCache);
	VERIFY3P(rxb->dma, !=, NULL);

	if (vmxnet3_rx_alloc_mblk(rxb) == NULL) {
		vmxnet3_bufcache_free(sc->bufCache, rxb->dma);
		rxb->dma = NULL;
		return (-1);
	}

	return (0);
}

/*
 * Called by vmxnet3_bufcache_free() to put the rxbuf back into a ready
 * to use state before re-adding it to the pool.
 */
static void
vmxnet3_rxbuf_reset(void *e, void *arg)
{
	vmxnet3_rxbuf_t *rxb = e;

	rxb->rxq = NULL;
	bzero(rxb->dma->buf, rxb->dma->bufLen);

	/*
	 * If we're not tearing everything down, we want to reset
	 * the rxbuf so it's ready to be used again by a RX ring.
	 */
	if (rxb->state != VMXNET3_RX_TEARDOWN) {
		(void) vmxnet3_rx_alloc_mblk(rxb);
		rxb->state = VMXNET3_RX_FREE;
	}
}

static void
vmxnet3_rxbuf_dtor(void *e, void *arg)
{
	vmxnet3_rxbuf_t		*rxb = e;
	vmxnet3_softc_t		*dp = arg;

	ASSERT3S(rxb->state, ==, VMXNET3_RX_FREE);

	/*
	 * Prevent recycling of the rxbuf by indicating we're tearing
	 * everything down.
	 */
	rxb->state = VMXNET3_RX_TEARDOWN;

	if (rxb->mblk != NULL)
		freemsg(rxb->mblk);

	vmxnet3_bufcache_free(dp->bufCache, rxb->dma);
}

int
vmxnet3_rxbuf_cache_init(vmxnet3_softc_t *dp)
{
	size_t nbuf;

	/* For now, add 50% extra rxbs (for loanout) */
	nbuf = (size_t)dp->rxRingSize + dp->rxRingSize / 2;

	/* We need as many bufs as the size of the ring */
	ASSERT3U(nbuf, >=, dp->rxRingSize);

	dp->rxBufCache = vmxnet3_bufcache_init(nbuf, sizeof (vmxnet3_rxbuf_t),
	    vmxnet3_rxbuf_ctor, vmxnet3_rxbuf_reset, vmxnet3_rxbuf_dtor, dp,
	    dp->intrPri);
	if (dp->rxBufCache == NULL)
		return (ENOMEM);

	return (0);
}
