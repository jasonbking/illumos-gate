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
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Racktop Systems, Inc.
 */

#include <vmxnet3.h>

typedef enum vmxnet3_txstatus {
	VMXNET3_TX_OK,
	VMXNET3_TX_FAILURE,
	VMXNET3_TX_PULLUP,
	VMXNET3_TX_RINGFULL
} vmxnet3_txstatus;

typedef struct vmxnet3_offload_t {
	uint16_t om;
	uint16_t hlen;
	uint16_t msscof;
} vmxnet3_offload_t;

/* Tx DMA engine description */
static ddi_dma_attr_t vmxnet3_dma_attrs_tx = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_align =	0x0000000000000001ull,
	.dma_attr_burstsizes =	0x0000000000000001ull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	0x000000000000FFFFull,
	.dma_attr_seg =		0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen =	-1,
	.dma_attr_granular =	0x00000001,
	.dma_attr_flags =	0
};

int
vmxnet3_tx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	vmxnet3_softc_t		*dp = txq->sc;
	int			rc;

	VMXNET3_DEBUG(txq->sc, 2, "%s: enter", __func__);

	mutex_enter(&txq->txLock);

	rc = ddi_dma_alloc_handle(dp->dip, &vmxnet3_dma_attrs_tx,
	    DDI_DMA_SLEEP, NULL, &txq->tx_dma_handle);
	if (rc != DDI_SUCCESS) {
		mutex_exit(&txq->txLock);
		return (DDI_FAILURE);
	}

	txq->gen_num = gen_num;

	vmxnet3_init_cmdring(&txq->cmdRing, txq->sc->txRingSize);
	vmxnet3_init_compring(&txq->compRing, txq->sc->rxRingSize);

	/* TODO: tx copy buffers */

	mutex_exit(&txq->txLock);
	return (0);
}

void
vmxnet3_tx_stop(mac_ring_driver_t rh)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	vmxnet3_softc_t		*dp = txq->sc;

	VMXNET3_DEBUG(dp, 2, "%s: enter", __func__);

	mutex_enter(&txq->txLock);

	vmxnet3_tx_flush(txq);
	vmxnet3_txqueue_fini(dp, txq);
	VERIFY0(ddi_dma_unbind_handle(txq->tx_dma_handle));
	txq->tx_dma_handle = NULL;

	mutex_exit(&txq->txLock);
}

int
vmxnet3_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *valp)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	vmxnet3_softc_t		*dp = txq->sc;
	UPT1_TxStats		*txStats;

	txStats = &VMXNET3_TQDESC(txq)->stats;

	switch (stat) {
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		break;
	default:
		return (ENOTSUP);
	}

	mutex_enter(&dp->genLock);
	vmxnet3_get_stats(dp);
	mutex_exit(&dp->genLock);

	mutex_enter(&txq->txLock);

	switch (stat) {
	case MAC_STAT_OBYTES:
		*valp = txStats->ucastBytesTxOK + txStats->mcastBytesTxOK +
		    txStats->bcastBytesTxOK;
		break;
	case MAC_STAT_OPACKETS:
		*valp = txStats->ucastPktsTxOK + txStats->mcastPktsTxOK +
		    txStats->bcastPktsTxOK;
		break;
	}

	mutex_exit(&txq->txLock);
	return (0);
}

/*
 * Finish a TxQueue by freeing all pending Tx.
 */
void
vmxnet3_txqueue_fini(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq)
{
	unsigned int i;

	for (i = 0; i < txq->cmdRing.size; i++) {
		mblk_t *mp = txq->metaRing[i].mp;

		freemsg(mp);
		txq->metaRing[i].mp = NULL;
	}
}

void
vmxnet3_tx_flush(vmxnet3_txqueue_t *txq)
{
	vmxnet3_softc_t *dp = txq->sc;
	uint_t idx = (uint_t)(txq - dp->txQueue);

	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_TXPROD(idx), 0);
}

/*
 * Build the offload context of a msg.
 *
 * Returns:
 *	0 if everything went well.
 *	+n if n bytes need to be pulled up.
 *	-1 in case of error (not used).
 */
static int
vmxnet3_tx_prepare_offload(vmxnet3_softc_t *dp, vmxnet3_offload_t *ol,
    mblk_t *mp)
{
	int ret = 0;
	uint32_t start, stuff, value, flags, lso_flag, mss;

	ol->om = VMXNET3_OM_NONE;
	ol->hlen = 0;
	ol->msscof = 0;

	mac_hcksum_get(mp, &start, &stuff, NULL, &value, &flags);

	mac_lso_get(mp, &mss, &lso_flag);

	if (flags || lso_flag) {
		struct ether_vlan_header *eth = (void *) mp->b_rptr;
		uint8_t ethLen;

		if (eth->ether_tpid == htons(ETHERTYPE_VLAN)) {
			ethLen = sizeof (struct ether_vlan_header);
		} else {
			ethLen = sizeof (struct ether_header);
		}

		VMXNET3_DEBUG(dp, 4, "flags=0x%x, ethLen=%u, start=%u, "
		    "stuff=%u, value=%u\n", flags, ethLen, start, stuff, value);

		if (lso_flag & HW_LSO) {
			mblk_t *mblk = mp;
			uint8_t *ip, *tcp;
			uint8_t ipLen, tcpLen;

			/*
			 * Copy e1000g's behavior:
			 * - Do not assume all the headers are in the same mblk.
			 * - Assume each header is always within one mblk.
			 * - Assume the ethernet header is in the first mblk.
			 */
			ip = mblk->b_rptr + ethLen;
			if (ip >= mblk->b_wptr) {
				mblk = mblk->b_cont;
				ip = mblk->b_rptr;
			}
			ipLen = IPH_HDR_LENGTH((ipha_t *)ip);
			tcp = ip + ipLen;
			if (tcp >= mblk->b_wptr) {
				mblk = mblk->b_cont;
				tcp = mblk->b_rptr;
			}
			tcpLen = TCP_HDR_LENGTH((tcph_t *)tcp);
			/* Careful, '>' instead of '>=' here */
			if (tcp + tcpLen > mblk->b_wptr) {
				mblk = mblk->b_cont;
			}

			ol->om = VMXNET3_OM_TSO;
			ol->hlen = ethLen + ipLen + tcpLen;
			ol->msscof = mss;

			if (mblk != mp) {
				ret = ol->hlen;
			}
		} else if (flags & HCK_PARTIALCKSUM) {
			ol->om = VMXNET3_OM_CSUM;
			ol->hlen = start + ethLen;
			ol->msscof = stuff + ethLen;
		}
	}

	return (ret);
}

/*
 * Map a msg into the Tx command ring of a vmxnet3 device.
 *
 * Returns:
 *	VMXNET3_TX_OK if everything went well.
 *	VMXNET3_TX_RINGFULL if the ring is nearly full.
 *	VMXNET3_TX_PULLUP if the msg is overfragmented.
 *	VMXNET3_TX_FAILURE if there was a DMA or offload error.
 *
 * Side effects:
 *	The ring is filled if VMXNET3_TX_OK is returned.
 */
static vmxnet3_txstatus
vmxnet3_tx_one(void *arg, vmxnet3_offload_t *ol, mblk_t *mp)
{
	vmxnet3_txqueue_t *txq = arg;
	vmxnet3_softc_t *dp = txq->sc;
	int ret = VMXNET3_TX_OK;
	unsigned int frags = 0, totLen = 0;
	vmxnet3_cmdring_t *cmdRing = &txq->cmdRing;
	Vmxnet3_TxQueueCtrl *txqCtrl = txq->sharedCtrl;
	Vmxnet3_GenericDesc *txDesc;
	uint16_t sopIdx, eopIdx;
	uint8_t sopGen, curGen;
	mblk_t *mblk;

	sopIdx = eopIdx = cmdRing->next2fill;
	sopGen = cmdRing->gen;
	curGen = !cmdRing->gen;

	for (mblk = mp; mblk != NULL; mblk = mblk->b_cont) {
		const ddi_dma_cookie_t *cookie = NULL;
		unsigned int len = MBLKL(mblk);

		if (len > 0) {
			totLen += len;
		} else {
			continue;
		}

		if (ddi_dma_addr_bind_handle(txq->tx_dma_handle, NULL,
		    (caddr_t)mblk->b_rptr, len,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
		    NULL, NULL) != DDI_DMA_MAPPED) {
			VMXNET3_WARN(dp, "ddi_dma_addr_bind_handle() failed\n");
			ret = VMXNET3_TX_FAILURE;
			goto error;
		}

		for (cookie = ddi_dma_cookie_iter(txq->tx_dma_handle, NULL);
		    cookie != NULL;
		    cookie = ddi_dma_cookie_iter(txq->tx_dma_handle, cookie)) {
			uint64_t addr = cookie->dmac_laddress;
			size_t len = cookie->dmac_size;

			do {
				uint32_t dw2, dw3;
				size_t chunkLen;

				ASSERT(!txq->metaRing[eopIdx].mp);
				ASSERT(cmdRing->avail - frags);

				if (frags >= cmdRing->size - 1 ||
				    (ol->om != VMXNET3_OM_TSO &&
				    frags >= VMXNET3_MAX_TXD_PER_PKT)) {
					VMXNET3_DEBUG(dp, 2,
					    "overfragmented mp (%u)\n", frags);
					(void) ddi_dma_unbind_handle(
					    txq->tx_dma_handle);
					ret = VMXNET3_TX_PULLUP;
					goto error;
				}
				if (cmdRing->avail - frags <= 1) {
					txq->reschedule = B_TRUE;
					(void) ddi_dma_unbind_handle(
					    txq->tx_dma_handle);
					ret = VMXNET3_TX_RINGFULL;
					goto error;
				}

				chunkLen = MIN(len, VMXNET3_MAX_TX_BUF_SIZE);
				frags++;
				eopIdx = cmdRing->next2fill;

				txDesc = &cmdRing->desc[eopIdx];
				ASSERT3U(txDesc->txd.gen, !=, cmdRing->gen);

				/* txd.addr */
				txDesc->txd.addr = addr;
				/* txd.dw2 */
				dw2 = chunkLen == VMXNET3_MAX_TX_BUF_SIZE ?
				    0 : chunkLen;
				dw2 |= curGen << VMXNET3_TXD_GEN_SHIFT;
				txDesc->dword[2] = dw2;
				ASSERT(txDesc->txd.len == len ||
				    txDesc->txd.len == 0);
				/* txd.dw3 */
				dw3 = 0;
				txDesc->dword[3] = dw3;

				VMXNET3_INC_RING_IDX(cmdRing,
				    cmdRing->next2fill);
				curGen = cmdRing->gen;

				addr += chunkLen;
				len -= chunkLen;
			} while (len > 0);
		}

		(void) ddi_dma_unbind_handle(txq->tx_dma_handle);
	}

	/* Update the EOP descriptor */
	txDesc = VMXNET3_GET_DESC(cmdRing, eopIdx);
	txDesc->dword[3] |= VMXNET3_TXD_CQ | VMXNET3_TXD_EOP;

	/* Update the SOP descriptor. Must be done last */
	txDesc = VMXNET3_GET_DESC(cmdRing, sopIdx);
	if (ol->om == VMXNET3_OM_TSO && txDesc->txd.len != 0 &&
	    txDesc->txd.len < ol->hlen) {
		ret = VMXNET3_TX_FAILURE;
		goto error;
	}
	txDesc->txd.om = ol->om;
	txDesc->txd.hlen = ol->hlen;
	txDesc->txd.msscof = ol->msscof;
	membar_producer();
	txDesc->txd.gen = sopGen;

	/* Update the meta ring & metadata */
	txq->metaRing[sopIdx].mp = mp;
	txq->metaRing[eopIdx].sopIdx = sopIdx;
	txq->metaRing[eopIdx].frags = frags;
	cmdRing->avail -= frags;
	if (ol->om == VMXNET3_OM_TSO) {
		txqCtrl->txNumDeferred +=
		    (totLen - ol->hlen + ol->msscof - 1) / ol->msscof;
	} else {
		txqCtrl->txNumDeferred++;
	}

	VMXNET3_DEBUG(dp, 3, "tx 0x%p on [%u;%u]\n", (void *)mp, sopIdx,
	    eopIdx);

	return (ret);

error:
	/* Reverse the generation bits */
	while (sopIdx != cmdRing->next2fill) {
		VMXNET3_DEC_RING_IDX(cmdRing, cmdRing->next2fill);
		txDesc = VMXNET3_GET_DESC(cmdRing, cmdRing->next2fill);
		txDesc->txd.gen = !cmdRing->gen;
	}

	return (ret);
}

static mblk_t *
vmxnet3_tx_mp(void *arg, mblk_t *orig_mp)
{
	vmxnet3_txqueue_t *txq = arg;
	vmxnet3_softc_t *dp = txq->sc;
	mblk_t *mp = orig_mp;
	vmxnet3_offload_t ol;
	vmxnet3_txstatus status = VMXNET3_TX_OK;
	int pullup;

	mutex_enter(&txq->txLock);

	pullup = vmxnet3_tx_prepare_offload(dp, &ol, mp);
	if (pullup > 0) {
		mp = msgpullup(orig_mp, pullup);
		txq->tx_pullup_needed++;
		if (mp == NULL) {
			txq->tx_pullup_failed++;
			txq->reschedule = B_TRUE;
			mutex_exit(&txq->txLock);
			return (orig_mp);
		}
	}

	switch ((status = vmxnet3_tx_one(txq, &ol, mp))) {
	case VMXNET3_TX_OK:
		if (mp != orig_mp)
			freemsg(orig_mp);
		mutex_exit(&txq->txLock);
		return (NULL);
	case VMXNET3_TX_FAILURE:
		txq->reschedule = B_TRUE;
		/*FALLTHRU*/
	case VMXNET3_TX_RINGFULL:
		txq->tx_ring_full++;
		if (mp != orig_mp)
			freemsg(mp);
		mutex_exit(&txq->txLock);
		return (orig_mp);
	case VMXNET3_TX_PULLUP:
		if (mp != orig_mp) {
			freemsg(mp);
			mp = NULL;
		}
		break;
	default:
		dev_err(dp->dip, CE_PANIC,
		    "vmxnet3_tx_one() invalid return value %d", status);
	}

	mp = msgpullup(orig_mp, -1);
	if (mp == NULL) {
		txq->tx_pullup_failed++;
		txq->reschedule = B_TRUE;
		mutex_exit(&txq->txLock);
		return (orig_mp);
	}
	txq->tx_pullup_needed++;

	switch ((status = vmxnet3_tx_one(txq, &ol, mp))) {
	case VMXNET3_TX_OK:
		break;
	case VMXNET3_TX_FAILURE:
	case VMXNET3_TX_RINGFULL:
		txq->tx_ring_full++;
		freemsg(mp);
		txq->reschedule = B_TRUE;
		mutex_exit(&txq->txLock);
		return (orig_mp);
	case VMXNET3_TX_PULLUP:
		dev_err(dp->dip, CE_PANIC,
		    "vmxnet3_tx_one() returned VMXNET3_TX_PULLUP on single "
		    "mblk_t");
		break;
	default:
		dev_err(dp->dip, CE_PANIC,
		    "vmxnet3_tx_one() invalid return value %d", status);
		break;
	}

	freemsg(orig_mp);
	mutex_exit(&txq->txLock);
	return (NULL);
}

/*
 * Send packets on a vmxnet3 device.
 *
 * Returns:
 *	NULL in case of success or failure.
 *	The mps to be retransmitted later if the ring is full.
 */
mblk_t *
vmxnet3_tx_chain(void *mrh, mblk_t *mps)
{
	vmxnet3_txqueue_t *txq = mrh;
	vmxnet3_softc_t *dp = txq->sc;
	vmxnet3_cmdring_t *cmdRing = &txq->cmdRing;
	Vmxnet3_TxQueueCtrl *txqCtrl = txq->sharedCtrl;
	mblk_t *mp = mps;
	uint_t qidx = (uint_t)(txq - dp->txQueue);

	while (mp != NULL) {
		mps = mp->b_next;
		mp->b_next = NULL;

		if (DB_TYPE(mp) != M_DATA) {
			/*
			 * PR #315560: M_PROTO mblks could be passed for
			 * some reason. Drop them because we don't understand
			 * them and because their contents are not Ethernet
			 * frames anyway.
			 */
			ASSERT(B_FALSE);
			freemsg(mp);
			mp = mps;
			continue;
		}

		mp = vmxnet3_tx_mp(txq, mp);
		if (mp != NULL)
			break;

		mp = mps;
	}

	/* Notify the device */
	mutex_enter(&txq->txLock);
	if (txqCtrl->txNumDeferred >= txqCtrl->txThreshold) {
		txqCtrl->txNumDeferred = 0;
		VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_TXPROD(qidx),
		    cmdRing->next2fill);
	}
	mutex_exit(&txq->txLock);

	if (mp != NULL)
		mp->b_next = mps;

	return (mp);
}

/*
 * Parse a transmit queue and complete packets.
 *
 * Returns:
 *	B_TRUE if Tx must be updated or B_FALSE if no action is required.
 */
boolean_t
vmxnet3_tx_complete(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq)
{
	vmxnet3_cmdring_t *cmdRing = &txq->cmdRing;
	vmxnet3_compring_t *compRing = &txq->compRing;
	Vmxnet3_GenericDesc *compDesc;
	boolean_t completedTx = B_FALSE;
	boolean_t ret = B_FALSE;

	mutex_enter(&txq->txLock);

	compDesc = &compRing->desc[compRing->next2comp];
	while (compDesc->tcd.gen == compRing->gen) {
		vmxnet3_metatx_t *sopMetaDesc, *eopMetaDesc;
		uint16_t sopIdx, eopIdx;
		mblk_t *mp;

		eopIdx = compDesc->tcd.txdIdx;
		eopMetaDesc = &txq->metaRing[eopIdx];
		sopIdx = eopMetaDesc->sopIdx;
		sopMetaDesc = &txq->metaRing[sopIdx];

		ASSERT(eopMetaDesc->frags);
		cmdRing->avail += eopMetaDesc->frags;

		ASSERT(sopMetaDesc->mp);
		mp = sopMetaDesc->mp;
		freemsg(mp);

		eopMetaDesc->sopIdx = 0;
		eopMetaDesc->frags = 0;
		sopMetaDesc->mp = NULL;

		completedTx = B_TRUE;

		VMXNET3_DEBUG(dp, 3, "cp 0x%p on [%u;%u]\n", (void *)mp, sopIdx,
		    eopIdx);

		VMXNET3_INC_RING_IDX(compRing, compRing->next2comp);
		compDesc = &compRing->desc[compRing->next2comp];
	}

	if (txq->reschedule && completedTx) {
		txq->reschedule = B_FALSE;
		ret = B_TRUE;
	}

	mutex_exit(&txq->txLock);

	return (ret);
}

/* MSI-X TX completion interrupt */
uint_t
vmxnet3_tx_intr(caddr_t arg1, caddr_t arg2)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)arg1;
	vmxnet3_softc_t		*dp = txq->sc;

	if (dp->intrMaskMode == VMXNET3_IMM_ACTIVE)
		(void) vmxnet3_tx_intr_disable((mac_intr_handle_t)txq);

	/*
	 * XXX: The FreeBSD source suggests that the work done by
	 * vmxnet3_tx_complete could be expensive. It explicitly does not
	 * use TX interrupts for completion. Perhaps we should do this
	 * in a softint?
	 */
	if (vmxnet3_tx_complete(dp, txq))
		mac_tx_ring_update(dp->mac, txq->mrh);

	(void) vmxnet3_tx_intr_enable((mac_intr_handle_t)txq);
	return (DDI_INTR_CLAIMED);
}

int
vmxnet3_tx_intr_enable(mac_intr_handle_t mih)
{
	vmxnet3_txqueue_t *txq = (vmxnet3_txqueue_t *)mih;
	vmxnet3_softc_t *dp = txq->sc;

	vmxnet3_intr_enable(dp, txq->intr_idx);
	return (0);
}

int
vmxnet3_tx_intr_disable(mac_intr_handle_t mih)
{
	vmxnet3_txqueue_t *txq = (vmxnet3_txqueue_t *)mih;
	vmxnet3_softc_t *dp = txq->sc;

	vmxnet3_intr_disable(dp, txq->intr_idx);
	return (0);
}
