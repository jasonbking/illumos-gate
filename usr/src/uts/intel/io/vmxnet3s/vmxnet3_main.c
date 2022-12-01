/*
 * Copyright (C) 2007-2014 VMware, Inc. All rights reserved.
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
 * Copyright 2022 RackTop Systems, Inc.
 */

#include <vmxnet3.h>

/*
 * This driver is based on VMware's version 3227872, and contains additional
 * enhancements (see README.txt).
 */
#define	BUILD_NUMBER_NUMERIC	3227872

/*
 * If we run out of rxPool buffers, only allocate if the MTU is <= PAGESIZE
 * so that we don't have to incur the cost of allocating multiple contiguous
 * pages (very slow) in interrupt context.
 */
#define	VMXNET3_ALLOC_OK(dp)	((dp)->cur_mtu <= PAGESIZE)

#define	VMXNET3_MACPROP_TXRINGSZ	"_txring_size"
#define	VMXNET3_MACPROP_RXRINGSZ	"_rxring_size"

#define	VMXNET3_MACPROP_RXBUFPOOL	"_rxbuf_pool"
#define	VMXNET3_RXPOOL_MIN		0
#define	VMXNET3_RXPOOL_MAXF		10
#define	VMXNET3_RXPOOL_DEFF		2

#define	VMXNET3_MACPROP_LSO		"_lso"
#define	VMXNET3_DEF_LSO			1

#define	VMXNET3_MACPROP_TX_COPY_THRESH	"_tx_copy_threshold"
#define	VMXNET3_DEF_TX_COPY_THRESH	128
#define	VMXNET3_TX_COPY_THRESH_MIN	VMXNET3_MIN_MTU
#define	VMXNET3_TX_COPY_THRESH_MAX	VMXNET3_MAX_MTU

/* For now at least, this isn't tunable */
#define	VMXNET3_TX_BUF_SIZE		2048

/*
 * TODO:
 *    - Tx data ring
 *    - MAC_CAPAB_POLL support
 *    - Dynamic RX pool
 */

static int vmxnet3_getstat(void *, uint_t, uint64_t *);
static int vmxnet3_start(void *);
static void vmxnet3_stop(void *);
static int vmxnet3_setpromisc(void *, boolean_t);
static int vmxnet3_multicst(void *, boolean_t, const uint8_t *);
static void vmxnet3_set_mac(vmxnet3_softc_t *, const uint8_t *);
static boolean_t vmxnet3_getcapab(void *, mac_capab_t, void *);
static int vmxnet3_get_prop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int vmxnet3_set_prop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void vmxnet3_prop_info(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static void vmxnet3_destroy_drivershared(vmxnet3_softc_t *);
static const char *vmxnet3_err_str(uint32_t);

#ifdef DEBUG
int vmxnet3s_debug = 2;
#else
int vmxnet3s_debug = 0;
#endif

/* This is the same key used by the Linux and FreeBSD driver. */
static const uint8_t rss_key[UPT1_RSS_MAX_KEY_SIZE] = {
	0x3b, 0x56, 0xd1, 0x56, 0x13, 0x4a, 0xe7, 0xac,
	0xe8, 0x79, 0x09, 0x75, 0xe8, 0x65, 0x79, 0x28,
	0x35, 0x12, 0xb9, 0x56, 0x7c, 0x76, 0x4b, 0x70,
	0xd8, 0x56, 0xa3, 0x18, 0x9b, 0x0a, 0xee, 0xf3,
	0x96, 0xa6, 0x9f, 0x8f, 0x9e, 0x8c, 0x90, 0xc9,
};

extern int ncpus;

static char *vmxnet3_priv_props[] = {
	VMXNET3_MACPROP_TXRINGSZ,
	VMXNET3_MACPROP_TX_COPY_THRESH,
	VMXNET3_MACPROP_RXRINGSZ,
	VMXNET3_MACPROP_RXBUFPOOL,
	VMXNET3_MACPROP_LSO,
	NULL,
};

/* MAC callbacks */
static mac_callbacks_t vmxnet3_mac_callbacks = {
	.mc_callbacks =	MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat =	vmxnet3_getstat,
	.mc_start =	vmxnet3_start,
	.mc_stop =	vmxnet3_stop,
	.mc_setpromisc = vmxnet3_setpromisc,
	.mc_multicst =	vmxnet3_multicst,
	.mc_unicst =	NULL,
	.mc_tx =	NULL,
	.mc_getcapab =	vmxnet3_getcapab,
	.mc_getprop =	vmxnet3_get_prop,
	.mc_setprop =	vmxnet3_set_prop,
	.mc_propinfo =	vmxnet3_prop_info
};

/* --- */

/*
 * Some commands generate a response that must be read before another command
 * is sent. As such we serialize access to the CMD register to avoid reading
 * bad responses.
 */
void
vmxnet3_send_cmd(vmxnet3_softc_t *dp, Vmxnet3_Cmd cmd)
{
	mutex_enter(&dp->cmdLock);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, (uint32_t)cmd);
	mutex_exit(&dp->cmdLock);
}

uint32_t
vmxnet3_send_cmd_val(vmxnet3_softc_t *dp, Vmxnet3_Cmd cmd)
{
	uint32_t val;

	mutex_enter(&dp->cmdLock);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, (uint32_t)cmd);
	val = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_CMD);
	mutex_exit(&dp->cmdLock);

	return (val);
}

/*
 * Getting stats is a global requests -- i.e. it is done for all rings.
 * To avoid potential repeated calls for stats from multiple rings, we
 * enforce a minimum interval between VMXNET3_CMD_GET_STAT calls.
 */
void
vmxnet3_get_stats(vmxnet3_softc_t *dp)
{
	hrtime_t now = gethrtime();

	ASSERT(MUTEX_HELD(&dp->genLock));

	if (now - dp->last_stat < VMXNET3_MIN_STAT_INTERVAL) {
		return;
	}
	vmxnet3_send_cmd(dp, VMXNET3_CMD_GET_STATS);
	dp->last_stat = now;
}

void
vmxnet3_intr_enable(vmxnet3_softc_t *dp, uint_t inum)
{
	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_IMR(inum), 0);
}

void
vmxnet3_intr_disable(vmxnet3_softc_t *dp, uint_t inum)
{
	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_IMR(inum), 1);
}

void
vmxnet3_intr_enable_all(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds = VMXNET3_DS(dp);

	for (uint_t i = 0; i < dp->intrCount; i++)
		vmxnet3_intr_enable(dp, i);
	ds->devRead.intrConf.intrCtrl &= ~VMXNET3_IC_DISABLE_ALL;
}

void
vmxnet3_intr_disable_all(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds = VMXNET3_DS(dp);

	ds->devRead.intrConf.intrCtrl |= VMXNET3_IC_DISABLE_ALL;
	for (uint_t i = 0; i < dp->intrCount; i++)
		vmxnet3_intr_disable(dp, i);
}

static int
vmxnet3_get_txstat(vmxnet3_softc_t *dp, uint_t stat, uint64_t *valp)
{
	if (stat == MAC_STAT_OERRORS)
		*valp = dp->tx_error;

	for (uint_t i = 0; i < dp->txNQueue; i++) {
		vmxnet3_txqueue_t	*txq = &dp->txQueue[i];
		UPT1_TxStats		*txStats = &VMXNET3_TQDESC(txq)->stats;

		mutex_enter(&txq->txLock);

		switch (stat) {
		case MAC_STAT_MULTIXMT:
			*valp += txStats->mcastPktsTxOK;
			break;
		case MAC_STAT_BRDCSTXMT:
			*valp += txStats->bcastPktsTxOK;
			break;
		case MAC_STAT_NOXMTBUF:
			*valp += txStats->pktsTxDiscard + txq->tx_pullup_failed;
			break;
		case MAC_STAT_OERRORS:
			*valp += txStats->pktsTxError;
			break;
		case MAC_STAT_OBYTES:
			*valp += txStats->ucastBytesTxOK +
			    txStats->mcastBytesTxOK + txStats->bcastBytesTxOK;
			break;
		case MAC_STAT_OPACKETS:
			*valp += txStats->ucastPktsTxOK +
			    txStats->mcastPktsTxOK + txStats->bcastPktsTxOK;
			break;
		default:
			/*
			 * We should only be called for stats we explicitly
			 * know about. Any unknown stats should have been
			 * handled in vmxnet3_getstat(), so getting here
			 * is a programming error.
			 */
			dev_err(dp->dip, CE_PANIC, "%s: invalid stat %u",
			    __func__, stat);
		}
		mutex_exit(&txq->txLock);
	}

	mutex_exit(&dp->genLock);
	return (0);
}

static int
vmxnet3_get_rxstat(vmxnet3_softc_t *dp, uint_t stat, uint64_t *valp)
{
	for (uint_t i = 0; i < dp->rxNQueue; i++) {
		vmxnet3_rxqueue_t	*rxq = &dp->rxQueue[i];
		UPT1_RxStats		*rxStats = &VMXNET3_RQDESC(rxq)->stats;

		mutex_enter(&rxq->rxLock);
		switch (stat) {
		case MAC_STAT_MULTIRCV:
			*valp += rxStats->mcastPktsRxOK;
			break;
		case MAC_STAT_BRDCSTRCV:
			*valp += rxStats->bcastPktsRxOK;
			break;
		case MAC_STAT_NORCVBUF:
			*valp += rxStats->pktsRxOutOfBuf + dp->rx_alloc_failed;
			break;
		case MAC_STAT_IERRORS:
			*valp += rxStats->pktsRxError;
			break;
		case MAC_STAT_RBYTES:
			*valp += rxStats->ucastBytesRxOK +
			    rxStats->mcastBytesRxOK + rxStats->bcastBytesRxOK;
			break;
		case MAC_STAT_IPACKETS:
			*valp += rxStats->ucastPktsRxOK +
			    rxStats->mcastPktsRxOK + rxStats->bcastPktsRxOK;
			break;
		default:
			/*
			 * For the same reason as vmxnet3_get_txstat(),
			 * reaching here is a programming error.
			 */
			dev_err(dp->dip, CE_PANIC, "%s: unknown stat %u",
			    __func__, stat);
		}
		mutex_exit(&rxq->rxLock);
	}
	mutex_exit(&dp->genLock);

	return (0);
}

/*
 * Fetch the statistics of a vmxnet3 device.
 *
 * Returns:
 *	0 on success, non-zero on failure.
 */
static int
vmxnet3_getstat(void *data, uint_t stat, uint64_t *val)
{
	vmxnet3_softc_t *dp = data;

	VMXNET3_DEBUG(dp, 3, "getstat(%u)\n", stat);

	mutex_enter(&dp->genLock);
	if (!dp->devEnabled) {
		mutex_exit(&dp->genLock);
		return (EBUSY);
	}

	/*
	 * First touch the related register
	 */
	switch (stat) {
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTXMT:
	case MAC_STAT_NORCVBUF:
	case MAC_STAT_IERRORS:
	case MAC_STAT_NOXMTBUF:
	case MAC_STAT_OERRORS:
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		vmxnet3_get_stats(dp);
		break;
	case MAC_STAT_IFSPEED:
		*val = dp->linkSpeed;
		mutex_exit(&dp->genLock);
		return (0);
	case MAC_STAT_COLLISIONS:
		*val = 0;
		mutex_exit(&dp->genLock);
		return (0);
	case ETHER_STAT_LINK_DUPLEX:
		/* nothing */
		*val = LINK_DUPLEX_FULL;
		mutex_exit(&dp->genLock);
		return (0);
	default:
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}

	switch (stat) {
	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTXMT:
	case MAC_STAT_NOXMTBUF:
	case MAC_STAT_OERRORS:
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		/* vmxnet3_get_txstat() will release genLock */
		return (vmxnet3_get_txstat(dp, stat, val));
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_NORCVBUF:
	case MAC_STAT_IERRORS:
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
		/* vmxnet3_get_rxstat() will release genLock */
		return (vmxnet3_get_rxstat(dp, stat, val));
	}

#ifndef __CHECKER__
	/*
	 * We should never reach here for any unknown stats. smatch agrees
	 * but gcc does not, so we're being extra paranoid.
	 */
	dev_err(dp->dip, CE_PANIC, "%s: unknown stat %u", __func__, stat);
	return (0);
#endif
}

/*
 * Allocate and initialize the shared data structures of a vmxnet3 device.
 */
static void
vmxnet3_prepare_drivershared(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds;

	ASSERT(MUTEX_HELD(&dp->genLock));

	ds = VMXNET3_DS(dp);
	ds->magic = VMXNET3_REV1_MAGIC;

	/* Take care of most of devRead */
	ds->devRead.misc.driverInfo.version = BUILD_NUMBER_NUMERIC;
	ds->devRead.misc.driverInfo.gos.gosBits = VMXNET3_GOS_BITS_64;
	ds->devRead.misc.driverInfo.gos.gosType = VMXNET3_GOS_TYPE_SOLARIS;
	ds->devRead.misc.driverInfo.gos.gosVer = 10;
	ds->devRead.misc.driverInfo.vmxnet3RevSpt = 1;
	ds->devRead.misc.driverInfo.uptVerSpt = 1;

	ds->devRead.misc.uptFeatures = UPT1_F_RXCSUM;
	ds->devRead.misc.mtu = dp->cur_mtu;

	/* XXX: ds->devRead.misc.maxNumRxSG */
	ds->devRead.misc.numTxQueues = dp->txNQueue;
	ds->devRead.misc.numRxQueues = dp->rxNQueue;
	ds->devRead.misc.queueDescPA = dp->queueDescs.bufPA;
	ds->devRead.misc.queueDescLen =
	    dp->rxNQueue * sizeof (Vmxnet3_RxQueueDesc) +
	    dp->txNQueue * sizeof (Vmxnet3_TxQueueDesc);
	VERIFY3U(ds->devRead.misc.queueDescLen, <=, dp->queueDescs.bufLen);

	ds->devRead.rxFilterConf.rxMode = 0;

	/* TxQueue and RxQueue information is filled in other functions */
	ds->devRead.intrConf.autoMask = (dp->intrMaskMode == VMXNET3_IMM_AUTO);
	ds->devRead.intrConf.numIntrs = dp->intrCount;
	for (uint_t i = 0; i < dp->intrCount; i++)
		ds->devRead.intrConf.modLevels[i] = UPT1_IML_ADAPTIVE;

	/*
	 * The event interrupt is always the last interrupt. If we only have
	 * a single interrupt, this is shared with everything else (0).
	 */
	ds->devRead.intrConf.eventIntrIdx = dp->intrCount - 1;
	ds->devRead.intrConf.intrCtrl = VMXNET3_IC_DISABLE_ALL;

	VERIFY(IS_P2ALIGNED(dp->txRingSize, VMXNET3_RING_SIZE_ALIGN));
	VERIFY3U(dp->txRingSize, >=, VMXNET3_TX_RING_MIN_SIZE);
	VERIFY3U(dp->txRingSize, <=, VMXNET3_TX_RING_MAX_SIZE);
	for (uint_t i = 0; i < dp->txNQueue; i++) {
		vmxnet3_txqueue_t *txq = &dp->txQueue[i];
		Vmxnet3_TxQueueDesc *tqdesc = VMXNET3_TQDESC(txq);

		ASSERT3U(dp->txRingSize * sizeof (Vmxnet3_GenericDesc), <=,
		    txq->cmdRing.dma.bufLen);
		ASSERT3U(dp->txRingSize * sizeof (Vmxnet3_GenericDesc), <=,
		    txq->compRing.dma.bufLen);

		vmxnet3_init_cmdring(&txq->cmdRing, dp->txRingSize);
		vmxnet3_init_compring(&txq->compRing, dp->txRingSize);

		mutex_enter(&txq->txLock);

		txq->sharedCtrl = &tqdesc->ctrl;
		txq->nent = dp->txRingSize;

		mutex_exit(&txq->txLock);

		tqdesc->conf.txRingBasePA = txq->cmdRing.dma.bufPA;
		tqdesc->conf.txRingSize = dp->txRingSize;
		tqdesc->conf.dataRingBasePA = 0;
		tqdesc->conf.dataRingSize = 0;

		tqdesc->conf.compRingBasePA = txq->compRing.dma.bufPA;
		tqdesc->conf.compRingSize = dp->txRingSize;

		tqdesc->conf.intrIdx = txq->intr_idx;
	}

	VERIFY(IS_P2ALIGNED(dp->rxRingSize, VMXNET3_RING_SIZE_ALIGN));
	VERIFY3U(dp->rxRingSize, >=, VMXNET3_RX_RING_MIN_SIZE);
	VERIFY3U(dp->rxRingSize, <=, VMXNET3_RX_RING_MAX_SIZE);
	for (uint_t i = 0; i < dp->rxNQueue; i++) {
		vmxnet3_rxqueue_t *rxq = &dp->rxQueue[i];
		Vmxnet3_RxQueueDesc *rqdesc = VMXNET3_RQDESC(rxq);

		ASSERT3U(dp->rxRingSize * sizeof (Vmxnet3_GenericDesc), <=,
		    rxq->cmdRing.dma.bufLen);
		ASSERT3U(dp->rxRingSize * sizeof (Vmxnet3_GenericDesc), <=,
		    rxq->compRing.dma.bufLen);

		vmxnet3_init_cmdring(&rxq->cmdRing, dp->rxRingSize);
		vmxnet3_init_compring(&rxq->compRing, dp->rxRingSize);

		rxq->sharedCtrl = &rqdesc->ctrl;
		rxq->nent = dp->rxRingSize;

		rqdesc->conf.rxRingBasePA[0] = rxq->cmdRing.dma.bufPA;
		rqdesc->conf.rxRingSize[0] = dp->rxRingSize;
		rqdesc->conf.rxRingBasePA[1] = 0;
		rqdesc->conf.rxRingSize[1] = 0;

		rqdesc->conf.compRingBasePA = rxq->compRing.dma.bufPA;
		rqdesc->conf.compRingSize = dp->rxRingSize;

		rqdesc->conf.intrIdx = rxq->intr_idx;
	}

	if (dp->rxNQueue > 1) {
		UPT1_RSSConf *rss = (UPT1_RSSConf *)dp->rss.buf;

		ds->devRead.misc.uptFeatures |= UPT1_F_RSS;
		ds->devRead.rssConfDesc.confVer = 1;
		ds->devRead.rssConfDesc.confPA = dp->rss.bufPA;
		ds->devRead.rssConfDesc.confLen = dp->rss.bufLen;

		rss->hashType =
		    UPT1_RSS_HASH_TYPE_IPV4 | UPT1_RSS_HASH_TYPE_TCP_IPV4 |
		    UPT1_RSS_HASH_TYPE_IPV6 | UPT1_RSS_HASH_TYPE_TCP_IPV6;
		rss->hashKeySize = UPT1_RSS_MAX_KEY_SIZE;
		rss->hashFunc = UPT1_RSS_HASH_FUNC_TOEPLITZ;
		rss->indTableSize = UPT1_RSS_MAX_IND_TABLE_SIZE;
		bcopy(rss_key, rss->hashKey, UPT1_RSS_MAX_KEY_SIZE);

		for (uint_t i = 0; i < UPT1_RSS_MAX_IND_TABLE_SIZE; i++) {
			rss->indTable[i] = i % dp->rxNQueue;
		}
	}

	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAL,
	    VMXNET3_ADDR_LO(dp->sharedData.bufPA));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAH,
	    VMXNET3_ADDR_HI(dp->sharedData.bufPA));
}

void
vmxnet3_init_cmdring(vmxnet3_cmdring_t *cmdRing, size_t nent)
{
	VERIFY3U(nent * sizeof (Vmxnet3_GenericDesc), <=, cmdRing->dma.bufLen);

	bzero(cmdRing->dma.buf, cmdRing->dma.bufLen);
	cmdRing->size = cmdRing->avail = nent;
	cmdRing->next2fill = 0;
	cmdRing->gen = VMXNET3_INIT_GEN;
}

/*
 * Allocate and initialize the command ring of a queue.
 */
static void
vmxnet3_alloc_cmdring(vmxnet3_softc_t *dp, vmxnet3_cmdring_t *cmdRing,
    size_t nent)
{
	VERIFY3U(nent, <=, UINT16_MAX);

	size_t sz = nent * sizeof (Vmxnet3_GenericDesc);

	VERIFY0(vmxnet3_alloc_dma_mem_512(dp, &cmdRing->dma, sz, B_TRUE));
	cmdRing->desc = (Vmxnet3_GenericDesc *)cmdRing->dma.buf;
	vmxnet3_init_cmdring(cmdRing, nent);
}

/* Initialize an allocated completion ring */
void
vmxnet3_init_compring(vmxnet3_compring_t *compRing, size_t nent)
{
	VERIFY3U(nent * sizeof (Vmxnet3_GenericDesc), <=, compRing->dma.bufLen);

	bzero(compRing->dma.buf, compRing->dma.bufLen);
	compRing->next2comp = 0;
	compRing->size = nent;
	compRing->gen = VMXNET3_INIT_GEN;
}

/*
 * Allocate and initialize the completion ring of a queue.
 */
void
vmxnet3_alloc_compring(vmxnet3_softc_t *dp, vmxnet3_compring_t *compRing,
    size_t nent)
{
	VERIFY3U(nent, <=, UINT16_MAX);

	size_t sz = nent * sizeof (Vmxnet3_TxCompDesc);

	VERIFY0(vmxnet3_alloc_dma_mem_512(dp, &compRing->dma, sz, B_TRUE));

	compRing->size = nent;
	compRing->desc = (Vmxnet3_GenericDesc *)compRing->dma.buf;

	vmxnet3_init_compring(compRing, nent);
}

/*
 * Initialize the tx queue of a vmxnet3 device.
 */
static void
vmxnet3_alloc_txqueue(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq, size_t nent)
{
	vmxnet3_alloc_cmdring(dp, &txq->cmdRing, nent);
	vmxnet3_alloc_compring(dp, &txq->compRing, nent);
	txq->metaRing = kmem_zalloc(nent * sizeof (vmxnet3_metatx_t), KM_SLEEP);
	txq->nalloc = nent;
}

static void
vmxnet3_alloc_rxqueue(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq, size_t nent)
{
	vmxnet3_alloc_cmdring(dp, &rxq->cmdRing, nent);
	vmxnet3_alloc_compring(dp, &rxq->compRing, nent);
	rxq->bufRing = kmem_zalloc(nent * sizeof (vmxnet3_bufdesc_t), KM_SLEEP);
	rxq->nalloc = nent;
}

/*
 * Destroy the tx queue of a vmxnet3 device.
 */
static void
vmxnet3_destroy_txqueue(vmxnet3_txqueue_t *txq)
{
	vmxnet3_softc_t *dp = txq->sc;

	ASSERT(txq->metaRing);
	ASSERT(txq->cmdRing.dma.buf && txq->compRing.dma.buf);

	vmxnet3_txqueue_fini(dp, txq);

	kmem_free(txq->metaRing, txq->nalloc * sizeof (vmxnet3_metatx_t));

	vmxnet3_free_dma_mem(&txq->cmdRing.dma);
	vmxnet3_free_dma_mem(&txq->compRing.dma);
}

/*
 * Destroy the rx queue of a vmxnet3 device.
 */
static void
vmxnet3_destroy_rxqueue(vmxnet3_rxqueue_t *rxq)
{
	ASSERT(rxq->bufRing);
	ASSERT(rxq->cmdRing.dma.buf && rxq->compRing.dma.buf);

	for (uint_t i = 0; i < rxq->cmdRing.size; i++) {
		vmxnet3_rxbuf_t *rxBuf = rxq->bufRing[i].rxBuf;

		if (rxBuf == NULL)
			continue;

		/*
		 * These are desballoc()ed mblk_ts. Calling freemsg() will
		 * call vmxnet3_free_rxbuf().
		 */
		if (rxBuf->mblk != NULL)
			freemsg(rxBuf->mblk);
	}

	kmem_free(rxq->bufRing, rxq->cmdRing.size * sizeof (vmxnet3_bufdesc_t));

	vmxnet3_free_dma_mem(&rxq->cmdRing.dma);
	vmxnet3_free_dma_mem(&rxq->compRing.dma);
}

/*
 * Apply new RX filters settings to a vmxnet3 device.
 */
static void
vmxnet3_refresh_rxfilter(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds = VMXNET3_DS(dp);

	ds->devRead.rxFilterConf.rxMode = dp->rxMode;
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, VMXNET3_CMD_UPDATE_RX_MODE);
}

/*
 * Fetch the link state of a vmxnet3 device.
 */
static void
vmxnet3_refresh_linkstate(vmxnet3_softc_t *dp)
{
	uint32_t ret32;

	ret32 = vmxnet3_send_cmd_val(dp, VMXNET3_CMD_GET_LINK);
	if (ret32 & 1) {
		dp->linkState = LINK_STATE_UP;
		dp->linkSpeed = (ret32 >> 16) * 1000000ULL;
	} else {
		dp->linkState = LINK_STATE_DOWN;
		dp->linkSpeed = 0;
	}
}

/*
 * Start a vmxnet3 device: allocate and initialize the shared data
 * structures and send a start command to the device.
 *
 * Returns:
 *	0 on success, non-zero error on failure.
 */
static int
vmxnet3_start(void *data)
{
	vmxnet3_softc_t *dp = data;
	uint32_t ret32;
	int err;

	VMXNET3_DEBUG(dp, 1, "start()\n");

	mutex_enter(&dp->genLock);

	/*
	 * Initialize vmxnet3's shared data and advertise its PA
	 */
	vmxnet3_prepare_drivershared(dp);

	/* Populate the rxpool */
	dp->rxPool.nBufsLimit = dp->rxBufPool;
	err = vmxnet3_rxpool_init(dp);
	if (err != 0) {
		VMXNET3_WARN(dp, "vmxnet3_rxpool_init() failed: %d", err);
		goto error_shared;
	}

	vmxnet3_set_mac(dp, dp->macaddr);

	/*
	 * Activate the device
	 */
	ret32 = vmxnet3_send_cmd_val(dp, VMXNET3_CMD_ACTIVATE_DEV);
	if (ret32 != 0) {
		VMXNET3_WARN(dp, "ACTIVATE_DEV failed: 0x%x\n", ret32);
		err = ENXIO;
		goto error_activate;
	}
	dp->devEnabled = B_TRUE;

	for (uint_t i = 0; i < dp->rxNQueue; i++) {
		VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_RXPROD(i), 0);
		/* VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_RXPROD2(i), 0); */
	}

	/*
	 * Update the RX filters, must be done after ACTIVATE_DEV
	 */
	dp->rxMode = VMXNET3_RXM_UCAST | VMXNET3_RXM_BCAST;
	vmxnet3_refresh_rxfilter(dp);

	/*
	 * Get the link state now because no events will be generated
	 */
	vmxnet3_refresh_linkstate(dp);
	mac_link_update(dp->mac, dp->linkState);

	vmxnet3_intr_enable_all(dp);
	mutex_exit(&dp->genLock);
	return (0);

error_activate:
	vmxnet3_rxpool_fini(dp);
error_shared:
	mutex_exit(&dp->genLock);
	return (err);
}

/*
 * Stop a vmxnet3 device: send a stop command to the device and
 * de-allocate the shared data structures.
 */
static void
vmxnet3_stop(void *data)
{
	vmxnet3_softc_t *dp = data;

	VMXNET3_DEBUG(dp, 1, "stop()\n");

	mutex_enter(&dp->genLock);

	/*
	 * Take the 2 locks related to asynchronous events.
	 * These events should always check dp->devEnabled before poking dp.
	 */
	vmxnet3_intr_disable_all(dp);

	dp->devEnabled = B_FALSE;
	vmxnet3_send_cmd(dp, VMXNET3_CMD_QUIESCE_DEV);

	vmxnet3_rxpool_fini(dp);

	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAL, 0);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAH, 0);

	mutex_exit(&dp->genLock);
}

/*
 * Set or unset promiscuous mode on a vmxnet3 device.
 */
static int
vmxnet3_setpromisc(void *data, boolean_t promisc)
{
	vmxnet3_softc_t *dp = data;

	VMXNET3_DEBUG(dp, 2, "setpromisc(%s)\n", promisc ? "TRUE" : "FALSE");

	mutex_enter(&dp->genLock);

	if (promisc) {
		dp->rxMode |= VMXNET3_RXM_PROMISC;
	} else {
		dp->rxMode &= ~VMXNET3_RXM_PROMISC;
	}

	vmxnet3_refresh_rxfilter(dp);

	mutex_exit(&dp->genLock);
	return (0);
}

/*
 * Add or remove a multicast address from/to a vmxnet3 device.
 *
 * Returns:
 *	0 on success, non-zero on failure.
 */
static int
vmxnet3_multicst(void *data, boolean_t add, const uint8_t *macaddr)
{
	vmxnet3_softc_t *dp = data;
	vmxnet3_dmabuf_t newMfTable;
	int ret = 0;
	uint16_t macIdx;
	size_t allocSize;

	VMXNET3_DEBUG(dp, 2, "multicst(%s, "MACADDR_FMT")\n",
	    add ? "add" : "remove", MACADDR_FMT_ARGS(macaddr));

	mutex_enter(&dp->genLock);

	/*
	 * First lookup the position of the given MAC to check if it is
	 * present in the existing MF table.
	 */
	for (macIdx = 0; macIdx < dp->mfTable.bufLen; macIdx += 6) {
		if (memcmp(&dp->mfTable.buf[macIdx], macaddr, 6) == 0) {
			break;
		}
	}

	/*
	 * Check for 2 situations we can handle gracefully by bailing out:
	 * Adding an already existing filter or removing a non-existing one.
	 */
	if (add && macIdx < dp->mfTable.bufLen) {
		VMXNET3_WARN(dp, MACADDR_FMT " already in MC filter list "
		    "@ %u\n", MACADDR_FMT_ARGS(macaddr), macIdx / 6);
		ASSERT(B_FALSE);
		goto done;
	}
	if (!add && macIdx == dp->mfTable.bufLen) {
		VMXNET3_WARN(dp, MACADDR_FMT " not in MC filter list @ %u\n",
		    MACADDR_FMT_ARGS(macaddr), macIdx / 6);
		ASSERT(B_FALSE);
		goto done;
	}

	/*
	 * Create the new MF table
	 */
	allocSize = dp->mfTable.bufLen + (add ? 6 : -6);
	if (allocSize) {
		ret = vmxnet3_alloc_dma_mem_1(dp, &newMfTable, allocSize,
		    B_TRUE);
		ASSERT(ret == 0);
		if (add) {
			(void) memcpy(newMfTable.buf, dp->mfTable.buf,
			    dp->mfTable.bufLen);
			(void) memcpy(newMfTable.buf + dp->mfTable.bufLen,
			    macaddr, 6);
		} else {
			(void) memcpy(newMfTable.buf, dp->mfTable.buf,
			    macIdx);
			(void) memcpy(newMfTable.buf + macIdx,
			    dp->mfTable.buf + macIdx + 6,
			    dp->mfTable.bufLen - macIdx - 6);
		}
	} else {
		newMfTable.buf = NULL;
		newMfTable.bufPA = 0;
		newMfTable.bufLen = 0;
	}

	/*
	 * Now handle 2 corner cases: if we're creating the first filter or
	 * removing the last one, we have to update rxMode accordingly.
	 */
	if (add && newMfTable.bufLen == 6) {
		ASSERT(!(dp->rxMode & VMXNET3_RXM_MCAST));
		dp->rxMode |= VMXNET3_RXM_MCAST;
		vmxnet3_refresh_rxfilter(dp);
	}
	if (!add && dp->mfTable.bufLen == 6) {
		ASSERT(newMfTable.buf == NULL);
		ASSERT(dp->rxMode & VMXNET3_RXM_MCAST);
		dp->rxMode &= ~VMXNET3_RXM_MCAST;
		vmxnet3_refresh_rxfilter(dp);
	}

	/*
	 * Now replace the old MF table with the new one
	 */
	if (dp->mfTable.buf) {
		vmxnet3_free_dma_mem(&dp->mfTable);
	}
	dp->mfTable = newMfTable;
	VMXNET3_DS(dp)->devRead.rxFilterConf.mfTablePA = newMfTable.bufPA;
	VMXNET3_DS(dp)->devRead.rxFilterConf.mfTableLen = newMfTable.bufLen;

done:
	/* Always update the filters */
	vmxnet3_send_cmd(dp, VMXNET3_CMD_UPDATE_MAC_FILTERS);
	mutex_exit(&dp->genLock);
	return (ret);
}

static int
vmxnet3_addmac(void *arg, const uint8_t *mac)
{
	vmxnet3_softc_t *dp = arg;

	if (ETHER_IS_MULTICAST(mac))
		return (EINVAL);

	if (bcmp(dp->macaddr, mac, ETHERADDRL) == 0)
		return (0);

	return (ENOTSUP);
}

static int
vmxnet3_remmac(void *arg, const uint8_t *mac)
{
	vmxnet3_softc_t *dp = arg;

	if (ETHER_IS_MULTICAST(mac))
		return (EINVAL);

	if (bcmp(dp->macaddr, mac, ETHERADDRL) == 0)
		return (0);

	return (ENOTSUP);
}

static void
vmxnet3_set_mac(vmxnet3_softc_t *dp, const uint8_t *macaddr)
{
	uint32_t val;

	val = *((uint32_t *)(macaddr + 0));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_MACL, val);

	val = *((uint16_t *)(macaddr + 4));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_MACH, val);
}

/*
 * Change the MTU as seen by the driver. This is only supported when
 * the mac is stopped.
 *
 * Returns:
 *	EBUSY if the device is enabled.
 *	EINVAL for invalid MTU values.
 *	0 on success.
 */
static int
vmxnet3_change_mtu(vmxnet3_softc_t *dp, uint32_t new_mtu)
{
	int ret;

	ASSERT(MUTEX_HELD(&dp->genLock));

	if (dp->devEnabled) {
		mutex_exit(&dp->genLock);
		return (EBUSY);
	}

	if (new_mtu == dp->cur_mtu) {
		VMXNET3_WARN(dp, "New MTU is same as old mtu : %d.\n", new_mtu);
		mutex_exit(&dp->genLock);
		return (0);
	}

	if (new_mtu < VMXNET3_MIN_MTU || new_mtu > VMXNET3_MAX_MTU) {
		VMXNET3_WARN(dp, "New MTU not in valid range [%d, %d].\n",
		    VMXNET3_MIN_MTU, VMXNET3_MAX_MTU);
		mutex_exit(&dp->genLock);
		return (EINVAL);
	} else if (new_mtu > ETHERMTU && !dp->allow_jumbo) {
		VMXNET3_WARN(dp, "MTU cannot be greater than %d because "
		    "accept-jumbo is not enabled.\n", ETHERMTU);
		mutex_exit(&dp->genLock);
		return (EINVAL);
	}

	dp->cur_mtu = new_mtu;
	dp->alloc_ok = VMXNET3_ALLOC_OK(dp);

	mutex_exit(&dp->genLock);

	if ((ret = mac_maxsdu_update(dp->mac, new_mtu)) != 0)
		VMXNET3_WARN(dp, "Unable to update mac with %d mtu: %d",
		    new_mtu, ret);

	return (ret);
}

static int
vmxnet3_get_prop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, void *prop_val)
{
	vmxnet3_softc_t *dp = data;
	uint32_t value;

	mutex_enter(&dp->genLock);

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT3U(prop_val_size, >=, sizeof (uint32_t));
		bcopy(&dp->cur_mtu, prop_val, sizeof (uint32_t));
		mutex_exit(&dp->genLock);
		return (0);
	case MAC_PROP_PRIVATE:
		if (strcmp(prop_name, VMXNET3_MACPROP_TXRINGSZ) == 0) {
			value = dp->txRingSize;
		} else if (strcmp(prop_name,
		    VMXNET3_MACPROP_TX_COPY_THRESH) == 0) {
			value = dp->txCopyThresh;
		} else if (strcmp(prop_name, VMXNET3_MACPROP_RXRINGSZ) == 0) {
			value = dp->rxRingSize;
		} else if (strcmp(prop_name, VMXNET3_MACPROP_RXBUFPOOL) == 0) {
			value = dp->rxBufPool;
		} else if (strcmp(prop_name, VMXNET3_MACPROP_LSO) == 0) {
			value = dp->lso;
		} else {
			mutex_exit(&dp->genLock);
			return (ENOTSUP);
		}

		if (prop_val == NULL) {
			mutex_exit(&dp->genLock);
			return (EINVAL);
		}

		if (snprintf(prop_val, prop_val_size, "%u",
		    value) >= prop_val_size) {
			mutex_exit(&dp->genLock);
			return (EOVERFLOW);
		}

		mutex_exit(&dp->genLock);
		return (0);
	default:
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}
}

static int
vmxnet3_set_prop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size __unused, const void *prop_val)
{
	vmxnet3_softc_t *dp = data;
	long result;
	char *endptr;
	boolean_t found = B_FALSE;

	mutex_enter(&dp->genLock);

	switch (prop_id) {
	case MAC_PROP_MTU: {
		uint32_t new_mtu;
		ASSERT3U(prop_val_size, >=, sizeof (uint32_t));
		bcopy(prop_val, &new_mtu, sizeof (new_mtu));
		/* vmxnet3_change_mtu() will release genLock */
		return (vmxnet3_change_mtu(dp, new_mtu));
	}
	case MAC_PROP_PRIVATE:
		if (ddi_strtol(prop_val, &endptr, 10, &result) != 0) {
			mutex_exit(&dp->genLock);
			return (EINVAL);
		}

		for (uint_t i = 0; vmxnet3_priv_props[i] != NULL; i++) {
			if (strcmp(vmxnet3_priv_props[i], prop_name) == 0) {
				found = B_TRUE;
				break;
			}
		}

		if (!found) {
			mutex_exit(&dp->genLock);
			return (ENOTSUP);
		}

		if (dp->devEnabled) {
			mutex_exit(&dp->genLock);
			return (EBUSY);
		}

		if (strcmp(prop_name, VMXNET3_MACPROP_TXRINGSZ) == 0) {
			if (result < VMXNET3_TX_RING_MIN_SIZE ||
			    result > VMXNET3_TX_RING_MAX_SIZE) {
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}

			/*
			 * The size must also be a multiple of 32. There is
			 * no way to express that via the dladm property
			 * interface, but this is a private property, so
			 * hopefully anyone trying to change the value will
			 * read this comment and be enlightened.
			 */
			if (!IS_P2ALIGNED(result, VMXNET3_RING_SIZE_ALIGN)) {
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}

			dp->txRingSize = result;
		} else if (strcmp(prop_name,
		    VMXNET3_MACPROP_TX_COPY_THRESH) == 0) {
			if (result < VMXNET3_TX_COPY_THRESH_MIN ||
			    result > VMXNET3_TX_COPY_THRESH_MAX) {
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}

			dp->txCopyThresh = result;
		} else if (strcmp(prop_name, VMXNET3_MACPROP_RXRINGSZ) == 0) {
			if (result < VMXNET3_RX_RING_MIN_SIZE ||
			    result > VMXNET3_RX_RING_MAX_SIZE) {
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}

			/*
			 * Similarly to the TX ring size, the RX ring size
			 * also must be a multiple of 32.
			 */
			if (!IS_P2ALIGNED(result, VMXNET3_RING_SIZE_ALIGN)) {
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}

			mutex_enter(&dp->rxPoolLock);
			dp->rxRingSize = result;
			mutex_exit(&dp->rxPoolLock);
		} else if (strcmp(prop_name, VMXNET3_MACPROP_RXBUFPOOL) == 0) {
			mutex_enter(&dp->rxPoolLock);
			if (result < VMXNET3_RXPOOL_MAXF * dp->rxRingSize) {
				mutex_exit(&dp->rxPoolLock);
				mutex_exit(&dp->genLock);
				return (EINVAL);
			}
			dp->rxBufPool = result;
			mutex_exit(&dp->rxPoolLock);
		} else if (strcmp(prop_name, VMXNET3_MACPROP_LSO) == 0) {
			dp->lso = result > 0 ? B_TRUE : B_FALSE;
		} else {
			mutex_exit(&dp->genLock);
			return (ENOTSUP);
		}
		break;
	default:
		break;
	}
	mutex_exit(&dp->genLock);
	return (ENOTSUP);
}

/* ARGSUSED */
static void
vmxnet3_prop_info(void *data, const char *prop_name, mac_prop_id_t prop_id,
    mac_prop_info_handle_t prop_handle)
{
	vmxnet3_softc_t *dp = data;

	switch (prop_id) {
	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, VMXNET3_MIN_MTU,
		    VMXNET3_MAX_MTU);
		return;
	case MAC_PROP_PRIVATE:
		if (strcmp(prop_name, VMXNET3_MACPROP_TXRINGSZ) == 0) {
			mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_range_uint32(prop_handle,
			    VMXNET3_TX_RING_MIN_SIZE, VMXNET3_TX_RING_MAX_SIZE);
			mac_prop_info_set_default_uint32(prop_handle,
			    VMXNET3_DEF_TX_RING_SIZE);
			return;
		}

		if (strcmp(prop_name, VMXNET3_MACPROP_TX_COPY_THRESH) == 0) {
			mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_range_uint32(prop_handle,
			    VMXNET3_TX_COPY_THRESH_MIN,
			    VMXNET3_TX_COPY_THRESH_MAX);
			mac_prop_info_set_default_uint32(prop_handle,
			    VMXNET3_DEF_TX_COPY_THRESH);
			return;
		}

		if (strcmp(prop_name, VMXNET3_MACPROP_RXRINGSZ) == 0) {
			mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_range_uint32(prop_handle,
			    VMXNET3_RX_RING_MIN_SIZE, VMXNET3_RX_RING_MAX_SIZE);
			mac_prop_info_set_default_uint32(prop_handle,
			    VMXNET3_DEF_RX_RING_SIZE);
			return;
		}

		if (strcmp(prop_name, VMXNET3_MACPROP_RXBUFPOOL) == 0) {
			mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_range_uint32(prop_handle,
			    VMXNET3_RXPOOL_MIN,
			    dp->rxRingSize * VMXNET3_RXPOOL_MAXF);
			mac_prop_info_set_default_uint32(prop_handle,
			    dp->rxRingSize * VMXNET3_RXPOOL_DEFF);
			return;
		}

		if (strcmp(prop_name, VMXNET3_MACPROP_LSO) == 0) {
			mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
			mac_prop_info_set_default_uint8(prop_handle,
			    VMXNET3_DEF_LSO);
			return;
		}
		break;
	default:
		return;
	}
}

static void
vmxnet3_fill_ring_info(void *driver, mac_ring_type_t rtype,
    const int group_index, const int ring_index, mac_ring_info_t *infop,
    mac_ring_handle_t rh)
{
	vmxnet3_softc_t *dp = (vmxnet3_softc_t *)driver;
	vmxnet3_txqueue_t *txq;
	vmxnet3_rxqueue_t *rxq;
	uint_t idx = 0;

	switch (rtype) {
	case MAC_RING_TYPE_TX:
		VERIFY3U(ring_index, <, dp->txNQueue);

		txq = &dp->txQueue[ring_index];
		txq->mrh = rh;
		idx = ring_index;

		infop->mri_driver = (mac_ring_driver_t)txq;
		infop->mri_start = vmxnet3_tx_start;
		infop->mri_stop = vmxnet3_tx_stop;
		infop->mri_tx = vmxnet3_tx_chain;
		infop->mri_stat = vmxnet3_tx_stat;

		infop->mri_intr.mi_handle = (mac_intr_handle_t)txq;
		infop->mri_intr.mi_enable = vmxnet3_tx_intr_enable;
		infop->mri_intr.mi_disable = vmxnet3_tx_intr_disable;
		break;
	case MAC_RING_TYPE_RX:
		VERIFY3U(ring_index, <, dp->rxNQueue);

		rxq = &dp->rxQueue[ring_index];
		rxq->mrh = rh;
		idx = dp->txNQueue + ring_index;

		infop->mri_driver = (mac_ring_driver_t)rxq;
		infop->mri_start = vmxnet3_rx_start;
		infop->mri_stop = vmxnet3_rx_stop;
		infop->mri_poll = NULL;
		infop->mri_stat = vmxnet3_rx_stat;
		infop->mri_intr.mi_handle = (mac_intr_handle_t)rxq;
		infop->mri_intr.mi_enable = vmxnet3_rx_intr_enable;
		infop->mri_intr.mi_disable = vmxnet3_rx_intr_disable;
		break;
	default:
		dev_err(dp->dip, CE_PANIC, "Unexpected ring type %d", rtype);
	}

	if (dp->intrType == DDI_INTR_TYPE_MSI ||
	    dp->intrType == DDI_INTR_TYPE_MSIX) {
		infop->mri_intr.mi_ddi_handle = dp->intrHandles[idx];
	}
}

static void
vmxnet3_fill_group_info(void *arg, mac_ring_type_t rtype,
    const int group_idx, mac_group_info_t *infop, mac_group_handle_t gh)
{
	vmxnet3_softc_t *dp = arg;

	switch (rtype) {
	case MAC_RING_TYPE_TX:
		return;
	case MAC_RING_TYPE_RX:
		infop->mgi_driver = (mac_group_driver_t)dp;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_count = dp->rxNQueue;
		infop->mgi_addmac = vmxnet3_addmac;
		infop->mgi_remmac = vmxnet3_remmac;
		infop->mgi_addvlan = NULL;
		infop->mgi_remvlan = NULL;
		break;
	default:
		dev_err(dp->dip, CE_PANIC, "unsupported ring type %d", rtype);
	}
}

/*
 * Get the capabilities of a vmxnet3 device.
 *
 * Returns:
 *	B_TRUE if the capability is supported, B_FALSE otherwise.
 */
static boolean_t
vmxnet3_getcapab(void *data, mac_capab_t capab, void *arg)
{
	vmxnet3_softc_t *dp = data;
	mac_capab_rings_t *cap_rings;
	mac_capab_lso_t *lso;
	uint32_t *txflags;
	boolean_t ret = B_TRUE;

	switch (capab) {
	case MAC_CAPAB_RINGS:
		cap_rings = arg;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = dp->txNQueue;
			cap_rings->mr_rget = vmxnet3_fill_ring_info;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rnum = dp->rxNQueue;
			cap_rings->mr_rget = vmxnet3_fill_ring_info;
			cap_rings->mr_gget = vmxnet3_fill_group_info;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		default:
			ret = B_FALSE;
			break;
		}
		break;
	case MAC_CAPAB_HCKSUM:
		txflags = arg;
		*txflags = HCKSUM_INET_PARTIAL;
		break;
	case MAC_CAPAB_LSO:
		lso = arg;
		lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		lso->lso_basic_tcp_ipv4.lso_max = IP_MAXPACKET;
		ret = dp->lso;
		break;
	default:
		ret = B_FALSE;
	}

	VMXNET3_DEBUG(dp, 2, "getcapab(0x%x) -> %s\n", capab,
	    ret ? "yes" : "no");

	return (ret);
}

/*
 * Reset a vmxnet3 device. Only to be used when the device is wedged.
 *
 * Side effects:
 *	The device is reset.
 */
static void
vmxnet3_reset(void *data)
{
	int ret;

	vmxnet3_softc_t *dp = data;

	VMXNET3_DEBUG(dp, 1, "vmxnet3_reset()\n");

	atomic_inc_32(&dp->reset_count);
	vmxnet3_stop(dp);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, VMXNET3_CMD_RESET_DEV);
	if ((ret = vmxnet3_start(dp)) != 0)
		VMXNET3_WARN(dp, "failed to reset the device: %d", ret);
}

/*
 * Process pending events on a vmxnet3 device.
 *
 * Returns:
 *	B_TRUE if the link state changed, B_FALSE otherwise.
 */
static boolean_t
vmxnet3_intr_events(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds = VMXNET3_DS(dp);
	boolean_t linkStateChanged = B_FALSE;
	uint32_t events = ds->ecr;

	mutex_enter(&dp->eventLock);

	if (events == 0) {
		mutex_exit(&dp->eventLock);
		return (B_FALSE);
	}

	VMXNET3_DEBUG(dp, 2, "events(0x%x)\n", events);
	if (events & (VMXNET3_ECR_RQERR | VMXNET3_ECR_TQERR)) {
		vmxnet3_send_cmd(dp, VMXNET3_CMD_GET_QUEUE_STATUS);

		for (uint_t i = 0; i < dp->txNQueue; i++) {
			Vmxnet3_TxQueueDesc *tqdesc =
			    VMXNET3_TQDESC(&dp->txQueue[i]);

			if (tqdesc->status.stopped) {
				VMXNET3_WARN(dp, "tq %u error 0x%x (%s)", i,
				    tqdesc->status.error,
				    vmxnet3_err_str(tqdesc->status.error));
			}
		}

		for (uint_t i = 0; i < dp->rxNQueue; i++) {
			Vmxnet3_RxQueueDesc *rqdesc =
			    VMXNET3_RQDESC(&dp->rxQueue[i]);

			if (rqdesc->status.stopped) {
				VMXNET3_WARN(dp, "rq %u error 0x%x (%s)", i,
				    rqdesc->status.error,
				    vmxnet3_err_str(rqdesc->status.error));
			}
		}

		if (ddi_taskq_dispatch(dp->resetTask, vmxnet3_reset,
		    dp, DDI_NOSLEEP) == DDI_SUCCESS) {
			VMXNET3_WARN(dp, "reset scheduled");
		} else {
			VMXNET3_WARN(dp, "ddi_taskq_dispatch() failed");
		}
	}
	if (events & VMXNET3_ECR_LINK) {
		vmxnet3_refresh_linkstate(dp);
		linkStateChanged = B_TRUE;
	}
	if (events & VMXNET3_ECR_DIC) {
		VMXNET3_DEBUG(dp, 1, "device implementation change\n");
	}
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_ECR, events);

	mutex_exit(&dp->eventLock);

	return (linkStateChanged);
}

/*
 * Interrupt handler of a vmxnet3 device.
 *
 * Returns:
 *	DDI_INTR_CLAIMED or DDI_INTR_UNCLAIMED.
 */
static uint_t
vmxnet3_intr(caddr_t arg1, caddr_t arg2 __unused)
{
	vmxnet3_softc_t *dp = (vmxnet3_softc_t *)arg1;

	VMXNET3_DEBUG(dp, 3, "intr()\n");

	if (!dp->devEnabled)
		return (DDI_INTR_UNCLAIMED);

	boolean_t linkStateChanged;
	boolean_t mustUpdateTx;
	mblk_t *mps;

	if (dp->intrType == DDI_INTR_TYPE_FIXED &&
	    !VMXNET3_BAR1_GET32(dp, VMXNET3_REG_ICR)) {
		return (DDI_INTR_UNCLAIMED);
	}

	if (dp->intrMaskMode == VMXNET3_IMM_ACTIVE) {
		vmxnet3_intr_disable(dp, 0);
	}

	linkStateChanged = vmxnet3_intr_events(dp);

	mustUpdateTx = vmxnet3_tx_complete(dp, &dp->txQueue[0]);

	mutex_enter(&dp->rxQueue[0].rxLock);
	mps = vmxnet3_rx(dp, &dp->rxQueue[0], 0);
	mutex_exit(&dp->rxQueue[0].rxLock);

	vmxnet3_intr_enable(dp, 0);

	if (linkStateChanged) {
		mac_link_update(dp->mac, dp->linkState);
	}
	if (mustUpdateTx) {
		mac_tx_ring_update(dp->mac, (mac_ring_handle_t)&dp->txQueue[0]);
	}
	if (mps != NULL) {
		mac_rx_ring(dp->mac, NULL, mps, dp->rxQueue[0].gen_num);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
vmxnet3_event_intr(caddr_t arg1, caddr_t arg2 __unused)
{
	vmxnet3_softc_t	*dp = (vmxnet3_softc_t *)arg1;
	boolean_t	linkStateChanged;

	linkStateChanged = vmxnet3_intr_events(dp);

	if (linkStateChanged)
		mac_link_update(dp->mac, dp->linkState);

	return (DDI_INTR_CLAIMED);
}

static int
vmxnet3_kstat_update(kstat_t *ksp, int rw)
{
	vmxnet3_softc_t *dp = ksp->ks_private;
	vmxnet3_kstats_t *statp = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	mutex_enter(&dp->genLock);
	statp->reset_count.value.ui64 = dp->reset_count;
	statp->tx_pullup_needed.value.ui64 = 0;
	statp->tx_ring_full.value.ui64 = 0;
	for (uint_t i = 0; i < dp->txNQueue; i++) {
		vmxnet3_txqueue_t *txq = &dp->txQueue[i];

		statp->tx_pullup_needed.value.ui64 += txq->tx_pullup_needed;
		statp->tx_ring_full.value.ui64 += txq->tx_ring_full;
	}
	statp->rx_alloc_buf.value.ui64 = dp->rx_alloc_buf;
	statp->rx_pool_empty.value.ui64 = dp->rx_pool_empty;
	statp->rx_num_bufs.value.ui64 = dp->rx_num_bufs;
	mutex_exit(&dp->genLock);

	return (0);
}

static int
vmxnet3_init_pci(vmxnet3_softc_t *dp)
{
	uint16_t vendorId, devId, ret16;

	/*
	 * Get access to the PCI bus configuration space
	 */
	if (pci_config_setup(dp->dip, &dp->pciHandle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "pci_config_setup() failed\n");
		return (DDI_FAILURE);
	}

	/*
	 * Make sure the chip is a vmxnet3 device
	 */
	vendorId = pci_config_get16(dp->pciHandle, PCI_CONF_VENID);
	devId = pci_config_get16(dp->pciHandle, PCI_CONF_DEVID);
	if (vendorId != PCI_VENDOR_ID_VMWARE ||
	    devId != PCI_DEVICE_ID_VMWARE_VMXNET3) {
		VMXNET3_WARN(dp, "wrong PCI venid/devid (0x%x, 0x%x)\n",
		    vendorId, devId);
		pci_config_teardown(&dp->pciHandle);
		return (DDI_FAILURE);
	}

	/*
	 * Make sure we can access the registers through the I/O space
	 */
	ret16 = pci_config_get16(dp->pciHandle, PCI_CONF_COMM);
	ret16 |= PCI_COMM_IO | PCI_COMM_ME;
	pci_config_put16(dp->pciHandle, PCI_CONF_COMM, ret16);

	return (DDI_SUCCESS);
}

static void
vmxnet3_fini_pci(vmxnet3_softc_t *dp)
{
	pci_config_teardown(&dp->pciHandle);
}

/*
 * Map the I/O space in memory
 */
static int
vmxnet3_init_regs(vmxnet3_softc_t *dp)
{
	if (ddi_regs_map_setup(dp->dip, 1, &dp->bar0, 0, 0, &vmxnet3_dev_attr,
	    &dp->bar0Handle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_regs_map_setup() for BAR0 failed\n");
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dp->dip, 2, &dp->bar1, 0, 0, &vmxnet3_dev_attr,
	    &dp->bar1Handle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_regs_map_setup() for BAR1 failed\n");
		ddi_regs_map_free(&dp->bar0Handle);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
vmxnet3_fini_regs(vmxnet3_softc_t *dp)
{
	ddi_regs_map_free(&dp->bar1Handle);
	ddi_regs_map_free(&dp->bar0Handle);
}

/*
 * Check the version number of the virtual device
 */
static int
vmxnet3_check_version(vmxnet3_softc_t *dp)
{
	if ((VMXNET3_BAR1_GET32(dp, VMXNET3_REG_VRRS) & 1) == 0) {
		VMXNET3_WARN(dp, "incompatible h/w version\n");
		return (DDI_FAILURE);
	}
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_VRRS, 1);

	if ((VMXNET3_BAR1_GET32(dp, VMXNET3_REG_UVRS) & 1) == 0) {
		VMXNET3_WARN(dp, "incompatible upt version\n");
		return (DDI_FAILURE);
	}
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_UVRS, 1);

	return (DDI_SUCCESS);
}

static int
vmxnet3_init_kstat(vmxnet3_softc_t *dp)
{
	vmxnet3_kstats_t *statp;

	dp->devKstats = kstat_create(VMXNET3_MODNAME, dp->instance,
	    "statistics", "dev",  KSTAT_TYPE_NAMED,
	    sizeof (vmxnet3_kstats_t) / sizeof (kstat_named_t), 0);
	if (dp->devKstats == NULL)
		return (DDI_FAILURE);

	dp->devKstats->ks_update = vmxnet3_kstat_update;
	dp->devKstats->ks_private = dp;

	statp = dp->devKstats->ks_data;

	kstat_named_init(&statp->reset_count, "reset_count", KSTAT_DATA_ULONG);
	kstat_named_init(&statp->tx_pullup_needed, "tx_pullup_needed",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&statp->tx_ring_full, "tx_ring_full",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&statp->rx_alloc_buf, "rx_alloc_buf",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&statp->rx_pool_empty, "rx_pool_empty",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&statp->rx_num_bufs, "rx_num_bufs",
	    KSTAT_DATA_ULONG);

	kstat_install(dp->devKstats);

	return (DDI_SUCCESS);
}

static void
vmxnet3_fini_kstat(vmxnet3_softc_t *dp)
{
	kstat_delete(dp->devKstats);
}

/*
 * Read the MAC address from the device
 */
static int
vmxnet3_get_macaddr(vmxnet3_softc_t *dp)
{
	uint32_t val;

	val = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_MACL);
	*((uint32_t *)(dp->macaddr + 0)) = val;
	val = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_MACH);
	*((uint16_t *)(dp->macaddr + 4)) = val;

	return (DDI_SUCCESS);
}

static int
vmxnet3_alloc_intr_handles(vmxnet3_softc_t *dp, int type)
{
	int req, count, avail, min, orig, actual;
	int ret;

	req = count = avail = min = orig = actual = 0;

	switch (type) {
	case DDI_INTR_TYPE_FIXED:
		req = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSI:
		req = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSIX:
		if (ncpus < dp->txNQueue)
			dp->txNQueue = ncpus;
		if (ncpus < dp->rxNQueue)
			dp->rxNQueue = ncpus;
		orig = req = dp->txNQueue + dp->rxNQueue + 1;
		min = 3;
		break;
	default:
		VMXNET3_WARN(dp, "%s: invalid interrupt type 0x%x",
		    __func__, type);
		return (DDI_FAILURE);
	}

	VMXNET3_DEBUG(dp, 2, "%s: type = 0x%x requested = %d min = %d\n",
	    __func__, type, req, min);

	ret = ddi_intr_get_nintrs(dp->dip, type, &count);
	if (ret != DDI_SUCCESS || count < min) {
		VMXNET3_DEBUG(dp, 2, "%s: ddi_intr_get_nintrs() failed "
		    "intr count = %d, min required = %d\n",
		    __func__, count, min);
		return (DDI_FAILURE);
	}

	VMXNET3_DEBUG(dp, 2, "%s: # of interrupts supported = %d\n", __func__,
	    count);

	ret = ddi_intr_get_navail(dp->dip, type, &avail);
	if (ret != DDI_SUCCESS) {
		VMXNET3_DEBUG(dp, 2, "%s: failed to get available interrupt "
		    "count\n", __func__);
		return (DDI_FAILURE);
	}

	if (avail < req) {
		VMXNET3_DEBUG(dp, 2,
		    "%s: requested %d interrupts, %d available\n", __func__,
		    req, avail);
	}

	if (avail > req) {
		VMXNET3_DEBUG(dp, 2,
		    "%s: more interrupts available (%d) than needed, "
		    "capping at %d", __func__, avail, req);
		avail = req;
	}

	dp->intrCount = 0;
	dp->intrHandleSz = avail * sizeof (ddi_intr_handle_t);
	dp->intrHandles = kmem_alloc(dp->intrHandleSz, KM_SLEEP);

	ret = ddi_intr_alloc(dp->dip, dp->intrHandles, type, 0, avail, &actual,
	    DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		VMXNET3_DEBUG(dp, 2, "%s: ddi_intr_alloc failed", __func__);
		goto fail;
	}

	if (actual < min) {
		VMXNET3_DEBUG(dp, 2, "%s: fewer interrupt handles allocated "
		    "(%d) than minimum required (%d)\n", __func__, actual, min);
		goto fail;
	}

	dp->intrCount = actual;

	/*
	 * For MSI-X, fewer interrupts will require us to reduce the number
	 * of rings.
	 */
	if (type == DDI_INTR_TYPE_MSIX && (orig > actual)) {
		int diff = orig - actual;

		if (diff < dp->txNQueue) {
			dp->txNQueue -= diff;
		} else {
			dp->txNQueue = 1;
			dp->rxNQueue = actual - 2;
		}

		dp->intrCount = dp->txNQueue + dp->rxNQueue + 1;

		VMXNET3_DEBUG(dp, 2, "%s: avail interrupts (%d) adjusted "
		    "#tx ring = %d #rx ring = %d\n", __func__, actual,
		    dp->txNQueue, dp->rxNQueue);
	}

	ret = ddi_intr_get_pri(dp->intrHandles[0], &dp->intrPri);
	if (ret != DDI_SUCCESS) {
		VMXNET3_DEBUG(dp, 2, "%s: failed to get interrupt priority\n",
		    __func__);
		goto fail;
	}

	ret = ddi_intr_get_cap(dp->intrHandles[0], &dp->intrCap);
	if (ret != DDI_SUCCESS) {
		VMXNET3_DEBUG(dp, 2,
		    "%s: failed to get interrupt capabilities\n", __func__);
		goto fail;
	}

	dp->intrType = type;
	return (DDI_SUCCESS);

fail:
	kmem_free(dp->intrHandles, dp->intrHandleSz);
	return (DDI_FAILURE);
}

/*
 * Register the interrupt(s) in this order of preference:
 * MSI-X, MSI, INTx
 */
static int
vmxnet3_alloc_intrs(vmxnet3_softc_t *dp)
{
	uint32_t val;
	int ret;

	/*
	 * We cannot use vmxnet3_send_cmd_val() here. dp->cmdLock is not
	 * yet initialized, and we cannot initialize cmdLock as that
	 * requires the interrupt priority (and we've not finished setting
	 * up interrupts at this point).
	 *
	 * Since we are in the attach path here, nothing else should be
	 * able to call into the driver during attach, so it should be
	 * safe to directly use the CMD register at this point.
	 */
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, VMXNET3_CMD_GET_CONF_INTR);
	val = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_CMD);

	switch (val & 0x3) {
	case VMXNET3_IT_AUTO:
	case VMXNET3_IT_MSIX:
		ret = vmxnet3_alloc_intr_handles(dp, DDI_INTR_TYPE_MSIX);
		if (ret == DDI_SUCCESS)
			break;
		VMXNET3_DEBUG(dp, 2, "DDI_INTR_TYPE_MSIX failed\n");
		/* FALLTHROUGH */
	case VMXNET3_IT_MSI:
		ret = vmxnet3_alloc_intr_handles(dp, DDI_INTR_TYPE_MSI);
		if (ret == DDI_SUCCESS) {
			dp->txNQueue = 1;
			dp->rxNQueue = 1;
			break;
		}
		VMXNET3_DEBUG(dp, 2, "DDI_INTR_TYPE_MSI failed\n");
		/* FALLTHROUGH */
	case VMXNET3_IT_INTX:
		ret = vmxnet3_alloc_intr_handles(dp, DDI_INTR_TYPE_FIXED);
		if (ret == DDI_SUCCESS) {
			dp->txNQueue = 1;
			dp->rxNQueue = 1;
			break;
		}
		VMXNET3_DEBUG(dp, 2, "DDI_INTR_TYPE_FIXED failed\n");
		/* FALLTHROUGH */
	default:
		VMXNET3_WARN(dp, "ddi_intr_alloc() failed\n");
		return (DDI_FAILURE);
	}

	dp->intrMaskMode = (val >> 2) & 0x3;
	if (dp->intrMaskMode == VMXNET3_IMM_LAZY) {
		VMXNET3_WARN(dp, "Lazy masking is not supported\n");
		kmem_free(dp->intrHandles,
		    dp->intrHandleSz * sizeof (ddi_intr_handle_t));
		dp->intrHandles = NULL;
		dp->intrHandleSz = 0;
		dp->intrCount = 0;
		return (DDI_FAILURE);
	}

	VMXNET3_DEBUG(dp, 2, "%s: intrType=0x%x, intrMaskMode=0x%x, intrPri=%u,"
	    " nintr=%d\n", __func__, dp->intrType, dp->intrMaskMode,
	    dp->intrPri, dp->intrCount);

	return (DDI_SUCCESS);
}

static void
vmxnet3_destroy_intrs(vmxnet3_softc_t *dp)
{
	uint_t i;

	if (dp->intrHandles == NULL)
		return;

	for (i = 0; i < dp->intrCount; i++)
		VERIFY0(ddi_intr_free(dp->intrHandles[i]));
	kmem_free(dp->intrHandles, dp->intrHandleSz);

	dp->intrHandles = NULL;
}

static int
vmxnet3_assign_intrs(vmxnet3_softc_t *dp)
{
	uint_t idx = 0;
	uint_t i;
	int ret;

	if (dp->intrType != DDI_INTR_TYPE_MSIX) {
		return (ddi_intr_add_handler(dp->intrHandles[0], vmxnet3_intr,
		    dp, NULL));
	}

	for (i = 0; i < dp->txNQueue; i++) {
		dp->txQueue[i].intr_idx = idx;

		ret = ddi_intr_add_handler(dp->intrHandles[idx++],
		    vmxnet3_tx_intr, &dp->txQueue[i], NULL);
		if (ret != DDI_SUCCESS)
			goto fail;
	}

	for (i = 0; i < dp->rxNQueue; i++) {
		dp->rxQueue[i].intr_idx = idx;

		ret = ddi_intr_add_handler(dp->intrHandles[idx++],
		    vmxnet3_rx_intr, &dp->rxQueue[i], NULL);
		if (ret != DDI_SUCCESS)
			goto fail;
	}


	ret = ddi_intr_add_handler(dp->intrHandles[idx++], vmxnet3_event_intr,
	    dp, NULL);
	if (ret != DDI_SUCCESS)
		goto fail;

	VERIFY3U(idx, ==, dp->intrCount);
	return (DDI_SUCCESS);

fail:
	while (idx > 0)
		VERIFY0(ddi_intr_remove_handler(dp->intrHandles[--idx]));
	return (DDI_FAILURE);
}

static void
vmxnet3_unassign_intrs(vmxnet3_softc_t *dp)
{
	uint_t i;

	for (i = 0; i < dp->intrCount; i++)
		VERIFY0(ddi_intr_remove_handler(dp->intrHandles[i]));
}

/*
 * Create a task queue to reset the device if it wedges.
 */
static int
vmxnet3_alloc_taskq(vmxnet3_softc_t *dp)
{
	dp->resetTask = ddi_taskq_create(dp->dip, "vmxnet3_reset_task", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (!dp->resetTask) {
		VMXNET3_WARN(dp, "ddi_taskq_create() failed()\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
vmxnet3_destroy_taskq(vmxnet3_softc_t *dp)
{
	ddi_taskq_destroy(dp->resetTask);
}

static int
vmxnet3_alloc_queues(vmxnet3_softc_t *dp)
{
	void *pri = DDI_INTR_PRI(dp->intrPri);
	uint_t i;

	/*
	 * Each ring consumes 64KB of DMA memory. Since that memory has to
	 * be physically contiguous, we preallocate enough DMA memory for
	 * all potential rings we may use during attachment. Since each TX
	 * queue uses two rings (cmd, completion) and there are a maximum of
	 * 8 TX queues allowed, that results in 1MB of DMA memory allocated
	 * for TX queues. Each RX queue also has 2 rings, however there are
	 * a maximum of 16 RX queues allowed, so RX queues use 2MB total of
	 * DMA memory (so 3MB total for both TX and RX).
	 *
	 * Since kernel memory can become fragmented as the system runs
	 * resulting in potentially _extremely_ long blocking during DMA memory
	 * allocation (in some cases minutes or more), preallocating this
	 * memory during attachment (when the odds are greater that the system
	 * can satisify the request without blocking for so long) seems like
	 * a reasonable tradeoff.
	 *
	 * Note that we do not preallocate any DMA memory for packets during
	 * attach. Since packets can always be segmented into PAGESIZE (or
	 * smaller) chunks during send or receive, allocating DMA memory for
	 * packets should (hopefully) not have the same concerns regarding
	 * kernel memory fragmentation. As such, we defer allocating DMA
	 * memory for packets until startup.
	 */
	for (i = 0; i < VMXNET3_MAX_TX_QUEUES; i++) {
		vmxnet3_txqueue_t *txq = &dp->txQueue[i];

		txq->sc = dp;
		mutex_init(&txq->txLock, NULL, MUTEX_DRIVER, pri);
		vmxnet3_alloc_txqueue(dp, txq, VMXNET3_TX_RING_MAX_SIZE);
	}

	for (i = 0; i < VMXNET3_MAX_RX_QUEUES; i++) {
		vmxnet3_rxqueue_t *rxq = &dp->rxQueue[i];

		rxq->sc = dp;
		mutex_init(&rxq->rxLock, NULL, MUTEX_DRIVER, pri);
		vmxnet3_alloc_rxqueue(dp, rxq, VMXNET3_RX_RING_MAX_SIZE);
	}

	return (0);
}

static void
vmxnet3_free_queues(vmxnet3_softc_t *dp)
{
	uint_t i;

	for (i = 0; i < VMXNET3_MAX_RX_QUEUES; i++) {
		mutex_destroy(&dp->rxQueue[i].rxLock);
		vmxnet3_destroy_rxqueue(&dp->rxQueue[i]);
	}

	for (i = 0; i < dp->txNQueue; i++) {
		mutex_destroy(&dp->txQueue[i].txLock);
		vmxnet3_destroy_txqueue(&dp->txQueue[i]);
	}
}

static int
vmxnet3_alloc_drivershared(vmxnet3_softc_t *dp)
{
	size_t qdescsz;

	VERIFY0(vmxnet3_alloc_dma_mem_1(dp, &dp->sharedData,
	    sizeof (Vmxnet3_DriverShared), B_TRUE));
	bzero(dp->sharedData.buf, dp->sharedData.bufLen);

	qdescsz = VMXNET3_MAX_TX_QUEUES * sizeof (Vmxnet3_TxQueueDesc) +
	    VMXNET3_MAX_RX_QUEUES * sizeof (Vmxnet3_RxQueueDesc);

	VERIFY0(vmxnet3_alloc_dma_mem_128(dp, &dp->queueDescs, qdescsz,
	    B_TRUE));
	bzero(dp->queueDescs.buf, dp->queueDescs.bufLen);

	VERIFY0(vmxnet3_alloc_dma_mem_128(dp, &dp->rss, sizeof (UPT1_RSSConf),
	    B_TRUE));

	return (0);
}

/*
 * Destroy the shared data structures of a vmxnet3 device.
 */
static void
vmxnet3_destroy_drivershared(vmxnet3_softc_t *dp)
{
	vmxnet3_free_dma_mem(&dp->rss);
	vmxnet3_free_dma_mem(&dp->queueDescs);
	vmxnet3_free_dma_mem(&dp->sharedData);
}

static int
vmxnet3_init_mutex(vmxnet3_softc_t *dp)
{
	uint_t pri = dp->intrPri;

	mutex_init(&dp->cmdLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&dp->genLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&dp->eventLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&dp->rxPoolLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	return (0);
}

static void
vmxnet3_fini_mutex(vmxnet3_softc_t *dp)
{
	mutex_destroy(&dp->rxPoolLock);
	mutex_destroy(&dp->eventLock);
	mutex_destroy(&dp->genLock);
	mutex_destroy(&dp->cmdLock);
}

static int
vmxnet3_register_mac(vmxnet3_softc_t *dp)
{
	mac_register_t *mac;
	int ret;

	mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		VMXNET3_WARN(dp, "mac_alloc() failed");
		return (DDI_FAILURE);
	}

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = dp;
	mac->m_dip = dp->dip;
	mac->m_instance = 0;
	mac->m_src_addr = dp->macaddr;
	mac->m_dst_addr = NULL;
	mac->m_callbacks = &vmxnet3_mac_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = ETHERMTU;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_pdata = NULL;
	mac->m_pdata_size = 0;
	mac->m_priv_props = vmxnet3_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	ret = mac_register(mac, &dp->mac);
	mac_free(mac);

	return ((ret == 0) ? DDI_SUCCESS : DDI_FAILURE);
}

static void
vmxnet3_unregister_mac(vmxnet3_softc_t *dp)
{
	VERIFY0(mac_unregister(dp->mac));
}

static int
vmxnet3_enable_intrs(vmxnet3_softc_t *dp)
{
	int ret;

	if (dp->intrCap & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_enable(dp->intrHandles, dp->intrCount);
		if (ret != DDI_SUCCESS) {
			VMXNET3_WARN(dp, "%s: failed to enable interrupts: %d",
			    __func__, ret);
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}

	for (uint_t i = 0; i < dp->intrCount; i++) {
		ret = ddi_intr_enable(dp->intrHandles[i]);
		if (ret != DDI_SUCCESS) {
			VMXNET3_WARN(dp,
			    "%s: failed to enable interrupt %u: %d", __func__,
			    i, ret);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static void
vmxnet3_disable_intrs(vmxnet3_softc_t *dp)
{
	if (dp->intrCap & DDI_INTR_FLAG_BLOCK) {
		VERIFY0(ddi_intr_block_disable(dp->intrHandles, dp->intrCount));
	}

	for (uint_t i = 0; i < dp->intrCount; i++) {
		VERIFY0(ddi_intr_disable(dp->intrHandles[i]));
	}
}

static struct {
	int		(*init_fn)(vmxnet3_softc_t *);
	void		(*fini_fn)(vmxnet3_softc_t *);
	const char	*desc;
} init_fns[] = {
	{ vmxnet3_init_pci, vmxnet3_fini_pci, "PCI configuration" },
	{ vmxnet3_init_regs, vmxnet3_fini_regs, "Map BARs" },
	{ vmxnet3_check_version, NULL, "Version check" },
	{ vmxnet3_init_kstat, vmxnet3_fini_kstat, "Create kstats" },
	{ vmxnet3_get_macaddr, NULL, "Read MAC address" },
	{ vmxnet3_alloc_intrs, vmxnet3_destroy_intrs, "Allocate interrupts" },
	{ vmxnet3_assign_intrs, vmxnet3_unassign_intrs, "Assign interrupts" },
	{ vmxnet3_alloc_taskq, vmxnet3_destroy_taskq, "Create taskq" },
	{ vmxnet3_alloc_queues, vmxnet3_free_queues, "Tx/Rx queues" },
	{ vmxnet3_alloc_drivershared, vmxnet3_destroy_drivershared,
	    "Shared driver data" },
	{ vmxnet3_init_mutex, vmxnet3_fini_mutex, "Mutex initialization" },
	{ vmxnet3_register_mac, vmxnet3_unregister_mac, "MAC registration" },
	{ vmxnet3_enable_intrs, vmxnet3_disable_intrs, "Enable interrupts" },
};

/*
 * Probe and attach a vmxnet3 instance to the stack.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 */
static int
vmxnet3_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	vmxnet3_softc_t *dp;
	int ret;
	uint_t i;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the soft state
	 */
	dp = kmem_zalloc(sizeof (vmxnet3_softc_t), KM_SLEEP);

	dp->dip = dip;
	dp->instance = ddi_get_instance(dip);
	dp->cur_mtu = ETHERMTU;
	dp->allow_jumbo = B_TRUE;
	dp->alloc_ok = VMXNET3_ALLOC_OK(dp);

	dp->txCopyThresh = VMXNET3_DEF_TX_COPY_THRESH;
	dp->txBufSize = VMXNET3_TX_BUF_SIZE;
	dp->txRingSize = VMXNET3_DEF_TX_RING_SIZE;
	dp->lso = VMXNET3_DEF_LSO;
	dp->txNQueue = VMXNET3_MAX_TX_QUEUES;

	dp->rxRingSize = VMXNET3_DEF_RX_RING_SIZE;
	dp->rxBufPool = VMXNET3_RXPOOL_DEFF * dp->rxRingSize;
	dp->rxNQueue = VMXNET3_MAX_RX_QUEUES;

	VMXNET3_DEBUG(dp, 1, "attach()\n");

	ddi_set_driver_private(dip, dp);

	for (i = 0; i < ARRAY_SIZE(init_fns); i++) {
		VMXNET3_DEBUG(dp, 2, "running attach step %u (%s)\n", i + 1,
		    init_fns[i].desc);

		/* If no init fn is defined, we treat as a successful step */
		if (init_fns[i].init_fn == NULL)
			continue;

		ret = init_fns[i].init_fn(dp);
		if (ret != DDI_SUCCESS) {
			VMXNET3_WARN(dp, "Attach step %u (%s) failed", i + 1,
			    init_fns[i].desc);
			goto fail;
		}
	}

	return (DDI_SUCCESS);

fail:
	while (i-- > 0) {
		VMXNET3_DEBUG(dp, 2, "running cleanup step %u (%s)\n", i + 1,
		    init_fns[i].desc);

		/* Treat a step w/o a cleanup function as successful */
		if (init_fns[i].fini_fn == NULL)
			continue;

		init_fns[i].fini_fn(dp);
	}

	kmem_free(dp, sizeof (*dp));
	return (DDI_FAILURE);
}

/*
 * Detach a vmxnet3 instance from the stack.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 */
static int
vmxnet3_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vmxnet3_softc_t *dp = ddi_get_driver_private(dip);
	unsigned int retries = 0;
	uint_t i;

	VMXNET3_DEBUG(dp, 1, "detach()\n");

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	while (dp->rx_num_bufs > 0) {
		if (retries++ < 10) {
			VMXNET3_WARN(dp, "rx pending (%u), waiting 1 second\n",
			    dp->rx_num_bufs);
			delay(drv_usectohz(1000000));
		} else {
			VMXNET3_WARN(dp, "giving up\n");
			return (DDI_FAILURE);
		}
	}

	i = ARRAY_SIZE(init_fns);
	while (i-- > 0) {
		VMXNET3_DEBUG(dp, 2, "running cleanup step %u (%s)\n", i + 1,
		    init_fns[i].desc);

		if (init_fns[i].fini_fn == NULL)
			continue;

		init_fns[i].fini_fn(dp);
	}

	kmem_free(dp, sizeof (vmxnet3_softc_t));
	return (DDI_SUCCESS);
}

static const char *
vmxnet3_err_str(uint32_t eval)
{
	switch (eval) {
	case 0x80000000:
		return ("cannot find the end of packet descriptor");
	case 0x80000001:
		return ("tx descriptor reused before tx complete");
	case 0x80000002:
		return ("too many tx descriptors for a packet");
	case 0x80000003:
		return ("descriptor type not supported");
	case 0x80000004:
		return ("type 0 buffer too small");
	case 0x80000005:
		return ("stress option firing in hypervisor");
	case 0x80000006:
		return ("mode switch failure");
	case 0x80000007:
		return ("invalid tx descriptor");
	default:
		return ("unknown");
	}
}

/*
 * Structures used by the module loader
 */

#define	VMXNET3_IDENT "VMware Ethernet v3 " VMXNET3_DRIVER_VERSION_STRING

DDI_DEFINE_STREAM_OPS(
	vmxnet3_dev_ops,
	nulldev,
	nulldev,
	vmxnet3_attach,
	vmxnet3_detach,
	nodev,
	NULL,
	D_NEW | D_MP,
	NULL,
	ddi_quiesce_not_supported);

static struct modldrv vmxnet3_modldrv = {
	&mod_driverops,		/* drv_modops */
	VMXNET3_IDENT,		/* drv_linkinfo */
	&vmxnet3_dev_ops	/* drv_dev_ops */
};

static struct modlinkage vmxnet3_modlinkage = {
	MODREV_1,			/* ml_rev */
	{ &vmxnet3_modldrv, NULL }	/* ml_linkage */
};

/* Module load entry point */
int
_init(void)
{
	int ret;

	mac_init_ops(&vmxnet3_dev_ops, VMXNET3_MODNAME);
	ret = mod_install(&vmxnet3_modlinkage);
	if (ret != DDI_SUCCESS) {
		mac_fini_ops(&vmxnet3_dev_ops);
	}

	return (ret);
}

/* Module unload entry point */
int
_fini(void)
{
	int ret;

	ret = mod_remove(&vmxnet3_modlinkage);
	if (ret == DDI_SUCCESS) {
		mac_fini_ops(&vmxnet3_dev_ops);
	}

	return (ret);
}

/* Module info entry point */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vmxnet3_modlinkage, modinfop));
}
