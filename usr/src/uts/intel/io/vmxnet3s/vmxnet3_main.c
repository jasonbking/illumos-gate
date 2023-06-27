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
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <vmxnet3.h>

/*
 * This driver is based on VMware's version 3227872, and contains additional
 * enhancements (see README.txt).
 */
#define	BUILD_NUMBER_NUMERIC	3227872

typedef enum vmxnet3_props {
	VMXNET3_PROP_TXRINGSZ = 0,
	VMXNET3_PROP_RXRINGSZ,
	VMXNET3_PROP_TXCOPY,
	VMXNET3_PROP_TXCOPYMAX,
	VMXNET3_PROP_RXCOPY,
	VMXNET3_PROP_RXLOANMAX,
	VMXNET3_PROP_LSO,
	VMXNET3_PROP_LRO,
} vmxnet3_props_t;

/*
 * The order of these must match vmxnet3_props_t. Currently
 * mac_register_t.m_priv_props doesn't allow const strings (unfortunately),
 * so this can't be const char *[].
 */
static char *vmxnet3_prop_strs[] = {
	"_txring_size",
	"_rxring_size",
	"_tx_copy_threshold",
	"_tx_copy_max",
	"_rx_copy_threshold",
	"_rx_loan_max",
	"_lso",
	"_lro",
	NULL
};

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
static int vmxnet3_unicst(void *, const uint8_t *);
static int vmxnet3_multicst(void *, boolean_t, const uint8_t *);
static boolean_t vmxnet3_getcapab(void *, mac_capab_t, void *);
static void vmxnet3_set_mac(vmxnet3_softc_t *, const uint8_t *);
static int vmxnet3_get_prop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int vmxnet3_set_prop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void vmxnet3_prop_info(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static boolean_t vmxnet3_parse_propstr(const char *, vmxnet3_props_t *);
static const char *vmxnet3_err_str(uint32_t);

#ifdef DEBUG
int vmxnet3s_debug = 2;
#else
int vmxnet3s_debug = 0;
#endif

/* MAC callbacks */
static mac_callbacks_t vmxnet3_legacy_mac_callbacks = {
	.mc_callbacks =	MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat =	vmxnet3_getstat,
	.mc_start =	vmxnet3_start,
	.mc_stop =	vmxnet3_stop,
	.mc_setpromisc = vmxnet3_setpromisc,
	.mc_multicst =	vmxnet3_multicst,
	.mc_unicst =	vmxnet3_unicst,
	.mc_tx =	vmxnet3_tx,
	.mc_ioctl =	NULL,
	.mc_getcapab =	vmxnet3_getcapab,
	.mc_getprop =	vmxnet3_get_prop,
	.mc_setprop =	vmxnet3_set_prop,
	.mc_propinfo =	vmxnet3_prop_info
};

static mac_callbacks_t vmxnet3_mac_callbacks = {
	.mc_callbacks =	MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat =	vmxnet3_getstat,
	.mc_start =	vmxnet3_start,
	.mc_stop =	vmxnet3_stop,
	.mc_setpromisc = vmxnet3_setpromisc,
	.mc_multicst =	vmxnet3_multicst,
	.mc_unicst =	NULL,
	.mc_tx =	NULL,
	.mc_ioctl =	NULL,
	.mc_getcapab =	vmxnet3_getcapab,
	.mc_getprop =	vmxnet3_get_prop,
	.mc_setprop =	vmxnet3_set_prop,
	.mc_propinfo =	vmxnet3_prop_info
};

/* --- */
void
vmxnet3_intr_enable(vmxnet3_softc_t *dp, uint_t inum)
{
	ASSERT3U(inum, <, dp->intrCount);
	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_IMR(inum), 0);
}

void
vmxnet3_intr_disable(vmxnet3_softc_t *dp, uint_t inum)
{
	ASSERT3U(inum, <, dp->intrCount);
	VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_IMR(inum), 1);
}

/*
 * Getting statistics is global, so to avoid repeated calls in succession
 * (e.g for tx or rx stats), we enforce a (hopefully) reasonable minimum
 * time between calls.
 */
void
vmxnet3_get_stats(vmxnet3_softc_t *dp)
{
	ASSERT(MUTEX_HELD(&dp->genLock));

	vmxnet3_send_cmd(dp, VMXNET3_CMD_GET_STATS);
}

static uint64_t
vmxnet3_get_txstat(vmxnet3_txqueue_t *txq, uint_t stat)
{
	UPT1_TxStats		*txStats;

	txStats = &vmxnet3_tqdesc(txq)->stats;

	switch (stat) {
	case MAC_STAT_MULTIXMT:
		return (txStats->mcastPktsTxOK);
	case MAC_STAT_BRDCSTXMT:
		return (txStats->bcastPktsTxOK);
	case MAC_STAT_NOXMTBUF:
		return (txStats->pktsTxDiscard + txq->tx_pullup_failed +
		    txq->tx_nobuf);
	case MAC_STAT_OERRORS:
		return (txStats->pktsTxError);
		break;
	case MAC_STAT_OBYTES:
		return (txStats->ucastBytesTxOK + txStats->mcastBytesTxOK +
		    txStats->bcastBytesTxOK);
	case MAC_STAT_OPACKETS:
		return (txStats->ucastPktsTxOK + txStats->mcastPktsTxOK +
		    txStats->bcastPktsTxOK);
	default:
		/* We should only be called for TX stats */
		dev_err(txq->sc->dip, CE_PANIC, "%s: invalid stat %u",
		    __func__, stat);
		/*
		 * Compiler doesn't know the above dev_err() call w/ CE_PANIC
		 * doesn't return, so return a dummy value to make it
		 * happy.
		 */
		return (0);
	}
}

static uint64_t
vmxnet3_get_rxstat(vmxnet3_rxqueue_t *rxq, uint_t stat)
{
	UPT1_RxStats		*rxStats;

	rxStats = &vmxnet3_rqdesc(rxq)->stats;

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		return (rxStats->mcastPktsRxOK);
	case MAC_STAT_BRDCSTRCV:
		return (rxStats->bcastPktsRxOK);
	case MAC_STAT_NORCVBUF:
		return (rxStats->pktsRxOutOfBuf + rxq->rx_nomblk +
		    rxq->rx_nobuf + rxq->rx_nodma);
	case MAC_STAT_IERRORS:
		return (rxStats->pktsRxError);
	case MAC_STAT_RBYTES:
		return (rxStats->ucastBytesRxOK + rxStats->mcastBytesRxOK +
		    rxStats->bcastBytesRxOK);
	case MAC_STAT_IPACKETS:
		return (rxStats->ucastPktsRxOK + rxStats->mcastPktsRxOK +
		    rxStats->bcastPktsRxOK);
	default:
		/* We should only be called for RX stats */
		dev_err(rxq->sc->dip, CE_PANIC, "%s: invalid stat %u",
		    __func__, stat);

		/*
		 * Compiler doesn't know the above dev_err() call w/ CE_PANIC
		 * doesn't return, so return a dummy value to make it
		 * happy.
		 */
		return (0);
	}
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
	uint_t		i;
	int		ret = 0;

	VMXNET3_DEBUG(dp, 3, "getstat(%u)\n", stat);

	mutex_enter(&dp->genLock);

	if (!dp->devEnabled) {
		mutex_exit(&dp->genLock);
		return (EBUSY);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = dp->linkSpeed;
		break;
	case MAC_STAT_COLLISIONS:
		*val = 0;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;
	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTXMT:
	case MAC_STAT_NOXMTBUF:
	case MAC_STAT_OERRORS:
	case MAC_STAT_OBYTES:
	case MAC_STAT_OPACKETS:
		*val = 0;
		vmxnet3_get_stats(dp);
		for (i = 0; i < dp->txNQueue; i++)
			*val += vmxnet3_get_txstat(&dp->txQueue[i], stat);
		break;
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_NORCVBUF:
	case MAC_STAT_IERRORS:
	case MAC_STAT_RBYTES:
	case MAC_STAT_IPACKETS:
		*val = 0;
		vmxnet3_get_stats(dp);
		for (i = 0; i < dp->rxNQueue; i++)
			*val += vmxnet3_get_rxstat(&dp->rxQueue[i], stat);
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&dp->genLock);
	return (ret);
}

/*
 * Allocate and initialize the shared data structures of a vmxnet3 device.
 *
 * Returns:
 *	0 on sucess, non-zero on failure.
 */
static int
vmxnet3_prepare_drivershared(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds;

	ASSERT(MUTEX_HELD(&dp->genLock));

	ds = vmxnet3_ds(dp);
	bzero(ds, sizeof (*ds));

	ds->magic = VMXNET3_REV1_MAGIC;

	/* Take care of most of devRead */
	ds->devRead.misc.driverInfo.version = BUILD_NUMBER_NUMERIC;
	ds->devRead.misc.driverInfo.gos.gosBits = VMXNET3_GOS_BITS_64;
	ds->devRead.misc.driverInfo.gos.gosType = VMXNET3_GOS_TYPE_SOLARIS;
	ds->devRead.misc.driverInfo.gos.gosVer = 11;
	ds->devRead.misc.driverInfo.vmxnet3RevSpt = 1;
	ds->devRead.misc.driverInfo.uptVerSpt = 1;

	ds->devRead.misc.uptFeatures = UPT1_F_RXCSUM;
	if (dp->lro)
		ds->devRead.misc.uptFeatures |= UPT1_F_LRO;
	ds->devRead.misc.mtu = dp->cur_mtu;

	ds->devRead.misc.maxNumRxSG = VMXNET3_MAX_RXD_PER_PKT;
	ds->devRead.misc.numTxQueues = dp->txNQueue;
	ds->devRead.misc.numRxQueues = dp->rxNQueue;
	ds->devRead.misc.queueDescPA = dp->queueDescs.bufPA;
	ds->devRead.misc.queueDescLen =
	    dp->txNQueue * sizeof (Vmxnet3_TxQueueDesc) +
	    dp->rxNQueue * sizeof (Vmxnet3_RxQueueDesc);

	/* TxQueue and RxQueue information is filled in other functions */
	ds->devRead.intrConf.autoMask = (dp->intrMaskMode == VMXNET3_IMM_AUTO);
	ds->devRead.intrConf.numIntrs = dp->intrCount;
	for (uint_t i = 0; i < dp->intrCount; i++)
		ds->devRead.intrConf.modLevels[i] = UPT1_IML_ADAPTIVE;
	ds->devRead.intrConf.eventIntrIdx = dp->intrEventNum;
	ds->devRead.intrConf.intrCtrl = VMXNET3_IC_DISABLE_ALL;

	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAL,
	    VMXNET3_ADDR_LO(dp->sharedData.bufPA));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAH,
	    VMXNET3_ADDR_HI(dp->sharedData.bufPA));

	return (0);
}

static int
vmxnet3_bufcache_ctor(void *el, void *arg)
{
	vmxnet3_dmabuf_t	*buf = el;
	vmxnet3_softc_t		*dp = arg;
	size_t			len;
	int			ret;

	len = MIN(dp->cur_mtu + sizeof (struct ether_vlan_header), PAGESIZE);

	ret = vmxnet3_alloc_dma_mem_1(dp, buf, len, B_TRUE);

	/* vmxnet3_alloc_dma_mem_1() will output warning message */
	if (ret != DDI_SUCCESS)
		return (-1);

	return (0);
}

static void
vmxnet3_bufcache_reset(void *e, void *arg __unused)
{
	vmxnet3_dmabuf_t *buf = e;

	bzero(buf->buf, buf->bufLen);
}

static void
vmxnet3_bufcache_dtor(void *e, void *arg __unused)
{
	vmxnet3_dmabuf_t *buf = e;

	if (e == NULL)
		return;

	vmxnet3_free_dma_mem(buf);
}

static int
vmxnet3_dmabuf_cache_init(vmxnet3_softc_t *dp)
{
	size_t	nent;

	ASSERT(MUTEX_HELD(&dp->genLock));

	/*
	 * It may be worth having a tunable scaling factor for the amount
	 * txRingSize contributes to the amount of buffers allocated. Since
	 * some amount of tx buffers will normally be bound and some amount of
	 * rx data will be copied which should lessen the demand on DMA
	 * buffers.
	 */
	nent = dp->txRingSize + dp->rxRingSize + dp->rxRingSize / 2;

	dp->bufCache = vmxnet3_bufcache_init(nent, sizeof (vmxnet3_dmabuf_t),
	    vmxnet3_bufcache_ctor, vmxnet3_bufcache_reset,
	    vmxnet3_bufcache_dtor, dp, dp->intrPri);
	if (dp->bufCache == NULL)
		return (ENOMEM);

	return (0);
}

/*
 * Apply new RX filters settings to a vmxnet3 device.
 */
static void
vmxnet3_refresh_rxfilter(vmxnet3_softc_t *dp)
{
	Vmxnet3_DriverShared *ds = vmxnet3_ds(dp);

	ds->devRead.rxFilterConf.rxMode = dp->rxMode;
	vmxnet3_send_cmd(dp, VMXNET3_CMD_UPDATE_RX_MODE);
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
	vmxnet3_softc_t	*dp = data;
	uint32_t	ret32;
	int		err;
	uint_t		i = 0;

	VMXNET3_DEBUG(dp, 1, "start()\n");

	mutex_enter(&dp->genLock);

	vmxnet3_set_mac(dp, dp->macaddr);

	/*
	 * Allocate vmxnet3's shared data and advertise its PA
	 */
	if ((err = vmxnet3_prepare_drivershared(dp)) != 0) {
		VMXNET3_WARN(dp, "vmxnet3_prepare_drivershared() failed: %d",
		    err);
		goto error;
	}

	if ((err = vmxnet3_dmabuf_cache_init(dp)) != 0) {
		VMXNET3_WARN(dp, "vmxnet3_dmabuf_cache_init() failed: %d", err);
		goto error_shared_data;
	}

	if ((err = vmxnet3_metatx_cache_init(dp)) != 0) {
		VMXNET3_WARN(dp, "failed to allocate metatx cache");
		goto error_dmabuf;
	}

	if ((err = vmxnet3_rxbuf_cache_init(dp)) != 0) {
		VMXNET3_WARN(dp, "failed to allocate rxbuf cache");
		goto error_meta;
	}

	for (i = 0; i < dp->txNQueue; i++) {
		vmxnet3_txqueue_t	*txq = &dp->txQueue[i];
		Vmxnet3_TxQueueDesc	*tqd = vmxnet3_tqdesc(txq);

		txq->sharedCtrl = &tqd->ctrl;

		tqd->conf.txRingBasePA = txq->cmdRing.dma.bufPA;
		tqd->conf.txRingSize = dp->txRingSize;
		tqd->conf.dataRingBasePA = 0;
		tqd->conf.dataRingSize = 0;

		tqd->conf.compRingBasePA = txq->compRing.dma.bufPA;
		tqd->conf.compRingSize = dp->txRingSize;

		if (!vmxnet3_intr_legacy(dp))
			tqd->conf.intrIdx = txq->intr_num;
	}

	for (i = 0; i < dp->rxNQueue; i++) {
		vmxnet3_rxqueue_t	*rxq = &dp->rxQueue[i];
		Vmxnet3_RxQueueDesc	*rqd = vmxnet3_rqdesc(rxq);

		rxq->sharedCtrl = &rqd->ctrl;

		rqd->conf.rxRingBasePA[0] = rxq->cmdRing.dma.bufPA;
		rqd->conf.rxRingSize[0] = dp->rxRingSize;

		rqd->conf.rxRingBasePA[1] = 0;
		rqd->conf.rxRingSize[1] = 0;

		rqd->conf.compRingBasePA = rxq->compRing.dma.bufPA;
		rqd->conf.compRingSize = dp->rxRingSize;

		if (!vmxnet3_intr_legacy(dp))
			rqd->conf.intrIdx = rxq->intr_num;
	}

	/*
	 * Activate the device
	 */
	ret32 = vmxnet3_send_cmd_val(dp, VMXNET3_CMD_ACTIVATE_DEV);
	if (ret32) {
		VMXNET3_WARN(dp, "ACTIVATE_DEV failed: 0x%x\n", ret32);
		err = ENXIO;
		goto error_rxbuf;
	}
	dp->devEnabled = B_TRUE;

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

	if (vmxnet3_intr_legacy(dp)) {
		ASSERT3U(dp->txNQueue, ==, 1);
		ASSERT3U(dp->rxNQueue, ==, 1);

		if (vmxnet3_tx_start((mac_ring_driver_t)&dp->txQueue[0],
		    0) != 0) {
			goto error_rxbuf;
		}

		if (vmxnet3_rx_start((mac_ring_driver_t)&dp->rxQueue[0],
		    0) != 0) {
			vmxnet3_tx_stop((mac_ring_driver_t)&dp->txQueue[0]);
			goto error_rxbuf;
		}

		/*
		 * Finally, unmask the interrupt
		 */
		vmxnet3_intr_enable(dp, dp->intrEventNum);
	}

	vmxnet3_ds(dp)->devRead.intrConf.intrCtrl &= ~VMXNET3_IC_DISABLE_ALL;

	mutex_exit(&dp->genLock);
	return (0);

error_rxbuf:
	vmxnet3_bufcache_fini(dp->rxBufCache);
	dp->rxBufCache = NULL;

error_meta:
	vmxnet3_bufcache_fini(dp->metaTxCache);
	dp->metaTxCache = NULL;

error_dmabuf:
	vmxnet3_bufcache_fini(dp->bufCache);
	dp->bufCache = NULL;

error_shared_data:
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAL, 0);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_DSAH, 0);

error:
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
	mutex_enter(&dp->intrLock);

	dp->devEnabled = B_FALSE;

	vmxnet3_ds(dp)->devRead.intrConf.intrCtrl |= VMXNET3_IC_DISABLE_ALL;

	vmxnet3_send_cmd(dp, VMXNET3_CMD_QUIESCE_DEV);

	mutex_exit(&dp->intrLock);

	if (vmxnet3_intr_legacy(dp)) {
		ASSERT3U(dp->txNQueue, ==, 1);
		ASSERT3U(dp->rxNQueue, ==, 1);

		vmxnet3_rx_stop((mac_ring_driver_t)&dp->rxQueue[0]);
		vmxnet3_tx_stop((mac_ring_driver_t)&dp->txQueue[0]);
	}

	vmxnet3_bufcache_fini(dp->rxBufCache);
	dp->rxBufCache = NULL;

	vmxnet3_bufcache_fini(dp->metaTxCache);
	dp->metaTxCache = NULL;

	vmxnet3_bufcache_fini(dp->bufCache);
	dp->bufCache = NULL;

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
	vmxnet3_ds(dp)->devRead.rxFilterConf.mfTablePA = newMfTable.bufPA;
	vmxnet3_ds(dp)->devRead.rxFilterConf.mfTableLen = newMfTable.bufLen;

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

/*
 * Set the mac address of a vmxnet3 device.
 *
 * Returns:
 *	0
 */
static void
vmxnet3_set_mac(vmxnet3_softc_t *dp, const uint8_t *macaddr)
{
	uint32_t val32;

	VMXNET3_DEBUG(dp, 2, "unicst("MACADDR_FMT")\n",
	    MACADDR_FMT_ARGS(macaddr));

	ASSERT(MUTEX_HELD(&dp->genLock));

	val32 = *((uint32_t *)(macaddr + 0));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_MACL, val32);
	val32 = *((uint16_t *)(macaddr + 4));
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_MACH, val32);
}

static int
vmxnet3_unicst(void *data, const uint8_t *macaddr)
{
	vmxnet3_softc_t *dp = data;

	ASSERT(vmxnet3_intr_legacy(dp));

	mutex_enter(&dp->genLock);

	vmxnet3_set_mac(dp, macaddr);
	(void) memcpy(dp->macaddr, macaddr, ETHERADDRL);

	mutex_exit(&dp->genLock);
	return (0);
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

	if (dp->devEnabled)
		return (EBUSY);

	if (new_mtu == dp->cur_mtu) {
		VMXNET3_WARN(dp, "New MTU is same as old mtu : %d.\n", new_mtu);
		return (0);
	}

	if (new_mtu < VMXNET3_MIN_MTU || new_mtu > VMXNET3_MAX_MTU) {
		VMXNET3_WARN(dp, "New MTU not in valid range [%d, %d].\n",
		    VMXNET3_MIN_MTU, VMXNET3_MAX_MTU);
		return (EINVAL);
	}

	dp->cur_mtu = new_mtu;

	if ((ret = mac_maxsdu_update(dp->mac, new_mtu)) != 0)
		VMXNET3_WARN(dp, "Unable to update mac with %d mtu: %d",
		    new_mtu, ret);

	return (ret);
}

/* ARGSUSED */
static int
vmxnet3_get_prop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, void *prop_val)
{
	vmxnet3_softc_t	*dp = data;

	mutex_enter(&dp->genLock);

	switch (prop_id) {
	case MAC_PROP_MTU:
		ASSERT(prop_val_size >= sizeof (uint32_t));

		bcopy(&dp->cur_mtu, prop_val, sizeof (uint32_t));
		mutex_exit(&dp->genLock);
		return (0);
	case MAC_PROP_PRIVATE:
		break;
	default:
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}

	/* Private properties */
	vmxnet3_props_t	vx_prop;
	uint32_t	value = 0;

	if (!vmxnet3_parse_propstr(prop_name, &vx_prop)) {
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}

	switch (vx_prop) {
	case VMXNET3_PROP_TXRINGSZ:
		value = dp->txRingSize;
		break;
	case VMXNET3_PROP_RXRINGSZ:
		value = dp->rxRingSize;
		break;
	case VMXNET3_PROP_TXCOPY:
		value = dp->txCopyThreshold;
		break;
	case VMXNET3_PROP_TXCOPYMAX:
		value = dp->txMaxCopy;
		break;
	case VMXNET3_PROP_RXCOPY:
		value = dp->rxCopyThreshold;
		break;
	case VMXNET3_PROP_RXLOANMAX:
		value = dp->rxMaxLoan;
		break;
	case VMXNET3_PROP_LSO:
		value = dp->lso;
		break;
	case VMXNET3_PROP_LRO:
		value = dp->lro;
		break;
	}

	if (snprintf(prop_val, prop_val_size, "%u", value) >= prop_val_size) {
		mutex_exit(&dp->genLock);
		return (EOVERFLOW);
	}

	mutex_exit(&dp->genLock);
	return (0);
}

/* ARGSUSED */
static int
vmxnet3_set_prop(void *data, const char *prop_name, mac_prop_id_t prop_id,
    uint_t prop_val_size, const void *prop_val)
{
	vmxnet3_softc_t *dp = data;

	mutex_enter(&dp->genLock);

	switch (prop_id) {
	case MAC_PROP_MTU: {
		uint32_t	new_mtu;
		int		ret;

		ASSERT3U(prop_val_size, >=, sizeof (uint32_t));
		bcopy(prop_val, &new_mtu, sizeof (new_mtu));
		ret = vmxnet3_change_mtu(dp, new_mtu);
		mutex_exit(&dp->genLock);

		return (ret);
	}
	case MAC_PROP_PRIVATE:
		break;
	default:
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}

	/* Private properties */
	char		*endptr;
	vmxnet3_props_t	vx_prop;
	ulong_t		value = 0;

	if (!vmxnet3_parse_propstr(prop_name, &vx_prop)) {
		mutex_exit(&dp->genLock);
		return (ENOTSUP);
	}

	if (ddi_strtoul(prop_val, &endptr, 10, &value) != 0)
		goto invalid;

	if (dp->devEnabled) {
		mutex_exit(&dp->genLock);
		return (EBUSY);
	}

	switch (vx_prop) {
	case VMXNET3_PROP_TXRINGSZ:
		if (value < VMXNET3_TX_RING_MIN_SIZE ||
		    value > VMXNET3_TX_RING_MAX_SIZE ||
		    (value & VMXNET3_RING_SIZE_MASK) != 0)
			goto invalid;

		dp->txRingSize = (uint16_t)value;
		break;
	case VMXNET3_PROP_RXRINGSZ:
		if (value < VMXNET3_RX_RING_MIN_SIZE ||
		    value > VMXNET3_RX_RING_MAX_SIZE ||
		    (value & VMXNET3_RING_SIZE_MASK) != 0)
			goto invalid;

		dp->rxRingSize = (uint16_t)value;
		break;
	case VMXNET3_PROP_TXCOPY:
		if (value > VMXNET3_MAX_MTU)
			goto invalid;
		dp->txCopyThreshold = (uint16_t)value;
		break;
	case VMXNET3_PROP_TXCOPYMAX:
		if (value > VMXNET3_TX_RING_MAX_SIZE)
			goto invalid;
		dp->txMaxCopy = (uint16_t)value;
		break;
	case VMXNET3_PROP_RXCOPY:
		if (value > VMXNET3_MAX_MTU)
			goto invalid;
		dp->rxCopyThreshold = (uint16_t)value;
		break;
	case VMXNET3_PROP_RXLOANMAX:
		if (value > VMXNET3_RX_RING_MAX_SIZE)
			goto invalid;
		dp->rxMaxLoan = (uint16_t)value;
		break;
	case VMXNET3_PROP_LSO:
		if (value > 1)
			goto invalid;
		dp->lso = (value == 1) ? B_TRUE : B_FALSE;
		break;
	case VMXNET3_PROP_LRO:
		if (value > 1)
			goto invalid;
		dp->lro = (value == 1) ? B_TRUE : B_FALSE;
		break;
	}

	mutex_exit(&dp->genLock);
	return (0);

invalid:
	mutex_exit(&dp->genLock);
	return (EINVAL);
}

/* ARGSUSED */
static void
vmxnet3_prop_info(void *data, const char *prop_name, mac_prop_id_t prop_id,
    mac_prop_info_handle_t prop_handle)
{
	switch (prop_id) {
	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, VMXNET3_MIN_MTU,
		    VMXNET3_MAX_MTU);
		return;
	case MAC_PROP_PRIVATE:
		break;
	default:
		return;
	}

	/* Private properties */
	vmxnet3_props_t vx_prop;

	if (!vmxnet3_parse_propstr(prop_name, &vx_prop))
		return;

	switch (vx_prop) {
	case VMXNET3_PROP_TXRINGSZ:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle,
		    VMXNET3_TX_RING_MIN_SIZE, VMXNET3_TX_RING_MAX_SIZE);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_TX_RING_SIZE);
		break;
	case VMXNET3_PROP_RXRINGSZ:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle,
		    VMXNET3_RX_RING_MIN_SIZE, VMXNET3_RX_RING_MAX_SIZE);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_RX_RING_SIZE);
		break;
	case VMXNET3_PROP_TXCOPY:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, VMXNET3_MIN_MTU,
		    VMXNET3_MAX_MTU);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_TX_COPY_THRESHOLD);
		break;
	case VMXNET3_PROP_TXCOPYMAX:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle,
		    0, VMXNET3_TX_RING_MAX_SIZE);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_TX_COPY_MAX);
		break;
	case VMXNET3_PROP_RXCOPY:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, VMXNET3_MIN_MTU,
		    VMXNET3_MAX_MTU);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_RX_COPY_THRESHOLD);
		break;
	case VMXNET3_PROP_RXLOANMAX:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle,
		    0, VMXNET3_RX_RING_MAX_SIZE);
		mac_prop_info_set_default_uint32(prop_handle,
		    VMXNET3_DEF_RX_LOAN_MAX);
		break;
	case VMXNET3_PROP_LSO:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, 0, 1);
		mac_prop_info_set_default_uint32(prop_handle, 1);
		break;
	case VMXNET3_PROP_LRO:
		mac_prop_info_set_perm(prop_handle, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prop_handle, 0, 1);
		mac_prop_info_set_default_uint32(prop_handle, 1);
		break;
	}
}

static void
vmxnet3_fill_ring_info(void *driver, mac_ring_type_t rtype,
    const int group_index, const int ring_index, mac_ring_info_t *infop,
    mac_ring_handle_t rh)
{
	vmxnet3_softc_t		*dp = (vmxnet3_softc_t *)driver;
	vmxnet3_txqueue_t	*txq;
	vmxnet3_rxqueue_t	*rxq;

	switch (rtype) {
	case MAC_RING_TYPE_TX:
		VERIFY3U(ring_index, <, dp->txNQueue);

		txq = &dp->txQueue[ring_index];
		txq->mrh = rh;

		infop->mri_driver = (mac_ring_driver_t)txq;
		infop->mri_start = vmxnet3_tx_start;
		infop->mri_stop = vmxnet3_tx_stop;
		infop->mri_tx = vmxnet3_ring_tx;
		infop->mri_stat = vmxnet3_tx_stat;

		infop->mri_intr.mi_handle = (mac_intr_handle_t)txq;
		infop->mri_intr.mi_enable = vmxnet3_tx_intr_enable;
		infop->mri_intr.mi_disable = vmxnet3_tx_intr_disable;
		break;
	case MAC_RING_TYPE_RX:
		VERIFY3U(ring_index, <, dp->rxNQueue);

		rxq = &dp->rxQueue[ring_index];
		rxq->mrh = rh;

		infop->mri_driver = (mac_ring_driver_t)rxq;
		infop->mri_start = vmxnet3_rx_start;
		infop->mri_stop = vmxnet3_rx_stop;
		infop->mri_poll = vmxnet3_rx_poll;
		infop->mri_stat = vmxnet3_rx_stat;
		infop->mri_intr.mi_handle = (mac_intr_handle_t)rxq;
		infop->mri_intr.mi_enable = vmxnet3_rx_intr_enable;
		infop->mri_intr.mi_disable = vmxnet3_rx_intr_disable;
		break;
	default:
		dev_err(dp->dip, CE_PANIC, "Unexpected ring type %d", rtype);
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
	vmxnet3_softc_t		*dp = data;
	mac_capab_rings_t	*cap_rings;
	mac_capab_lso_t		*lso;
	uint32_t		*txflags;
	boolean_t		ret = B_FALSE;

	switch (capab) {
	case MAC_CAPAB_HCKSUM:
		txflags = arg;
		*txflags = HCKSUM_INET_PARTIAL;
		ret = B_TRUE;
		break;

	case MAC_CAPAB_LSO:
		lso = arg;
		lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		lso->lso_basic_tcp_ipv4.lso_max = IP_MAXPACKET;

		mutex_enter(&dp->genLock);
		ret = dp->lso;
		mutex_exit(&dp->genLock);
		break;

	case MAC_CAPAB_RINGS:
		if (vmxnet3_intr_legacy(dp)) {
			ret = B_FALSE;
			break;
		}

		ret = B_TRUE;
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

	default:
		break;
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
	vmxnet3_send_cmd(dp, VMXNET3_CMD_RESET_DEV);
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
	Vmxnet3_DriverShared *ds = vmxnet3_ds(dp);
	boolean_t linkStateChanged = B_FALSE;
	uint32_t events = ds->ecr;

	if (events == 0)
		return (B_FALSE);

	VMXNET3_DEBUG(dp, 2, "events(0x%x)\n", events);
	if (events & (VMXNET3_ECR_RQERR | VMXNET3_ECR_TQERR)) {
		uint_t i;

		vmxnet3_send_cmd(dp, VMXNET3_CMD_GET_QUEUE_STATUS);

		for (i = 0; i < dp->txNQueue; i++) {
			Vmxnet3_TxQueueDesc *tqdesc;

			tqdesc = vmxnet3_tqdesc(&dp->txQueue[i]);
			if (tqdesc->status.stopped) {
				VMXNET3_WARN(dp, "tq%u error 0x%x %s\n",
				    i, tqdesc->status.error,
				    vmxnet3_err_str(tqdesc->status.error));
			}
		}

		for (i = 0; i < dp->rxNQueue; i++) {
			Vmxnet3_RxQueueDesc *rqdesc;

			rqdesc = vmxnet3_rqdesc(&dp->rxQueue[i]);
			if (rqdesc->status.stopped) {
				VMXNET3_WARN(dp, "rq%u error 0x%x %s\n",
				    i, rqdesc->status.error,
				    vmxnet3_err_str(rqdesc->status.error));
			}
		}

		if (ddi_taskq_dispatch(dp->resetTask, vmxnet3_reset,
		    dp, DDI_NOSLEEP) == DDI_SUCCESS) {
			VMXNET3_WARN(dp, "reset scheduled\n");
		} else {
			VMXNET3_WARN(dp, "ddi_taskq_dispatch() failed\n");
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

	return (linkStateChanged);
}

/*
 * Interrupt handler of a vmxnet3 device.
 *
 * Returns:
 *	DDI_INTR_CLAIMED or DDI_INTR_UNCLAIMED.
 */
/* ARGSUSED1 */
static uint_t
vmxnet3_intr(caddr_t data1, caddr_t data2)
{
	vmxnet3_softc_t *dp = (void *)data1;
	mblk_t		*mps = NULL;
	uint64_t	mustUpdateTx = 0;
	boolean_t	linkStateChanged;

	VMXNET3_DEBUG(dp, 3, "intr()\n");

	mutex_enter(&dp->intrLock);

	if (!dp->devEnabled)
		goto intr_unclaimed;

	if (dp->intrType == DDI_INTR_TYPE_FIXED &&
	    !VMXNET3_BAR1_GET32(dp, VMXNET3_REG_ICR)) {
		goto intr_unclaimed;
	}

	if (dp->intrMaskMode == VMXNET3_IMM_ACTIVE) {
		vmxnet3_intr_disable(dp, dp->intrEventNum);
	}

	linkStateChanged = vmxnet3_intr_events(dp);

	if (vmxnet3_intr_legacy(dp)) {
		ASSERT3U(dp->txNQueue, ==, 1);
		mustUpdateTx = vmxnet3_tx_complete(dp, &dp->txQueue[0]);

		ASSERT3U(dp->rxNQueue, ==, 1);
		mps = vmxnet3_rx_intr(dp, &dp->rxQueue[0]);
	} else {
		/*
		 * If all the TX queues are sharing the event interrupt,
		 * check them for completed packets.
		 */
		for (uint_t i = 0; i < dp->txNQueue; i++) {
			if (dp->txQueue[i].intr_num != dp->intrEventNum)
				continue;

			if (vmxnet3_tx_complete(dp, &dp->txQueue[i]))
				mustUpdateTx |= (uint64_t)1 << i;
		}
	}

	mutex_exit(&dp->intrLock);

	vmxnet3_intr_enable(dp, dp->intrEventNum);

	if (linkStateChanged) {
		mac_link_update(dp->mac, dp->linkState);
	}

	if (mustUpdateTx != 0) {
		if (vmxnet3_intr_legacy(dp)) {
			mac_tx_update(dp->mac);
		} else {
			for (uint_t i = 0; i < dp->txNQueue; i++) {
				uint64_t val = (uint64_t)1 << i;

				if ((mustUpdateTx & val) == 0)
					continue;

				mac_tx_ring_update(dp->mac,
				    dp->txQueue[i].mrh);
			}
		}
	}

	if (mps != NULL) {
		ASSERT3U(dp->rxNQueue, ==, 1);
		mac_rx(dp->mac, NULL, mps);
	}

	return (DDI_INTR_CLAIMED);

intr_unclaimed:
	mutex_exit(&dp->intrLock);
	return (DDI_INTR_UNCLAIMED);
}

static int
vmxnet3_kstat_update(kstat_t *ksp, int rw)
{
	vmxnet3_softc_t *dp = ksp->ks_private;
	vmxnet3_kstats_t *statp = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	statp->reset_count.value.ul = dp->reset_count;
	statp->rx_nqueue.value.ul = dp->rxNQueue;
	statp->tx_nqueue.value.ul = dp->txNQueue;

	return (0);
}

static int
vmxnet3_alloc_txqueue(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq)
{
	vmxnet3_cmdring_t	*cmdRing = &txq->cmdRing;
	vmxnet3_compring_t	*compRing = &txq->compRing;
	int err;

	txq->intr_num = -1;

	err = vmxnet3_alloc_dma_mem_512(dp, &cmdRing->dma,
	    VMXNET3_TX_RING_MAX_SIZE * sizeof (Vmxnet3_TxDesc), B_TRUE);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	err = vmxnet3_alloc_dma_mem_512(dp, &compRing->dma,
	    VMXNET3_TC_RING_MAX_SIZE * sizeof (Vmxnet3_TxCompDesc), B_TRUE);
	if (err != DDI_SUCCESS) {
		vmxnet3_free_dma_mem(&cmdRing->dma);
		return (DDI_FAILURE);
	}

	txq->metaRing = kmem_zalloc(VMXNET3_TX_RING_MAX_SIZE *
	    sizeof (vmxnet3_metatx_t *), KM_SLEEP);

	txq->sc = dp;
	mutex_init(&txq->txLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(dp->intrPri));

	return (DDI_SUCCESS);
}

static void
vmxnet3_free_txqueue(vmxnet3_txqueue_t *txq)
{
	vmxnet3_cmdring_t	*cmdRing = &txq->cmdRing;
	vmxnet3_compring_t	*compRing = &txq->compRing;

	kmem_free(txq->metaRing,
	    VMXNET3_TX_RING_MAX_SIZE * sizeof (vmxnet3_metatx_t *));
	txq->metaRing = NULL;

	mutex_destroy(&txq->txLock);
	vmxnet3_free_dma_mem(&compRing->dma);
	vmxnet3_free_dma_mem(&cmdRing->dma);
}

static int
vmxnet3_alloc_rxqueue(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
	vmxnet3_compring_t	*compRing = &rxq->compRing;
	int err;

	err = vmxnet3_alloc_dma_mem_512(dp, &cmdRing->dma,
	    VMXNET3_RX_RING_MAX_SIZE * sizeof (Vmxnet3_RxDesc), B_TRUE);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	err = vmxnet3_alloc_dma_mem_512(dp, &compRing->dma,
	    VMXNET3_RX_RING_MAX_SIZE * sizeof (Vmxnet3_RxCompDesc), B_TRUE);
	if (err != DDI_SUCCESS) {
		vmxnet3_free_dma_mem(&cmdRing->dma);
		return (DDI_FAILURE);
	}

	rxq->bufRing = kmem_zalloc(VMXNET3_RX_RING_MAX_SIZE *
	    sizeof (vmxnet3_rxbuf_t *), KM_SLEEP);

	rxq->sc = dp;
	mutex_init(&rxq->rxLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(dp->intrPri));

	return (DDI_SUCCESS);
}

static void
vmxnet3_free_rxqueue(vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_cmdring_t	*cmdRing = &rxq->cmdRing;
	vmxnet3_compring_t	*compRing = &rxq->compRing;

	kmem_free(rxq->bufRing,
	    VMXNET3_RX_RING_MAX_SIZE * sizeof (vmxnet3_rxbuf_t *));
	rxq->bufRing = NULL;

	mutex_destroy(&rxq->rxLock);
	vmxnet3_free_dma_mem(&compRing->dma);
	vmxnet3_free_dma_mem(&cmdRing->dma);
}

static int
vmxnet3_alloc_drivershared(vmxnet3_softc_t *dp)
{
	size_t	desc_size;
	int	err;

	err = vmxnet3_alloc_dma_mem_1(dp, &dp->sharedData,
	    sizeof (Vmxnet3_DriverShared), B_TRUE);
	if (err != 0)
		return (err);

	desc_size = dp->txNQueue * sizeof (Vmxnet3_TxQueueDesc) +
	    dp->rxNQueue * sizeof (Vmxnet3_RxQueueDesc);
	err = vmxnet3_alloc_dma_mem_128(dp, &dp->queueDescs, desc_size, B_TRUE);
	if (err != 0) {
		vmxnet3_free_dma_mem(&dp->sharedData);
		return (err);
	}

	return (0);
}

static void
vmxnet3_free_drivershared(vmxnet3_softc_t *dp)
{
	vmxnet3_free_dma_mem(&dp->queueDescs);
	vmxnet3_free_dma_mem(&dp->sharedData);
}

static boolean_t
vmxnet3_regs_init(vmxnet3_softc_t *dp)
{
	uint32_t ret32;
	uint16_t vendorId, devId, ret16;

	/*
	 * Get access to the PCI bus configuration space
	 */
	if (pci_config_setup(dp->dip, &dp->pciHandle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "pci_config_setup() failed\n");
		return (B_FALSE);
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
		goto fail_pcicfg;
	}

	/*
	 * Make sure we can access the registers through the I/O space
	 */
	ret16 = pci_config_get16(dp->pciHandle, PCI_CONF_COMM);
	ret16 |= PCI_COMM_IO | PCI_COMM_ME;
	pci_config_put16(dp->pciHandle, PCI_CONF_COMM, ret16);

	/*
	 * Map the I/O space in memory
	 */
	if (ddi_regs_map_setup(dp->dip, 1, &dp->bar0, 0, 0, &vmxnet3_dev_attr,
	    &dp->bar0Handle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_regs_map_setup() for BAR0 failed\n");
		goto fail_pcicfg;
	}

	if (ddi_regs_map_setup(dp->dip, 2, &dp->bar1, 0, 0, &vmxnet3_dev_attr,
	    &dp->bar1Handle) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_regs_map_setup() for BAR1 failed\n");
		goto fail_bar0;
	}

	/*
	 * Check the version number of the virtual device
	 */
	if (VMXNET3_BAR1_GET32(dp, VMXNET3_REG_VRRS) & 1) {
		VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_VRRS, 1);
	} else {
		VMXNET3_WARN(dp, "incompatible h/w version\n");
		goto fail_bar1;
	}

	if (VMXNET3_BAR1_GET32(dp, VMXNET3_REG_UVRS) & 1) {
		VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_UVRS, 1);
	} else {
		VMXNET3_WARN(dp, "incompatible upt version\n");
		goto fail_bar1;
	}

	/*
	 * Read the MAC address from the device
	 */
	ret32 = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_MACL);
	*((uint32_t *)(dp->macaddr + 0)) = ret32;
	ret32 = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_MACH);
	*((uint16_t *)(dp->macaddr + 4)) = ret32;

	return (B_TRUE);

fail_bar1:
	ddi_regs_map_free(&dp->bar1Handle);
fail_bar0:
	ddi_regs_map_free(&dp->bar0Handle);
fail_pcicfg:
	pci_config_teardown(&dp->pciHandle);
	return (B_FALSE);
}

static boolean_t
vmxnet3_kstat_init(vmxnet3_softc_t *dp)
{
	vmxnet3_kstats_t	*statp;
	uint_t			i = 0;

	dp->devKstats = kstat_create(VMXNET3_MODNAME, dp->instance,
	    "statistics", "dev",  KSTAT_TYPE_NAMED,
	    sizeof (vmxnet3_kstats_t) / sizeof (kstat_named_t), 0);
	if (dp->devKstats == NULL)
		return (B_FALSE);

	dp->devKstats->ks_update = vmxnet3_kstat_update;
	dp->devKstats->ks_private = dp;

	statp = dp->devKstats->ks_data;

	kstat_named_init(&statp->reset_count, "reset_count", KSTAT_DATA_ULONG);
	kstat_named_init(&statp->rx_nqueue, "rx_nqueue", KSTAT_DATA_ULONG);
	kstat_named_init(&statp->tx_nqueue, "tx_nqueue", KSTAT_DATA_ULONG);

	kstat_install(dp->devKstats);

	for (i = 0; i < dp->txNQueue; i++) {
		if (vmxnet3_tx_kstat_init(dp, &dp->txQueue[i]) != DDI_SUCCESS)
			goto fail_txstat;
	}

	for (i = 0; i < dp->rxNQueue; i++) {
		if (vmxnet3_rx_kstat_init(dp, &dp->rxQueue[i]) != DDI_SUCCESS)
			goto fail_rxstat;
	}

	return (B_TRUE);

fail_rxstat:
	while (i-- > 0)
		kstat_delete(dp->rxQueue[i].rxRingStats);
	i = dp->txNQueue;

fail_txstat:
	while (i-- > 0)
		kstat_delete(dp->txQueue[i].txRingStats);

	kstat_delete(dp->devKstats);
	return (B_FALSE);
}

static boolean_t
vmxnet3_mac_init(vmxnet3_softc_t *dp)
{
	mac_register_t *macr;
	int		ret;

	macr = mac_alloc(MAC_VERSION);
	if (macr == NULL) {
		VMXNET3_WARN(dp, "mac_alloc() failed\n");
		return (B_FALSE);
	}

	macr->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macr->m_driver = dp;
	macr->m_dip = dp->dip;
	macr->m_instance = 0;
	macr->m_src_addr = dp->macaddr;
	macr->m_dst_addr = NULL;
	macr->m_min_sdu = 0;
	macr->m_max_sdu = ETHERMTU;
	macr->m_margin = VLAN_TAGSZ;
	macr->m_pdata = NULL;
	macr->m_pdata_size = 0;
	macr->m_priv_props = vmxnet3_prop_strs;
	if (!vmxnet3_intr_legacy(dp)) {
		macr->m_callbacks = &vmxnet3_mac_callbacks;
		macr->m_v12n = MAC_VIRT_LEVEL1;
	} else {
		macr->m_callbacks = &vmxnet3_legacy_mac_callbacks;
	}

	ret = mac_register(macr, &dp->mac);
	mac_free(macr);
	if (ret != 0)
		VMXNET3_WARN(dp, "mac_register() failed\n");

	return (ret == 0 ? B_TRUE : B_FALSE);
}

static boolean_t
vmxnet3_intr_alloc_handles(vmxnet3_softc_t *dp, int type)
{
	int requested, count, avail, min, actual;
	int ret;

	requested = count = avail = min = actual = 0;

	switch (type) {
	case DDI_INTR_TYPE_FIXED:
		requested = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSI:
		requested = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSIX:
		requested = 1;
		min = 1;
		break;
	default:
		VMXNET3_WARN(dp, "unexpected interrupt type 0x%x\n", type);
		return (B_FALSE);
	}

	if (ddi_intr_get_nintrs(dp->dip, type, &count) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "failed to get interrupt count\n");
		return (B_FALSE);
	}

	if (ddi_intr_get_navail(dp->dip, type, &avail) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "failed to get count of available "
		    "interrupts\n");
		return (B_FALSE);
	}

	VERIFY3S(avail, <=, count);

	VMXNET3_DEBUG(dp, 2, "%s: intr type=0x%x min=%d requested=%d nintr=%d "
	    "avail=%d\n",
	    __func__, type, min, requested, count, avail);

	if (avail < min) {
		VMXNET3_DEBUG(dp, 2, "%s: # intr avail < min\n", __func__);
		return (B_FALSE);
	}

	if (avail > requested) {
		count = requested;
	} else if (avail < requested) {
		count = min;
	} else {
		count = avail;
	}

	dp->intrHandles = kmem_zalloc(count * sizeof (ddi_intr_handle_t),
	    KM_SLEEP);
	ret = ddi_intr_alloc(dp->dip, dp->intrHandles, type, 0, count, &actual,
	    DDI_INTR_ALLOC_STRICT);
	if (ret != DDI_SUCCESS) {
		VMXNET3_DEBUG(dp, 1,
		    "failed to allocate interrupts (type = 0x%x): %d\n",
		    type, ret);
		kmem_free(dp->intrHandles, count * sizeof (ddi_intr_handle_t));
		dp->intrHandles = NULL;
		return (B_FALSE);
	}

	dp->intrType = type;
	dp->intrCount = count;
	return (B_TRUE);
}

static boolean_t
vmxnet3_intr_alloc(vmxnet3_softc_t *dp)
{
	int ret32;

	dp->intrCount = 1;
	dp->intrEventNum = 0;

	/*
	 * Register the interrupt(s) in this order of preference:
	 * MSI-X, MSI, INTx
	 */
	ret32 = vmxnet3_send_cmd_val(dp, VMXNET3_CMD_GET_CONF_INTR);

	dp->intrMaskMode = (ret32 >> 2) & 0x3;
	if (dp->intrMaskMode == VMXNET3_IMM_LAZY) {
		VMXNET3_WARN(dp, "Lazy masking is not supported\n");
		return (B_FALSE);
	}

	switch (ret32 & 0x3) {
	case VMXNET3_IT_AUTO:
	case VMXNET3_IT_MSIX:
		if (vmxnet3_intr_alloc_handles(dp, DDI_INTR_TYPE_MSIX))
			break;
		/*FALLTHRU*/
	case VMXNET3_IT_MSI:
		if (vmxnet3_intr_alloc_handles(dp, DDI_INTR_TYPE_MSI))
			break;
		/*FALLTHRU*/
	case VMXNET3_IT_INTX:
		if (vmxnet3_intr_alloc_handles(dp, DDI_INTR_TYPE_FIXED))
			break;
		VMXNET3_WARN(dp, "Failed to allocate any type of interrupt\n");
		return (B_FALSE);
	}

	if (ddi_intr_get_pri(dp->intrHandles[0], &dp->intrPri) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_intr_get_pri() failed\n");
		goto error;
	}

	VMXNET3_DEBUG(dp, 2, "intrType=0x%x, intrMaskMode=0x%x, intrPrio=%u\n",
	    dp->intrType, dp->intrMaskMode, dp->intrPri);

	return (B_TRUE);

error:
	for (uint_t i = 0; i < dp->intrCount; i++)
		VERIFY0(ddi_intr_free(dp->intrHandles[i]));

	kmem_free(dp->intrHandles, dp->intrCount * sizeof (ddi_intr_handle_t));
	dp->intrHandles = NULL;
	return (B_FALSE);
}

static boolean_t
vmxnet3_sync_init(vmxnet3_softc_t *dp)
{
	dp->resetTask = ddi_taskq_create(dp->dip, "vmxnet3_reset_task", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (!dp->resetTask) {
		VMXNET3_WARN(dp, "ddi_taskq_create() failed()\n");
		return (B_FALSE);
	}

	/*
	 * Initialize our mutexes now that we know the interrupt priority
	 * This _must_ be done before ddi_intr_enable()
	 */
	mutex_init(&dp->intrLock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dp->intrPri));
	mutex_init(&dp->genLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(dp->intrPri));
	mutex_init(&dp->cmdLock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(dp->intrPri));

	return (B_TRUE);
}

static boolean_t
vmxnet3_queues_init(vmxnet3_softc_t *dp)
{
	uint_t i = 0;

	dp->txQueue = kmem_zalloc(dp->txNQueue * sizeof (vmxnet3_txqueue_t),
	    KM_SLEEP);
	dp->rxQueue = kmem_zalloc(dp->rxNQueue * sizeof (vmxnet3_rxqueue_t),
	    KM_SLEEP);

	for (i = 0; i < dp->txNQueue; i++) {
		if (vmxnet3_alloc_txqueue(dp, &dp->txQueue[i]) != DDI_SUCCESS) {
			VMXNET3_WARN(dp, "vmxnet3_alloc_txqueue() failed");
			goto fail_txqueue;
		}
	}

	for (i = 0; i < dp->rxNQueue; i++) {
		if (vmxnet3_alloc_rxqueue(dp, &dp->rxQueue[i]) != DDI_SUCCESS) {
			VMXNET3_WARN(dp, "vmxnet3_alloc_rxqueue() failed");
			goto fail_rxqueue;
		}
	}

	if (vmxnet3_alloc_drivershared(dp) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "vmxnet3_alloc_drivershared() failed");
		goto fail_rxqueue;
	}

	return (B_TRUE);

fail_rxqueue:
	while (i-- > 0)
		vmxnet3_free_rxqueue(&dp->rxQueue[i]);

	i = dp->txNQueue;

fail_txqueue:
	while (i-- > 0)
		vmxnet3_free_txqueue(&dp->txQueue[i]);

	kmem_free(dp->txQueue, dp->txNQueue * sizeof (vmxnet3_txqueue_t));
	kmem_free(dp->rxQueue, dp->rxNQueue * sizeof (vmxnet3_rxqueue_t));
	return (B_FALSE);
}

static boolean_t
vmxnet3_ddi_intr_enable(vmxnet3_softc_t *dp)
{
	int err;

	if (ddi_intr_add_handler(dp->intrHandles[0], vmxnet3_intr,
	    dp, NULL) != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_intr_add_handler() failed\n");
		return (B_FALSE);
	}

	err = ddi_intr_get_cap(dp->intrHandles[0], &dp->intrCap);
	if (err != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_intr_get_cap() failed %d", err);
		goto error;
	}

	if (dp->intrCap & DDI_INTR_FLAG_BLOCK) {
		err = ddi_intr_block_enable(dp->intrHandles, 1);
		if (err != DDI_SUCCESS) {
			VMXNET3_WARN(dp, "ddi_intr_block_enable() failed, "
			    "err:%d\n", err);
			goto error;
		}
	} else {
		err = ddi_intr_enable(dp->intrHandles[0]);
		if ((err != DDI_SUCCESS)) {
			VMXNET3_WARN(dp, "ddi_intr_enable() failed, err:%d\n",
			    err);
			goto error;
		}
	}

	return (B_TRUE);

error:
	VERIFY0(ddi_intr_remove_handler(dp->intrHandles[0]));
	return (B_FALSE);
}

static boolean_t
vmxnet3_ddi_intr_disable(vmxnet3_softc_t *dp)
{
	if (dp->intrCap & DDI_INTR_FLAG_BLOCK) {
		VERIFY0(ddi_intr_block_disable(dp->intrHandles, 1));
	} else {
		VERIFY0(ddi_intr_disable(dp->intrHandles[0]));
	}

	VERIFY0(ddi_intr_remove_handler(dp->intrHandles[0]));
	return (B_TRUE);
}

static boolean_t
vmxnet3_queues_fini(vmxnet3_softc_t *dp)
{
	uint_t i;

	if (dp->mfTable.buf != NULL)
		vmxnet3_free_dma_mem(&dp->mfTable);

	vmxnet3_free_drivershared(dp);

	for (i = 0; i < dp->rxNQueue; i++)
		vmxnet3_free_rxqueue(&dp->rxQueue[i]);

	for (i = 0; i < dp->txNQueue; i++)
		vmxnet3_free_txqueue(&dp->txQueue[i]);

	kmem_free(dp->txQueue, dp->txNQueue * sizeof (vmxnet3_txqueue_t));
	kmem_free(dp->rxQueue, dp->rxNQueue * sizeof (vmxnet3_rxqueue_t));
	return (B_TRUE);
}

static boolean_t
vmxnet3_sync_fini(vmxnet3_softc_t *dp)
{
	mutex_destroy(&dp->cmdLock);
	mutex_destroy(&dp->genLock);
	mutex_destroy(&dp->intrLock);
	ddi_taskq_destroy(dp->resetTask);
	return (B_TRUE);
}

static boolean_t
vmxnet3_intr_free(vmxnet3_softc_t *dp)
{
	for (uint_t i = 0; i < dp->intrCount; i++)
		VERIFY0(ddi_intr_free(dp->intrHandles[i]));

	kmem_free(dp->intrHandles, dp->intrCount * sizeof (ddi_intr_handle_t));
	dp->intrHandles = NULL;

	return (B_TRUE);
}

static boolean_t
vmxnet3_mac_fini(vmxnet3_softc_t *dp)
{
	int	ret;

	ret = mac_unregister(dp->mac);
	if (ret != 0) {
		VMXNET3_WARN(dp, "mac_unregister() failed: %d", ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
vmxnet3_kstat_fini(vmxnet3_softc_t *dp)
{
	uint_t i;

	for (i = 0; i < dp->rxNQueue; i++)
		kstat_delete(dp->rxQueue[i].rxRingStats);
	for (i = 0; i < dp->txNQueue; i++)
		kstat_delete(dp->txQueue[i].txRingStats);
	kstat_delete(dp->devKstats);
	return (B_TRUE);
}

static boolean_t
vmxnet3_regs_fini(vmxnet3_softc_t *dp)
{
	ddi_regs_map_free(&dp->bar1Handle);
	ddi_regs_map_free(&dp->bar0Handle);
	pci_config_teardown(&dp->pciHandle);
	return (B_TRUE);
}

static struct {
	boolean_t	(*initf)(vmxnet3_softc_t *);
	boolean_t	(*finif)(vmxnet3_softc_t *);
	const char	*desc;
} init_tbl[] = {
	{ vmxnet3_regs_init,	vmxnet3_regs_fini,	"Map registers" },
	{ vmxnet3_intr_alloc,	vmxnet3_intr_free,	"Allocate interrupts" },
	{ vmxnet3_sync_init,	vmxnet3_sync_fini,	"Synchronization" },
	{ vmxnet3_queues_init,	vmxnet3_queues_fini,	"Queues" },
	{ vmxnet3_mac_init,	vmxnet3_mac_fini,	"MAC framework" },
	{ vmxnet3_kstat_init,	vmxnet3_kstat_fini,	"kstats" },
	{ vmxnet3_ddi_intr_enable, vmxnet3_ddi_intr_disable,
	    "Enable interrupts" },
};

static int
vmxnet3_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	vmxnet3_softc_t *dp;
	uint_t		i;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Allocate the soft state
	 */
	dp = kmem_zalloc(sizeof (vmxnet3_softc_t), KM_SLEEP);
	ASSERT(dp);

	dp->dip = dip;
	dp->instance = ddi_get_instance(dip);
	dp->cur_mtu = ETHERMTU;
	dp->txRingSize = VMXNET3_DEF_TX_RING_SIZE;
	dp->rxRingSize = VMXNET3_DEF_RX_RING_SIZE;
	dp->txCopyThreshold = VMXNET3_DEF_TX_COPY_THRESHOLD;
	dp->rxCopyThreshold = VMXNET3_DEF_RX_COPY_THRESHOLD;
	dp->lso = B_TRUE;
	dp->lro = B_TRUE;

	dp->txNQueue = 1;
	dp->rxNQueue = 1;

	ddi_set_driver_private(dip, dp);

	VMXNET3_DEBUG(dp, 1, "attach()\n");

	for (i = 0; i < ARRAY_SIZE(init_tbl); i++) {
		VMXNET3_DEBUG(dp, 2, "Running attach step %u (%s)", i + 1,
		    init_tbl[i].desc);
		if (!init_tbl[i].initf(dp)) {
			dev_err(dp->dip, CE_WARN,
			    "Attach step %u (%s) failed", i + 1,
			    init_tbl[i].desc);
			goto cleanup;
		}
	}

	/* Set to index of last step run */
	dp->init_lvl = i - 1;

	return (DDI_SUCCESS);

cleanup:
	while (i > 0) {
		VMXNET3_DEBUG(dp, 2, "Cleaning up attach step %u (%s)", i,
		    init_tbl[i].desc);
		/*
		 * While we allow these to fail during detach, they
		 * should not fail when cleaning up from an attach.
		 */
		VERIFY(init_tbl[--i].finif(dp));
	}

	kmem_free(dp, sizeof (*dp));

	return (DDI_FAILURE);
}

static int
vmxnet3_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vmxnet3_softc_t *dp = ddi_get_driver_private(dip);

	VMXNET3_DEBUG(dp, 1, "detach()");

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	while (dp->init_lvl >= 0) {
		VMXNET3_DEBUG(dp, 2, "Running detach step %u (%s)",
		    dp->init_lvl + 1, init_tbl[dp->init_lvl].desc);

		if (!init_tbl[dp->init_lvl].finif(dp)) {
			dev_err(dp->dip, CE_WARN, "Detach step %u (%s) failed",
			    dp->init_lvl + 1, init_tbl[dp->init_lvl].desc);
			return (DDI_FAILURE);
		}
		dp->init_lvl--;
	}

	kmem_free(dp, sizeof (*dp));
	return (DDI_SUCCESS);
}

static boolean_t
vmxnet3_parse_propstr(const char *name, vmxnet3_props_t *propp)
{
	for (uint_t i = 0; vmxnet3_prop_strs[i] != NULL; i++) {
		if (strcmp(vmxnet3_prop_strs[i], name) == 0) {
			*propp = i;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static const char *
vmxnet3_err_str(uint32_t val)
{
	switch (val) {
	case VMXNET3_ERR_NOEOP:
		return ("end of packet descriptor not found");
	case VMXNET3_ERR_TXD_REUSE:
		return ("tx descriptor reused before tx completion");
	case VMXNET3_ERR_BIG_PKT:
		return ("packet used too many tx descriptors");
	case VMXNET3_ERR_DESC_NOT_SPT:
		return ("descriptor type not supported");
	case VMXNET3_ERR_SMALL_BUF:
		return ("type 0 buffer too small");
	case VMXNET3_ERR_STRESS:
		return ("stress option firing in hypervisor");
	case VMXNET3_ERR_SWITCH:
		return ("mode switch failure");
	case VMXNET3_ERR_TXD_INVALID:
		return ("invalid tx descriptor");
	default:
		return ("");
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
