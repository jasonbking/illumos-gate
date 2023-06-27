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

#ifndef	_VMXNET3_H_
#define	_VMXNET3_H_

#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>
#include <sys/mac.h>
#include <sys/sockio.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/list.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include <vmxnet3_defs.h>

struct vmxnet3_softc_t;
typedef struct vmxnet3_softc_t vmxnet3_softc_t;

struct vmxnet3_bufcache;
typedef struct vmxnet3_bufcache vmxnet3_bufcache_t;

struct vmxnet3_rxqueue_t;
typedef struct vmxnet3_rxqueue_t vmxnet3_rxqueue_t;

typedef struct vmxnet3_dmabuf_t {
	caddr_t		buf;
	uint64_t	bufPA;
	size_t		bufLen;
	ddi_dma_handle_t dmaHandle;
	ddi_acc_handle_t dataHandle;
} vmxnet3_dmabuf_t;

typedef struct vmxnet3_cmdring_t {
	vmxnet3_dmabuf_t dma;
	uint16_t	size;
	uint16_t	next2fill;
	uint16_t	avail;
	uint8_t		gen;
} vmxnet3_cmdring_t;

typedef struct vmxnet3_compring_t {
	vmxnet3_dmabuf_t dma;
	uint16_t	size;
	uint16_t	next2comp;
	uint8_t		gen;
} vmxnet3_compring_t;

typedef enum vmxnet3_metatx_state {
	VMS_FREE,
	VMS_ALLOC,
	VMS_COPY,
	VMS_BIND,
} vmxnet3_metatx_state_t;

typedef struct vmxnet3_metatx_t {
	struct vmxnet3_metatx_t	*vmtx_next;
	mblk_t			*vmtx_mp;
	ddi_dma_handle_t	vmtx_bind_hdl;
	vmxnet3_dmabuf_t	*vmtx_dmabuf;
	uint_t			vmtx_buflen;
	vmxnet3_metatx_state_t	vmtx_state;
} vmxnet3_metatx_t;

typedef struct vmxnet3_txqueue_t {
	kmutex_t		txLock;
	vmxnet3_softc_t		*sc;

	uint64_t		gen_num;
	mac_ring_handle_t	mrh;
	int			intr_num;	/* -1 implies no intr */
	boolean_t		started;

	vmxnet3_cmdring_t	cmdRing;
	vmxnet3_compring_t	compRing;
	vmxnet3_metatx_t	**metaRing;
	Vmxnet3_TxQueueCtrl	*sharedCtrl;
	kstat_t			*txRingStats;
	uint32_t		txDescNeeded;
	boolean_t		txMustResched;

	uint32_t		tx_bufinuse;

	uint64_t		tx_copy_frags;
	uint64_t		tx_bind_frags;
	uint64_t		tx_nonlso_bytes;
	uint64_t		tx_nonlso_pkts;

	uint32_t		tx_pullup_needed;
	uint32_t		tx_pullup_failed;
	uint32_t		tx_ring_full;
	uint32_t		tx_nobuf;
} vmxnet3_txqueue_t __aligned(64);

typedef enum vmxnet3_rxbuf_state {
	VMXNET3_RX_FREE,
	VMXNET3_RX_ONRING,
	VMXNET3_RX_ONLOAN,
	VMXNET3_RX_TEARDOWN,
} vmxnet3_rxbuf_state_t;

typedef struct vmxnet3_rxbuf_t {
	vmxnet3_dmabuf_t	*dma;
	mblk_t			*mblk;
	frtn_t			freeCB;
	vmxnet3_softc_t		*sc;
	vmxnet3_rxqueue_t	*rxq;
	vmxnet3_rxbuf_state_t	state;
} vmxnet3_rxbuf_t;

typedef struct vmxnet3_rxpool_t {
	vmxnet3_rxbuf_t	*listHead;
	unsigned int	nBufs;
	unsigned int	nBufsLimit;
} vmxnet3_rxpool_t;

struct vmxnet3_rxqueue_t {
	kmutex_t		rxLock;

	struct vmxnet3_softc_t	*sc;
	uint64_t		gen_num;
	mac_ring_handle_t	mrh;
	uint_t			intr_num;
	boolean_t		started;

	vmxnet3_cmdring_t	cmdRing;
	vmxnet3_compring_t	compRing;
	vmxnet3_rxbuf_t		**bufRing;
	Vmxnet3_RxQueueCtrl	*sharedCtrl;
	uint16_t		rx_onloan;

	kstat_t			*rxRingStats;
	uint64_t		rx_nomblk;
	uint64_t		rx_nobuf;
	uint64_t		rx_nodma;
	uint64_t		rx_loaned;
	uint64_t		rx_loaned_bytes;
	uint64_t		rx_copied;
	uint64_t		rx_copied_bytes;
	uint64_t		rx_dropped;
} __aligned(64);

struct vmxnet3_softc_t {
	dev_info_t		*dip;
	int			instance;
	mac_handle_t		mac;
	int			init_lvl;

	ddi_acc_handle_t	pciHandle;
	ddi_acc_handle_t	bar0Handle;
	ddi_acc_handle_t	bar1Handle;
	caddr_t			bar0;
	caddr_t			bar1;
	kmutex_t		cmdLock;

	kmutex_t		genLock;
	boolean_t		devEnabled;
	boolean_t		lso;
	boolean_t		lro;
	uint8_t			macaddr[ETHERADDRL];
	uint32_t		cur_mtu;
	link_state_t		linkState;
	uint64_t		linkSpeed;
	vmxnet3_dmabuf_t	sharedData;
	vmxnet3_dmabuf_t	queueDescs;

	kmutex_t		intrLock;
	int			intrCount;
	int			intrType;
	int			intrMaskMode;
	int			intrCap;
	int			intrEventNum;
	uint_t			intrPri;
	ddi_intr_handle_t	*intrHandles;
	ddi_taskq_t		*resetTask;

	vmxnet3_bufcache_t	*bufCache;
	vmxnet3_bufcache_t	*metaTxCache;
	vmxnet3_bufcache_t	*rxBufCache;

	vmxnet3_txqueue_t	*txQueue;
	uint16_t		txNQueue;
	uint16_t		txRingSize;
	uint16_t		txCopyThreshold;
	uint16_t		txMaxCopy;

	vmxnet3_rxqueue_t	*rxQueue;
	uint16_t		rxNQueue;
	uint16_t		rxRingSize;
	uint16_t		rxCopyThreshold;
	uint16_t		rxMaxLoan;
	uint32_t		rxMode;

	vmxnet3_dmabuf_t	mfTable;
	kstat_t			*devKstats;
	uint32_t		reset_count;
};

typedef struct vmxnet3_kstats_t {
	kstat_named_t	reset_count;
	kstat_named_t	rx_nqueue;
	kstat_named_t	tx_nqueue;
} vmxnet3_kstats_t;

typedef struct vmxnet3_tx_kstats_t {
	/* Stats the driver maintains */
	kstat_named_t	tx_pullup_needed;
	kstat_named_t	tx_pullup_failed;
	kstat_named_t	tx_ring_full;
	kstat_named_t	tx_nobuf;
	kstat_named_t	tx_copy_frags;
	kstat_named_t	tx_bind_frags;
	kstat_named_t	tx_nonlso_bytes;
	kstat_named_t	tx_nonlso_pkts;

	/* Stats maintained by the hardware */
	kstat_named_t	tx_hw_lso_pkts;
	kstat_named_t	tx_hw_lso_bytes;
	kstat_named_t	tx_hw_tx_error;
	kstat_named_t	tx_hw_tx_discard;
	kstat_named_t	tx_hw_ucast_pkts;
	kstat_named_t	tx_hw_ucast_bytes;
	kstat_named_t	tx_hw_mcast_pkts;
	kstat_named_t	tx_hw_mcast_bytes;
	kstat_named_t	tx_hw_bcast_pkts;
	kstat_named_t	tx_hw_bcast_bytes;
} vmxnet3_tx_kstats_t;

typedef struct vmxnet3_rx_kstats_t {
	kstat_named_t	rx_nomblk;
	kstat_named_t	rx_nobuf;
	kstat_named_t	rx_nodma;
	kstat_named_t	rx_loaned;
	kstat_named_t	rx_loaned_bytes;
	kstat_named_t	rx_copied;
	kstat_named_t	rx_copied_bytes;
	kstat_named_t	rx_dropped;

	kstat_named_t	rx_hw_lro_pkts;
	kstat_named_t	rx_hw_lro_bytes;
	kstat_named_t	rx_hw_ucast_pkts;
	kstat_named_t	rx_hw_ucast_bytes;
	kstat_named_t	rx_hw_mcast_pkts;
	kstat_named_t	rx_hw_mcast_bytes;
	kstat_named_t	rx_hw_bcast_pkts;
	kstat_named_t	rx_hw_bcast_bytes;
	kstat_named_t	rx_hw_nobuf;
	kstat_named_t	rx_hw_error;
} vmxnet3_rx_kstats_t;

int	vmxnet3_dmaerr2errno(int);
int	vmxnet3_alloc_dma_mem_1(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
int	vmxnet3_alloc_dma_mem_128(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
int	vmxnet3_alloc_dma_mem_512(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
void	vmxnet3_free_dma_mem(vmxnet3_dmabuf_t *dma);
int	vmxnet3_getprop(vmxnet3_softc_t *dp, char *name, int min, int max,
	    int def);

void	vmxnet3_intr_enable(vmxnet3_softc_t *, uint_t);
void	vmxnet3_intr_disable(vmxnet3_softc_t *, uint_t);
void	vmxnet3_get_stats(vmxnet3_softc_t *);

int	vmxnet3_tx_kstat_init(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq);
int	vmxnet3_metatx_cache_init(vmxnet3_softc_t *dp);
int	vmxnet3_tx_start(mac_ring_driver_t rh, uint64_t gen_num);
void	vmxnet3_tx_stop(mac_ring_driver_t rh);
int	vmxnet3_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *valp);
int	vmxnet3_tx_intr_enable(mac_intr_handle_t);
int	vmxnet3_tx_intr_disable(mac_intr_handle_t);
mblk_t	*vmxnet3_tx(void *dp, mblk_t *mps);
mblk_t	*vmxnet3_ring_tx(void *mrh, mblk_t *mps);
boolean_t vmxnet3_tx_complete(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq);

int	vmxnet3_rx_kstat_init(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq);
int	vmxnet3_rxbuf_cache_init(vmxnet3_softc_t *dp);
int	vmxnet3_rx_start(mac_ring_driver_t, uint64_t);
void	vmxnet3_rx_stop(mac_ring_driver_t);
mblk_t	*vmxnet3_rx_poll(void *, int);
int	vmxnet3_rx_stat(mac_ring_driver_t, uint_t, uint64_t *);
int	vmxnet3_rx_intr_enable(mac_intr_handle_t);
int	vmxnet3_rx_intr_disable(mac_intr_handle_t);
mblk_t	*vmxnet3_rx_intr(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq);
void	vmxnet3_log(int level, vmxnet3_softc_t *dp, char *fmt, ...);

vmxnet3_bufcache_t *vmxnet3_bufcache_init(uint32_t nent, size_t elsize,
    int (*vb_ctor)(void *, void *), void (*vb_reset)(void *, void *),
    void (*vb_dtor)(void *, void *), void *arg, uint_t pri);
void vmxnet3_bufcache_fini(vmxnet3_bufcache_t *c);
void *vmxnet3_bufcache_alloc(vmxnet3_bufcache_t *c);
void vmxnet3_bufcache_free(vmxnet3_bufcache_t *c, void *buf);

extern ddi_device_acc_attr_t vmxnet3_dev_attr;

extern int vmxnet3s_debug;

#define	VMXNET3_MODNAME	"vmxnet3s"
#define	VMXNET3_DRIVER_VERSION_STRING	"1.1.0.0"

/* Logging stuff */
#define	VMXNET3_WARN(Device, ...) \
	dev_err((Device)->dip, CE_WARN, "!" __VA_ARGS__)

#ifdef	DEBUG
#define	VMXNET3_DEBUG(Device, Level, ...) {				\
	if (Level <= vmxnet3s_debug) {					\
		dev_err((Device)->dip, CE_CONT, "?" __VA_ARGS__);	\
	}								\
}
#else
#define	VMXNET3_DEBUG(Device, Level, ...)
#endif

#define	MACADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define	MACADDR_FMT_ARGS(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

/* Default ring size */
#define	VMXNET3_DEF_TX_RING_SIZE	256
#define	VMXNET3_DEF_RX_RING_SIZE	256

#define	VMXNET3_DEF_TX_COPY_THRESHOLD	256
#define	VMXNET3_DEF_RX_COPY_THRESHOLD	256

#define	VMXNET3_DEF_TX_COPY_MAX		(VMXNET3_DEF_TX_RING_SIZE / 2)
#define	VMXNET3_DEF_RX_LOAN_MAX		(VMXNET3_DEF_RX_RING_SIZE / 2)

/* Register access helpers */
#define	VMXNET3_BAR0_GET32(Device, Reg) \
	ddi_get32((Device)->bar0Handle, (uint32_t *)((Device)->bar0 + (Reg)))
#define	VMXNET3_BAR0_PUT32(Device, Reg, Value) \
	ddi_put32((Device)->bar0Handle, (uint32_t *)((Device)->bar0 + (Reg)), \
	    (Value))
#define	VMXNET3_BAR1_GET32(Device, Reg) \
	ddi_get32((Device)->bar1Handle, (uint32_t *)((Device)->bar1 + (Reg)))
#define	VMXNET3_BAR1_PUT32(Device, Reg, Value) \
	ddi_put32((Device)->bar1Handle, (uint32_t *)((Device)->bar1 + (Reg)), \
	    (Value))

static inline boolean_t
vmxnet3_intr_legacy(const vmxnet3_softc_t *dp)
{
	if (dp->intrType == DDI_INTR_TYPE_FIXED || dp->intrCount == 1)
		return (B_TRUE);
	return (B_FALSE);
}

/* Misc helpers */
static inline Vmxnet3_DriverShared *
vmxnet3_ds(vmxnet3_softc_t *dp)
{
	return ((Vmxnet3_DriverShared *)dp->sharedData.buf);
}

static inline uint_t
vmxnet3_tqidx(const vmxnet3_txqueue_t *txq)
{
	const vmxnet3_softc_t *dp = txq->sc;
	uint_t idx = (uint_t)(txq - dp->txQueue);

	ASSERT3P(txq, >=, dp->txQueue);
	ASSERT3U(idx, <, dp->txNQueue);
	return (idx);
}

static inline Vmxnet3_TxQueueDesc *
vmxnet3_tqdesc(vmxnet3_txqueue_t *txq)
{
	const vmxnet3_softc_t *dp = txq->sc;
	Vmxnet3_TxQueueDesc *tqd = (Vmxnet3_TxQueueDesc *)dp->queueDescs.buf;
	uint_t idx = vmxnet3_tqidx(txq);

	return (&tqd[idx]);
}

static inline uint_t
vmxnet3_rqidx(const vmxnet3_rxqueue_t *rxq)
{
	const vmxnet3_softc_t *dp = rxq->sc;
	uint_t idx = (uint_t)(rxq - dp->rxQueue);

	ASSERT3P(rxq, >=, dp->rxQueue);
	ASSERT3U(idx, <, dp->rxNQueue);
	return (idx);
}

static inline Vmxnet3_RxQueueDesc *
vmxnet3_rqdesc(vmxnet3_rxqueue_t *rxq)
{
	const vmxnet3_softc_t *dp = rxq->sc;
	Vmxnet3_TxQueueDesc *tqd = (Vmxnet3_TxQueueDesc *)dp->queueDescs.buf;
	Vmxnet3_RxQueueDesc *rqd = (Vmxnet3_RxQueueDesc *)(tqd + dp->txNQueue);
	uint_t idx = vmxnet3_rqidx(rxq);

	return (&rqd[idx]);
}

#define	VMXNET3_ADDR_LO(addr) ((uint32_t)(addr))
#define	VMXNET3_ADDR_HI(addr) ((uint32_t)(((uint64_t)(addr)) >> 32))

#define	VMXNET3_GET_DESC(Ring, Idx) \
	(((Vmxnet3_GenericDesc *) (Ring)->dma.buf) + Idx)

/* Rings handling */
#define	VMXNET3_INC_RING_IDX(Ring, Idx) {	\
	(Idx)++;				\
	if ((Idx) == (Ring)->size) {		\
		(Idx) = 0;			\
		(Ring)->gen ^= 1;		\
	}					\
}

#define	VMXNET3_DEC_RING_IDX(Ring, Idx) {	\
	if ((Idx) == 0) {			\
		(Idx) = (Ring)->size;		\
		(Ring)->gen ^= 1;		\
	}					\
	(Idx)--;				\
}

static inline void
vmxnet3_init_cmdring(vmxnet3_cmdring_t *cmdRing, uint16_t size)
{
	cmdRing->avail = cmdRing->size = size;
	cmdRing->next2fill = 0;
	cmdRing->gen = VMXNET3_INIT_GEN;
}

static inline void
vmxnet3_init_compring(vmxnet3_compring_t *compRing, uint16_t size)
{
	compRing->size = size;
	compRing->next2comp = 0;
	compRing->gen = VMXNET3_INIT_GEN;
}

static inline void
vmxnet3_send_cmd(vmxnet3_softc_t *dp, Vmxnet3_Cmd cmd)
{
	mutex_enter(&dp->cmdLock);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, (uint32_t)cmd);
	mutex_exit(&dp->cmdLock);
}

static inline uint32_t
vmxnet3_send_cmd_val(vmxnet3_softc_t *dp, Vmxnet3_Cmd cmd)
{
	uint32_t val;

	mutex_enter(&dp->cmdLock);
	VMXNET3_BAR1_PUT32(dp, VMXNET3_REG_CMD, (uint32_t)cmd);
	val = VMXNET3_BAR1_GET32(dp, VMXNET3_REG_CMD);
	mutex_exit(&dp->cmdLock);

	return (val);
}

#define	PCI_VENDOR_ID_VMWARE		0x15AD
#define	PCI_DEVICE_ID_VMWARE_VMXNET3	0x07B0

#endif /* _VMXNET3_H_ */
