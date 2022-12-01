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
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include <vmxnet3_defs.h>

typedef struct vmxnet3_dmabuf {
	caddr_t			buf;
	uint64_t		bufPA;
	size_t			bufLen;
	ddi_dma_handle_t	dmaHandle;
	ddi_acc_handle_t	dataHandle;
} vmxnet3_dmabuf_t;

typedef struct vmxnet3_cmdring {
	vmxnet3_dmabuf_t	dma;
	Vmxnet3_GenericDesc	*desc;
	uint16_t		size;
	uint16_t		next2fill;
	uint16_t		avail;
	uint8_t			gen;
} vmxnet3_cmdring_t;

typedef struct vmxnet3_compring {
	vmxnet3_dmabuf_t	dma;
	Vmxnet3_GenericDesc	*desc;
	uint16_t		size;
	uint16_t		next2comp;
	uint8_t			gen;
} vmxnet3_compring_t;

typedef struct vmxnet3_metatx {
	mblk_t			*mp;
	size_t			len;
	vmxnet3_dmabuf_t	buf;
	ddi_dma_handle_t	bind_hdl;
	uint16_t		sopIdx;
	uint16_t		frags;
	boolean_t		copied;
} vmxnet3_metatx_t;

typedef struct vmxnet3_txqueue {
	kmutex_t		txLock;

	struct vmxnet3_softc	*sc;

	ddi_dma_handle_t	tx_dma_handle;

	size_t			nalloc;
	size_t			nent;
	uint64_t		gen_num;
	uint_t			intr_idx;
	mac_ring_handle_t	mrh;

	vmxnet3_cmdring_t	cmdRing;
	vmxnet3_compring_t	compRing;
	vmxnet3_metatx_t	*metaRing;
	Vmxnet3_TxQueueCtrl	*sharedCtrl;
	boolean_t		reschedule;

	uint64_t		tx_pullup_needed;
	uint64_t		tx_pullup_failed;
	uint64_t		tx_ring_full;
	uint64_t		tx_bind_failed;
} vmxnet3_txqueue_t;

typedef struct vmxnet3_rxbuf {
	vmxnet3_dmabuf_t	dma;
	mblk_t			*mblk;
	frtn_t			freeCB;
	struct vmxnet3_softc	*dp;
	struct vmxnet3_rxbuf	*next;
} vmxnet3_rxbuf_t;

typedef struct vmxnet3_bufdesc {
	vmxnet3_rxbuf_t	*rxBuf;
} vmxnet3_bufdesc_t;

typedef struct vmxnet3_rxpool {
	vmxnet3_rxbuf_t	*listHead;
	unsigned int	nBufs;
	unsigned int	nBufsLimit;
} vmxnet3_rxpool_t;

typedef struct vmxnet3_rxqueue {
	kmutex_t		rxLock;

	struct vmxnet3_softc	*sc;

	size_t			nalloc;
	size_t			nent;
	uint64_t		gen_num;
	uint_t			intr_idx;
	mac_ring_handle_t	mrh;

	vmxnet3_cmdring_t	cmdRing;
	vmxnet3_compring_t	compRing;
	vmxnet3_bufdesc_t	*bufRing;
	Vmxnet3_RxQueueCtrl	*sharedCtrl;
} vmxnet3_rxqueue_t;

typedef struct vmxnet3_softc {
	dev_info_t	*dip;
	int		instance;
	mac_handle_t	mac;

	kmutex_t	cmdLock;

	ddi_acc_handle_t pciHandle;
	ddi_acc_handle_t bar0Handle, bar1Handle;
	caddr_t		bar0, bar1;

	kmutex_t	genLock;
	boolean_t	devEnabled;
	uint8_t		macaddr[6];
	uint32_t	cur_mtu;
	boolean_t	allow_jumbo;
	boolean_t	lso;
	link_state_t	linkState;
	uint64_t	linkSpeed;
	vmxnet3_dmabuf_t sharedData;
	vmxnet3_dmabuf_t queueDescs;

	kmutex_t	eventLock;

	int		intrType;
	int		intrMaskMode;
	int		intrCap;
	int		intrCount;
	uint_t		intrPri;
	ddi_intr_handle_t *intrHandles;
	size_t		intrHandleSz;
	ddi_taskq_t	*resetTask;

	uint32_t	txBufSize;
	uint32_t	txCopyThresh;
	uint32_t	txRingSize;
	uint_t		txNQueue;
	vmxnet3_txqueue_t txQueue[VMXNET3_MAX_TX_QUEUES];

	kmutex_t	rxPoolLock;
	uint32_t	rxRingSize;
	uint32_t	rxBufPool;
	vmxnet3_rxpool_t rxPool;

	uint32_t	rxMode;
	boolean_t	alloc_ok;
	uint_t		rxNQueue;
	vmxnet3_rxqueue_t rxQueue[VMXNET3_MAX_RX_QUEUES];
	vmxnet3_dmabuf_t rss;

	vmxnet3_dmabuf_t mfTable;

	kstat_t		*devKstats;
	hrtime_t	last_stat;
	uint32_t	reset_count;
	uint32_t	tx_error;
	uint32_t	rx_num_bufs;
	uint32_t	rx_alloc_buf;
	uint32_t	rx_alloc_failed;
	uint32_t	rx_pool_empty;
} vmxnet3_softc_t;

typedef struct vmxnet3_kstats {
	kstat_named_t	reset_count;
	kstat_named_t	tx_pullup_needed;
	kstat_named_t	tx_ring_full;
	kstat_named_t	rx_alloc_buf;
	kstat_named_t	rx_pool_empty;
	kstat_named_t	rx_num_bufs;
} vmxnet3_kstats_t;

int	vmxnet3_dmaerr2errno(int);
int	vmxnet3_alloc_dma_mem_1(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
int	vmxnet3_alloc_dma_mem_128(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
int	vmxnet3_alloc_dma_mem_512(vmxnet3_softc_t *dp, vmxnet3_dmabuf_t *dma,
	    size_t size, boolean_t canSleep);
void	vmxnet3_free_dma_mem(vmxnet3_dmabuf_t *dma);

void	vmxnet3_init_cmdring(vmxnet3_cmdring_t *, size_t);
void	vmxnet3_init_compring(vmxnet3_compring_t *, size_t);

void	vmxnet3_intr_enable(vmxnet3_softc_t *dp, uint_t);
void	vmxnet3_intr_disable(vmxnet3_softc_t *dp, uint_t);

int	vmxnet3_tx_start(mac_ring_driver_t, uint64_t);
void	vmxnet3_tx_stop(mac_ring_driver_t);
mblk_t	*vmxnet3_tx_chain(void *, mblk_t *);
int	vmxnet3_tx_stat(mac_ring_driver_t, uint_t, uint64_t *);
uint_t	vmxnet3_tx_intr(caddr_t, caddr_t);
int	vmxnet3_tx_intr_enable(mac_intr_handle_t);
int	vmxnet3_tx_intr_disable(mac_intr_handle_t);
void	vmxnet3_tx_flush(vmxnet3_txqueue_t *);

boolean_t vmxnet3_tx_complete(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq);
int	vmxnet3_txqueue_init(vmxnet3_txqueue_t *txq, size_t, size_t);
void	vmxnet3_txqueue_fini(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq);

int	vmxnet3_rx_start(mac_ring_driver_t, uint64_t);
void	vmxnet3_rx_stop(mac_ring_driver_t);
mblk_t	*vmxnet3_rx_poll(mac_ring_driver_t, int);
int	vmxnet3_rx_stat(mac_ring_driver_t, uint_t, uint64_t *);
uint_t	vmxnet3_rx_intr(caddr_t, caddr_t);
int	vmxnet3_rx_intr_enable(mac_intr_handle_t);
int	vmxnet3_rx_intr_disable(mac_intr_handle_t);

int	vmxnet3_rxpool_init(vmxnet3_softc_t *);
void	vmxnet3_rxpool_fini(vmxnet3_softc_t *);

int	vmxnet3_rxqueue_init(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq);
mblk_t	*vmxnet3_rx(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq, int);
void	vmxnet3_rxqueue_fini(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq);
void	vmxnet3_log(int level, vmxnet3_softc_t *dp, char *fmt, ...);

void	vmxnet3_get_stats(vmxnet3_softc_t *);

extern ddi_device_acc_attr_t vmxnet3_dev_attr;

extern int vmxnet3s_debug;

#define	VMXNET3_MODNAME	"vmxnet3s"
#define	VMXNET3_DRIVER_VERSION_STRING	"1.1.0.0"

#define	VMXNET3_MIN_STAT_INTERVAL	SEC2NSEC(1)

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

/* Misc helpers */
#define	VMXNET3_DS(Device) ((Vmxnet3_DriverShared *) (Device)->sharedData.buf)

static inline Vmxnet3_TxQueueDesc *
VMXNET3_TQDESC(const vmxnet3_txqueue_t *txq)
{
	const vmxnet3_softc_t *dp = txq->sc;
	Vmxnet3_TxQueueDesc *tqd = (Vmxnet3_TxQueueDesc *)dp->queueDescs.buf;
	uint_t idx = (uint_t)(txq - dp->txQueue);

	ASSERT3U(idx, <, dp->txNQueue);
	return (&tqd[idx]);
}

static inline Vmxnet3_RxQueueDesc *
VMXNET3_RQDESC(const vmxnet3_rxqueue_t *rxq)
{
	const vmxnet3_softc_t *dp = rxq->sc;
	Vmxnet3_TxQueueDesc *tqd = (Vmxnet3_TxQueueDesc *)dp->queueDescs.buf;
	Vmxnet3_RxQueueDesc *rqd = (Vmxnet3_RxQueueDesc *)(tqd + dp->txNQueue);
	uint_t idx = (uint_t)(rxq - dp->rxQueue);

	ASSERT3U(idx, <, dp->rxNQueue);
	return (&rqd[idx]);
}

static inline UPT1_RSSConf *
VMXNET3_RSS(vmxnet3_softc_t *dp)
{
	return ((UPT1_RSSConf *)dp->rss.buf);
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

#define	PCI_VENDOR_ID_VMWARE		0x15AD
#define	PCI_DEVICE_ID_VMWARE_VMXNET3	0x07B0

#endif /* _VMXNET3_H_ */
