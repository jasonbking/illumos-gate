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
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <vmxnet3.h>

typedef enum vmxnet3_txstatus {
	VMXNET3_TX_OK,
	VMXNET3_TX_FAILURE,
	VMXNET3_TX_PULLUP,
	VMXNET3_TX_RINGFULL,
	VMXNET3_TX_NOBUF,
} vmxnet3_txstatus;

typedef struct vmxnet3_offload_t {
	uint16_t om;
	uint16_t hlen;
	uint16_t msscof;
} vmxnet3_offload_t;

/* The absolute # of metatx_ts we can have for a packet */
#define	TXPKT_MAX	VMXNET3_MAX_TSO_TXD_PER_PKT

typedef struct vmxnet3_txpkt_t {
	mblk_t			*vtx_mp;
	vmxnet3_metatx_t	*vtx_head;
	vmxnet3_metatx_t	*vtx_tail;
	uint32_t		vtx_len;
	uint8_t			vtx_metacnt;
	uint8_t			vtx_fragcnt;
} vmxnet3_txpkt_t;

static void vmxnet3_metatx_free(vmxnet3_txqueue_t *, vmxnet3_metatx_t *);

/* Tx DMA engine description */
static ddi_dma_attr_t vmxnet3_dma_attrs_tx = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	/* The TX descriptor length field is 14 bits wide */
	.dma_attr_count_max =	0x0000000000003FFFull,
	.dma_attr_align =	0x0000000000000001ull,
	.dma_attr_burstsizes =	0x0000000000000001ull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	0x000000000000FFFFull,
	.dma_attr_seg =		0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen =	-1,
	.dma_attr_granular =	0x00000001,
	.dma_attr_flags =	0
};

static inline void
txpkt_cleanup(vmxnet3_txqueue_t *txq, vmxnet3_txpkt_t *pkt)
{
	vmxnet3_metatx_t	*m = pkt->vtx_head;
	uint8_t			n = 0;

	while (m != NULL) {
		vmxnet3_metatx_t *next = m->vmtx_next;

		vmxnet3_metatx_free(txq, m);
		n++;
		m = next;
	}
	VERIFY3U(n, ==, pkt->vtx_metacnt);
	bzero(pkt, sizeof (*pkt));
}

static inline ddi_dma_handle_t
meta_dma_hdl(const vmxnet3_metatx_t *meta)
{
	switch (meta->vmtx_state) {
	case VMS_COPY:
		return (meta->vmtx_dmabuf->dmaHandle);
	case VMS_BIND:
		return (meta->vmtx_bind_hdl);
	default:
		panic("unexpected metatx state");
	}
}

/* How much space is left for copying */
static inline uint32_t
meta_copy_left(const vmxnet3_metatx_t *meta)
{
	ASSERT3S(meta->vmtx_state, ==, VMS_COPY);
	ASSERT3U(meta->vmtx_dmabuf->bufLen, >=, meta->vmtx_buflen);
	return (meta->vmtx_dmabuf->bufLen - meta->vmtx_buflen);
}

static inline uint_t
meta_ncookies(const vmxnet3_metatx_t *meta)
{
	uint_t n;

	n = ddi_dma_ncookies(meta_dma_hdl(meta));
	IMPLY(meta->vmtx_state == VMS_COPY, n == 1);
	return (n);
}

static inline void
txpkt_add_meta(vmxnet3_txpkt_t *pkt, vmxnet3_metatx_t *meta)
{
	if (pkt->vtx_head == NULL) {
		pkt->vtx_head = pkt->vtx_tail = meta;
	} else {
		pkt->vtx_tail->vmtx_next = meta;
		pkt->vtx_tail = meta;
	}
	ASSERT3P(meta->vmtx_next, ==, NULL);
	pkt->vtx_fragcnt += meta_ncookies(meta);
	pkt->vtx_metacnt++;
}

static inline boolean_t
too_many_frags(const vmxnet3_offload_t *ol, unsigned int nfrags)
{
	if (ol->om == VMXNET3_OM_TSO) {
		if (nfrags > VMXNET3_MAX_TSO_TXD_PER_PKT)
			return (B_TRUE);
		else
			return (B_FALSE);
	}

	if (nfrags > VMXNET3_MAX_TXD_PER_PKT)
		return (B_TRUE);

	return (B_FALSE);
}

static vmxnet3_metatx_t *
vmxnet3_metatx_alloc(vmxnet3_softc_t *dp)
{
	vmxnet3_metatx_t *m = vmxnet3_bufcache_alloc(dp->metaTxCache);

	if (m == NULL)
		return (NULL);

	ASSERT0(m->vmtx_buflen);
	ASSERT3P(m->vmtx_mp, ==, NULL);
	ASSERT3P(m->vmtx_next, ==, NULL);
	ASSERT3S(m->vmtx_state, ==, VMS_FREE);
	m->vmtx_state = VMS_ALLOC;
	return (m);
}

static void
vmxnet3_metatx_free(vmxnet3_txqueue_t *txq, vmxnet3_metatx_t *m)
{
	if (m == NULL)
		return;

	ASSERT(MUTEX_HELD(&txq->txLock));

	switch (m->vmtx_state) {
	case VMS_FREE:
		dev_err(txq->sc->dip, CE_PANIC, "metatx double free\n");
		break;
	case VMS_ALLOC:
	case VMS_BIND:
		break;
	case VMS_COPY:
		VERIFY3P(m->vmtx_dmabuf, !=, NULL);
		ASSERT3U(txq->tx_bufinuse, >, 0);
		txq->tx_bufinuse--;
		break;
	}

	vmxnet3_bufcache_free(txq->sc->metaTxCache, m);
}

int
vmxnet3_tx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	vmxnet3_softc_t		*dp = txq->sc;
	uint_t			idx __maybe_unused;

	idx = vmxnet3_tqidx(txq);
	VMXNET3_DEBUG(dp, 1, "tx %u start", idx);

	mutex_enter(&txq->txLock);

	txq->gen_num = gen_num;

	vmxnet3_init_cmdring(&txq->cmdRing, dp->txRingSize);
	vmxnet3_init_compring(&txq->compRing, dp->txRingSize);

	txq->started = B_TRUE;
	mutex_exit(&txq->txLock);

	return (0);
}

void
vmxnet3_tx_stop(mac_ring_driver_t rh)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	uint_t			idx __maybe_unused;

	idx = vmxnet3_tqidx(txq);
	VMXNET3_DEBUG(txq->sc, 1, "tx %u stop", idx);

	mutex_enter(&txq->txLock);
	txq->started = B_FALSE;

	for (uint_t i = 0; i < txq->cmdRing.size; i++) {
		vmxnet3_metatx_t *meta = txq->metaRing[i];

		if (meta == NULL)
			continue;

		while (meta != NULL) {
			vmxnet3_metatx_t *next = meta->vmtx_next;

			vmxnet3_metatx_free(txq, meta);
			meta = next;
		}

		txq->metaRing[i] = NULL;
	}

	bzero(txq->cmdRing.dma.buf, txq->cmdRing.dma.bufLen);
	bzero(txq->compRing.dma.buf, txq->compRing.dma.bufLen);
	bzero(txq->metaRing,
	    VMXNET3_TX_RING_MAX_SIZE * sizeof (vmxnet3_metatx_t *));

	mutex_exit(&txq->txLock);
}

int
vmxnet3_tx_intr_enable(mac_intr_handle_t mih)
{
	vmxnet3_txqueue_t *txq = (vmxnet3_txqueue_t *)mih;

	mutex_enter(&txq->txLock);

	/* No interrupts to enable */
	if (txq->intr_num >= 0) {
		vmxnet3_intr_enable(txq->sc, txq->intr_num);
	}

	mutex_exit(&txq->txLock);
	return (0);
}

int
vmxnet3_tx_intr_disable(mac_intr_handle_t mih)
{
	vmxnet3_txqueue_t *txq = (vmxnet3_txqueue_t *)mih;

	mutex_enter(&txq->txLock);

	/* No interrupts to disable */
	if (txq->intr_num >= 0) {
		vmxnet3_intr_disable(txq->sc, txq->intr_num);
	}

	mutex_exit(&txq->txLock);
	return (0);
}

/*
 * Build the offload context of a msg.
 *
 * Returns:
 *	0 if everything went well.
 *	+n if n bytes need to be pulled up.
 *	-1 in case of error (not used).
 */
static mblk_t *
vmxnet3_tx_prepare_offload(vmxnet3_txqueue_t *txq, vmxnet3_offload_t *ol,
    mblk_t *mp)
{
	uint32_t start, stuff, value, flags, lso_flag, mss;

	ASSERT(MUTEX_HELD(&txq->txLock));

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

		VMXNET3_DEBUG(txq->sc, 4, "flags=0x%x, ethLen=%u, start=%u, "
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
				/* Get all the headers into a single mblk_t */
				mblk = msgpullup(mp, ol->hlen);
				if (mblk == NULL)
					txq->tx_pullup_failed++;

				return (mblk);
			}

		} else if (flags & HCK_PARTIALCKSUM) {
			ol->om = VMXNET3_OM_CSUM;
			ol->hlen = start + ethLen;
			ol->msscof = stuff + ethLen;
		}
	}

	return (mp);
}

static vmxnet3_txstatus
vmxnet3_tx_copy(vmxnet3_txqueue_t *txq, const vmxnet3_offload_t *ol,
    const mblk_t *mp, vmxnet3_txpkt_t *pkt)
{
	vmxnet3_metatx_t	*meta = pkt->vtx_tail;
	const uint32_t		len = MBLKL(mp);
	uint32_t		amt = 0;
	uint32_t		copied = 0;

	ASSERT(MUTEX_HELD(&txq->txLock));
	ASSERT3U(len, >, 0);

	while (copied != len) {
		if (meta == NULL || meta->vmtx_state != VMS_COPY ||
		    meta_copy_left(meta) == 0) {
			vmxnet3_softc_t *dp = txq->sc;

			if (pkt->vtx_metacnt == TXPKT_MAX ||
			    too_many_frags(ol, pkt->vtx_fragcnt + 1)) {
				return (VMXNET3_TX_PULLUP);
			}

			meta = vmxnet3_metatx_alloc(dp);
			if (meta == NULL) {
				txq->tx_nobuf++;
				return (VMXNET3_TX_NOBUF);
			}

			meta->vmtx_dmabuf =
			    vmxnet3_bufcache_alloc(dp->bufCache);
			if (meta->vmtx_dmabuf == NULL) {
				txq->tx_nobuf++;
				vmxnet3_metatx_free(txq, meta);
				return (VMXNET3_TX_NOBUF);
			}
			meta->vmtx_state = VMS_COPY;
			txq->tx_bufinuse++;

			/* We should always get a single cookie for copy bufs */
			ASSERT3U(meta_ncookies(meta), ==, 1);
			txpkt_add_meta(pkt, meta);
		}

		amt = MIN(len - copied, meta_copy_left(meta));
		bcopy(mp->b_rptr + copied, meta->vmtx_dmabuf->buf +
		    meta->vmtx_buflen, amt);

		meta->vmtx_buflen += amt;
		copied += amt;
	}

	pkt->vtx_len += len;
	return (VMXNET3_TX_OK);
}

static vmxnet3_txstatus
vmxnet3_tx_bind(vmxnet3_txqueue_t *txq, const vmxnet3_offload_t *ol,
    const mblk_t *mp, vmxnet3_txpkt_t *pkt)
{
	const size_t		len = MBLKL(mp);
	vmxnet3_metatx_t	*meta;

	ASSERT(MUTEX_HELD(&txq->txLock));

	if (pkt->vtx_metacnt == TXPKT_MAX)
		return (VMXNET3_TX_PULLUP);

	meta = vmxnet3_metatx_alloc(txq->sc);
	if (meta == NULL) {
		txq->tx_nobuf++;
		return (VMXNET3_TX_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(meta->vmtx_bind_hdl, NULL,
	    (caddr_t)mp->b_rptr, len, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, NULL, NULL) != DDI_DMA_MAPPED) {
		vmxnet3_metatx_free(txq, meta);
		return (VMXNET3_TX_FAILURE);
	}
	meta->vmtx_state = VMS_BIND;

	if (too_many_frags(ol, pkt->vtx_fragcnt + meta_ncookies(meta))) {
		vmxnet3_metatx_free(txq, meta);
		return (VMXNET3_TX_PULLUP);
	}

	/*
	 * All of the headers must be within a single descriptor (e.g. the
	 * same cookie) when using TSO. We already guarantee that the
	 * headers will be in a single mblk_t in vmxnet3_tx_prepare_offload()
	 * when using TSO. Therefore the first vmxnet3_metatx_t will correspond
	 * to the header mblk_t. If binding couldn't get all of the headers
	 * into a single cookie, we fail and attempt to copy instead.
	 */
	if (ol->om == VMXNET3_OM_TSO && pkt->vtx_metacnt == 0) {
		const ddi_dma_cookie_t *c;

		c = ddi_dma_cookie_get(meta->vmtx_bind_hdl, 0);
		if (c->dmac_size < ol->hlen) {
			vmxnet3_metatx_free(txq, meta);
			return (VMXNET3_TX_PULLUP);
		}
	}

	meta->vmtx_buflen = len;
	txpkt_add_meta(pkt, meta);
	pkt->vtx_len += len;
	return (VMXNET3_TX_OK);
}

/*
 * Prepare mp for transmission. Copy/bind segments of mp as required
 * into one or more vmxnet3_metatx_ts in pkt. If we fail for any reason,
 * pkt is left in its initial initialized state (i.e. anything allocated
 * is freed before returning).
 *
 * On success, pkt will contain all the vmxnet3_metatx_ts for the packet.
 * If msgpullup() was required, pkt->mp may be different from mp.
 */
static vmxnet3_txstatus
vmxnet3_tx_prepare_pkt(vmxnet3_txqueue_t *txq, const vmxnet3_offload_t *ol,
    mblk_t *mp, vmxnet3_txpkt_t *pkt)
{
	const uint32_t		frag_limit = txq->cmdRing.avail;

	mblk_t			*mblk;
	vmxnet3_txstatus	ret = VMXNET3_TX_OK;
	boolean_t		is_retry = B_FALSE;

	ASSERT(MUTEX_HELD(&txq->txLock));

	pkt->vtx_mp = mp;

retry:
	/* If we're retrying, there should be a single mblk */
	IMPLY(is_retry, pkt->vtx_mp->b_cont == NULL);

	for (mblk = pkt->vtx_mp; mblk != NULL; mblk = mblk->b_cont) {
		const uint32_t len = MBLKL(mblk);

		if (len == 0)
			continue;

		ASSERT3U(pkt->vtx_metacnt, <=, TXPKT_MAX);

		/*
		 * Try to bind larger segments and when we've used our limit
		 * of preallocated buffers for copy.
		 */
		if (len > txq->sc->txCopyThreshold ||
		    txq->tx_bufinuse < txq->sc->txMaxCopy) {
			ret = vmxnet3_tx_bind(txq, ol, mblk, pkt);
			switch (ret) {
			case VMXNET3_TX_OK:
				continue;
			case VMXNET3_TX_PULLUP:
				if (is_retry)
					break;

				/*
				 * This could be an overly fragmented mblk
				 * chain. Consolidate it into a single
				 * mblk_t and see if we can bind it that way.
				 */
				txpkt_cleanup(txq, pkt);
				pkt->vtx_mp = msgpullup(mp, -1);
				if (pkt->vtx_mp == NULL) {
					txq->tx_pullup_failed++;
					ret = VMXNET3_TX_FAILURE;
					goto fail;
				}
				goto retry;
			default:
				/*
				 * If we failed to bind for any other reason,
				 * we'll fall through and try to copy instead.
				 */
				break;
			}
		}

		ret = vmxnet3_tx_copy(txq, ol, mblk, pkt);
		switch (ret) {
		case VMXNET3_TX_OK:
			break;
		case VMXNET3_TX_PULLUP:
			/* We should never pullup twice */
			VERIFY(!is_retry);

			txpkt_cleanup(txq, pkt);
			pkt->vtx_mp = msgpullup(mp, -1);
			if (pkt->vtx_mp == NULL) {
				txq->tx_pullup_failed++;
				ret = VMXNET3_TX_FAILURE;
				goto fail;
			}

			is_retry = B_TRUE;
			goto retry;
		case VMXNET3_TX_NOBUF:
			goto fail;
		case VMXNET3_TX_FAILURE:
			/*
			 * vmxnet3_tx_copy() should never return
			 * VMXNET3_TX_FAILURE.
			 */
		default:
			dev_err(txq->sc->dip, CE_PANIC,
			    "vmxnet3_tx_copy invalid return value: %d", ret);
		}
	}

	ASSERT3S(ret, ==, VMXNET3_TX_OK);

	/*
	 * If there aren't enough available descriptors to TX this packet,
	 * we return VMXNET3_TX_RINGFULL which will ultimately signal
	 * MAC to queue packets for this ring until more descriptors are
	 * available.
	 *
	 * We also keep track of how many descriptors are needed for
	 * this mblk_t. vmxnet3_tx_complete() will not signal MAC to continue
	 * until txDescNeeded descriptors are available to allow us to proceed.
	 * To state it slightly differently, if there are insufficient
	 * resources to send this packet, we assert flow control (to MAC)
	 * until there are enough resources to send this packet.
	 *
	 * Since different packets may require differing amounts of
	 * resources (i.e. different amounts of descriptors) to transmit,
	 * we are implicitly assuming that once we tell MAC to pause
	 * transmission, when we resume transmission, we will pick up with the
	 * same mblk_t that led us to pause. Given the importance of
	 * packet ordering for performant TCP, this seems like a reasonable
	 * assumption.
	 *
	 * If this assumption is wrong, the only harm is that TX will either
	 * pause for slightly longer than is necessary (because we waited for
	 * more free descriptors than we needed) or MAC will try to
	 * send and block again (because we need even more descriptors).
	 *
	 * It is also worth noting that the vmxnet3s 'hardware' appears to
	 * freeze if the TX ring is filled completely. As such we consider
	 * the ring 'full' for flow control purposes once
	 * 'txq->cmdRing.avail - 1' descriptors are in use (instead of
	 * 'txq->cmdRing.avail'.
	 */
	if (pkt->vtx_fragcnt >= frag_limit) {
		ret = VMXNET3_TX_RINGFULL;
		txq->txDescNeeded = pkt->vtx_fragcnt;
		txq->txMustResched = B_TRUE;
		txq->tx_ring_full++;
		goto fail;
	}

	ASSERT3U(pkt->vtx_metacnt, >, 0);
	ASSERT3U(pkt->vtx_fragcnt, >, 0);
	return (ret);

fail:
	if (pkt->vtx_mp != NULL && pkt->vtx_mp != mp)
		freemsg(pkt->vtx_mp);
	txpkt_cleanup(txq, pkt);
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
#define	DESC_LEN(d) \
	(((d)->txd.len == 0) ? VMXNET3_MAX_TX_BUF_SIZE : (d)->txd.len)
static mblk_t *
vmxnet3_tx_one(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq, mblk_t *mp)
{
	vmxnet3_cmdring_t	*cmdRing = &txq->cmdRing;
	Vmxnet3_TxQueueCtrl	*txqCtrl = txq->sharedCtrl;
	Vmxnet3_GenericDesc	*txDesc = NULL;
	mblk_t			*mblk;
	vmxnet3_metatx_t	*meta;
	vmxnet3_offload_t	ol = { 0 };
	vmxnet3_txpkt_t		pkt = { 0 };
	uint32_t		dw2, dw3;
	uint16_t		len, sopIdx, eopIdx;
	uint8_t			frags, mfrags;
	uint8_t			sopGen, curGen;
	vmxnet3_txstatus	status;

	mutex_enter(&txq->txLock);

	mblk = vmxnet3_tx_prepare_offload(txq, &ol, mp);
	if (mblk == NULL) {
		txq->txMustResched = B_TRUE;
		mutex_exit(&txq->txLock);
		return (mp);
	}

	status = vmxnet3_tx_prepare_pkt(txq, &ol, mblk, &pkt);
	switch (status) {
	case VMXNET3_TX_OK:
		break;
	case VMXNET3_TX_RINGFULL:
	case VMXNET3_TX_FAILURE:
	case VMXNET3_TX_NOBUF:
		mutex_exit(&txq->txLock);
		if (mblk != mp)
			freemsg(mblk);
		return (mp);
	case VMXNET3_TX_PULLUP:
		/*
		 * vmxnet3_tx_prepare_pkt() should never return
		 * VMXNET3_TX_PULLUP -- it should handle that case itself.
		 * Treat it like any other unexpected return value (i.e.
		 * fallthru).
		 */
	default:
		/* vmxnet3_tx_prepare_pkt() should not return any other value */
		dev_err(dp->dip, CE_PANIC,
		    "vmxnet3_tx_prepare_pkt() invalid return value %d", status);
	}

	/*
	 * If we get this far, there should always be enough available
	 * descriptors
	 */
	VERIFY3U(pkt.vtx_fragcnt, <, cmdRing->avail);

	sopIdx = eopIdx = cmdRing->next2fill;
	sopGen = cmdRing->gen;
	curGen = !cmdRing->gen;

	/*
	 * Populate the metaRing and TX descriptor ring with the
	 * prepared packet. The metaRing tracks additional data
	 * (e.g. the mblk_t) that needs to be cleaned up after the
	 * packet has been transmitted.
	 */
	frags = mfrags = 0;
	dw2 = dw3 = 0;
	len = 0;
	for (meta = pkt.vtx_head; meta != NULL; meta = meta->vmtx_next) {
		ddi_dma_handle_t	dh;

		dh = meta_dma_hdl(meta);
		mfrags += meta_ncookies(meta);

		if (meta->vmtx_state == VMS_COPY)
			txq->tx_copy_frags++;
		else
			txq->tx_bind_frags++;

		VERIFY0(ddi_dma_sync(dh, 0, meta->vmtx_buflen,
		    DDI_DMA_SYNC_FORDEV));

		for (const ddi_dma_cookie_t *c = ddi_dma_cookie_iter(dh, NULL);
		    c != NULL;
		    c = ddi_dma_cookie_iter(dh, c)) {
			uint16_t fraglen;

			eopIdx = cmdRing->next2fill;
			txDesc = VMXNET3_GET_DESC(cmdRing, eopIdx);
			ASSERT3U(txDesc->txd.gen, !=, cmdRing->gen);

			/*
			 * If this vmxnet3_metatx_t is used as a copy buffer,
			 * the cookie size reflects the total size of the
			 * buffer. If it's used as a bind, then each cookie's
			 * length should be the size of the current fragment.
			 */
			fraglen = meta->vmtx_state == VMS_COPY ?
			    meta->vmtx_buflen : c->dmac_size;

			dw2 = (fraglen == VMXNET3_MAX_TX_BUF_SIZE) ?
			    0 : fraglen;
			dw2 |= curGen << VMXNET3_TXD_GEN_SHIFT;

			dw3 = 0;

			txDesc->txd.addr = LE_64(c->dmac_laddress);
			txDesc->dword[2] = LE_32(dw2);
			txDesc->dword[3] = LE_32(dw3);

			VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
			curGen = cmdRing->gen;

			len += fraglen;
			frags++;
		}

		ASSERT3U(meta->vmtx_buflen, <=, len);
	}

	VERIFY3U(len, ==, pkt.vtx_len);
	VERIFY3U(frags, ==, pkt.vtx_fragcnt);
	VERIFY3U(mfrags, ==, pkt.vtx_fragcnt);

	txq->metaRing[eopIdx] = pkt.vtx_head;

	/* Set the EOP flag in the last descriptor */
	dw3 |= VMXNET3_TXD_CQ | VMXNET3_TXD_EOP;
	txDesc->dword[3] = LE_32(dw3);

	/* Update the SOP descriptor. Must be done last */
	txDesc = VMXNET3_GET_DESC(cmdRing, sopIdx);
	if (ol.om == VMXNET3_OM_TSO) {
		/*
		 * We always guarantee all the headers are in a single
		 * descriptor when performing TSO.
		 */
		VERIFY3U(DESC_LEN(txDesc), >=, ol.hlen);
	} else {
		txq->tx_nonlso_bytes += len;
		txq->tx_nonlso_pkts++;
	}

	txDesc->txd.om = ol.om;
	txDesc->txd.hlen = ol.hlen;
	txDesc->txd.msscof = ol.msscof;
	membar_producer();
	txDesc->txd.gen = sopGen;

	/* Update the meta ring & metadata */
	txq->metaRing[eopIdx] = pkt.vtx_head;
	txq->metaRing[eopIdx]->vmtx_mp = pkt.vtx_mp;
	cmdRing->avail -= frags;

	if (ol.om == VMXNET3_OM_TSO) {
		txqCtrl->txNumDeferred +=
		    (pkt.vtx_len - ol.hlen + ol.msscof - 1) / ol.msscof;
	} else {
		txqCtrl->txNumDeferred++;
	}

	VMXNET3_DEBUG(dp, 3, "tx 0x%p on [%u;%u]\n", (void *)mblk, sopIdx,
	    eopIdx);

	mutex_exit(&txq->txLock);

	/*
	 * If we're here, the packet has been successfully mapped onto
	 * the descriptor ring and will be transmitted. If we generated a
	 * new mblk_t (because we had to pullup at least part of it for
	 * offloading, or to make it fit), we can get rid of the original
	 * mblk_t at his point (mp) since we'll be keeping the new mblk_t
	 * (mblk) around until we cleanup in the tx callback.
	 */
	if (pkt.vtx_mp != mp)
		freemsg(mp);

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
vmxnet3_ring_tx(void *mrh, mblk_t *mps)
{
	vmxnet3_txqueue_t	*txq = mrh;
	vmxnet3_softc_t		*dp = txq->sc;
	Vmxnet3_TxQueueCtrl	*txqCtrl = txq->sharedCtrl;
	mblk_t			*mp = mps;

	membar_consumer();
	VERIFY(txq->started);

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

		mp = vmxnet3_tx_one(dp, txq, mp);
		if (mp != NULL)
			break;

		mp = mps;
	}

	/* Notify the device */
	mutex_enter(&txq->txLock);
	if (txqCtrl->txNumDeferred >= txqCtrl->txThreshold) {
		vmxnet3_cmdring_t	*cmdRing = &txq->cmdRing;
		uint_t			idx = vmxnet3_tqidx(txq);

		txqCtrl->txNumDeferred = 0;
		VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_TXPROD(idx),
		    cmdRing->next2fill);
	}
	mutex_exit(&txq->txLock);

	if (mp != NULL)
		mp->b_next = mps;

	return (mp);
}

mblk_t *
vmxnet3_tx(void *arg, mblk_t *mps)
{
	vmxnet3_softc_t *dp = arg;
	vmxnet3_txqueue_t *txq = &dp->txQueue[0];

	ASSERT3U(dp->txNQueue, ==, 1);
	return (vmxnet3_ring_tx(txq, mps));
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

	compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
	while (compDesc->tcd.gen == compRing->gen) {
		vmxnet3_metatx_t	*meta;
		uint16_t		idx;

		idx = compDesc->tcd.txdIdx;

		meta = txq->metaRing[idx];
		txq->metaRing[idx] = NULL;

		freemsg(meta->vmtx_mp);

		while (meta != NULL) {
			vmxnet3_metatx_t *next = meta->vmtx_next;

			cmdRing->avail += meta_ncookies(meta);
			vmxnet3_metatx_free(txq, meta);
			meta = next;
		}

		completedTx = B_TRUE;

		VMXNET3_INC_RING_IDX(compRing, compRing->next2comp);
		compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
	}

	/*
	 * As noted in vmxnet3_tx_prepare_pkt(), because the TX ring appears
	 * to freeze when all of the descriptors in the ring are used, if
	 * we've asserted flow control to MAC, we only resume TX once the
	 * number of free descriptors exceeds what is necessary to send the
	 * next packet to ensure there's always at least one free descriptor.
	 */
	if (txq->txMustResched && completedTx &&
	    cmdRing->avail > txq->txDescNeeded) {
		txq->txMustResched = B_FALSE;
		txq->txDescNeeded = 0;
		ret = B_TRUE;
	}

	mutex_exit(&txq->txLock);

	return (ret);
}

static int
vmxnet3_tx_kstat_update(kstat_t *ksp, int rw)
{
	vmxnet3_txqueue_t	*txq = ksp->ks_private;
	vmxnet3_tx_kstats_t	*txs = ksp->ks_data;
	UPT1_TxStats		*txStats;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	mutex_enter(&txq->sc->genLock);
	vmxnet3_get_stats(txq->sc);
	mutex_exit(&txq->sc->genLock);

	txStats = &vmxnet3_tqdesc(txq)->stats;

	mutex_enter(&txq->txLock);

	txs->tx_pullup_needed.value.ui64 = txq->tx_pullup_needed;
	txs->tx_pullup_failed.value.ui64 = txq->tx_pullup_failed;
	txs->tx_ring_full.value.ui64 = txq->tx_ring_full;
	txs->tx_nobuf.value.ui64 = txq->tx_nobuf;
	txs->tx_copy_frags.value.ui64 = txq->tx_copy_frags;
	txs->tx_bind_frags.value.ui64 = txq->tx_bind_frags;
	txs->tx_nonlso_bytes.value.ui64 = txq->tx_nonlso_bytes;
	txs->tx_nonlso_pkts.value.ui64 = txq->tx_nonlso_pkts;

	txs->tx_hw_lso_pkts.value.ui64 = txStats->TSOPktsTxOK;
	txs->tx_hw_lso_bytes.value.ui64 = txStats->TSOBytesTxOK;
	txs->tx_hw_ucast_pkts.value.ui64 = txStats->ucastPktsTxOK;
	txs->tx_hw_ucast_bytes.value.ui64 = txStats->ucastBytesTxOK;
	txs->tx_hw_mcast_pkts.value.ui64 = txStats->mcastPktsTxOK;
	txs->tx_hw_mcast_bytes.value.ui64 = txStats->mcastBytesTxOK;
	txs->tx_hw_bcast_pkts.value.ui64 = txStats->bcastPktsTxOK;
	txs->tx_hw_bcast_bytes.value.ui64 = txStats->bcastBytesTxOK;
	txs->tx_hw_tx_error.value.ui64 = txStats->pktsTxError;
	txs->tx_hw_tx_discard.value.ui64 = txStats->pktsTxDiscard;

	mutex_exit(&txq->txLock);
	return (0);
}

int
vmxnet3_tx_kstat_init(vmxnet3_softc_t *dp, vmxnet3_txqueue_t *txq)
{
	vmxnet3_tx_kstats_t	*txs;
	char			buf[32];
	uint_t			txq_num = vmxnet3_tqidx(txq);

	(void) snprintf(buf, sizeof (buf), "tx_ring%u", txq_num);

	txq->txRingStats = kstat_create(VMXNET3_MODNAME, dp->instance, buf,
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (vmxnet3_tx_kstats_t) / sizeof (kstat_named_t), 0);
	if (txq->txRingStats == NULL)
		return (DDI_FAILURE);

	txq->txRingStats->ks_update = vmxnet3_tx_kstat_update;
	txq->txRingStats->ks_private = txq;

	txs = txq->txRingStats->ks_data;
	kstat_named_init(&txs->tx_pullup_needed, "pullup_needed",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_pullup_failed, "pullup_failed",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_ring_full, "ring_full", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_nobuf, "no_buf", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_copy_frags, "copy_frags", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_bind_frags, "bind_frags", KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_nonlso_bytes, "nonlso_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_nonlso_pkts, "nonlso_pkts",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&txs->tx_hw_lso_pkts, "lso_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_lso_bytes, "lso_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_tx_error, "tx_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_tx_discard, "tx_discard",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_ucast_pkts, "ucast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_ucast_bytes, "ucast_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_mcast_pkts, "mcast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_mcast_bytes, "mcast_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_bcast_pkts, "bcast_pkts",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&txs->tx_hw_bcast_bytes, "bcast_bytes",
	    KSTAT_DATA_UINT64);

	kstat_install(txq->txRingStats);
	return (DDI_SUCCESS);
}

int
vmxnet3_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *valp)
{
	vmxnet3_txqueue_t	*txq = (vmxnet3_txqueue_t *)rh;
	vmxnet3_softc_t		*dp = txq->sc;
	UPT1_TxStats		*txStats;

	txStats = &vmxnet3_tqdesc(txq)->stats;

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


static int
vmxnet3_metatx_ctor(void *el, void *arg)
{
	vmxnet3_metatx_t	*meta = el;
	vmxnet3_softc_t		*dp = arg;
	int			ret;

	ret = ddi_dma_alloc_handle(dp->dip, &vmxnet3_dma_attrs_tx,
	    DDI_DMA_SLEEP, NULL, &meta->vmtx_bind_hdl);
	if (ret != DDI_SUCCESS) {
		VMXNET3_WARN(dp, "ddi_dma_alloc_handle() failed: %d", ret);
		return (-1);
	}

	meta->vmtx_state = VMS_FREE;
	return (0);
}

static void
vmxnet3_metatx_reset(void *el, void *arg)
{
	vmxnet3_metatx_t	*m = el;
	vmxnet3_softc_t		*dp = arg;

	if (m->vmtx_mp != NULL)
		freemsg(m->vmtx_mp);
	m->vmtx_mp = NULL;

	m->vmtx_buflen = 0;
	m->vmtx_next = NULL;

	switch (m->vmtx_state) {
	case VMS_FREE:
		dev_err(dp->dip, CE_PANIC, "metatx double free\n");
		break;
	case VMS_ALLOC:
		break;
	case VMS_COPY:
		VERIFY3P(m->vmtx_dmabuf, !=, NULL);
		vmxnet3_bufcache_free(dp->bufCache, m->vmtx_dmabuf);
		m->vmtx_dmabuf = NULL;
		break;
	case VMS_BIND:
		VERIFY0(ddi_dma_unbind_handle(m->vmtx_bind_hdl));
		break;
	}

	m->vmtx_state = VMS_FREE;
}

static void
vmxnet3_metatx_dtor(void *el, void *arg __unused)
{
	vmxnet3_metatx_t *meta = el;

	if (meta == NULL)
		return;

	VERIFY3S(meta->vmtx_state, ==, VMS_FREE);
	ddi_dma_free_handle(&meta->vmtx_bind_hdl);
}

int
vmxnet3_metatx_cache_init(vmxnet3_softc_t *dp)
{
	size_t nent;

	nent = dp->txNQueue * dp->txRingSize;

	dp->metaTxCache = vmxnet3_bufcache_init(nent, sizeof (vmxnet3_metatx_t),
	    vmxnet3_metatx_ctor, vmxnet3_metatx_reset, vmxnet3_metatx_dtor,
	    dp, dp->intrPri);
	if (dp->metaTxCache == NULL)
		return (ENOMEM);

	return (0);
}
