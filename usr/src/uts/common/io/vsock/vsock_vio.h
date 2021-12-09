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
 * Copyright 2021 Joyent, Inc.
 * Copyright 2021 Jason King
 */

#ifndef _VSOCK_VIO_H
#define	_VSOCK_VIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>
#include "virtio.h"

/*
 * VIRTIO VSOCK CONFIGURATION REGISTERS
 *
 * These are offsets into the device-specific configuration space available
 * through the virtio_dev_*() family of functions.
 */
#define	VIRTO_VSOCK_CONFIG_CID	0x00	/* 16 R */

/*
 * VIRTIO VSOCK VIRTQUEUES
 */
#define	VIRTIO_VSOCK_VIRTQ_RX		0
#define	VIRTIO_VSOCK_VIRTQ_TX		1
#define	VIRTIO_VSOCK_VIRTQ_EVENT	2

typedef struct virtio_vsock_hdr {
	uint64_t	vvh_src_cid;
	uint64_t	vvh_dst_cid;
	uint32_t	vvh_src_port;
	uint32_t	vvh_dst_port;
	uint32_t	vvh_len;
	uint16_t	vvh_type;
	uint16_t	vvh_op;
	uint32_t	vvh_flags;
	uint32_t	vvh_buf_alloc;
	uint32_t	vvh_fwd_cnt;
} virtio_vsock_hdr_t __packed;

#define	VIRTIO_VSOCK_TYPE_STREAM	1

#define	VIRTIO_VSOCK_OP_INVALID		0
#define	VIRTIO_VSOCK_OP_REQUEST		1
#define	VIRTIO_VSOCK_OP_RESPONSE	2
#define	VIRTIO_VSOCK_OP_RST		3
#define	VIRTIO_VSOCK_OP_SHUTDOWN	4
#define	VIRTIO_VSOCK_OP_RW		5
#define	VIRTIO_VSOCK_OP_CREDIT_UPDATE	6
#define	VIRTIO_VSOCK_OP_CREDIT_REQUEST	7

typedef struct virtio_vsock_event {
	vve_id;
} virtio_vsock_event_t __packed;

#define	VIRTIO_VSOCK_EVENT_TRANSPORT_RESET	0

typedef struct vsock_vio_dev vsock_vio_dev_t;

typedef struct vsock_vio_evbuf {
	vsock_vio_dev_t	*ev_viodev;

	virtio_dma_t	*ev_dma;
	virtio_chain_t	*ev_chain;

	list_node_t	ev_link;
} vsock_vio_evbuf_t;

struct vsock_vio_dev {
	dev_info_t	*vsd_dip;
	virtio_t	*vsd_virtio;

	kmutex_t	vsd_mutex;

	virtio_queue_t	*vsd_rx_vq;
	virtio_queue_t	*vsd_tx_vq;
	virtio_queue_t	*vsd_event_vq;

	list_t		vsd_evbufs;
	uint_t		vsd_nevbufs_alloc;
	uint_t		vsd_evbufs_capacity;

	uint64_t	vsd_cid;

	ddi_taskq_t	*vsd_taskq;
};


#ifdef __cplusplus
}
#endif

#endif /* _VSOCK_H */
