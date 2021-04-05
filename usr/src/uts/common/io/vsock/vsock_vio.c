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
 */

/*
 * AF_VSOCK VIRTIO TRANSPORT 
 */

#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/modctl.h>
#include <sys/strsun.h>

#include "virtio.h"
#include "vsock.h"

/* There are currently no feature flags defined for vsock devices */
#define	VIRTIO_VSOCK_WANTED_FEATURES	0

static int vsock_vio_attach(dev_info_t *, ddi_attach_cmd_t);
static int vsock_vio_detach(dev_info_t *, ddi_detach_cmd_t);
static int vsock_vio_quiesce(dev_info_t *);

static struct cb_ops vsock_vio_cb_ops = {
	.cb_rev			CB_REV,
	.cb_flags =		D_MP | D_NEW,

	.cb_open =		nulldev,
	.cb_close =		nulldev,
	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		nodev,
	.cb_devmap = 		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev,
};

statuc struct dev_ops vsock_vio_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt = 		0,

	.devo_attach =		vsock_vio_attach,
	.devo_detach =		vsock_vio_detach,
	.devo_quiesce =		vsock_vio_quiesce,

	.devo_cb_ops =		&vsock_vio_cb_ops,

	.devo_getinfo =		NULL,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset = 		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
};

static struct modldrv vsock_vio_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"AF_VSOCK VIRTIO transport driver",
	.drv_dev_ops =		&vsock_vio_dev_ops,
};

static struct modlinkage vsock_vio_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &vsock_vio_modldrv, NULL }
};

static uint_t
vsock_vio_rx_handler(caddr_t arg0, caddr_t arg1)
{
	return (DDI_INTR_CLAIMED);
}

static uint_t
vsock_vio_tx_handler(caddr_t arg0, caddr_t arg1)
{
	return (DDI_INTR_CLAIMED);
}

static uint_t
vsock_vio_event_handler(caddr_t arg0, caddr_t arg1)
{
	return (DDI_INTR_CLAINED);
}

static int
vsock_vio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	vsock_dev_t *vsd;
	virtio_t *vio;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if ((vio = virtio_init(dip, VIRTIO_VSOCK_WANTED_FEATURES, B_TRUE)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	vsd = kmem_zalloc(sizeof (*vs_vio), KM_SLEEP);
	vsd->vsd_dip = dip;
	vsd->vsd_vio = vio;
	ddi_set_driver_private(dip, vsd);

	if ((vsd->vsd_rx_vq = virtio_queue_alloc(vio, VIRTIO_VSOCK_VIRTQ_RX,
	    "rx", vsock_vio_rx_handler, vsd, B_FALSE, VSOCK_VIO_MAX_SEGS)) ==
	    NULL ||
	    (vsd->vsd_tx_vq = virtio_queue_alloc(vio, VIRTIO_VSOCK_VIRTQ_TX,
	    "tx", vsock_vio_tx_handler, vsd, B_FALSE, VSOCK_VIO_MAX_SEGS)) ==
	    NULL ||
	    (vsd->vsd_event_vq = virtio_queue_alloc(vio,
	    VIRTIO_VOSCK_VIRTQ_EVENT, "event", vsock_vio_event_handler, vsd,
	    B_FALSE, VSOCK_VIO_MAX_SEGS)) == NULL)
		goto fail;
	}

	if (virtio_init_complete(vio, vsock_vio_select_interrupt_types()) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete vsock virtio init");
		goto fail;
	}

	virtio_queue_no_interrupt(vsd->vsd_rx_vq, B_TRUE);
	virtio_queue_no_interrupt(vsd->vsd_tx_vq, B_TRUE);
	virtio_queue_no_interrupt(vsd->vsd_event_vq, B_TRUE);

	mutex_init(&vsd->vsd_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	
	mutex_enter(&vsd->vsd_mutex);
	vsd->vsd_cid = virtio_dev_get64(vsd->vsd_virtio,
	    VIRTIO_VSOCK_CONFIG_CID);

	/* XXX: allocate bufs ? */
	mutex_exit(&vsd->vsd_mutex);

	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to enable interrupts");
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	/* XXX: free bufs? */
	(void) virtio_fini(vio, B_TRUE);
	kmem_free(vsd, sizeof (*vsd));
	return (DDI_FAILURE);
}

static int
vsock_vio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	virtio_dev_t *vsd;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if ((vsd = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	mutex_enter(&vsd->vsd_mutex);

	virtio_shutdown(vsd->vsd_virtio);
	for (;;) {
		virtio_chain_t *vic;

		if ((vic = virtio_queue_evacuate(vsd->vsd_rx_vq)) == NULL)
			break;

		/* XXX: ??? *rb = virtio_chain_data(vic);
		 * ?? _free(vsd, rb);
		 */
	}

	/* XXX: free bufs */
	(void) virtio_fini(vsd->vsd_virtio, B_FALSE);

	mutex_exit(&vsd->vsd_mutex);
	mutex_destroy(&vsd->vsd_mutex);

	kmem_free(vsd, sizeof (*vsd));

	return (DDI_SUCCESS);
}

static int
vsock_vio_quiesce(dev_info_t *dip)
{
	virtio_dev_t *vsd;

	if ((vsd = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	return (virtio_quiesce(vsd->vsd_virtio));
}

int
_init(void)
{
	int rc;

	rc = mod_install(&vsock_vio_modlinkage);
	return (rc);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&vsock_vio_modlinkage);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vsock_vio_modlinkage, modinfop));
}
