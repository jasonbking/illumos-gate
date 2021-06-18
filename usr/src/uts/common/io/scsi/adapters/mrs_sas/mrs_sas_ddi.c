/*
 * Copyright (c) 2015, AVAGO Tech. All rights reserved. Author: Marian Choy
 * Copyright (c) 2014, LSI Corp. All rights reserved. Author: Marian Choy
 * Support: freebsdraid@avagotech.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of the
 * <ORGANIZATION> nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing
 * official policies,either expressed or implied, of the FreeBSD Project.
 *
 * Send feedback to: <megaraidfbsd@avagotech.com> Mail to: AVAGO TECHNOLOGIES 1621
 * Barber Lane, Milpitas, CA 95035 ATTN: MegaRaid FreeBSD
 *
 */

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/dditypes.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/scsi/scsi.h>

#include "mrs_sas.h"

void *mrs_sas_state;

static int mrs_sas_attach(dev_info_t *, ddi_attach_cmd_t);
static int mrs_sas_detach(dev_info_t *, ddi_detach_cmd_t);
static int mrs_sas_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops mrs_sas_cb_ops = {
	.cb_rev =		CB_REV,
	.cb_flag =		D_NEW | D_MP,

	.cb_open =		scsi_hba_open,
	.cb_close = 		scsi_hba_close,

	.cb_ioctl =		mrs_sas_ioctl,

	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev,
};

static struct dev_ops mrs_sas_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,

	.devo_attach =		mrs_sas_attach,
	.devo_detach =		mrs_sas_detach,

	.devo_cb_ops =		&mrs_sas_cb_ops,

	.devo_getinfo =		ddi_no_info,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset =		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		nodev,
};

static struct modldrv mrs_sas_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"MRS SAS",
	.drv_dev_ops =		&mrs_sas_dev_ops,
};

static struct modlinkage mrs_sas_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &mrs_sas_modldrv, NULL },
};

/*
 * Since the max sgl length can vary, we create a per-instance copy of
 * mrs_sas_dma_attr and fill in .dma_attr_sgllen with the correct value
 * during attach.
 */
ddi_dma_attr_t mrs_sas_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x00000000,
	.dma_attr_addr_hi =		0xFFFFFFFF,
	.dma_attr_count_max =		0xFFFFFFFF,
	.dma_attr_align =		8,
	.dma_attr_burstsizes =		0x7,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	.dma_attr_seg =			0xFFFFFFFF,
	.dma_attr_sgllen =		0,
	.dma_attr_granular =		512,
	.dma_attr_flags =		0,
};

int
_init(void)
{
	int ret;

	VERIFY0(ddi_soft_state_init(&mrs_sas_state, sizeof (mrs_sas_t), 0));

	if ((ret = scsi_hba_init(&mrs_sas_modlinkage)) != 0) {
		goto fail;
	}

	if ((ret = mod_install(&mrs_sas_modlinkage)) != 0) {
		scsi_hba_fini(&mrs_sas_modlinkage);
		goto fail;
	}

	return (ret);

fail:
	ddi_soft_state_fini(&mrs_sas_state);
	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&mrs_sas_modlinkage)) != 0) {
		scsi_hba_fini(&mrs_sas_modlinkage);
		ddi_soft_state_fini(&mrs_sas_state);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mrs_sas_modlinkage, modinfop));
}

static int
mrs_sas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static int
mrs_sas_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static int
mrs_sas_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	return (ENXIO);
}
