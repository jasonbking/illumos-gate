/*
 * Copyright (c) 2015, AVAGO Tech. All rights reserved. Author: Marian Choy
 * Copyright (c) 2014, LSI Corp. All rights reserved. Author: Marian Choy
 * Copyright 2021 Racktop Systems, Inc.
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
 */

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/dditypes.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>

#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include "mrs_sas.h"
#include "mrs_sas_reg.h"

#define	INST2LSIRDCTL(x)	((x) << INST_MINOR_SHIFT)

void *mrs_sas_state;

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

static struct ddi_device_acc_attr mrs_sas_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC,
};

static void mrs_sas_get_class(mrs_sas_t *);
static int mrs_sas_regs_init(mrs_sas_t *);
static int mrs_sas_intr_init(mrs_sas_t *);
static void mrs_sas_intr_fini(mrs_sas_t *);
static void mrs_sas_cleanup(mrs_sas_t *, boolean_t);
static void mrs_sas_fm_init(mrs_sas_t *);
static void mrs_sas_fm_fini(mrs_sas_t *);

static uint_t mrs_sas_isr(caddr_t, caddr_t arg2);

static int
mrs_sas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	mrs_sas_t *mrs;
	uint32_t instance;
	int nregs;
	uint16_t command;

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (mrs_sas_iport_attach(dip, cmd));

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(mrs_sas_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not allocate soft state");
		return (DDI_FAILURE);
	}

	if ((mrs = ddi_get_soft_state(mrs_sas_state, instance)) == NULL) {
		dev_err(dip, CE_WARN, "could not get soft state");
		ddi_soft_state_free(mrs_sas_state, instance);
		return (DDI_FAILURE);
	}

	mrs->mrs_dip = dip;
	mrs->mrs_instance = instance;
	mrs->mrs_hba_dma_attr = mrs_sas_dma_attr;
	mrs->mrs_hba_acc_attr = mrs_sas_acc_attr;
	INITLEVEL_SET(mrs, MRS_INITLEVEL_BASIC);

	/* Tunables */
	mrs->mrs_io_timeout = MRS_SAS_IO_TIMEOUT;
	mrs->mrs_fw_fault_check_delay = 1;
	mrs->mrs_reset_count = 0;
	mrs->mrs_reset_in_progress = 0;
	mrs->mrs_block_sync_cache = 0;
	mrs->mrs_drv_stream_detection = 1;

	if (pci_config_setup(dip, &mrs->mrs_pci_handle) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "pci config setup failed");
		goto fail;
	}
	INITLEVEL_SET(mrs, MRS_INITLEVEL_PCI_CONFIG);

	mrs_sas_get_class(mrs);

	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to get registers");
		goto fail;
	}

	/* Enable bus mastering if not already set */
	command = pci_config_get16(mrs->mrs_pci_handle, PCI_CONF_COMM);
	if ((command & PCI_COMM_ME) == 0) {
		pci_config_put16(mrs->mrs_pci_handle, PCI_CONF_COMM,
		    command | PCI_COMM_ME);
	}

	mrs_sas_fm_init(mrs);
	INITLEVEL_SET(mrs, MRS_INITLEVEL_FM);

	if (mrs_sas_regs_init(mrs) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(mrs, MRS_INITLEVEL_REGS);

	if (mrs_sas_intr_init(mrs) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(mrs, MRS_INITLEVEL_INTR);

	mutex_init(&mrs->mrs_mpt_cmd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mrs->mrs_intr_pri));
	list_create(&mrs->mrs_mpt_cmd_list, sizeof (mrs_sas_mpt_cmd_t),
	    offsetof(mrs_sas_mpt_cmd_t, mptc_node));

	mutex_init(&mrs->mrs_mfi_cmd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mrs->mrs_intr_pri));
	list_create(&mrs->mrs_mfi_cmd_list, sizeof (mrs_sas_mfi_cmd_t),
	    offsetof(mrs_sas_mfi_cmd_t, mfic_node));

	mutex_init(&mrs->mrs_ioctl_count_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mrs->mrs_intr_pri));
	cv_init(&mrs->mrs_ioctl_count_cv, NULL, CV_DRIVER, NULL);

	INITLEVEL_SET(mrs, MRS_INITLEVEL_SYNC);

	if (mrs_sas_hba_attach(mrs) != DDI_SUCCESS)
		goto fail;

	(void) snprintf(mrs->mrs_iocname, "%d:lsirdctl", instance);
	if (ddi_create_minor_node(dip, mrs->mrs_iocname, S_IFCHR,
	    INST2LSIRDCTL(instance), DDI_PSEUDO, 0) != DDI_SUCCESS) {
		dev_err(cip, CE_WARN, "failed to create ioctl node.");
		goto fail;
	}
	INITLEVEL_SET(mrs, MRS_INITLEVEL_NODE);

	mrs->mrs_taskq = ddi_taskq_create(dip, "mrs_sas_taskq", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (mrs->mrs_taskq == NULL) {
		dev_err(dip, CE_WARN, "failed to create taskq.");
		goto fail;
	}
	INITLEVEL_SET(mrs, MRS_INITLEVEL_TASKQ);

	mrs_sas_enable_intr(mrs);

	if (mrs_sas_start_mfi_aen(mrs) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to initiate AEN.");
		goto fail;
	}
	INITLEVEL_SET(mrs, MRS_INITLEVEL_AEN);

	ddi_report_dev(dip);

	if (mrs_sas_check_acc_handle(mrs->mrs_reghandle) != DDI_SUCCESS)
		goto fail;
	if (mrs_sas_check_acc_handle(mrs->mrs_pci_handle) != DDI_SUCCESS)
		goto fail;

	return (DDI_SUCCESS);

fail:
	mrs_sas_fm_ereport(mrs, DDI_FM_DEVICE_NO_RESPONSE);
	ddi_fm_service_impact(mrs->mrs_dip, DDI_SERVICE_LOST);
	mrs_sas_cleanup(mrs, B_TRUE);
	return (DDI_FAILURE);
}

static int
mrs_sas_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	mrs_sas_t *mrs;
	int instance;

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (mrs_sas_iport_detach(dip, cmd));

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	mrs = ddi_get_soft_state(mrs_sas_state, instance);
	if (mrs == NULL) {
		dev_err(dip, CE_WARN,
		    "could not get instance %d data in detach", instance);
		return (DDI_FAILURE);
	}

	mrs_sas_cleanup(mrs, B_FALSE);
	return (DDI_SUCCESS);
}

static void
mrs_sas_cleanup(mrs_sas_t *mrs, boolean_t failed)
{
	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_TASKQ)) {
		ddi_taskq_destroy(mrs->mrs_taskq);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_TASKQ);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_NODE)) {
		ddi_remove_minor_node(mrs->mrs_dip, mrs->mrs_iocname);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_NODE);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_HBA)) {
		mrs_sas_hba_detach(mrs);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_HBA);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_SYNC)) {
		cv_destroy(&mrs->mrs_ioctl_count_cv);
		mutex_destroy(&mrs->mrs_ioctl_count_lock);

		list_destory(&mrs->mrs_mfi_cmd_list);
		mutex_destroy(&mrs->mrs_mfi_cmd_lock);

		mutex_destroy(&mrs->mrs_mpt_cmd_lock);
		list_destroy(&mrs->mrs_mpt_cmd_list);

		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_SYNC);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_INTR)) {
		mrs_sas_intr_fini(mrs);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_REGS);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_REGS)) {
		ddi_regs_map_free(&mrs->mrs_reghandle);
		mrs->mrs_regmap = NULL;
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_REGS);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_FM)) {
		mrs_sas_fm_fini(mrs);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_FM);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_PCI_CONFIG)) {
		pci_config_teardown(&mrs->mrs_pci_handle);
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_PCI_CONFIG);
	}

	if (INITLEVEL_ACTIVE(mrs, MRS_INITLEVEL_BASIC))
		INITLEVEL_CLEAR(mrs, MRS_INITLEVEL_BASIC);

	VERIFY0(mrs->mrs_init_level);
	ddi_soft_state_free(mrs_sas_state, ddi_get_instance(mrs->mrs_dip));
}

static int
mrs_sas_regs_init(mrs_sas_t *mrs)
{
	uint_t regno;
	off_t regsize;

	switch (mrs->mrs_class) {
	case MRS_ACLASS_VENTURA:
	case MRS_ACLASS_AERO:
		regno = 1;
		break;
	default:
		regno = 2;
		break;
	}

	if (ddi_dev_regsize(mrs->mrs_dip, regno, &regsize) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (regsize < MRS_SAS_MFI_MIN_MEM) {
		dev_err(mrs->mrs_dip, CE_WARN, "reg %d size (%ld) is too small",
		    regno, regsize);
		return (DDI_FAILURE);
	}

	if (regsize > MRS_SAS_MFI_DEF_MEM) {
		dev_err(mrs->mrs_dip, CE_CONT,
		    "?reg %d map is %ld bytes, only mapping %d bytes\n",
		    regno, regsize, MRS_SAS_MFI_DEF_MEM);
		regsize = MRS_SAS_MFI_DEF_MEM;
	}

	if (ddi_regs_map_setup(mrs->mrs_dip, regno, &mrs->mrs_regmap, 0,
	    regsize, &mrs->mrs_hba_acc_attr, &mrs->mrs_reghandle)
	    != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "unable to map control registers");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
mrs_sas_add_intrs(mrs_sas_t *mrs, int intr_type)
{
	int avail, actual, count;
	int flag, i;

	if (ddi_intr_get_nintrs(mrs->mrs_dip, intr_type,
	    &count) != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN, "failed to get interrupt count");
		return (DDI_FAILURE);
	}
	if (count == 0) {
		/* XXX: Better error msg? */
		dev_err(mrs->mrs_dip, CE_WARN, "zero interrupts exist");
		return (DDI_FAILURE);
	}

	if (ddi_intr_get_navail(mrs->mrs_dip, intr_type,
	    &avail) != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "failed to get available interrupts");
		return (DDI_FAILURE);
	}
	if (avail == 0) {
		dev_err(mrs->mrs_dip, CE_WARN, "zero interrupts available");
		return (DDI_FAILURE);
	}

	if ((intr_type == DDI_INTR_TYPE_MSI) && (count > 1))
		count = 1;

	mrs->mrs_intr_htable_size = count * sizeof (ddi_intr_handle_t);
	mrs->mrs_intr_htable = kmem_zalloc(mrs->mrs_intr_htable_size, KM_SLEEP);

	flag = ((intr_type == DDI_INTR_TYPE_MSI) ||
	    (intr_type == DDI_INTR_TYPE_MSIX)) ?
	    DDI_INTR_ALLOC_STRICT : DDI_INTR_ALLOC_NORMAL;

	if (ddi_intr_alloc(mrs->mrs_dip, mrs->mrs_intr_htable, intr_type, 0,
	    count, &actual, flag) != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN, "failed to allocate interrupts");
		goto free_htable;
	}
	if (actual == 0) {
		/*
		 * It seems like it might be useful to distinguish between
		 * ddi_intr_alloc() failing, and returning 0 w/ success, so
		 * we use separate errors messages for each condition.
		 */
		dev_err(mrs->mrs_dip, CE_WARN, "allocated zero interrupts");
		goto free_htable;
	}

	if (actual < count) {
		dev_err(mrs->mrs_dip, CE_CONT,
		    "?requested %d interrupts, received %d\n", count, actual);
	}
	mrs->mrs_intr_count = actual;

	if (ddi_intr_get_pri(mrs->mrs_intr_htable[0],
	    &mrs->mrs_intr_pri) != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_CONT,
		    "failed to get interrupt priority");
		goto free_handles;
	}
	if (mrs->mrs_intr_pri >= ddi_intr_get_hilevel_pri()) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "high level interrupts not supported");
		goto free_handles;
	}

	for (i = 0; i < actual; i++) {
		if (ddi_intr_add_handler(mrs->mrs_intr_htable[i], mrs_sas_isr,
		    (caddr_t)mrs, (caddr_t)(uintptr_t)i) != DDI_SUCCESS) {
			dev_err(mrs->mrs_dip, CE_WARN,
				    "failed to add interrupt handler");
			goto free_handlers;
		}
	}

	if (ddi_intr_get_cap(mrs->mrs_intr_htable[0],
	    &mrs->mrs_intr_cap) != DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "failed to get interrupt capabilities");
		goto free_handlers;
	}

	if ((mrs->mrs_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
		(void) ddi_intr_block_enable(mrs->mrs_intr_htable,
		    mrs->mrs_intr_count);
	} else {
		for (i = 0; i < mrs->mrs_intr_count; i++)
			(void) ddi_intr_enable(mrs->mrs_intr_htable[i]);
	}

	return (DDI_SUCCESS);

free_handlers:
	/* i will be the # of interrupts that were enabled before failing */
	while (--i > 0)
		(void) ddi_intr_remove_handler(mrs->mrs_intr_htable[i]);

free_handles:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(mrs->mrs_intr_htable[i]);

free_htable:
	if (mrs->mrs_intr_htable != NULL)
		kmem_free(mrs->mrs_intr_htable, mrs->mrs_intr_htable_size);

	mrs->mrs_intr_htable = NULL;
	mrs->mrs_intr_htable_size = 0;

	return (DDI_FAILURE);
}

static uint_t
mrs_sas_isr(caddr_t arg1, caddr_t arg2 __unused)
{
	mrs_sas_t *mrs = (mrs_sas_t *)arg1;
	uint_t ret = DDI_INTR_UNCLAIMED;

	if (mrs->mrs_intr_type == DDI_INTR_TYPE_FIXED) {
		ret = mrs_sas_intr_ack(mrs);
		if (ret != DDI_INTR_CLAIMED)
			return (ret);
	}

	ret = mrs_sas_process_cmd(mrs);
	return (DDI_INTR_UNCLAIMED);
}

static int
mrs_sas_intr_init(mrs_sas_t *mrs)
{
	char *data;
	int intr_types = 0;
	boolean_t msi_enable = B_TRUE;

	mrs_sas_disable_intr(mrs);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, mrs->mrs_dip, 0,
	    "mrs-sas-enable-msi", &data) == DDI_SUCCESS) {
		if (strcmp(data, "no") == 0) {
			msi_enable = B_FALSE;
			dev_err(mrs->mrs_dip, CE_CONT, "?msi disabled\n");
		}
		ddi_prop_free(data);
	}

#if 0
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, mrs->mrs_dip, 0,
	    "mrs-sas-enable-fp", &data) == DDI_SUCCESS) {
		if (strcmp(data, "no") == 0) {
			enable_fp = B_FALSE;
			dev_err(mrs->mrs_dip, CE_CONT, "?fp disabled\n");
		}
		ddi_prop_free(data);
	}
#endif

	if (ddi_intr_get_supported_types(mrs->mrs_dip,
	    &intr_types) != DDI_SUCCESS	) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "ddi_intr_get_supported_types() failed");
		return (DDI_FAILURE);
	}

	if (msi_enable &&
	    (intr_types & DDI_INTR_TYPE_MSIX) == DDI_INTR_TYPE_MSIX) {
		if (mrs_sas_add_intrs(mrs, DDI_INTR_TYPE_MSIX) != DDI_SUCCESS) {
			dev_err(mrs->mrs_dip, CE_WARN,
			    "MSIX interrupt query failed");
			return (DDI_FAILURE);
		}
		mrs->mrs_intr_type = DDI_INTR_TYPE_MSIX;
		return (DDI_SUCCESS);
	}

	if (msi_enable &&
	    (intr_types & DDI_INTR_TYPE_MSI) == DDI_INTR_TYPE_MSI) {
		if (mrs_sas_add_intrs(mrs, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) {
			dev_err(mrs->mrs_dip, CE_WARN,
			    "MSI interrupt query failed");
			return (DDI_FAILURE);
		}
		mrs->mrs_intr_type = DDI_INTR_TYPE_MSI;
		return (DDI_SUCCESS);
	}

	if ((intr_types & DDI_INTR_TYPE_FIXED) == DDI_INTR_TYPE_FIXED) {
		if (mrs_sas_add_intrs(mrs,
		    DDI_INTR_TYPE_FIXED) != DDI_SUCCESS) {
			dev_err(mrs->mrs_dip, CE_WARN,
				"Fixed interrupt query failed");
			return (DDI_FAILURE);
		}
		mrs->mrs_intr_type = DDI_INTR_TYPE_FIXED;
		return (DDI_SUCCESS);
	}

	dev_err(mrs->mrs_dip, CE_WARN,
	    "Device does not have any compatible interrupts");
	return (DDI_FAILURE);
}

static void
mrs_sas_intr_fini(mrs_sas_t *mrs)
{
	uint_t i;

	if ((mrs->mrs_mrs_intr_cap & DDIR_INTR_FLAG_BLOCK) != 0) {
		(void) ddi_intr_block_disable(mrs->mrs_intr_htable,
		    mrs->mrs_intr_count);
	} else {
		for (i = 0; i < mrs->mrs_intr_count; i++)
			(void) ddi_intr_disable(mrs->mrs_intr_htable[i]);
	}

	for (i = 0; i < mrs->mrs_intr_count; i++) {
		(void) ddi_intr_remove_handler(mrs->mrs_intr_htable[i]);
		(void) ddi_intr_free(mrs->mrs_intr_htable[i]);
	}

	if (mrs->mrs_intr_htable != NULL)
		kmem_free(mrs->mrs_intr_htable, mrs->mrs_intr_htable_size);

	mrs->mrs_intr_htable = NULL;
	mrs->mrs_intr_htable_size = 0;
}

static int
mrs_sas_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err_status,
    const void *arg)
{
	pci_ereport_post(dip, err_status, NULL);
	return (err_status->fme_status);
}

static void
mrs_sas_fm_init(mrs_sas_t *mrs)
{
	ddi_iblock_cookie_t fm_ibc;

	mrs->mrs_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    mrs->mrs_dip, DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	if (mrs->mrs_fm_capabilities == 0)
		return;

	mrs->mrs_hba_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
	mrs->mrs_hba_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;

	ddi_fm_init(mrs->mrs_dip, &mrs->mrs_fm_capabilities, &fm_ibc);

	if (DDI_FM_EREPORT_CAP(mrs->mrs_fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(mrs->mrs_fm_capabilities)) {
		pci_ereport_setup(mrs->mrs_dip);
	}

	if (DDI_FM_ERRCB_CAP(mrs->mrs_fm_capabilities)) {
		ddi_fm_handler_register(mrs->mrs_dip, mrs_sas_fm_error_cb,
		    mrs);
	}
}

static void
mrs_sas_fm_fini(mrs_sas_t *mrs)
{
	if (mrs->mrs_fm_capabilities == 0)
		return;

	if (DDI_FM_ERRCB_CAP(mrs->mrs_fm_capabilities))
		ddi_fm_handler_unregister(mrs->mrs_dip);

	if (DDI_FM_EREPORT_CAP(mrs->mrs_fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(mrs->mrs_fm_capabilities)) {
		pci_ereport_teardown(mrs->mrs_dip);
	}

	ddi_fm_fini(mrs->mrs_dip);
}

void
mrs_sas_fm_ereport(mrs_sas_t *mrs, const char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, sizeof (buf), "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(mrs->mrs_fm_capabilities)) {
		ddi_fm_ereport_post(mrs->mrs_dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERSION, NULL);
	}
}

int
mrs_sas_check_acc_handle(ddi_acc_handle_t h)
{
	ddi_fm_error_t de;

	if (h == NULL)
		return (DDI_FAILURE);

	ddi_fm_acc_err_get(h, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

int
mrs_sas_check_dma_handle(ddi_dma_handle_t h)
{
	ddi_fm_error_t de;

	if (h == NULL)
		return (DDI_FAILURE);

	ddi_fm_dma_err_get(h, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

static int
mrs_sas_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	mrs_sas_t *mrs;
	mrs_sas_ioctl_t *ioc;
	mrs_sas_aen_t	aen;
	int inst = MINOR2INST(getminor(dev));
	int ret;

	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	mrs = ddi_get_soft_state(mrs_sas_state, inst);
	if (mrs == NULL)
		return (ENXIO);

	switch ((uint_t) cmd) {
	case MRS_SAS_IOCTL_FIRMWARE:
		ioc = kmem_zalloc(sizeof (*ioc), KM_SLEEP);
		if (ddi_copyin((void *)arg, ioc, sizeof (*ioc), mode) != 0) {
			kmem_free(ioc, sizeof (*ioc);
			return (EFAULT);
		}

		if (ioc->mrsioc_control_code == MRS_SAS_DRIVER_IOCTL_COMMON)
			ret = mrs_sas_drv_ioctl(mrs, ioc, mode);
		else
			ret = mrs_sas_mfi_ioct(mrs, ioc, mode);

		if (ddi_copyout(ioc, (void *)arg, sizeof (*ioc) - 1,
		    mode) != 0) {
			ret = 1;
		}

		kmem_free(ioc, sizeof (*ioc));
		break;
	case MRS_SAS_IOCTL_AEN:
		if (ddi_copyin((void *)arg, &aen, sizeof (aen), mode) != 0)
			return (EFAULT);

		ret = mrs_sas_mfi_aen_ioctl(mrs, &aen);

		if (ddi_copyout(&aen, (void *)arg, sizeof (aen), mode) != 0)
			ret = 1;
		break;
	default:
		ret = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rval);
		break;
	}

	return (ret);
}

static int
mrs_sas_alloc_dma(mrs_sas_t *mrs)
{

}

struct mpt_iter {
	uint8_t	*mi_ptr;
	uint64_t mi_phys;
	uint64_t mi_incr;
}

static void
mpt_iter_init(struct mpt_iter *i, mpt_dma_t *dmap , uint64_t incr)
{
	const dma_cookie_t *c = ddi_dma_cookie_one(dmap->mrsd_hdl);

	i->mi_ptr = dmap->mrsd_buf;
	i->mi_phys = c->dmac_laddr;
	i->mi_incr = incr;
}

static void
mpt_iter(struct mpt_iter *i, void *addrp, uint64_t *physp)
{
	uint8_t **ap = addrp;

	*ap = i->mi_ptr;
	*physp = i->mi_phys;

	i->mi_ptr += i->mi_incr;
	i->mi_phys += i->mi_phys;
}

static int
mrs_sas_alloc_mpt(mrs_sas_t *mrs, const uint32_t ncmd)
{
	mrs_mpt_cmd_t **cmds;
	mrs_mpt_cmd_t *cmd;
	size_t ioreq_len, chain_len, reply_len, sense_len;
	int ret;

	ioreq_len = XXX;
	chain_len = XXX;
	reply_len = XXX;
	sense_len = XXX;

	ret = mrs_sas_alloc_mpt_item(mrs, &mrs->mrs_ioreq_dma, ioreq_len, 256);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = mrs_sas_alloc_mpt_item(mrs, &mrs->mrs_chain_dma, chain_len, 4);
	if (ret != DDI_SUCCESS) {
		mrs_sas_dma_free(&mrs->mrs_ioreq_dma);
		return (ret);
	}

	ret = mrs_sas_alloc_mpt_item(mrs, &mrs->mrs_reply_dma, reply_len, 16);
	if (ret != DDI_SUCCESS) {
		mrs_sas_dma_free(&mrs->mrs_chain_dma);
		mrs_sas_dma_free(&mrs->mrs_ioreq_dma);
		return (ret);
	}

	ret = mrs_sas_alloc_mpt_item(mrs, &mrs->mrs_sense_dma, sense_len, 64);
	if (ret != DDI_SUCCESS) {
		mrs_sas_dma_free(&mrs->mrs_reply_dma);
		mrs_sas_dma_free(&mrs->mrs_chain_dma);
		mrs_sas_dma_free(&mrs->mrs_ioreq_dma);
		return (ret);
	}

	struct mpt_iter req_i;
	struct mpt_iter sgl_i;
	struct mpt_iter sense_i;
	uint32_t i;

	mpt_iter_init(&req_i, &mrs->mrs_ioreq_dma, MRSAS_MPI2_RAID_DEFAULT_IO_FRAME_SIZE);
	mpt_iter_init(&sgl_i, &mrs->mrs_chain_dma, mrs->mrs_max_chain_frame_sz);
	mpt_iter_init(&sense_i, &mrs->mrs_sense_dma, MRSAS_SENSE_LEN);

	cmds = kmem_zalloc(ncmd * sizeof (mrs_mpt_cmd_t *), KM_SLEEP);
	for (i = 0; i < ncmd; i++) {
		cmd = kmem_zalloc(sizeof (mrs_mpt_cmd_t), KM_SLEEP);
		cmd->mptc_index = i;

		mpt_iter(&req_i, &cmd->mptc_req, &cmd->mptc_req_phys);
		mpt_iter(&sgl_i, &cmd->mptc_sgl, &cmd->mptc_sql_phys);
		mpt_iter(&sense_i, &cmd->mptc_sense, &cmd->mptc_sense_phys);

		cmds[i] = cmd;
		list_insert_tail(&mrs->mrs_mpt_cmd_list, cmd);
	}


	mrs->mrs_mpt_cmds = cmds;
	return (DDI_SUCCESS);
}

static int
mrs_sas_alloc_mpt_item(rms_sas_t *mrs, mrs_sas_dma_t *dmap, size_t len,
    uint64_t align)
{
	ddi_dma_attr_t attr = {
		.dma_attr_version = DMA_ATTR_V0,
		.dma_attr_addr_lo = 0,
		.dma_attr_addr_hi = UINT32_MAX,
		.dma_attr_count_max = UINT32_MAX,
		.dma_attr_align = align,
		.dma_attr_burstsizes = 0x7,
		.dma_attr_minxfer = 1,
		.dma_attr_maxxfer = UINT32_MAX,
		.dma_attr_seg = UINT32_MAX,
		.dma_attr_sgllen = 1,
		.dma_attr_granular = 512,
		.dma_attr_flags = mrs->mrs_hba_dma_attr.dma_attr_flags,
	};
	return (mrs_sas_dma_alloc(mrs, &attr, &mrs->mrs_hba_acc_attr, len,
	    dmap);
}

static int
mrs_sas_alloc_mfi(mrs_sas_t *mrs, const uint32_t ncmd)
{
	mrs_mpt_cmd_t **cmds;
	mrs_sas_mfi_cmd_t *cmd;
	size_t len = ncmd * sizeof (mrs_sas_mfi_cmd_t *);
	uint32_t i;
	int ret = DDI_SUCCESS;
	ddi_dma_attr_t dma_attr = {
		.dma_attr_version = DMA_ATTR_V0,
		.dma_attr_addr_lo = 0,
		.dma_attr_addr_hi = UINT32_MAX,
		.dma_attr_count_max = UINT32_MAX,
		.dma_attr_align = 64,
		.dma_attr_burstsizes = 0x7,
		.dma_attr_minxfer = 1,
		.dma_attr_maxxfer = UINT32_MAX,
		.dma_attr_seg = UINT32_MAX,
		.dma_attr_sgllen = 1,
		.dma_attr_granular = 512,
		.dma_attr_flags = mrs->mrs_hba_dma_attr.dma_attr_flags,
	};
		
	cmds = kmem_zalloc(len, KM_SLEEP);
	for (i = 0; i < ncmd; i++) {
		cmd = kmem_zalloc(sizeof (mrs_sas_mfi_cmd_t), KM_SLEEP);
		ret = mrs_sas_dma_alloc(mrs, &dma_attr, &mrs->mrs_hba_acc_attr,
		    sizeof (*cmd->mfic_frame), &cmd->mfic_dma);
		if (ret != DDI_SUCCESS) {
			kmem_free(cmd, sizeof (mrs_sas_mfi_cmd_t);
			goto fail;
		}

		cmd->mfic_frame = cmd->cmd_mfic_dma.mrsd_buf;
		cmd->mfic_frame->mrsf_io.mrsiof_context = i;
		cmd->mfic_idx = i;
		cmds[i] = cmd;
	}

	for (i = 0; i < ncmd; i++)
		list_insert_tail(&mrs->mrs_sas_mfi_cmd_list, cmd[i]);

	mrs->mrs_mpt_cmds = cmds;
	return (DDI_SUCCESS);

fail:
	/* i should be the index of the failed entry */
	while (i-- > 0) {
		cmd = mrs->mrs_mfi_cmds[i];
		mrs_sas_dma_free(&cmd->mfic_dma);
		kmem_free(cmd, sizeof (*cmd));
	}

	kmem_free(cmds, len);
	return (DDI_FAILURE);
}

int
mrs_sas_dma_alloc(mrs_sas_t *mrs, ddi_dma_attr_t *dma_attr,
    ddi_device_acc_attr_t *acc_attr, size_t len, mrs_sas_dma_t *dmap)
{
	int ret;

	ret = ddi_dma_alloc_handle(mrs->mrs_dip, dma_attr, DDI_DMA_SLEEP,
	    NULL, &dmap->mrsd_hdl);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = ddi_dma_mem_alloc(dmap->mrsd_hdl, len, acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &dmap->mrsd_buf, &dmap->mrsd_len, &dmap->mrsd_acc);
	if (ret != DDI_SUCCESS) {
		ddi_dma_free_handle(&dmap->mrsd_hdl);
		return (ret);
	}

	ret = ddi_dma_addr_bind_handle(dmap->mrsd_hdl, NULL, dmap->mrsd_buf,
	    dmap->mrsd_len, DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dmap->mrsd_cookie, NULL);
	if (ret != DDI_SUCCESS) {
		ddi_dma_mem_free(&dmap->mrsd_acc);
		ddi_dma_free_handle(&dmap->mrsd_hdl);
		return (ret);
	}

	if (mrsas_check_dma_handle(dmap->mrsd_hdl) != DDI_SUCCESS ||
	    mrsas_check_acc_handle(dmap->mrsd_acc) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(dmap->mrsd_hdl);
		ddi_dma_mem_free(&dmap->mrsd_acc);
		ddi_dma_free_handle(&dmap->mrsd_hdl);
		return (DDI_FAILURE);
	}

	bzero(dmap->mrsd_buf, dmap->mrsd_len);
	return (DDI_SUCCESS);
}

void
mrs_sas_dma_free(mrs_dma_t *dmap)
{
	(void) ddi_dma_unbind_handle(dmap->mrsd_hdl);
	ddi_dma_mem_free(dmap->mrsd_acc);
	ddi_dma_free_handle(&dmap->mrsd_hdl);
}

static void
mrs_sas_get_class(mrs_sas_t *mrs)
{
	uint16_t devid;

	devid = pci_config_get16(mrs->mrs_pci_handle, PCI_CONF_DEVID);
	switch (devid) {
	case MRS_SAS_INVADER:
	case MRS_SAS_FURY:
	case MRS_SAS_INTRUDER:
	case MRS_SAS_INTRUDER_24:
	case MRS_SAS_CUTLASS_52:
	case MRS_SAS_CUTLASS_53:
		mrs->mrs_class = MRS_ACLASS_GEN3;
		break;
	case MRS_SAS_VENTURA:
	case MRS_SAS_CRUSADER:
	case MRS_SAS_HARPOON:
	case MRS_SAS_VENTURA_4PORT:
	case MRS_SAS_CRUSADER_4PORT:
		mrs->mrs_class = MRS_ACLASS_VENTURA;
		break;
	case MRS_SAS_AERO_10E1:
	case MRS_SAS_AERO_10E2:
	case MRS_SAS_AERO_10E5:
	case MRS_SAS_AERO_10E6:
		mrs->mrs_class = MRS_ACLASS_AERO;
		break;
	case MRS_SAS_AERO_10E0:
	case MRS_SAS_AERO_10E3:
	case MRS_SAS_AERO_10E4:
	case MRS_SAS_AERO_10E7:
		mrs->mrs_class = MRS_ACLASS_OTHER;
		break;
	}

	switch (devid) {
	case MRS_SAS_AERO_10E1:
	case MRS_SAS_AERO_10E5:
		dev_err(mrs->mrs_dip, CE_CONT,
		    "?Adapter is in configurable secure mode\n");
		break;
	case MRS_SAS_AERO_10E0:
	case MRS_SAS_AERO_10E3:
	case MRS_SAS_AERO_10E4:
	case MRS_SAS_AERO_10E7:
		dev_err(mrs->mrs_dip, CE_CONT,
		    "?Adapter is in non-secure mode\n");
		break;
	}
}

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
