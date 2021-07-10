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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>

#include "mrs_sas.h"
#include "mrs_sas_reg.h"

boolean_t mrs_sas_relaxed_ordering = B_TRUE;

int
mrs_sas_iport_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

int
mrs_sas_iport_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static int
mrs_sas_getcap(struct scsi_address *sa, char *cap, int whom)
{
	struct scsi_device *sd;
	mrs_sas_target_t *mrst;
	mrs_sas_t *mrs;
	int index;

	VERIFY((sd = scsi_address_device(sa)) != NULL);
	VERIFY((mrst = scsi_device_hba_private_get(sd)) != NULL);
	VERIFY((mrs = mrst->mrst_mrs) != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE)
		return (-1);

	switch (index) {
	case SCSI_CAP_DMA_MAX:
		/* TODO */
		break;
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QUING:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_RESET_NOTIFICATION:
		return (1);
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_LINKED_CMDS:
		return (0);
	case SCSI_CAP_INITIATOR_ID:
		/* TODO */
		break;
	default:
		return (-1);
	}
}

static int
mrs_sas_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int index;

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE)
		return (-1);

	if (whom == 0)
		return (-1);

	switch (index) {
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_TOTAL_SECTORS:
		return (1);
	default:
		return (-1);
	}
}

static int
mrs_sas_no_tran_tgt_init(dev_into_t *hba_dip, dev_into_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	return (DDI_FAILURE);
}

static int
mrs_sas_no_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	return (TRAN_BADPKT);
}

int
mrs_sas_hba_attach(mrs_sas_t *mrs)
{
	scsi_hba_tran_t	*tran;
	ddi_dma_attr_t tran_attr = mrs->mrs_hba_dma_attr;

	tran = scsi_hba_tran_alloc(mrs->mrs_dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL) {
		dev_err(mrs->mrs_dip, CE_WARN, "scsi_hba_tran_alloc failed");
		return (DDI_FAILURE);
	}

	mrs->mrs_hba_tran = tran;
	tran->tran_hba_private = mrs;

	tran->tran_tgt_init = mrs_sas_no_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = mrs_sas_no_tran_start;

	tran->tran_getcap = mrs_sas_getcap;
	tran->tran_setcap = mrs_sas_setcap;

	tran->tran_setup_pkt = mrs_sas_tran_setup_pkt;
	tran->tran_teardown_pkt = mrs_sas_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (mrs_sas_cmd_scsa_t);
	tran->tran_interconnect_type = INTERCONNECT_SAS;

	if (mrs_sas_relaxed_ordering)
		tran_attr.dma_attr_flags |= DDI_DMA_RELAXED_ORDERING;
	tran_attr.dma_attr_sgllen = mrs->mrs_max_num_seg;

	if (scsi_hba_attach_setup(mrs->mrs_dip, &tran_attr, tran,
	    SCSI_HBA_HBA | SCSI_HBA_ADDR_COMPLEX | SCSI_HBA_TRAN_SCB) !=
	    DDI_SUCCESS) {
		dev_err(mrs->mrs_dip, CE_WARN,
		    "could not attach to SCSA framework");
		mrs->mrs_tran = NULL;
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
mrs_sas_hba_detach(mrs_sas_t *mrs)
{
	return (DDI_SUCCESS);
}
