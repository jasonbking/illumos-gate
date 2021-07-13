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
 * Copyright 2021 Racktop Systems, Inc.
 */


#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>

#include "mrs_sas.h"
#include "mrs_sas_reg.h"

void
mrs_sas_disable_intr(mrs_sas_t *mrs)
{
	uint32_t mask = 0xFFFFFFFF;

	mrs->mrs_mask_interrupts = B_TRUE;

	mrs_sas_write_reg(mrs, MRS_SAS_OB_INTR_MASK, mask);
	/* Dummy read to force pci flush */
	(void) mrs_sas_read_reg(mrs, MRS_SAS_OB_INTR_MASK);
}

void
mrs_sas_enable_intr(mrs_sas_t *mrs)
{
	uint32_t mask = MFI_FUSION_ENABLE_INTERRUPT_MASK;

	mrs->mrs_mask_interrupts = B_FALSE;

	mrs_sas_write_reg(mrs, MRS_SAS_OB_INTR_STATUS, ~0);
	(void) mrs_sas_read_reg(mrs, MRS_SAS_OB_INTR_STATUS);

	mrs_sas_write_reg(mrs, MRS_SAS_OB_INTR_MASK, ~mask);
	(void) mrs_sas_read_reg(mrs, MRS_SAS_OB_INTR_MASK);
}

boolean_t
mrs_sas_clear_intr(mrs_sas_t *mrs)
{
	uint32_t status = mrs_sas_read_reg_retry(mrs, MRS_SAS_OB_INTR_STATUS);

	if ((status & MFI_FUSION_ENABLE_INTERRUPT_MASK) == 0)
		return (B_FALSE);
	return (B_TRUE);
}

uint32_t
mrs_sas_read_reg(mrs_sas_t *mrs, uint32_t reg)
{
	uint32_t *addr = (uint32_t *)((uintptr_t)mrs->mrs_regmap + reg);
	return (ddi_get32(mrs->mrs_reghandle, addr));
}

uint32_t
mrs_sas_read_reg_retry(mrs_sas_t *mrs, uint32_t reg)
{
	if (mrs->mrs_class != MRS_ACLASS_AERO)
		return (mrs_sas_read_reg(mrs, reg));

	for (uint_t i = 0; i < 3; i++) {
		uint32_t val = mrs_sas_read_reg(mrs, reg);

		if (val != 0)
			return (val);
	}

	return (0);
}

void
mrs_sas_write_reg(mrs_sas_t *mrs, uint32_t reg, uint32_t val)
{
	uint32_t *addr = (uint32_t *)((uintptr_t)mrs->mrs_regmap + reg);
	ddi_put32(mrs->mrs_reghandle, addr, val);
}

int
mrs_transition_to_ready(mrs_sas_t *mrs, int ocr)
{
	uint32_t val;
	uint32_t fw_state, cur_state, abs_state, curr_abs_state;
	uint_t i;
	uint8_t max_wait;

	val = mrs_sas_read_reg_retry(mrs, MRS_SAS_OB_SCRATCH_PAD);
	fw_state = val & MFI_STATE_MASK;
	max_wait = MRS_SAS_RESET_WAIT_TIME;

	if (fw_state != MFI_STATE_READY)
		dev_err(mrs->mrs_dip, CE_CONT, "?fw state = %x\n", fw_state);

	while (fw_state != MFI_STATE_READY) {
		switch (fw_state) {
		case MFI_STATE_FAULT:
			dev_err(mrs->mrs_dip, CE_NOTE, "FW is in fault state!");
			if (ocr != 0)
				break;
			return (DDI_FAILURE);
		case MFI_STATE_WAIT_HANDSHAKE:
			mrs_sas_write_reg(mrs, MRS_SAS_DOORBELL,
			    MFI_INIT_CLEAR_HANDSHAKE | MFI_INIT_HOTPLUG);
			break;
		case MFI_STATE_BOOT_MESSAGE_PENDING:
			mrs_sas_write_reg(mrs, MRS_SAS_DOORBELL,
			    MFI_INIT_HOTPLUG);
			break;
		case MFI_STATE_OPERATIONAL:
			mrs_sas_disable_intr(mrs);
			mrs_sas_write_reg(mrs, MRS_SAS_DOORBELL,
			    MFI_RESET_FLAGS);
			for (i = 0; i < max_wait * 1000; i++) {
				if ((mrs_sas_read_reg_retry(mrs,
				    MRS_SAS_DOORBELL) & 1) != 0) {
					delay(drv_usectohz(MILLISEC));
				} else {
					break;
				}
			}
		case MFI_STATE_UNDEFINED:
			/* This state should not last for more than 2 sec */
		case MFI_STATE_BB_INIT:
		case MFI_STATE_FW_INIT:
		case MFI_STATE_FW_INIT_2:
		case MFI_STATE_DEVICE_SCAN:
		case MFI_STATE_FLUSH_CACHE:
			break;
		default:
			dev_err(mrs->mrs_dip, CE_WARN, "Unknown FW state %x",
			    fw_state);	
			return (DDI_FAILURE);
		}
		cur_state = fw_state;

		/*
		 * The current state should not last for more than max_wait
		 * seconds.
		 */
		for (i = 0; i < max_wait * 1000; i++) {
			fw_state = mrs_sas_read_reg_retry(mrs,
			    MRS_SAS_OB_SCRATCH_PAD) & MFI_STATE_MASK;
			curr_abs_state = mrs_sas_read_reg_retry(mrs,
			    MRS_SAS_OB_SCRATCH_PAD);

			if (abs_state == curr_abs_state)
				delay(drv_usectohz(MILLISEC));
			else
				break;
		}

		if (curr_abs_state == abs_state) {
			dev_err(mrs->mrs_dip, CE_WARN,
			    "FW state (%x) hasn't changed in %d seconds",
			    fw_state, max_wait);
			return (DDI_FAILURE);
		}
	}

	if (mrs_sas_check_acc_handle(mrs->mrs_reghandle) != DDI_FM_OK)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

mrs_sas_mpt_cmd_t *
mrs_sas_get_mpt(mrs_sas_t *mrs)
{
	mrs_sas_mpt_cmd_t *cmd;

	mutex_enter(&mrs->mrs_mpt_cmd_lock);
	cmd = list_remove_head(&mrs->mrs_mpt_cmd_list);
	mutex_exit(&mrs->mrs_mpt_cmd_lock);

	if (cmd != NULL) {
		/* cmd->pkt = NULL */
		/* cmd->retry_count_for_ocr = 0 */
		/* cmd->drv_pkt_time = 0 */
	}

	return (cmd);
}

mrs_sas_mfi_cmd_t *
mrs_sas_get_mfi(mrs_sas_t *mrs)
{
	mrs_sas_mfi_cmd_t *cmd;

	mutex_enter(&mrs->mrs_mfi_cmd_lock);
	cmd = list_remove_head(&mrs->mrs_mfi_cmd_list);
	mutex_exit(&mrs->mrs_mfi_cmd_lock);

	if (cmd != NULL) {
		/* cmd->pkt = NULL */
		/* cmd->retry_count_for_ocr = 0 */
		/* cmd->drv_pkt_time = 0 */
	}

	return (cmd);
}

void
mrs_sas_put_mpt(mrs_sas_t *mrs, mrs_sas_mpt_cmd_t *cmd)
{
	mutex_enter(&mrs->mrs_mpt_cmd_lock);
	list_insert_tail(&mrs->mrs_mpt_cmd_list, cmd);
	mutex_exit(&mrs->mrs_mpt_cmd_lock);
}

void
mrs_sas_put_mfi(mrs_sas_t *mrs, mrs_sas_mfi_cmd_t *cmd)
{
	mutex_enter(&mrs->mrs_mfi_cmd_lock);
	list_insert_tail(&mrs->mrs_mfi_cmd-List, cmd);
	mutex_exit(&mrs->mrs_mfi_cmd_lock);
}

void
mrs_sas_alloc_mfi(mrs_sas_t *mrs)
{
	size_t len = MRS_SAS_MFI_MAX_CMD * sizeof (mrs_sas_mfi_cmd_t *);

	mrs->mrs_mfi_cmds = kmem_zalloc(len, KM_SLEEP);
	for (uint32_t i = 0; i < MRS_SAS_MFI_MAX_CMD; i++) {
		mrs_sas_mfi_cmd_t *cmd;

		cmd = kmem_zalloc(sizeof (mrs_sas_mfi_cmd_t), KM_SLEEP);
		cmd->mfic_idx = i;
		mrs->mrs_mfi_cmds[i] = cmd;
		list_insert_tail(&mrs->mrs_sas_mfi_cmd_list, cmd);

		/* TODO DMA */
	}
}

uint_t
mrs_sas_intr_ack(mrs_sas_t *mrs)
{
	uint32_t status;

	status = mrs_sas_read_reg_retry(mrs, MRS_SAS_OB_INTR_STATUS);

	if ((status & MFI_FUCTION_ENABLE_INTERRUPT_MASK) == 0)
		return (DDI_INTR_UNCLAIMED);

	if (mrs_sas_check_acc_handle(mrs->mrs_regmap) != DDI_SUCCESS) {
		ddi_fm_service_impact(mrs->irs_dip, DDI_SERVICE_LOST);
		return (DDI_INTR_UNCLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}
