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
 * Copyright 2021 Racktop Systems, Inc.
 */
#ifndef _MRS_SAS_REG_H
#define	_MRS_SAS_REG_H

#ifdef __cplusplus
extern "C" {
#endif

/* PCI device IDs */
#define	MRS_SAS_CUTLASS_52	0x0052
#define	MRS_SAS_CUTLASS_53	0x0053
#define	MRS_SAS_TBOLT		0x005b
#define	MRS_SAS_INVADER		0x005d
#define	MRS_SAS_FURY		0x005f
#define	MRS_SAS_INTRUDER	0x00ce
#define	MRS_SAS_INTRUDER_24	0x00cf

/* Gen 3.5 Controllers */

#define	MRS_SAS_VENTURA			0x0014
#define	MRS_SAS_CRUSADER		0x0015
#define	MRS_SAS_HARPOON			0x0016
#define	MRS_SAS_TOMCAT			0x0017
#define	MRS_SAS_VENTURA_4PORT		0x001B
#define	MRS_SAS_CRUSADER_4PORT		0x001C
#define	MRS_SAS_AERO_10E0		0x10E0
#define	MRS_SAS_AERO_10E1		0x10E1
#define	MRS_SAS_AERO_10E2		0x10E2
#define	MRS_SAS_AERO_10E3		0x10E3
#define	MRS_SAS_AERO_10E4		0x10E4
#define	MRS_SAS_AERO_10E5		0x10E5
#define	MRS_SAS_AERO_10E6		0x10E6
#define	MRS_SAS_AERO_10E7		0x10E7


#define	MFI_FUSION_ENABLE_INTERRUPT_MASK	0x00000009

#define	MRS_SAS_RESET_WAIT_TIME			180

#define	MFI_STATE_MASK				0xF0000000
#define	MFI_STATE_UNDEFINED			0x00000000
#define	MFI_STATE_BB_INIT			0x10000000
#define	MFI_STATE_FW_INIT			0x40000000
#define	MFI_STATE_WAIT_HANDSHAKE		0x60000000
#define	MFI_STATE_FW_INIT_2			0x70000000
#define	MFI_STATE_DEVICE_SCAN			0x80000000
#define	MFI_STATE_BOOT_MESSAGE_PENDING		0x90000000
#define	MFI_STATE_FLUSH_CACHE			0xA0000000
#define	MFI_STATE_READY				0xB0000000
#define	MFI_STATE_OPERATIONAL			0xC0000000
#define	MFI_STATE_FAULT				0xF0000000
#define	MFI_RESET_REQUIRED			0x00000001
#define	MFI_RESET_ADAPTER			0x00000002

#define	MFI_ADP_RESET				0x00000040
#define	MFI_INIT_ABORT				0x00000001
#define	MFI_INIT_READY				0x00000002
#define	MFI_INIT_MFIMODE			0x00000004
#define	MFI_INIT_CLEAR_HANDSHAKE		0x00000008
#define	MFI_INIT_HOTPLUG			0x00000010
#define	MFI_STOP_ADP				0x00000020
#define	MFI_RESET_FLAGS		(MFI_INIT_READY|MFI_INIT_MFIMODE|MFI_INIT_ABORT)
 

/* Register offsets */
#define	MRS_SAS_DOORBELL		0x0000
#define	MRS_SAS_FUSION_SEQ_OFF		0x0004
#define	MRS_SAS_FUSION_HOST_DIAG	0x0008
/* reserved				0x000C */

#define	MRS_SAS_IB_MSG0			0x0010
#define	MRS_SAS_IB_MSG1			0x0014
#define	MRS_SAS_OB_MSG0			0x0018
#define	MRS_SAS_OB_MSG1			0x001C

#define	MRS_SAS_IB_DOORBELL		0x0020
#define	MRS_SAS_IB_INTR_STATUS		0x0024
#define	MRS_SAS_IB_INTR_MASK		0x0028

#define	MRS_SAS_OB_DOORBELL		0x002C
#define	MRS_SAS_OB_INTR_STATUS		0x0030
#define	MRS_SAS_OB_INTR_MASK		0x0034

#define	MRS_SAS_OB_SCRATCH_PAD		0x00B0
#define	MRS_SAS_OB_SCRATCH_PAD_2	0x00B4
#define	MRS_SAS_OB_SCRATCH_PAD_3	0x00B8
#define	MRS_SAS_OB_SCRATCH_PAD_4	0x00BC

#ifdef __cplusplus
}
#endif

#endif /* _MRS_SAS_REG_H */
