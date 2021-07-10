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

#ifndef _MRS_SAS_RAID_H
#define	_MRS_SAS_RAID_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mrs_raidctx {
	uint8_t		mrsrc_ntype;
	uint8_t		mrsrc_reserved0;
	uint16_t	mrsrc_timeout;
	uint8_t		mrsrc_reg_lock_flags;
	uint8_t		mrsrc_reserved1;
	uint16_t	mrsrc_virt_disk_tgtid;
	uint64_t	mrsrc_reg_lock_rowlba;
	uint32_t	mrsrc_reg_lock_len;
	uint16_t	mrsrc_next_lmid;
	uint8_t		mrsrc_exstatus;
	uint8_t		mrsrc_status;
	uint8_t		mrsrc_raid_flags;
	uint8_t		mrsrc_num_sge;
	uint16_t	mrsrc_cfg_seqnum;
	uint8_t		mrsrc_span_arm;
	uint8_t		mrsrc_pri;
	uint8_t		mrsrc_num_sge_ext;
	uint8_t		mrsrc_reserved2;
} mrs_raidctx_t;
#define	MRS_RC_NTYPE(_type, _nseg) (((_nseg) & 0xf) << 4 | ((_type) & 0xf))

typedef struct mrs_raidctx_g35 {
	uint16_t	mrsrcg35_ntype;		/* MRS_RC_NTYPE() */
	uint16_t	mrsrcg35_timeout;
	uint16_t	mrsrcg35_routing_flags;
	uint16_t	mrsrcg35_virt_disk_tgtid;
	uint64_t	mrsrcg35_reg_lock_rowlba;
	uint32_t	mrsrcg35_reg_lock_len;
	union {
		uint16_t	mrsrcg35_next_lmid;
		uint16_t	mrsrcg35_peer_smid;
	} mrsrcg36_smidu;
	uint8_t		mrsrcg35_exstatus;
	uint8_t		mrsrcg35_status;
	uint8_t		mrsrcg35_raid_flags;
	uint8_t		mrsrcg35_span_arm;
	uint16_t	mrsrcg35_cfg_seqnum;
	uint16_t	mrsrcg35_nsge_stream;
	uint8_t		mrsrc635_reserved[2];
} mrs_raidctx_g35_t;

/* mrsrcg35_routing_flag bits */
					/* Bit 0 reserved */
#define	MRS_RCG35_RF_SLD		((uint16_t)1 << 1)
#define	MRS_RCG35_RF_C2F		((uint16_t)1 << 2)
#define	MRS_RCG35_RF_FWN		((uint16_t)1 << 3)
#define	MRS_RCG35_RF_SQN		((uint16_t)1 << 4)
#define	MRS_RCG35_RF_SBS		((uint16_t)1 << 5)
#define	MRS_RCG35_RF_RW			((uint16_t)1 << 6)
#define	MRS_RCG35_RF_LOG		((uint16_t)1 << 7)
#define	MRS_RCG35_RF_CPUSEL(x)		(((uint16_t)(x) & 0x7) << 8)
#define	MRS_RCG35_RF_SETDIVERT(x)	(((uint16_t)(x) & 0x7) << 12)

#define	MRS_RCG35_SET_STREAM_DETECTED(_rc) \
	((_rc)->mrsrcg35_nsge_stream |= (uint16_t)1 << 15)
#define	MRS_RCG35_SET_NUM_SGE(_rc, _n) \
	((_rc)->mrsrcg35_nsge_stream |= (uint16_t)(_n) & 0xFFFF)

typedef union MRS_RAIDCTX_U {
	mrs_raidctx_t		mrs_rc;
	mrs_raidctxg35_t	mrs_rcg35;
} mrs_raidctx_u_t;

/* mrsrc{,g35}_raid_flags values */
typedef enum mrs_rf_io_subtype {
	MRSRF_IO_SUB_TYPE_NONE = 0,
	MRSRF_IO_SUB_TYPE_SYSTEM_PD = 1,
	MRSRF_IO_SUB_TYPE_RMW_DATA = 2,
	MRSRF_IO_SUB_TYPE_RMW_P = 3,
	MRSRF_IO_SUB_TYPE_RMW_Q = 4,
	MRSRF_IO_SUB_TYPE_CACHE_BYPASS = 6,
	MRSRC_IO_SUB_TYPE_LDIO_BW_LIMIT = 7,
} mrs_rf_io_subtype_t;

#define	MRSR_MAX_SPAN_DEPTH		8
#define	MRSR_MAX_QUAD_DEPTH		MRSR_SPAN_DEPTH
#define	MRSR_MAX_ROW_SIZE		32
#define	MRSR_MAX_LOGICAL_DRIVES		64
#define	MRSR_LOGICAL_DRIVES_EXT		256
#define	MRSR_LOGICAL_DRIVES_DYN		512
#define	MRSR_MAX_ARRAYS			128
#define	MRSR_ARRAYS_EXT			256
#define	MRSR_MAX_API_ARRAYS_EXT		(MAX_ARRAYS_EXT)
#define	MRSR_MAX_API_ARRAYS_DYN		512
#define	MRSR_MAX_PHYSICAL_DEVICES	256

#define	MRSR_RAIDMAP_SPAN_DEPTH		(MRSR_MAX_SPAN_DEPTH)
#define	MRSR_RAIDMAP_MAX_ROW_SIZE	(MRSR_MAX_ROW_SIZE)
#define	MRSR_RAIDMAP_LOGICAL_DRIVES	(MRSR_MAX_LOGICAL_DRIVES)
#define	MRSR_RAIDMAP_VIEWS		(MRSR_MAX_LOGICAL_DRIVES)
#define	MRSR_RAIDMAP_ARRAYS		(MRSR_MAX_ARRAYS)
#define	MRSR_RAIDMAP_MAX_PHYSICAL_DEVICES (MRSR_MAX_PHYSICAL_DEVICES)
#define	MRSR_RAIDMAP_MAX_PHYSICAL_DEVICES_DYN 512

typedef struct mrs_dev_handle_info __packed {
	uint16_t	mrsdhi_cur_devhdl;
	uint8_t		mrsdhi_valid_handles;
	uint8_t		mrsdhi_iftype;
	uint16_t	mrsdhi_devhdl[2];
} mrs_dev_handle_info_t;

typedef struct mrs_array_info {
	uint16_t	mrsai_pd[MRSR_RAIDMAP_MAX_ROW_SIZE];
} mrs_array_info_t;

typedef struct mrs_quad_element {
	uint64_t	mrsqe_logstart;
	uint64_t	mrsqe_logend;
	uint64_t	mrsqe_offset_in_span;
	uint32_t	mrsqe_diff;
	uint32_t	mrsqe_reserved;
} mrs_quad_element_t;

typedef struct mrs_span_info {
	uint32_t		mrssi_nelem;
	uint32_t		mrssi_reserved;
	mrs_quad_element_t	mrssi_quad[MRSR_RAIDMAP_SPAN_DEPTH];
} mrs_span_info_t;

typedef struct mrs_ld_span {
	uint64_t	mrsls_start_blk;
	uint64_t	mrsls_nblk;
	uint16_t	mrsls_arrayref;
	uint8_t		mrsls_span_rowsz;
	uint8_t		mrsls_span_row_datasz;
	uint8_t		mrsls_reserved[4];
} mrs_ld_span_t;

#ifdef __cplusplus
}
#endif

#endif /* _MRS_SAS_RAID_H */
