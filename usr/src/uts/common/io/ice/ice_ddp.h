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
 * Copyright 2026 RackTop Systems, Inc.
 */

#ifndef _ICE_DDP_H
#define	_ICE_DDP_H

#include "ice.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The version of the DDP package file itself. Note that segments can have
 * their own individual format versions, all of which itself is idependent from
 * the version of the package file itself.
 */
#define	ICE_PKG_FMT_VERSION_MAJ		0x01
#define	ICE_PKG_FMT_VERSION_MIN		0x00
#define	ICE_PKG_FMT_VERSION_UPDATE	0x00
#define	ICE_PKG_FMT_VERSION_DRAFT	0x00

/*
 * Section 7.11 of the E810 datasheet holds most of the details of the
 * DDP format, however some of the details appear to only be available
 * via inspection of the FreeBSD driver (specifically
 * src/dev/ice/ice_ddp_common.[ch]).
 */
#define	ICE_SIGN_TYPE_RSA2K		0x00000001
#define	ICE_SIGN_TYPE_RSA3K		0x00000002
#define	ICE_SIGN_TYPE_RSA3K_E825	0x00000005
#define	ICE_SIGN_TYPE_RSA3K_SBB		0x00000003

#define	ICE_PKG_NAME	"ice.pkg"

/*
 * An index entry for a segment in the DDP file. Note that in the segment
 * header in the DDP file, the offset and length include the segment header
 * while the indexed version does not. That is, isi_offset points to the
 * start of the segment contents (after the segment header) and isi_length
 * is the length of the segment excluding the header.
 */
typedef struct ice_seg_idx {
	uint32_t	isi_offset;
	uint32_t	isi_length;
	uint32_t	isi_type;
	ice_pkg_ver_t	isi_version;
} ice_seg_idx_t;
CTASSERT(sizeof (ice_seg_idx_t) == 16);

/*
 * Section 7.11.5 of the E810 datasheet documents the format of the
 * package file, the definitions come from there.
 */
typedef struct ice_pkg_hdr {
	ice_pkg_ver_t	iph_version;
	uint32_t	iph_seg_count;
} ice_pkg_hdr_t;
CTASSERT(sizeof (ice_pkg_hdr_t) == 8);

typedef struct ice_pkg_seg_hdr {
	uint32_t	ipsh_type;
	ice_pkg_ver_t	ipsh_version;
	uint32_t	ipsh_size;
	char		ipsh_name[32];
} ice_pkg_seg_hdr_t;
CTASSERT(sizeof (ice_pkg_seg_hdr_t) == 44);

#define	ICE_PKG_SEG_GLOBAL_METADATA	0x0001
#define	ICE_PKG_SEG_NOTES		0x0002
#define	ICE_PKG_SEG_CFG_DATA_E810	0x0010
#define	ICE_PKG_SEG_CFG_DATA_E830	0x0017
#define	ICE_PKG_SEG_SIGNING		0x1001

typedef struct ice_pkg_global_metadata {
	ice_pkg_ver_t	ipgm_version;
	uint8_t		ipgm_reserved[4];
	char		ipgm_name[32];
} ice_pkg_global_metadata_t;
CTASSERT(sizeof (ice_pkg_global_metadata_t) == 40);

typedef struct ice_pkg_sign_hdr {
	uint32_t	ipsh_id;
	uint32_t	ipsh_type;
	uint32_t	ipsh_signed_idx;
	uint32_t	ipsh_sbuf_start;
	uint32_t	ipsh_sbuf_count;
	uint32_t	ipsh_flags;
	uint8_t		ipsh_reserved[40];
} ice_pkg_sign_hdr_t;
CTASSERT(sizeof (ice_pkg_sign_hdr_t) == 64);
#define	ICE_PKG_SIGN_FLAG_VALID		0x80000000
#define	ICE_PKG_SIGN_FLAG_LAST		0x00000001

/*
 * The contents of the signing and config segments contains a number of headers
 * followed by a 4 byte buffer count and then `count` fixed sized buffers
 * of 4096 bytes. The name is unfortunately generic but we're matching
 * what's in 7.11.5 of the datasheet.
 */
#define	ICE_PKG_BUF_LEN			4096
typedef struct ice_pkg_buf_hdr {
	uint16_t	ipbh_size;
	uint16_t	ipbh_data_end;
} ice_pkg_buf_hdr_t;
CTASSERT(sizeof (ice_pkg_buf_hdr_t) == 4);

typedef struct ice_pkg_sect {
	uint32_t	ips_type;
	uint16_t	ips_offset;
	uint16_t	ips_size;
} ice_pkg_sect_t;
CTASSERT(sizeof (ice_pkg_sect_t) == 8);
#define	ICE_PKG_SECT_METADATA	0x80000000

typedef enum ice_block {
	ICE_BLK_SW = 0,
	ICE_BLK_ACL,
	ICE_BLK_FD,
	ICE_BLK_RSS,
	ICE_BLK_PE,
	ICE_BLK_COUNT
} ice_block_t;

typedef enum ice_sect {
	ICE_XLT0 = 0,
	ICE_XLT_KB,
	ICE_XLT1,
	ICE_XLT2,
	ICE_PROF_TCAM,
	ICE_PROF_REDIR,
	ICE_VEC_TBL,
	ICE_CDID_KB,
	ICE_CDID_REDIR,
	ICE_SECT_COUNT
} ice_sect_t;

#ifdef __cplusplus
}
#endif

#endif /* _ICE_DDP_H */
