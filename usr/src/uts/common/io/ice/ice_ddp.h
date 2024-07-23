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


typedef struct ice_pkg_ver {
	uint8_t	ipv_major;
	uint8_t ipv_minor;
	uint8_t ipv_update;
	uint8_t ipv_draft;
} ice_pkg_ver_t;
CTASSERT(sizeof (ice_pkg_ver_t) == 4);

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

/*
 * Response format for the GET PKG INFO LIST admin queue command (0x0C43).
 * The device reports every DDP package it currently knows about (including
 * the one built into NVM, flagged via ipi_is_in_nvm) so that the driver can
 * verify the OS package it is about to download is compatible with it.
 */
#define	ICE_SEG_NAME_SIZE	28

typedef struct ice_pkg_info {
	ice_pkg_ver_t	ipi_version;
	char		ipi_name[ICE_SEG_NAME_SIZE];
	uint32_t	ipi_track_id;
	uint8_t		ipi_is_in_nvm;
	uint8_t		ipi_is_active;
	uint8_t		ipi_is_active_at_boot;
	uint8_t		ipi_is_modified;
} ice_pkg_info_t;
CTASSERT(sizeof (ice_pkg_info_t) == 40);

typedef struct ice_pkg_info_resp {
	uint32_t	ipir_count;
	ice_pkg_info_t	ipir_info[];
} ice_pkg_info_resp_t;

/*
 * The GET PKG INFO LIST command always returns a fixed size 4096 byte
 * buffer (see ICE_CQ_GET_PKG_INFO_BUF_SZ), so bound the number of entries
 * we will ever look at to however many can fit within it.
 */
#define	ICE_PKG_INFO_MAX_ENTRIES \
	((ICE_CQ_GET_PKG_INFO_BUF_SZ - sizeof (uint32_t)) / \
	sizeof (ice_pkg_info_t))

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

/*
 * Limits for buffers built by us (as opposed to those supplied to us in the
 * DDP package) when constructing an update package command -- see section
 * 7.11.5 of the E810 datasheet and the FreeBSD driver's
 * ice_pkg_buf_reserve_section()/ice_pkg_buf_alloc_section().
 */
#define	ICE_MAX_S_COUNT		511
#define	ICE_MAX_S_DATA_END	ICE_PKG_BUF_LEN

/* ice package section IDs */
#define	ICE_SID_METADATA		1
#define	ICE_SID_XLT0_SW			10
#define	ICE_SID_XLT_KEY_BUILDER_SW	11
#define	ICE_SID_XLT1_SW			12
#define	ICE_SID_XLT2_SW			13
#define	ICE_SID_PROFID_TCAM_SW		14
#define	ICE_SID_PROFID_REDIR_SW		15
#define	ICE_SID_FLD_VEC_SW		16
#define	ICE_SID_CDID_KEY_BUILDER_SW	17
#define	ICE_SID_CDID_REDIR_SW		18

#define	ICE_SID_XLT0_ACL		20
#define	ICE_SID_XLT_KEY_BUILDER_ACL	21
#define	ICE_SID_XLT1_ACL		22
#define	ICE_SID_XLT2_ACL		23
#define	ICE_SID_PROFID_TCAM_ACL		24
#define	ICE_SID_PROFID_REDIR_ACL	25
#define	ICE_SID_FLD_VEC_ACL		26
#define	ICE_SID_CDID_KEY_BUILDER_ACL	27
#define	ICE_SID_CDID_REDIR_ACL		28

#define	ICE_SID_XLT0_FD			30
#define	ICE_SID_XLT_KEY_BUILDER_FD	31
#define	ICE_SID_XLT1_FD			32
#define	ICE_SID_XLT2_FD			33
#define	ICE_SID_PROFID_TCAM_FD		34
#define	ICE_SID_PROFID_REDIR_FD		35
#define	ICE_SID_FLD_VEC_FD		36
#define	ICE_SID_CDID_KEY_BUILDER_FD	37
#define	ICE_SID_CDID_REDIR_FD		38

#define	ICE_SID_XLT0_RSS		40
#define	ICE_SID_XLT_KEY_BUILDER_RSS	41
#define	ICE_SID_XLT1_RSS		42
#define	ICE_SID_XLT2_RSS		43
#define	ICE_SID_PROFID_TCAM_RSS		44
#define	ICE_SID_PROFID_REDIR_RSS	45
#define	ICE_SID_FLD_VEC_RSS		46
#define	ICE_SID_CDID_KEY_BUILDER_RSS	47
#define	ICE_SID_CDID_REDIR_RSS		48

#define	ICE_SID_RXPARSER_CAM		50
#define	ICE_SID_RXPARSER_NOMATCH_CAM	51
#define	ICE_SID_RXPARSER_IMEM		52
#define	ICE_SID_RXPARSER_XLT0_BUILDER	53
#define	ICE_SID_RXPARSER_NODE_PTYPE	54
#define	ICE_SID_RXPARSER_MARKER_PTYPE	55
#define	ICE_SID_RXPARSER_BOOST_TCAM	56
#define	ICE_SID_RXPARSER_PROTO_GRP	57
#define	ICE_SID_RXPARSER_METADATA_INIT	58
#define	ICE_SID_RXPARSER_XLT0		59

#define	ICE_SID_TXPARSER_CAM		60
#define	ICE_SID_TXPARSER_NOMATCH_CAM	61
#define	ICE_SID_TXPARSER_IMEM		62
#define	ICE_SID_TXPARSER_XLT0_BUILDER	63
#define	ICE_SID_TXPARSER_NODE_PTYPE	64
#define	ICE_SID_TXPARSER_MARKER_PTYPE	65
#define	ICE_SID_TXPARSER_BOOST_TCAM	66
#define	ICE_SID_TXPARSER_PROTO_GRP	67
#define	ICE_SID_TXPARSER_METADATA_INIT	68
#define	ICE_SID_TXPARSER_XLT0		69

#define	ICE_SID_RXPARSER_INIT_REDIR	70
#define	ICE_SID_TXPARSER_INIT_REDIR	71
#define	ICE_SID_RXPARSER_MARKER_GRP	72
#define	ICE_SID_TXPARSER_MARKER_GRP	73
#define	ICE_SID_RXPARSER_LAST_PROTO	74
#define	ICE_SID_TXPARSER_LAST_PROTO	75
#define	ICE_SID_RXPARSER_PG_SPILL	76
#define	ICE_SID_TXPARSER_PG_SPILL	77
#define	ICE_SID_RXPARSER_NOMATCH_SPILL	78
#define	ICE_SID_TXPARSER_NOMATCH_SPILL	79

#define	ICE_SID_XLT0_PE			80
#define	ICE_SID_XLT_KEY_BUILDER_PE	81
#define	ICE_SID_XLT1_PE			82
#define	ICE_SID_XLT2_PE			83
#define	ICE_SID_PROFID_TCAM_PE		84
#define	ICE_SID_PROFID_REDIR_PE		85
#define	ICE_SID_FLD_VEC_PE		86
#define	ICE_SID_CDID_KEY_BUILDER_PE	87
#define	ICE_SID_CDID_REDIR_PE		88

#define	ICE_SID_RXPARSER_FLAG_REDIR	97

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
