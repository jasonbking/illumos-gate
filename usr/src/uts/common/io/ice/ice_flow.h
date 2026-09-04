/*  Copyright (c) 2024, Intel Corporation
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
  *
  *   2. Redistributions in binary form must reproduce the above copyright
  *      notice, this list of conditions and the following disclaimer in the
  *      documentation and/or other materials provided with the distribution.
  *
  *   3. Neither the name of the Intel Corporation nor the names of its
  *      contributors may be used to endorse or promote products derived from
  *      this software without specific prior written permission.
  *
  *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  *  POSSIBILITY OF SUCH DAMAGE.
  */

/* Copyright 2026 RackTop Systems, Inc. */

#ifndef _ICE_FLOW_H
#define	_ICE_FLOW_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This currently contains a subset of the contents of the FreeBSD ice_flow.h
 * basically enough for us to get RSS working.
 */
#define ICE_FLOW_FLD_OFF_INVAL		0xffff

typedef enum ice_rss_cfg_hdr_type {
	ICE_RSS_OUTER_HEADERS, /* take outer headers as inputset. */
	ICE_RSS_INNER_HEADERS, /* take inner headers as inputset. */
	/* take inner headers as inputset for packet with outer IPv4. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV4,
	/* take inner headers as inputset for packet with outer IPv6. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV6,
	/* take outer headers first then inner headers as inputset */
	/* take inner as inputset for GTPoGRE with outer IPv4 + GRE. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV4_GRE,
	/* take inner as inputset for GTPoGRE with outer IPv6 + GRE. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV6_GRE,
	ICE_RSS_ANY_HEADERS
} ice_rss_cfg_hdr_type_t;

typedef struct ice_rss_hash_cfg {
	uint32_t		irhc_headers;
	uint64_t		irhc_fields;
	ice_rss_cfg_hdr_type_t	irhc_hdr_type;
	/*
	 * The symmetric argument is never used and currently must be
	 * false in the FreeBSD driver, so we've omitted here for now
	 * at least.
	 */
} ice_rss_hash_cfg_t;

typedef enum ice_flow_dir {
	ICEE_FLOW_DIR_UNDEFINED	= 0,
 	ICE_FLOW_TX		= 0x01,
 	ICE_FLOW_RX		= 0x02,
 	ICE_FLOW_TX_RX		= ICE_FLOW_RX | ICE_FLOW_TX
 } ice_flow_dir_t;
  
/* Protocol header fields within a packet segment. A segment consists of one or
 * more protocol headers that make up a logical group of protocol headers. Each
 * logical group of protocol headers encapsulates or is encapsulated using/by
 * tunneling or encapsulation protocols for network virtualization such as GRE,
 * VxLAN, etc.
 */
typedef enum ice_flow_seg_hdr {
	ICE_FLOW_SEG_HDR_NONE		= 0x00000000,
	ICE_FLOW_SEG_HDR_ETH		= 0x00000001,
	ICE_FLOW_SEG_HDR_VLAN		= 0x00000002,
	ICE_FLOW_SEG_HDR_IPV4		= 0x00000004,
	ICE_FLOW_SEG_HDR_IPV6		= 0x00000008,
	ICE_FLOW_SEG_HDR_ARP		= 0x00000010,
	ICE_FLOW_SEG_HDR_ICMP		= 0x00000020,
	ICE_FLOW_SEG_HDR_TCP		= 0x00000040,
	ICE_FLOW_SEG_HDR_UDP		= 0x00000080,
	ICE_FLOW_SEG_HDR_SCTP		= 0x00000100,
	ICE_FLOW_SEG_HDR_GRE		= 0x00000200,
	/* The following is an additive bit for ICE_FLOW_SEG_HDR_IPV4 and
	 * ICE_FLOW_SEG_HDR_IPV6.
	 */
	ICE_FLOW_SEG_HDR_IPV_FRAG	= 0x40000000,
	ICE_FLOW_SEG_HDR_IPV_OTHER	= 0x80000000,
} ice_flow_seg_hdr_t;

typedef enum ice_flow_field {
	/* L2 */
	ICE_FLOW_FIELD_IDX_ETH_DA,
	ICE_FLOW_FIELD_IDX_ETH_SA,
	ICE_FLOW_FIELD_IDX_S_VLAN,
	ICE_FLOW_FIELD_IDX_C_VLAN,
	ICE_FLOW_FIELD_IDX_ETH_TYPE,
	/* L3 */
	ICE_FLOW_FIELD_IDX_IPV4_DSCP,
	ICE_FLOW_FIELD_IDX_IPV6_DSCP,
	ICE_FLOW_FIELD_IDX_IPV4_TTL,
	ICE_FLOW_FIELD_IDX_IPV4_PROT,
	ICE_FLOW_FIELD_IDX_IPV6_TTL,
	ICE_FLOW_FIELD_IDX_IPV6_PROT,
	ICE_FLOW_FIELD_IDX_IPV4_SA,
	ICE_FLOW_FIELD_IDX_IPV4_DA,
	ICE_FLOW_FIELD_IDX_IPV6_SA,
	ICE_FLOW_FIELD_IDX_IPV6_DA,
	/* L4 */
	ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
	ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
	ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_SCTP_DST_PORT,
	ICE_FLOW_FIELD_IDX_TCP_FLAGS,
	/* ARP */
	ICE_FLOW_FIELD_IDX_ARP_SIP,
	ICE_FLOW_FIELD_IDX_ARP_DIP,
	ICE_FLOW_FIELD_IDX_ARP_SHA,
	ICE_FLOW_FIELD_IDX_ARP_DHA,
	ICE_FLOW_FIELD_IDX_ARP_OP,
	/* ICMP */
	ICE_FLOW_FIELD_IDX_ICMP_TYPE,
	ICE_FLOW_FIELD_IDX_ICMP_CODE,
	/* GRE */
	ICE_FLOW_FIELD_IDX_GRE_KEYID,
	 /* The total number of enums must not exceed 64 */
	ICE_FLOW_FIELD_IDX_MAX
} ice_flow_field_t;

typedef enum ice_flow_fld_match_type {
	ICE_FLOW_FLD_TYPE_REG,		/* Value, mask */
	ICE_FLOW_FLD_TYPE_RANGE,	/* Value, mask, last (upper bound) */
	ICE_FLOW_FLD_TYPE_PREFIX,	/* IP address, prefix, size of prefix */
	ICE_FLOW_FLD_TYPE_SIZE,		/* Value, mask, size of match */
} ice_flow_fld_match_type_t;

typedef struct ice_flow_fld_loc {
	/*
	 * Describe offsets of field information relative to the beginning of
	 * input buffer provided when adding flow entries.
	 */
	uint16_t iffl_val;	/* Offset where the value is located */
	uint16_t iffl_mask;	/* Offset where the mask/prefix value is located */
	uint16_t iffl_last;	/* Length or offset where the upper value is located */
} ice_flow_fld_loc_t;

#define ICE_FLOW_SEG_SINGLE		1
#define ICE_FLOW_SEG_MAX		2
#define ICE_FLOW_PROFILE_MAX		1024
#define ICE_FLOW_ACL_FIELD_VECTOR_MAX	32
#define ICE_FLOW_FV_EXTRACT_SZ		2

typedef struct ice_flow_seg_xtrct {
	uint8_t		ifsx_prot_id;	/* Protocol ID of extracted header field */
	uint16_t	ifsx_off;	/* Starting offset of the field in header in bytes */
	uint8_t		ifs_idx;	/* Index of FV entry used */
	uint8_t		ifsx_disp;	/* Displacement of field in bits fr. FV entry's start */
} ice_flow_seg_xtrct_t;

typedef struct ice_flow_fld_info {
	ice_flow_fld_match_type_t	iffi_type;
	ice_flow_fld_loc_t		iffi_src;
	ice_flow_fld_loc_t		iffi_entry;
	ice_flow_seg_xtrct_t		iffi_xtrct;
} ice_flow_fld_info_t;

typedef struct ice_flow_seg_info {
	uint32_t		ifsi_headers;
	uint64_t		ifsi_match;
	uint64_t		ifsi_range;
	icE_flow_fld_info_t	ifsi_fields[ICE_FLOW_FIELD_IDX_MAX];
} ice_flow_seg_info_t;

#ifdef __cplusplus
}
#endif

#endif /* _ICE_FLOW_H */
