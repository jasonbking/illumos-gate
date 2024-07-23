/* SPDX-License-Identifier: BSD-3-Clause */
/*
 *  Copyright (c) 2024, Intel Corporation
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

#ifndef _ICE_FLEX_TYPE_H_
#define	_ICE_FLEX_TYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/list.h>

#define	ICE_FV_OFFSET_INVAL	0x1FF

/* Extraction Sequence (Field Vector) Table */
typedef struct ice_fv_word {
	uint8_t ifw_prot_id;
	uint16_t ifw_off;	/* Offset within the protocol header */
	uint8_t ifw_resvrd;
} __packed ice_fv_word_t;

#define	ICE_MAX_NUM_PROFILES 256

#define	ICE_MAX_FV_WORDS 48
typedef struct ice_fv {
	ice_fv_word_t ifw_ew[ICE_MAX_FV_WORDS];
} ice_fv_t;

/* Packet Type (PTYPE) values */
#define	ICE_PTYPE_MAC_PAY		1
#define	ICE_PTYPE_IPV4FRAG_PAY		22
#define	ICE_PTYPE_IPV4_PAY		23
#define	ICE_PTYPE_IPV4_UDP_PAY		24
#define	ICE_PTYPE_IPV4_TCP_PAY		26
#define	ICE_PTYPE_IPV4_SCTP_PAY		27
#define	ICE_PTYPE_IPV4_ICMP_PAY		28
#define	ICE_PTYPE_IPV6FRAG_PAY		88
#define	ICE_PTYPE_IPV6_PAY		89
#define	ICE_PTYPE_IPV6_UDP_PAY		90
#define	ICE_PTYPE_IPV6_TCP_PAY		92
#define	ICE_PTYPE_IPV6_SCTP_PAY		93
#define	ICE_PTYPE_IPV6_ICMP_PAY		94

typedef struct ice_es {
	uint32_t	ie_sid;
	uint16_t	ie_count;
	uint16_t	ie_fvw;
	uint16_t	*ie_ref_count;
	list_t		ie_prof_map;
	ice_fv_word_t	*ie_t;
	bool		*ie_written;
	bool		ie_reverse;
} ice_es_t;

/* PTYPE Group management */

/*
 * Note: XLT1 table takes 13-bit as input, and results in an 8-bit packet type
 * group (PTG) ID as output.
 *
 * Note: PTG 0 is the default packet type group and it is assumed that all PTYPE
 * are a part of this group until moved to a new PTG.
 */
#define	ICE_DEFAULT_PTG 0

typedef struct ice_ptg_entry {
	struct ice_ptg_ptype *ipe_first_ptype;
	bool ipe_in_use;
} ice_ptg_entry_t;

typedef struct ice_ptg_ptype {
	struct ice_ptg_ptype *ipp_next_ptype;
	uint8_t ipp_ptg;
} ice_ptg_ptype_t;

#define	ICE_MAX_PTG_PER_PROFILE		32

typedef struct ice_prof_map {
	list_node_t	ipm_node;
	uint64_t	ipm_profile_cookie;
	uint64_t	ipm_context;
	uint8_t		ipm_prof_id;
	uint8_t		ipm_ptg_cnt;
	uint8_t		ipm_ptg[ICE_MAX_PTG_PER_PROFILE];
} ice_prof_map_t;

typedef struct ice_vsig_entry {
	list_t ive_prop_lst;
	struct ice_vsig_vsi *ive_first_vsi;
	bool ive_in_use;
} ice_vsig_entry_t;

typedef struct ice_vsig_vsi {
	struct ice_vsig_vsi *ivv_next_vsi;
	uint32_t ivv_prop_mask;
	uint16_t ivv_changed;
	uint16_t ivv_vsig;
} ice_vsig_vsi_t;

/*
 * Each ice_vsig_prof_t tracks the set of hardware profile TCAM entries
 * (PTG, profile ID pairs) that make up a single flow profile's contribution
 * to a VSI group's (VSIG's) characteristic list.
 */
#define	ICE_MAX_TCAM_PER_PROFILE	ICE_MAX_PTG_PER_PROFILE
#define	ICE_INVALID_TCAM		0xffff

typedef struct ice_tcam_inf {
	uint16_t	itc_tcam_idx;
	uint8_t		itc_ptg;
	uint8_t		itc_prof_id;
	bool		itc_in_use;
} ice_tcam_inf_t;

typedef struct ice_vsig_prof {
	list_node_t	ivp_node;
	uint64_t	ivp_profile_cookie;
	uint8_t		ivp_prof_id;
	uint8_t		ivp_tcam_count;
	ice_tcam_inf_t	ivp_tcam[ICE_MAX_TCAM_PER_PROFILE];
} ice_vsig_prof_t;

/*
 * A record of a single change made (or to be made) to one of the hardware
 * flow tables (XLT1, XLT2, profile ID TCAM, or extraction sequence table).
 * These are accumulated into a list while a flow profile <-> VSI
 * association is being computed and are then used both to determine what
 * needs to be written out to hardware and, on failure, what needs to be
 * unwound.
 */
typedef enum ice_chg_type {
	ICE_CHG_NONE = 0,
	ICE_PTG_ES_ADD,
	ICE_TCAM_ADD,
	ICE_VSIG_ADD,
	ICE_VSIG_REM,
	ICE_VSI_MOVE
} ice_chg_type_t;

typedef struct ice_chs_chg {
	list_node_t	icc_node;
	ice_chg_type_t	icc_type;

	bool		icc_add_ptg;
	bool		icc_add_vsig;
	bool		icc_add_tcam_idx;
	bool		icc_add_prof;
	uint16_t	icc_ptype;
	uint8_t		icc_ptg;
	uint8_t		icc_prof_id;
	uint16_t	icc_vsi;
	uint16_t	icc_vsig;
	uint16_t	icc_orig_vsig;
	uint16_t	icc_tcam_idx;
} ice_chs_chg_t;

#define	ICE_XLT1_CNT		1024
#define	ICE_FLOW_PTYPE_MAX	ICE_XLT1_CNT
#define	ICE_MAX_PTGS		256

/* XLT1 Table */
typedef struct ice_xlt1 {
	struct ice_ptg_entry *ix1_ptg_tbl;
	struct ice_ptg_ptype *ix1_ptypes;
	uint8_t *ix1_t;
	uint32_t ix1_sid;
	uint16_t ix1_count;
} ice_xlt1_t;

#define	ICE_XLT2_CNT    768
#define	ICE_MAX_VSIGS   768
#define	ICE_DEFAULT_VSIG	0

/*
 * A VSIG value is made up of a 13-bit index into the VSIG table and a 3-bit
 * PF number (used to keep VSIGs unique across PFs sharing a device).
 */
#define	ICE_VSIG_IDX_M		0x1fff
#define	ICE_PF_NUM_S		13
#define	ICE_PF_NUM_M		(0x07 << ICE_PF_NUM_S)
#define	ICE_VSIG_VALUE(vsig, pfid) \
	((uint16_t)((((uint16_t)(vsig)) & ICE_VSIG_IDX_M) | \
	(((uint16_t)(pfid) << ICE_PF_NUM_S) & ICE_PF_NUM_M)))

/* XLT2 Table */
typedef struct ice_xlt2 {
	struct ice_vsig_entry *ix2_vsig_tbl;
	struct ice_vsig_vsi *ix2_vsis;
	uint16_t *ix2_t;
	uint32_t ix2_sid;
	uint16_t ix2_count;
} ice_xlt2_t;

/*
 * Keys are made up of two values, each one-half the size of the key.
 * For TCAM, the entire key is 80 bits wide (or 2, 40-bit wide values)
 */
#define	ICE_TCAM_KEY_VAL_SZ	5
#define	ICE_TCAM_KEY_SZ	 (2 * ICE_TCAM_KEY_VAL_SZ)

/*
 * The (unencoded) contents of a profile ID TCAM key, used as the input value
 * when generating the actual (encoded) ice_prof_tcam_entry_t.ipte_key value.
 *
 * This is copied verbatim to the hardware, so this must match Table 7-225
 * from the datasheet.
 */
typedef struct ice_prof_id_key {
	uint16_t	ipk_flags;
	uint8_t		ipk_xlt1;
	uint16_t	ipk_xlt2_cdid;
} __packed ice_prof_id_key_t;

typedef struct ice_prof_tcam_entry {
	uint16_t	ipte_addr;
	uint8_t		ipte_key[ICE_TCAM_KEY_SZ];
	uint8_t		ipte_prof_id;
} __packed ice_prof_tcam_entry_t;

typedef struct ice_prof_tcam {
	uint32_t		ipt_sid;
	uint16_t		ipt_count;
	uint16_t		ipt_max_prof_id;
	ice_prof_tcam_entry_t	*ipt_t;
	/* # CDID bits to use in key, 0, 2, 4, or 8 */
	uint8_t			ipt_cdid_bits;
} ice_prof_tcam_t;

typedef struct ice_prof_redir {
	uint8_t		*ipr_t;
	uint32_t	ipr_sid;
	uint16_t	ipr_count;
} ice_prof_redir_t;

typedef struct ice_blk_info {
	ice_xlt1_t		ibi_xlt1;
	ice_xlt2_t		ibi_xlt2;
	ice_prof_tcam_t		ibi_prof;
	ice_prof_redir_t	ibi_prof_redir;
	ice_es_t		ibi_es;
	bool			ibi_overwrite;
	uint8_t			ibi_is_list_init;
	/*
	 * Tracks every ice_flow_prof_t (see ice_flow.h) that has been
	 * successfully added for this block via ice_flow_add_prof(), so
	 * that they can later be looked up and released (e.g. by
	 * ice_flow_rem_prof()).
	 */
	list_t			ibi_flow_profs;
} ice_blk_info_t;

#ifdef __cplusplus
}
#endif

#endif /* _ICE_FLEX_TYPE_H_ */
