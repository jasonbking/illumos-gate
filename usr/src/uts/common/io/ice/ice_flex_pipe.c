/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Intel Corporation
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

/*
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <sys/bitmap.h>
#include <sys/byteorder.h>
#include <sys/stdbit.h>
#include "ice.h"

#if 0
static const uint32_t ice_sect_lkup[ICE_BLK_COUNT][ICE_SECT_COUNT] = {
	/* SWITCH */
	{
		ICE_SID_XLT0_SW,
		ICE_SID_XLT_KEY_BUILDER_SW,
		ICE_SID_XLT1_SW,
		ICE_SID_XLT2_SW,
		ICE_SID_PROFID_TCAM_SW,
		ICE_SID_PROFID_REDIR_SW,
		ICE_SID_FLD_VEC_SW,
		ICE_SID_CDID_KEY_BUILDER_SW,
		ICE_SID_CDID_REDIR_SW
	},

	/* ACL */
	{
		ICE_SID_XLT0_ACL,
		ICE_SID_XLT_KEY_BUILDER_ACL,
		ICE_SID_XLT1_ACL,
		ICE_SID_XLT2_ACL,
		ICE_SID_PROFID_TCAM_ACL,
		ICE_SID_PROFID_REDIR_ACL,
		ICE_SID_FLD_VEC_ACL,
		ICE_SID_CDID_KEY_BUILDER_ACL,
		ICE_SID_CDID_REDIR_ACL
	},

	/* FD */
	{
		ICE_SID_XLT0_FD,
		ICE_SID_XLT_KEY_BUILDER_FD,
		ICE_SID_XLT1_FD,
		ICE_SID_XLT2_FD,
		ICE_SID_PROFID_TCAM_FD,
		ICE_SID_PROFID_REDIR_FD,
		ICE_SID_FLD_VEC_FD,
		ICE_SID_CDID_KEY_BUILDER_FD,
		ICE_SID_CDID_REDIR_FD
	},

	/* RSS */
	{
		ICE_SID_XLT0_RSS,
		ICE_SID_XLT_KEY_BUILDER_RSS,
		ICE_SID_XLT1_RSS,
		ICE_SID_XLT2_RSS,
		ICE_SID_PROFID_TCAM_RSS,
		ICE_SID_PROFID_REDIR_RSS,
		ICE_SID_FLD_VEC_RSS,
		ICE_SID_CDID_KEY_BUILDER_RSS,
		ICE_SID_CDID_REDIR_RSS
	},

	/* PE */
	{
		ICE_SID_XLT0_PE,
		ICE_SID_XLT_KEY_BUILDER_PE,
		ICE_SID_XLT1_PE,
		ICE_SID_XLT2_PE,
		ICE_SID_PROFID_TCAM_PE,
		ICE_SID_PROFID_REDIR_PE,
		ICE_SID_FLD_VEC_PE,
		ICE_SID_CDID_KEY_BUILDER_PE,
		ICE_SID_CDID_REDIR_PE
	}
};
#endif

static int
ice_ptg_find_ptype(ice_xlt1_t *xlt1, uint16_t ptype, uint8_t *ptg)
{
	if (ptype >= ICE_XLT1_CNT || ptg == NULL)
		return (EINVAL);

	*ptg = xlt1->ix1_ptypes[ptype].ipp_ptg;
	return (0);
}

static void
ice_ptg_alloc_val(ice_xlt1_t *xlt1, uint8_t ptg)
{
	xlt1->ix1_ptg_tbl[ptg].ipe_in_use = true;
}

static int
ice_ptg_remove_ptype(ice_xlt1_t *xlt1, uint16_t ptype, uint8_t ptg)
{
	ice_ptg_ptype_t **ch, *p;

	if (ptype > ICE_XLT1_CNT - 1)
		return (EINVAL);

	if (!xlt1->ix1_ptg_tbl[ptg].ipe_in_use)
		return (ENOENT);

	VERIFY3P(xlt1->ix1_ptg_tbl[ptg].ipe_first_ptype, !=, NULL);

	p = xlt1->ix1_ptg_tbl[ptg].ipe_first_ptype;
	ch = &xlt1->ix1_ptg_tbl[ptg].ipe_first_ptype;

	while (p != NULL) {
		if (ptype == (p - xlt1->ix1_ptypes)) {
			*ch = p->ipp_next_ptype;
			break;
		}

		ch = &p->ipp_next_ptype;
		p = p->ipp_next_ptype;
	}

	xlt1->ix1_ptypes[ptype].ipp_ptg = ICE_DEFAULT_PTG;
	xlt1->ix1_ptypes[ptype].ipp_next_ptype = NULL;

	return (0);
}

static int
ice_ptg_add_mv_ptype(ice_xlt1_t *xlt1, uint16_t ptype, uint8_t ptg)
{
	uint8_t original_ptg;
	int status;

	if (ptype > ICE_XLT1_CNT - 1)
		return (EINVAL);

	if (!xlt1->ix1_ptg_tbl[ptg].ipe_in_use && ptg != ICE_DEFAULT_PTG)
		return (ENOENT);

	status = ice_ptg_find_ptype(xlt1, ptype, &original_ptg);
	if (status != 0)
		return (status);

	if (original_ptg == ptg)
		return (0);

	if (original_ptg != ICE_DEFAULT_PTG)
		VERIFY0(ice_ptg_remove_ptype(xlt1, ptype, original_ptg));

	if (ptg == ICE_DEFAULT_PTG)
		return (0);

	xlt1->ix1_ptypes[ptype].ipp_next_ptype =
	    xlt1->ix1_ptg_tbl[ptg].ipe_first_ptype;
	xlt1->ix1_ptg_tbl[ptg].ipe_first_ptype = &xlt1->ix1_ptypes[ptype];

	xlt1->ix1_ptypes[ptype].ipp_ptg = ptg;
	xlt1->ix1_t[ptype] = ptg;

	return (0);
}

typedef struct ice_blk_size_details {
	uint16_t ibsd_xlt1;		/* # XLT1 entries */
	uint16_t ibsd_xlt2;		/* # XLT2 entries */
	uint16_t ibsd_prof_tcam;	/* # profile ID TCAM entries */
	uint16_t ibsd_prof_id;		/* # profile IDs */
	uint8_t ibsd_prof_cdid_bits;	/* # CDID one-hot bits used in key */
	uint16_t ibsd_prof_redir;	/* # profile redirection entries */
	uint16_t ibsd_es;		/* # extraction sequence entries */
	uint16_t ibsd_fvw;		/* # field vector words */
	bool ibsd_overwrite;		/* overwrite existing entries allowed */
	bool ibsd_reverse;		/* reverse FV order */
} ice_blk_size_details_t;

static const ice_blk_size_details_t blk_sizes[ICE_BLK_COUNT] = {
	/*
	 * Table Definitions
	 * XLT1 - Number of entries in XLT1 table
	 * XLT2 - Number of entries in XLT2 table
	 * TCAM - Number of entries Profile ID TCAM table
	 * CDID - Control Domain ID of the hardware block
	 * PRED - Number of entries in the Profile Redirection Table
	 * FV   - Number of entries in the Field Vector
	 * FVW  - Width (in WORDs) of the Field Vector
	 * OVR  - Overwrite existing table entries
	 * REV  - Reverse FV
	 */
	/*		XLT1	, XLT2		,TCAM, PID,CDID,PRED, FV, FVW */
	/*		Overwrite   , Reverse FV */
	/* SW  */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 256,   0,  256, 256,  48,
			false, false },
	/* ACL */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  32,
			false, false },
	/* FD  */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  24,
			false, true  },
	/* RSS */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  24,
			true,  true  },
	/* PE  */ { ICE_XLT1_CNT, ICE_XLT2_CNT,  64,  32,   0,   32,  32,  24,
			false, false },
};

typedef enum ice_sid_all {
	ICE_SID_XLT1_OFF = 0,
	ICE_SID_XLT2_OFF,
	ICE_SID_PR_OFF,
	ICE_SID_PR_REDIR_OFF,
	ICE_SID_ES_OFF,
	ICE_SID_OFF_COUNT,
} ice_sid_all_t;

/* Block / table section IDs */
static const uint32_t ice_blk_sids[ICE_BLK_COUNT][ICE_SID_OFF_COUNT] = {
	/* SWITCH */
	{	ICE_SID_XLT1_SW,
		ICE_SID_XLT2_SW,
		ICE_SID_PROFID_TCAM_SW,
		ICE_SID_PROFID_REDIR_SW,
		ICE_SID_FLD_VEC_SW
	},

	/* ACL */
	{	ICE_SID_XLT1_ACL,
		ICE_SID_XLT2_ACL,
		ICE_SID_PROFID_TCAM_ACL,
		ICE_SID_PROFID_REDIR_ACL,
		ICE_SID_FLD_VEC_ACL
	},

	/* FD */
	{	ICE_SID_XLT1_FD,
		ICE_SID_XLT2_FD,
		ICE_SID_PROFID_TCAM_FD,
		ICE_SID_PROFID_REDIR_FD,
		ICE_SID_FLD_VEC_FD
	},

	/* RSS */
	{	ICE_SID_XLT1_RSS,
		ICE_SID_XLT2_RSS,
		ICE_SID_PROFID_TCAM_RSS,
		ICE_SID_PROFID_REDIR_RSS,
		ICE_SID_FLD_VEC_RSS
	},

	/* PE */
	{	ICE_SID_XLT1_PE,
		ICE_SID_XLT2_PE,
		ICE_SID_PROFID_TCAM_PE,
		ICE_SID_PROFID_REDIR_PE,
		ICE_SID_FLD_VEC_PE
	}
};

static void
ice_init_sw_xlt1_db(ice_blk_info_t *info)
{
	ice_xlt1_t *xlt1 = &info->ibi_xlt1;
	uint16_t pt;

	for (pt = 0; pt < xlt1->ix1_count; pt++) {
		uint8_t ptg;

		ptg = xlt1->ix1_t[pt];
		if (ptg != ICE_DEFAULT_PTG) {
			ice_ptg_alloc_val(xlt1, ptg);
			VERIFY0(ice_ptg_add_mv_ptype(xlt1, pt, ptg));
		}
	}
}

static bool
ice_vsig_find_vsi(ice_xlt2_t *xlt2, uint16_t vsi, uint16_t *vsig)
{
	if (vsig == NULL || vsi >= ICE_MAX_VSIS)
		return (false);

	*vsig = xlt2->ix2_vsis[vsi].ivv_vsig;
	return (true);
}

static uint16_t
ice_vsig_alloc_val(ice_xlt2_t *xlt2, uint16_t vsig, uint16_t pfid)
{
	ice_vsig_entry_t	*e;
	uint16_t		idx = BITX(vsig, 12, 0);

	ASSERT3U(pfid, <, 8);

	e = &xlt2->ix2_vsig_tbl[idx];
	if (!e->ive_in_use) {
		e->ive_in_use = true;
	}

	return (pfid << 13 | idx);
}

static int
ice_vsig_remove_vsi(ice_xlt2_t *xlt2, uint16_t vsi, uint16_t vsig)
{
	ice_vsig_vsi_t	**vsi_head, *vsi_cur, *vsi_tgt;
	uint16_t	idx = BITX(vsig, 12, 0);

	if (vsi >= ICE_MAX_VSIS || idx >= ICE_MAX_VSIGS)
		return (EINVAL);

	if (!xlt2->ix2_vsig_tbl[idx].ive_in_use)
		return (ENOENT);

	if (idx == ICE_DEFAULT_VSIG)
		return (0);

	vsi_head = &xlt2->ix2_vsig_tbl[idx].ive_first_vsi;
	VERIFY3P(*vsi_head, !=, NULL);

	vsi_tgt = &xlt2->ix2_vsis[vsi];
	vsi_cur = *vsi_head;

	while (vsi_cur != NULL) {
		if (vsi_tgt == vsi_cur) {
			*vsi_head = vsi_cur->ivv_next_vsi;
			break;
		}
		vsi_head = &vsi_cur->ivv_next_vsi;
		vsi_cur = vsi_cur->ivv_next_vsi;
	}

	if (vsi_cur == NULL)
		return (ENOENT);

	vsi_cur->ivv_vsig = ICE_DEFAULT_VSIG;
	vsi_cur->ivv_changed = 1;
	vsi_cur->ivv_next_vsi = NULL;

	return (0);
}

static int
ice_vsig_add_mv_vsi(ice_xlt2_t *xlt2, uint16_t vsi, uint16_t vsig, uint_t pfid)
{
	ice_vsig_vsi_t	*tmp;
	uint16_t	orig_vsig, idx;
	int		status;

	idx = BITX(vsig, 12, 0);

	if (vsi >= ICE_MAX_VSIS || idx >= ICE_MAX_VSIGS)
		return (EINVAL);

	if (!xlt2->ix2_vsig_tbl[idx].ive_in_use && vsig != ICE_DEFAULT_VSIG)
		return (ENOENT);

	if (!ice_vsig_find_vsi(xlt2, vsi, &orig_vsig))
		return (EINVAL);

	if (orig_vsig == vsig)
		return (0);

	if (orig_vsig != ICE_DEFAULT_VSIG) {
		status = ice_vsig_remove_vsi(xlt2, vsi, orig_vsig);
		if (status != 0)
			return (status);
	}

	if (idx == ICE_DEFAULT_VSIG)
		return (0);

	xlt2->ix2_vsis[vsi].ivv_vsig = vsig;
	xlt2->ix2_vsis[vsi].ivv_changed = 1;

	tmp = xlt2->ix2_vsig_tbl[idx].ive_first_vsi;
	xlt2->ix2_vsig_tbl[idx].ive_first_vsi =
	    &xlt2->ix2_vsis[vsi];
	xlt2->ix2_vsis[vsi].ivv_next_vsi = tmp;
	xlt2->ix2_t[vsi] = vsig;

	return (0);
}

static bool
ice_find_prof_id(ice_es_t *es, ice_fv_word_t *fv, uint8_t *prof_id)
{
	uint_t i;
	uint16_t off;

	for (i = 0; i < es->ie_count; i++) {
		off = i * es->ie_fvw;

		if (memcmp(&es->ie_t[off], fv, es->ie_fvw * sizeof (*fv)) != 0)
			continue;

		*prof_id = i;
		return (true);
	}

	return (false);
}

static bool
ice_prof_id_rsrc_type(ice_block_t blk, uint16_t *type)
{
	switch (blk) {
	case ICE_BLK_RSS:
		*type = ICE_RES_TYPE_HASH_PROF_BLDR_PROFID;
		break;
	case ICE_BLK_PE:
		*type = ICE_RES_TYPE_QHASH_PROF_BLDR_PROFID;
		break;
	default:
		return (false);
	}

	return (true);
}

static bool
ice_alloc_prof_id(ice_t *ice, ice_block_t blk, uint8_t *prof_id)
{
	uint16_t	type;
	uint16_t	nres;
	uint16_t	buf[3] = { 0 };
	ice_res_entry_t *res = (ice_res_entry_t *)buf;

	VERIFY(ice_prof_id_rsrc_type(blk, &type));

	res->ire_info = ICE_RES_INFO_SET_TYPE(0, type);
	res->ire_info = ICE_RES_INFO_SET_PERSISTENT(res->ire_info, 0);
	res->ire_info = ICE_RES_INFO_SET_IGNORE_IDX(res->ire_info, 1);
	res->ire_info = LE_16(res->ire_info);

	res->ire_ndesc = LE_16(1);
	nres = 1;

	if (!ice_cmd_allocate_resource(ice, res, &nres)) {
		return (false);
	}

	*prof_id = LE_16(res->ire_descs[0]);
	return (true);
}

static bool
ice_free_prof_id(ice_t *ice, ice_block_t blk, uint8_t prof_id)
{
	uint16_t	type;
	uint16_t	nres;
	uint16_t	buf[3] = { 0 };
	ice_res_entry_t	*res = (ice_res_entry_t *)buf;

	VERIFY(ice_prof_id_rsrc_type(blk, &type));

	res->ire_info = LE_16(ICE_RES_INFO_SET_TYPE(0, type));
	res->ire_ndesc = LE_16(1);
	res->ire_descs[0] = LE_16(prof_id);

	nres = 1;

	return (ice_cmd_free_resource(ice, res, nres));
}

static void
ice_init_sw_xlt2_db(ice_t *ice, ice_blk_info_t *info)
{
	ice_xlt2_t *xlt2 = &info->ibi_xlt2;
	uint16_t vsi;

	for (vsi = 0; vsi < xlt2->ix2_count; vsi++) {
		uint16_t vsig;

		vsig = xlt2->ix2_t[vsi];
		if (vsig != 0) {
			/*
			 * ice_vsig_alloc_val() returns the encoded VSIG
			 * value itself (pfid << 13 | idx), we don't
			 * care about the value, we just need to ensure
			 * the VSIG is marked in use.
			 */
			(void) ice_vsig_alloc_val(xlt2, vsig, ice->ice_pf_id);
			VERIFY0(ice_vsig_add_mv_vsi(xlt2, vsi, vsig,
			    ice->ice_pf_id));
			xlt2->ix2_vsis[vsi].ivv_changed = 0;
		}
	}
}

static void
ice_init_sw_db(ice_t *ice)
{
	for (ice_block_t i = 0; i < ICE_BLK_COUNT; i++) {
		ice_init_sw_xlt1_db(&ice->ice_blk[i]);
		ice_init_sw_xlt2_db(ice, &ice->ice_blk[i]);
	}
}

struct ice_fill_tbl_info {
	ice_block_t	ifti_blk;
	uint32_t	ifti_n;
};

static bool
ice_fill_tbl(ice_t *ice, uint32_t sid, const void *buf, size_t len, void *arg)
{
	struct ice_fill_tbl_info *ti = arg;
	ice_blk_info_t	*info;
	const uint8_t	*p = buf;
	const void	*src;
	void		*dst;
	size_t		elsize, nsrc, ndst;

	if (len == 0)
		return (true);

	info = &ice->ice_blk[ti->ifti_blk];

	/*
	 * Every section starts with a 16-bit entry count.
	 * With the exception of the profile id sections, a 16-bit
	 * value follows (in some cases it's reserved, in some it's
	 * an offset, in either case we don't care what it's value is)
	 * followed by the data.
	 */
	nsrc = LE_IN16(p);
	p += sizeof (uint16_t);

	switch (sid) {
	case ICE_SID_PROFID_TCAM_SW:
	case ICE_SID_PROFID_TCAM_FD:
	case ICE_SID_PROFID_TCAM_RSS:
	case ICE_SID_PROFID_TCAM_ACL:
	case ICE_SID_PROFID_TCAM_PE:
		/* No 2nd 16-bit value in the header */
		break;
	default:
		/* Skip over the second 16-bit value in the header */
		p += sizeof (uint16_t);
		break;
	}
	/* The start of the data to copy immediately follows the header */
	src = p;

	switch (sid) {
	case ICE_SID_XLT1_SW:
	case ICE_SID_XLT1_FD:
	case ICE_SID_XLT1_RSS:
	case ICE_SID_XLT1_ACL:
	case ICE_SID_XLT1_PE:
		elsize = sizeof (*info->ibi_xlt1.ix1_t);
		ndst = info->ibi_xlt1.ix1_count;
		dst = info->ibi_xlt1.ix1_t;
		break;
	case ICE_SID_XLT2_SW:
	case ICE_SID_XLT2_FD:
	case ICE_SID_XLT2_RSS:
	case ICE_SID_XLT2_ACL:
	case ICE_SID_XLT2_PE:
		elsize = sizeof (*info->ibi_xlt2.ix2_t);
		ndst = info->ibi_xlt2.ix2_count;
		dst = info->ibi_xlt2.ix2_t;
		break;
	case ICE_SID_PROFID_TCAM_SW:
	case ICE_SID_PROFID_TCAM_FD:
	case ICE_SID_PROFID_TCAM_RSS:
	case ICE_SID_PROFID_TCAM_ACL:
	case ICE_SID_PROFID_TCAM_PE:
		elsize = sizeof (*info->ibi_prof.ipt_t);
		ndst = info->ibi_prof.ipt_count;
		dst = info->ibi_prof.ipt_t;
		break;
	case ICE_SID_PROFID_REDIR_SW:
	case ICE_SID_PROFID_REDIR_FD:
	case ICE_SID_PROFID_REDIR_RSS:
	case ICE_SID_PROFID_REDIR_ACL:
	case ICE_SID_PROFID_REDIR_PE:
		elsize = sizeof (*info->ibi_prof_redir.ipr_t);
		ndst = info->ibi_prof_redir.ipr_count;
		dst = info->ibi_prof_redir.ipr_t;
		break;
	case ICE_SID_FLD_VEC_SW:
	case ICE_SID_FLD_VEC_FD:
	case ICE_SID_FLD_VEC_RSS:
	case ICE_SID_FLD_VEC_ACL:
	case ICE_SID_FLD_VEC_PE:
		elsize = sizeof (*info->ibi_es.ie_t);
		ndst = info->ibi_es.ie_count * info->ibi_es.ie_fvw;
		dst = info->ibi_es.ie_t;
		nsrc *= info->ibi_es.ie_fvw;
		break;
	default:
		return (true);
	}

	/*
	 * If there's more entries than we have space for, the FreeBSD
	 * driver silently caps the copy at the destination size.
	 * We do the same since we don't know if this might be expected
	 * and logging may just generate needless noise.
	 */
	if (ti->ifti_n + nsrc > ndst)
		nsrc = ndst - ti->ifti_n;

	dst = (uint8_t *)dst + (ti->ifti_n * elsize);

	bcopy(src, dst, nsrc * elsize);
	ti->ifti_n += nsrc;

	return (true);
}

bool
ice_fill_blk_tbls(ice_t *ice, const uint8_t *p, uint32_t nblk)
{
	ice_blk_info_t	*info;
	ice_block_t	i;

	for (i = 0; i < ICE_BLK_COUNT; i++) {
		struct ice_fill_tbl_info ti = {
			.ifti_blk = i,
			.ifti_n = 0,
		};

		info = &ice->ice_blk[i];

		if (!ice_pkg_iter_section(ice, p, nblk, info->ibi_xlt1.ix1_sid,
		    ice_fill_tbl, &ti)) {
			return (false);
		}

		ti.ifti_n = 0;
		if (!ice_pkg_iter_section(ice, p, nblk, info->ibi_xlt2.ix2_sid,
		    ice_fill_tbl, &ti)) {
			return (false);
		}

		ti.ifti_n = 0;
		if (!ice_pkg_iter_section(ice, p, nblk, info->ibi_prof.ipt_sid,
		    ice_fill_tbl, &ti)) {
			return (false);
		}

		ti.ifti_n = 0;
		if (!ice_pkg_iter_section(ice, p, nblk,
		    info->ibi_prof_redir.ipr_sid, ice_fill_tbl, &ti)) {
			return (false);
		}

		ti.ifti_n = 0;
		if (!ice_pkg_iter_section(ice, p, nblk, info->ibi_es.ie_sid,
		    ice_fill_tbl, &ti)) {
			return (false);
		}
	}

	ice_init_sw_db(ice);

	return (true);
}

void
ice_init_hw_tbls(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ICE_BLK_COUNT; i++) {
		ice_prof_redir_t *prof_redir = &ice->ice_blk[i].ibi_prof_redir;
		ice_prof_tcam_t	*prof = &ice->ice_blk[i].ibi_prof;
		ice_xlt1_t	*xlt1 = &ice->ice_blk[i].ibi_xlt1;
		ice_xlt2_t	*xlt2 = &ice->ice_blk[i].ibi_xlt2;
		ice_es_t	*es = &ice->ice_blk[i].ibi_es;
		uint_t		j;

		ice->ice_blk[i].ibi_overwrite = blk_sizes[i].ibsd_overwrite;
		es->ie_reverse = blk_sizes[i].ibsd_reverse;
		list_create(&es->ie_prof_map, sizeof (ice_prof_map_t),
		    offsetof(ice_prof_map_t, ipm_node));
		list_create(&ice->ice_blk[i].ibi_flow_profs,
		    sizeof (ice_flow_prof_t), offsetof(ice_flow_prof_t,
		    ifp_list));

		xlt1->ix1_sid = ice_blk_sids[i][ICE_SID_XLT1_OFF];
		xlt1->ix1_count = blk_sizes[i].ibsd_xlt1;

		xlt1->ix1_ptypes = kmem_zalloc(xlt1->ix1_count *
		    sizeof (*xlt1->ix1_ptypes), KM_SLEEP);
		xlt1->ix1_ptg_tbl = kmem_zalloc(xlt1->ix1_count *
		    sizeof (*xlt1->ix1_ptg_tbl), KM_SLEEP);
		xlt1->ix1_t = kmem_zalloc(xlt1->ix1_count *
		    sizeof (*xlt1->ix1_t), KM_SLEEP);

		xlt2->ix2_sid = ice_blk_sids[i][ICE_SID_XLT2_OFF];
		xlt2->ix2_count = blk_sizes[i].ibsd_xlt2;
		xlt2->ix2_vsis = kmem_zalloc(xlt2->ix2_count *
		    sizeof (*xlt2->ix2_vsis), KM_SLEEP);
		xlt2->ix2_vsig_tbl = kmem_zalloc(xlt2->ix2_count *
		    sizeof (*xlt2->ix2_vsig_tbl), KM_SLEEP);

		for (j = 0; j < xlt2->ix2_count; j++) {
			list_create(&xlt2->ix2_vsig_tbl[j].ive_prop_lst,
			    sizeof (ice_vsig_prof_t),
			    offsetof(ice_vsig_prof_t, ivp_node));
		}
		xlt2->ix2_t = kmem_zalloc(xlt2->ix2_count *
		    sizeof (*xlt2->ix2_t), KM_SLEEP);

		prof->ipt_sid = ice_blk_sids[i][ICE_SID_PR_OFF];
		prof->ipt_count = blk_sizes[i].ibsd_prof_tcam;
		prof->ipt_max_prof_id = blk_sizes[i].ibsd_prof_id;
		prof->ipt_cdid_bits = blk_sizes[i].ibsd_prof_cdid_bits;
		prof->ipt_t = kmem_zalloc(prof->ipt_count *
		    sizeof (*prof->ipt_t), KM_SLEEP);

		prof_redir->ipr_sid = ice_blk_sids[i][ICE_SID_PR_REDIR_OFF];
		prof_redir->ipr_count = blk_sizes[i].ibsd_prof_redir;
		prof_redir->ipr_t = kmem_zalloc(prof_redir->ipr_count *
		    sizeof (*prof_redir->ipr_t), KM_SLEEP);

		es->ie_sid = ice_blk_sids[i][ICE_SID_ES_OFF];
		es->ie_count = blk_sizes[i].ibsd_es;
		es->ie_fvw = blk_sizes[i].ibsd_fvw;
		es->ie_t = kmem_zalloc(es->ie_count * es->ie_fvw *
		    sizeof (*es->ie_t), KM_SLEEP);

		es->ie_ref_count = kmem_zalloc(es->ie_count *
		    sizeof (*es->ie_ref_count), KM_SLEEP);
		es->ie_written = kmem_zalloc(es->ie_count *
		    sizeof (*es->ie_written), KM_SLEEP);
	}
}

void
ice_fini_hw_tbls(ice_t *ice)
{
	uint_t i;

	for (i = 0; i < ICE_BLK_COUNT; i++) {
		ice_prof_redir_t *prof_redir = &ice->ice_blk[i].ibi_prof_redir;
		ice_prof_tcam_t	*prof = &ice->ice_blk[i].ibi_prof;
		ice_xlt1_t	*xlt1 = &ice->ice_blk[i].ibi_xlt1;
		ice_xlt2_t	*xlt2 = &ice->ice_blk[i].ibi_xlt2;
		ice_es_t	*es = &ice->ice_blk[i].ibi_es;
		uint_t		j;

		ice_prof_map_t *pm;
		ice_flow_prof_t *fp;

		/*
		 * Normally every flow profile here has already been removed
		 * by ice_rss_config_fini() (called from ice_vsi_free()) as
		 * each VSI referencing it is torn down, leaving this list
		 * empty by the time we get here. But when rebuilding
		 * software state after a CORE/GLOBAL/EMP reset, we get here
		 * with VSIs (and hence flow profiles) still around, since
		 * the reset itself -- not an explicit VSI teardown --
		 * invalidated the hardware profiles this list describes. In
		 * that case, just free whatever is left directly; there's no
		 * hardware-side cleanup to do since the reset already wiped
		 * it out.
		 */
		while ((fp = list_remove_head(&ice->ice_blk[i].ibi_flow_profs))
		    != NULL) {
			kmem_free(fp, sizeof (*fp));
		}
		list_destroy(&ice->ice_blk[i].ibi_flow_profs);

		while ((pm = list_remove_head(&es->ie_prof_map)) != NULL)
			kmem_free(pm, sizeof (*pm));
		list_destroy(&es->ie_prof_map);

		kmem_free(es->ie_written,
		    es->ie_count * sizeof (*es->ie_written));
		es->ie_written = NULL;

		kmem_free(es->ie_ref_count,
		    es->ie_count * sizeof (*es->ie_ref_count));
		es->ie_ref_count = NULL;

		kmem_free(es->ie_t, es->ie_count * es->ie_fvw *
		    sizeof (*es->ie_t));
		es->ie_t = NULL;

		kmem_free(prof_redir->ipr_t,
		    prof_redir->ipr_count * sizeof (*prof_redir->ipr_t));

		kmem_free(prof->ipt_t,
		    prof->ipt_count * sizeof (*prof->ipt_t));
		prof->ipt_t = NULL;

		kmem_free(xlt2->ix2_t, xlt2->ix2_count * sizeof (*xlt2->ix2_t));
		xlt2->ix2_t = NULL;

		for (j = 0; j < xlt2->ix2_count; j++) {
			ice_vsig_prof_t *vp;
			list_t *lp = &xlt2->ix2_vsig_tbl[j].ive_prop_lst;

			while ((vp = list_remove_head(lp)) != NULL)
				kmem_free(vp, sizeof (*vp));
			list_destroy(lp);
		}

		kmem_free(xlt2->ix2_vsig_tbl,
		    xlt2->ix2_count * sizeof (*xlt2->ix2_vsig_tbl));
		xlt2->ix2_vsig_tbl = NULL;

		kmem_free(xlt2->ix2_vsis,
		    xlt2->ix2_count * sizeof (*xlt2->ix2_vsis));
		xlt2->ix2_vsis = NULL;

		kmem_free(xlt1->ix1_t,
		    xlt1->ix1_count * sizeof (*xlt1->ix1_t));
		xlt1->ix1_t = NULL;

		kmem_free(xlt1->ix1_ptg_tbl,
		    xlt1->ix1_count * sizeof (*xlt1->ix1_ptg_tbl));
		xlt1->ix1_ptg_tbl = NULL;

		kmem_free(xlt1->ix1_ptypes,
		    xlt1->ix1_count * sizeof (*xlt1->ix1_ptypes));
		xlt1->ix1_ptypes = NULL;
	}
}

static void
ice_write_es(ice_es_t *es, uint8_t prof_id, ice_fv_word_t *fv)
{
	size_t		len;
	uint16_t	off;

	off = (uint16_t)prof_id * es->ie_fvw;
	len = es->ie_fvw * sizeof (*fv);

	if (fv == NULL) {
		(void) memset(&es->ie_t[off], '\0', len);
		es->ie_written[prof_id] = false;
	} else {
		bcopy(fv, &es->ie_t[off], len);
	}
}

static bool
ice_prof_inc_ref(ice_es_t *es, uint8_t prof_id)
{
	if (prof_id > es->ie_count)
		return (false);

	es->ie_ref_count[prof_id]++;
	return (true);
}

bool
ice_add_prof(ice_t *ice, ice_block_t blk, uint64_t id, ulong_t *ptypes,
    ice_fv_word_t *fv)
{
	ulong_t		ptgs_used[ICE_XLT1_CNT / BT_NBIPUL] = { 0 };
	ice_prof_map_t *prof;
	ice_xlt1_t	*xlt1;
	ice_es_t	*es;
	uint16_t	ptype;
	uint8_t		prof_id;

	xlt1 = &ice->ice_blk[blk].ibi_xlt1;
	es = &ice->ice_blk[blk].ibi_es;

	if (!ice_find_prof_id(es, fv, &prof_id)) {
		if (!ice_alloc_prof_id(ice, blk, &prof_id))
			return (false);

		ice_write_es(es, prof_id, fv);
	}

	VERIFY(ice_prof_inc_ref(es, prof_id));

	prof = kmem_zalloc(sizeof (*prof), KM_SLEEP);
	prof->ipm_profile_cookie = id;
	prof->ipm_prof_id = prof_id;
	prof->ipm_ptg_cnt = 0;
	prof->ipm_context = 0;

	for (ptype = 0; ptype < ICE_FLOW_PTYPE_MAX; ptype++) {
		uint8_t ptg;

		if (!BT_TEST(ptypes, ptype))
			continue;

		VERIFY0(ice_ptg_find_ptype(xlt1, ptype, &ptg));

		if (BT_TEST(ptgs_used, ptg))
			continue;

		BT_SET(ptgs_used, ptg);
		prof->ipm_ptg[prof->ipm_ptg_cnt] = ptg;

		if (++prof->ipm_ptg_cnt >= ICE_MAX_PTG_PER_PROFILE)
			break;
	}

	list_insert_head(&es->ie_prof_map, prof);

	return (true);
}

/*
 * The following functions implement the dynamic (run-time) portion of the
 * flow-profile/VSIG state machine: allocating and writing profile ID TCAM
 * entries, allocating and freeing VSI groups (VSIGs), associating flow
 * profiles with VSIGs (and VSIs with VSIGs), and building/pushing the
 * resulting hardware table updates via the AQ "update package" command.
 * This is a fairly direct port of the equivalent logic in the FreeBSD ice
 * driver's ice_flex_pipe.c.
 */

/* Mask/invert bit values used when encoding profile ID TCAM key bits */
#define	ICE_DC_KEY	0x1	/* don't care */
#define	ICE_DC_KEYINV	0x1
#define	ICE_NM_KEY	0x0	/* never match */
#define	ICE_NM_KEYINV	0x0
#define	ICE_0_KEY	0x1	/* match 0 */
#define	ICE_0_KEYINV	0x0
#define	ICE_1_KEY	0x0	/* match 1 */
#define	ICE_1_KEYINV	0x1

/*
 * ice_gen_key_word - generate 16-bits of a key/mask pair for TCAM
 *
 * This encodes 8 bits of value/valid/dont_care/nvr_mtch into 8 bits of key
 * and 8 bits of key-invert, one bit at a time.
 */
static bool
ice_gen_key_word(uint8_t val, uint8_t valid, uint8_t dont_care,
    uint8_t nvr_mtch, uint8_t *key, uint8_t *key_inv)
{
	uint8_t in_key = *key, in_key_inv = *key_inv;
	uint_t i;

	/* 'dont_care' and 'nvr_mtch' masks cannot overlap */
	if ((dont_care ^ nvr_mtch) != (dont_care | nvr_mtch))
		return (false);

	*key = 0;
	*key_inv = 0;

	for (i = 0; i < 8; i++) {
		*key >>= 1;
		*key_inv >>= 1;

		if (!(valid & 0x1)) {
			*key |= (in_key & 0x1) << 7;
			*key_inv |= (in_key_inv & 0x1) << 7;
		} else if (dont_care & 0x1) {
			*key |= ICE_DC_KEY << 7;
			*key_inv |= ICE_DC_KEYINV << 7;
		} else if (nvr_mtch & 0x1) {
			*key |= ICE_NM_KEY << 7;
			*key_inv |= ICE_NM_KEYINV << 7;
		} else if (val & 0x1) {
			*key |= ICE_1_KEY << 7;
			*key_inv |= ICE_1_KEYINV << 7;
		} else {
			*key |= ICE_0_KEY << 7;
			*key_inv |= ICE_0_KEYINV << 7;
		}

		dont_care >>= 1;
		nvr_mtch >>= 1;
		valid >>= 1;
		val >>= 1;
		in_key >>= 1;
		in_key_inv >>= 1;
	}

	return (true);
}

/*
 * ice_bits_max_set - determine if at most 'max' bits are set in a byte array
 */
static bool
ice_bits_max_set(const uint8_t *mask, uint16_t size, uint16_t max)
{
	uint16_t count = 0;
	uint16_t i;

	for (i = 0; i < size; i++) {
		if (mask[i] == 0)
			continue;

		if (count == max)
			return (false);

		count += stdc_count_ones_uc(mask[i]);

		if (count > max)
			return (false);
	}

	return (true);
}

/*
 * ice_set_key - generate a variable sized key with multiples of 16-bits
 *
 * upd, dc, and nm are optional and may be NULL:
 *	upd == NULL --> upd mask is all 1's (update all bits)
 *	dc == NULL  --> dc mask is all 0's (no don't care bits)
 *	nm == NULL  --> nm mask is all 0's (no never match bits)
 */
static bool
ice_set_key(uint8_t *key, uint16_t size, uint8_t *val, uint8_t *upd,
    uint8_t *dc, uint8_t *nm, uint16_t off, uint16_t len)
{
	uint16_t half_size;
	uint16_t i;

	if ((size % 2) != 0)
		return (false);
	half_size = size / 2;

	if ((uint32_t)off + len > half_size)
		return (false);

#define	ICE_NVR_MTCH_BITS_MAX	1
	if (nm != NULL && !ice_bits_max_set(nm, len, ICE_NVR_MTCH_BITS_MAX))
		return (false);

	for (i = 0; i < len; i++) {
		if (!ice_gen_key_word(val[i], upd != NULL ? upd[i] : 0xff,
		    dc != NULL ? dc[i] : 0, nm != NULL ? nm[i] : 0,
		    key + off + i, key + half_size + off + i)) {
			return (false);
		}
	}

	return (true);
}

/*
 * ice_prof_gen_key - generate a 80-bit profile ID TCAM key
 */
static bool
ice_prof_gen_key(ice_t *ice, ice_block_t blk, uint8_t ptg, uint16_t vsig,
    uint8_t cdid, uint16_t flags, uint8_t vl_msk[ICE_TCAM_KEY_VAL_SZ],
    uint8_t dc_msk[ICE_TCAM_KEY_VAL_SZ], uint8_t nm_msk[ICE_TCAM_KEY_VAL_SZ],
    uint8_t key[ICE_TCAM_KEY_SZ])
{
	ice_prof_id_key_t inkey;
	uint16_t xlt2_cdid;

#define	ICE_CD_2_M	0xc000U
#define	ICE_CD_2_S	14
#define	ICE_CD_4_M	0xf000U
#define	ICE_CD_4_S	12
#define	ICE_CD_8_M	0xff00U
#define	ICE_CD_8_S	16

	inkey.ipk_xlt1 = ptg;
	xlt2_cdid = vsig;
	inkey.ipk_flags = LE_16(flags);

	switch (ice->ice_blk[blk].ibi_prof.ipt_cdid_bits) {
	case 0:
		break;
	case 2:
		xlt2_cdid &= (uint16_t)~ICE_CD_2_M;
		xlt2_cdid |= (uint16_t)(((uint32_t)1 << cdid) << ICE_CD_2_S);
		break;
	case 4:
		xlt2_cdid &= (uint16_t)~ICE_CD_4_M;
		xlt2_cdid |= (uint16_t)(((uint32_t)1 << cdid) << ICE_CD_4_S);
		break;
	case 8:
		xlt2_cdid &= (uint16_t)~ICE_CD_8_M;
		xlt2_cdid |= (uint16_t)(((uint32_t)1 << cdid) << ICE_CD_8_S);
		break;
	default:
		break;
	}

	inkey.ipk_xlt2_cdid = LE_16(xlt2_cdid);

	return (ice_set_key(key, ICE_TCAM_KEY_SZ, (uint8_t *)&inkey, vl_msk,
	    dc_msk, nm_msk, 0, ICE_TCAM_KEY_SZ / 2));
}

/*
 * ice_tcam_write_entry - write a single profile ID TCAM entry
 */
static bool
ice_tcam_write_entry(ice_t *ice, ice_block_t blk, uint16_t idx,
    uint8_t prof_id, uint8_t ptg, uint16_t vsig, uint8_t cdid, uint16_t flags,
    uint8_t vl_msk[ICE_TCAM_KEY_VAL_SZ], uint8_t dc_msk[ICE_TCAM_KEY_VAL_SZ],
    uint8_t nm_msk[ICE_TCAM_KEY_VAL_SZ])
{
	ice_prof_tcam_t *prof = &ice->ice_blk[blk].ibi_prof;

	if (!ice_prof_gen_key(ice, blk, ptg, vsig, cdid, flags, vl_msk, dc_msk,
	    nm_msk, prof->ipt_t[idx].ipte_key)) {
		return (false);
	}

	prof->ipt_t[idx].ipte_addr = LE_16(idx);
	prof->ipt_t[idx].ipte_prof_id = prof_id;

	return (true);
}

/*
 * ice_tcam_ent_rsrc_type - map a block to its TCAM entry resource type
 */
static bool
ice_tcam_ent_rsrc_type(ice_block_t blk, uint16_t *type)
{
	switch (blk) {
	case ICE_BLK_RSS:
		*type = ICE_RES_TYPE_HASH_PROF_BLDR_TCAM;
		break;
	case ICE_BLK_PE:
		*type = ICE_RES_TYPE_QHASH_PROF_BLDR_TCAM;
		break;
	default:
		return (false);
	}

	return (true);
}

/*
 * ice_alloc_tcam_ent - allocate a single profile ID TCAM entry
 */
static bool
ice_alloc_tcam_ent(ice_t *ice, ice_block_t blk, bool btm, uint16_t *tcam_idx)
{
	uint16_t	type;
	uint16_t	nres;
	uint16_t	buf[3] = { 0 };
	ice_res_entry_t	*res = (ice_res_entry_t *)buf;

	if (!ice_tcam_ent_rsrc_type(blk, &type))
		return (false);

	res->ire_info = ICE_RES_INFO_SET_TYPE(0, type);
	res->ire_info = ICE_RES_INFO_SET_PERSISTENT(res->ire_info, 0);
	res->ire_info = ICE_RES_INFO_SET_IGNORE_IDX(res->ire_info, 1);
	if (btm)
		res->ire_info = ICE_RES_INFO_SET_SCAN_LAST(res->ire_info, 1);
	res->ire_info = LE_16(res->ire_info);

	res->ire_ndesc = LE_16(1);
	nres = 1;

	if (!ice_cmd_allocate_resource(ice, res, &nres))
		return (false);

	*tcam_idx = LE_16(res->ire_descs[0]);
	return (true);
}

/*
 * ice_free_tcam_ent - free a single profile ID TCAM entry
 */
static bool
ice_free_tcam_ent(ice_t *ice, ice_block_t blk, uint16_t tcam_idx)
{
	uint16_t	type;
	uint16_t	nres;
	uint16_t	buf[3] = { 0 };
	ice_res_entry_t	*res = (ice_res_entry_t *)buf;

	if (!ice_tcam_ent_rsrc_type(blk, &type))
		return (false);

	res->ire_info = LE_16(ICE_RES_INFO_SET_TYPE(0, type));
	res->ire_ndesc = LE_16(1);
	res->ire_descs[0] = LE_16(tcam_idx);

	nres = 1;

	return (ice_cmd_free_resource(ice, res, nres));
}

/*
 * ice_prof_dec_ref - drop a reference on a hardware profile, freeing it
 * (clearing its extraction sequence entry and releasing the profile ID)
 * once the last reference is dropped.
 */
static bool
ice_prof_dec_ref(ice_t *ice, ice_block_t blk, uint8_t prof_id)
{
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;

	if (prof_id > es->ie_count)
		return (false);

	if (es->ie_ref_count[prof_id] > 0) {
		if (--es->ie_ref_count[prof_id] == 0) {
			ice_write_es(es, prof_id, NULL);
			return (ice_free_prof_id(ice, blk, prof_id));
		}
	}

	return (true);
}

/*
 * ice_vsig_alloc - find a free VSIG entry and mark it in use
 */
static uint16_t
ice_vsig_alloc(ice_t *ice, ice_block_t blk)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t i;

	for (i = 1; i < ICE_MAX_VSIGS; i++) {
		if (!xlt2->ix2_vsig_tbl[i].ive_in_use)
			return (ice_vsig_alloc_val(xlt2, i, ice->ice_pf_id));
	}

	return (ICE_DEFAULT_VSIG);
}

/*
 * ice_match_prop_lst - determine if two VSIG characteristic (profile) lists
 * are identical, including order (which reflects priority).
 */
static bool
ice_match_prop_lst(list_t *l1, list_t *l2)
{
	ice_vsig_prof_t *p1, *p2;
	uint16_t count = 0, chk_count = 0;

	for (p1 = list_head(l1); p1 != NULL; p1 = list_next(l1, p1))
		count++;
	for (p2 = list_head(l2); p2 != NULL; p2 = list_next(l2, p2))
		chk_count++;

	if (count == 0 || count != chk_count)
		return (false);

	p1 = list_head(l1);
	p2 = list_head(l2);

	while (count-- != 0) {
		if (p1 == NULL || p2 == NULL)
			return (false);

		if (p1->ivp_profile_cookie != p2->ivp_profile_cookie)
			return (false);

		p1 = list_next(l1, p1);
		p2 = list_next(l2, p2);
	}

	return (true);
}

/*
 * ice_find_dup_props_vsig - find a VSIG whose characteristic list exactly
 * matches (including order) the given list.
 */
static bool
ice_find_dup_props_vsig(ice_t *ice, ice_block_t blk, list_t *chs,
    uint16_t *vsig)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t i;

	for (i = 0; i < xlt2->ix2_count; i++) {
		if (xlt2->ix2_vsig_tbl[i].ive_in_use &&
		    ice_match_prop_lst(chs,
		    &xlt2->ix2_vsig_tbl[i].ive_prop_lst)) {
			*vsig = ICE_VSIG_VALUE(i, ice->ice_pf_id);
			return (true);
		}
	}

	return (false);
}

/*
 * ice_vsig_free - remove all VSIs from a VSIG (moving them to the default
 * VSIG), free its characteristic list, and mark the VSIG entry free.
 */
static bool
ice_vsig_free(ice_t *ice, ice_block_t blk, uint16_t vsig)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	ice_vsig_vsi_t *vsi_cur;
	ice_vsig_prof_t *p;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;

	if (idx >= ICE_MAX_VSIGS)
		return (false);

	if (!xlt2->ix2_vsig_tbl[idx].ive_in_use)
		return (false);

	xlt2->ix2_vsig_tbl[idx].ive_in_use = false;

	vsi_cur = xlt2->ix2_vsig_tbl[idx].ive_first_vsi;
	if (vsi_cur != NULL) {
		ice_vsig_vsi_t *tmp;

		do {
			tmp = vsi_cur->ivv_next_vsi;

			vsi_cur->ivv_vsig = ICE_DEFAULT_VSIG;
			vsi_cur->ivv_changed = 1;
			vsi_cur->ivv_next_vsi = NULL;
			vsi_cur = tmp;
		} while (vsi_cur != NULL);

		xlt2->ix2_vsig_tbl[idx].ive_first_vsi = NULL;
	}

	while ((p = list_remove_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst)) !=
	    NULL) {
		kmem_free(p, sizeof (*p));
	}

	return (true);
}

/*
 * ice_vsig_get_ref - return the number of VSIs belonging to a VSIG
 */
static bool
ice_vsig_get_ref(ice_t *ice, ice_block_t blk, uint16_t vsig, uint16_t *refs)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	ice_vsig_vsi_t *p;

	*refs = 0;

	if (!xlt2->ix2_vsig_tbl[idx].ive_in_use)
		return (false);

	for (p = xlt2->ix2_vsig_tbl[idx].ive_first_vsi; p != NULL;
	    p = p->ivv_next_vsi) {
		(*refs)++;
	}

	return (true);
}

/*
 * ice_has_prof_vsig - determine if a VSIG already contains the profile
 * indicated by the given profile handle.
 */
static bool
ice_has_prof_vsig(ice_t *ice, ice_block_t blk, uint16_t vsig, uint64_t hdl)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	ice_vsig_prof_t *ent;

	for (ent = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst);
	    ent != NULL;
	    ent = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, ent)) {
		if (ent->ivp_profile_cookie == hdl)
			return (true);
	}

	return (false);
}

/*
 * ice_vsig_prof_id_count - count the number of profiles associated with a
 * VSIG.
 */
static uint16_t
ice_vsig_prof_id_count(ice_t *ice, ice_block_t blk, uint16_t vsig)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	uint16_t count = 0;
	ice_vsig_prof_t *p;

	for (p = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst); p != NULL;
	    p = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, p)) {
		count++;
	}

	return (count);
}

/*
 * ice_find_prof_vsig - find a VSIG with only the specified profile handle
 * (used to find/re-use a VSIG for a brand new VSI/profile association).
 */
static bool
ice_find_prof_vsig(ice_t *ice, ice_block_t blk, uint64_t hdl, uint16_t *vsig)
{
	list_t lst;
	ice_vsig_prof_t *t;
	bool found;

	list_create(&lst, sizeof (ice_vsig_prof_t),
	    offsetof(ice_vsig_prof_t, ivp_node));

	t = kmem_zalloc(sizeof (*t), KM_SLEEP);
	t->ivp_profile_cookie = hdl;
	list_insert_head(&lst, t);

	found = ice_find_dup_props_vsig(ice, blk, &lst, vsig);

	list_remove(&lst, t);
	kmem_free(t, sizeof (*t));
	list_destroy(&lst);

	return (found);
}

/*
 * ice_rel_tcam_idx - release a TCAM index, first overwriting it with a
 * "never match" entry so hardware doesn't act on stale data before the
 * index is reused.
 */
static bool
ice_rel_tcam_idx(ice_t *ice, ice_block_t blk, uint16_t idx)
{
	uint8_t vl_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t dc_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xfe, 0xff, 0xff, 0xff, 0xff };
	uint8_t nm_msk[ICE_TCAM_KEY_VAL_SZ] = { 0x01, 0x00, 0x00, 0x00, 0x00 };

	if (!ice_tcam_write_entry(ice, blk, idx, 0, 0, 0, 0, 0, vl_msk, dc_msk,
	    nm_msk)) {
		return (false);
	}

	return (ice_free_tcam_ent(ice, blk, idx));
}

/*
 * ice_rem_prof_id - release all of the TCAM entries used by one profile
 * within a VSIG's characteristic list.
 */
static bool
ice_rem_prof_id(ice_t *ice, ice_block_t blk, ice_vsig_prof_t *prof)
{
	uint16_t i;

	for (i = 0; i < prof->ivp_tcam_count; i++) {
		if (prof->ivp_tcam[i].itc_in_use) {
			prof->ivp_tcam[i].itc_in_use = false;
			if (!ice_rel_tcam_idx(ice, blk,
			    prof->ivp_tcam[i].itc_tcam_idx)) {
				return (false);
			}
		}
	}

	return (true);
}

/*
 * ice_rem_vsig - remove a VSIG entirely: release all of its profiles' TCAM
 * entries, move all of its VSIs back to the default VSIG (recording a
 * change-list entry for each), and free the VSIG entry itself.
 */
static bool
ice_rem_vsig(ice_t *ice, ice_block_t blk, uint16_t vsig, list_t *chg)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	ice_vsig_vsi_t *vsi_cur;
	ice_vsig_prof_t *d, *dtmp;

	for (d = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst); d != NULL;
	    d = dtmp) {
		dtmp = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, d);

		if (!ice_rem_prof_id(ice, blk, d))
			return (false);

		list_remove(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, d);
		kmem_free(d, sizeof (*d));
	}

	vsi_cur = xlt2->ix2_vsig_tbl[idx].ive_first_vsi;
	if (vsi_cur != NULL) {
		do {
			ice_vsig_vsi_t *tmp = vsi_cur->ivv_next_vsi;
			ice_chs_chg_t *p;

			p = kmem_zalloc(sizeof (*p), KM_SLEEP);
			p->icc_type = ICE_VSIG_REM;
			p->icc_orig_vsig = vsig;
			p->icc_vsig = ICE_DEFAULT_VSIG;
			p->icc_vsi = (uint16_t)(vsi_cur - xlt2->ix2_vsis);

			list_insert_head(chg, p);

			vsi_cur = tmp;
		} while (vsi_cur != NULL);
	}

	return (ice_vsig_free(ice, blk, vsig));
}

/*
 * ice_rem_prof_id_vsig - remove a single profile from a VSIG; if it is the
 * last profile in the VSIG, remove the whole VSIG instead.
 */
static bool
ice_rem_prof_id_vsig(ice_t *ice, ice_block_t blk, uint16_t vsig, uint64_t hdl,
    list_t *chg)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	ice_vsig_prof_t *p;

	for (p = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst); p != NULL;
	    p = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, p)) {
		if (p->ivp_profile_cookie != hdl)
			continue;

		if (ice_vsig_prof_id_count(ice, blk, vsig) == 1)
			return (ice_rem_vsig(ice, blk, vsig, chg));

		if (!ice_rem_prof_id(ice, blk, p))
			return (false);

		list_remove(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, p);
		kmem_free(p, sizeof (*p));
		return (true);
	}

	return (false);
}

/*
 * ice_rem_prof_from_list - remove and free a single profile entry from a
 * (software-only) list of ice_vsig_prof_t, matched by profile handle.
 */
static bool
ice_rem_prof_from_list(list_t *lst, uint64_t hdl)
{
	ice_vsig_prof_t *p;

	for (p = list_head(lst); p != NULL; p = list_next(lst, p)) {
		if (p->ivp_profile_cookie == hdl) {
			list_remove(lst, p);
			kmem_free(p, sizeof (*p));
			return (true);
		}
	}

	return (false);
}

/*
 * ice_get_prof - add a change-list entry to (re)write the extraction
 * sequence table entry for the profile indicated by the given handle, if it
 * has not already been written to hardware.
 */
static bool
ice_get_prof(ice_t *ice, ice_block_t blk, uint64_t hdl, list_t *chg)
{
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;
	ice_prof_map_t *map;
	uint16_t i;

	for (map = list_head(&es->ie_prof_map); map != NULL;
	    map = list_next(&es->ie_prof_map, map)) {
		if (map->ipm_profile_cookie == hdl)
			break;
	}

	if (map == NULL)
		return (false);

	for (i = 0; i < map->ipm_ptg_cnt; i++) {
		ice_chs_chg_t *p;

		if (es->ie_written[map->ipm_prof_id])
			continue;

		p = kmem_zalloc(sizeof (*p), KM_SLEEP);
		p->icc_type = ICE_PTG_ES_ADD;
		p->icc_ptype = 0;
		p->icc_ptg = map->ipm_ptg[i];
		p->icc_add_ptg = false;

		p->icc_add_prof = true;
		p->icc_prof_id = map->ipm_prof_id;

		es->ie_written[map->ipm_prof_id] = true;

		list_insert_head(chg, p);
	}

	return (true);
}

/*
 * ice_get_profs_vsig - make a copy of a VSIG's characteristic (profile)
 * list.
 */
static bool
ice_get_profs_vsig(ice_t *ice, ice_block_t blk, uint16_t vsig, list_t *lst)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;
	ice_vsig_prof_t *ent;

	for (ent = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst);
	    ent != NULL;
	    ent = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, ent)) {
		ice_vsig_prof_t *p;

		p = kmem_alloc(sizeof (*p), KM_SLEEP);
		bcopy(ent, p, sizeof (*p));
		list_insert_tail(lst, p);
	}

	return (true);
}

/*
 * ice_add_prof_to_lst - add an entry for the given profile handle to a
 * (software-only) list of ice_vsig_prof_t.
 */
static bool
ice_add_prof_to_lst(ice_t *ice, ice_block_t blk, list_t *lst, uint64_t hdl)
{
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;
	ice_prof_map_t *map;
	ice_vsig_prof_t *p;
	uint16_t i;

	for (map = list_head(&es->ie_prof_map); map != NULL;
	    map = list_next(&es->ie_prof_map, map)) {
		if (map->ipm_profile_cookie == hdl)
			break;
	}

	if (map == NULL)
		return (false);

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);
	p->ivp_profile_cookie = map->ipm_profile_cookie;
	p->ivp_prof_id = map->ipm_prof_id;
	p->ivp_tcam_count = map->ipm_ptg_cnt;

	for (i = 0; i < map->ipm_ptg_cnt; i++) {
		p->ivp_tcam[i].itc_prof_id = map->ipm_prof_id;
		p->ivp_tcam[i].itc_tcam_idx = ICE_INVALID_TCAM;
		p->ivp_tcam[i].itc_ptg = map->ipm_ptg[i];
	}

	list_insert_head(lst, p);

	return (true);
}

/*
 * ice_move_vsi - move (or add) a VSI to the given VSIG, recording a
 * change-list entry describing the move.
 */
static bool
ice_move_vsi(ice_t *ice, ice_block_t blk, uint16_t vsi, uint16_t vsig,
    list_t *chg)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	ice_chs_chg_t *p;
	uint16_t orig_vsig;

	if (!ice_vsig_find_vsi(xlt2, vsi, &orig_vsig))
		return (false);

	if (ice_vsig_add_mv_vsi(xlt2, vsi, vsig, ice->ice_pf_id) != 0)
		return (false);

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);
	p->icc_type = ICE_VSI_MOVE;
	p->icc_vsi = vsi;
	p->icc_orig_vsig = orig_vsig;
	p->icc_vsig = vsig;

	list_insert_head(chg, p);

	return (true);
}

/*
 * ice_rem_chg_tcam_ent - remove any pending "add TCAM" change-list entry
 * for the given TCAM index. Used when a TCAM entry is being disabled
 * (freed) before it was ever pushed to hardware.
 */
static void
ice_rem_chg_tcam_ent(uint16_t idx, list_t *chg)
{
	ice_chs_chg_t *tmp, *next;

	for (tmp = list_head(chg); tmp != NULL; tmp = next) {
		next = list_next(chg, tmp);

		if (tmp->icc_type == ICE_TCAM_ADD &&
		    tmp->icc_tcam_idx == idx) {
			list_remove(chg, tmp);
			kmem_free(tmp, sizeof (*tmp));
		}
	}
}

/*
 * ice_prof_tcam_ena_dis - enable or disable a single TCAM entry belonging
 * to a profile within a VSIG, recording the appropriate change-list entry.
 */
static bool
ice_prof_tcam_ena_dis(ice_t *ice, ice_block_t blk, bool enable, uint16_t vsig,
    ice_tcam_inf_t *tcam, list_t *chg)
{
	uint8_t vl_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t dc_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xff, 0xff, 0x00, 0x00, 0x00 };
	uint8_t nm_msk[ICE_TCAM_KEY_VAL_SZ] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	ice_chs_chg_t *p;

	if (!enable) {
		bool ret = ice_rel_tcam_idx(ice, blk, tcam->itc_tcam_idx);

		ice_rem_chg_tcam_ent(tcam->itc_tcam_idx, chg);
		tcam->itc_tcam_idx = 0;
		tcam->itc_in_use = false;
		return (ret);
	}

	if (!ice_alloc_tcam_ent(ice, blk, true, &tcam->itc_tcam_idx))
		return (false);

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);

	if (!ice_tcam_write_entry(ice, blk, tcam->itc_tcam_idx,
	    tcam->itc_prof_id, tcam->itc_ptg, vsig, 0, 0, vl_msk, dc_msk,
	    nm_msk)) {
		kmem_free(p, sizeof (*p));
		return (false);
	}

	tcam->itc_in_use = true;

	p->icc_type = ICE_TCAM_ADD;
	p->icc_add_tcam_idx = true;
	p->icc_prof_id = tcam->itc_prof_id;
	p->icc_ptg = tcam->itc_ptg;
	p->icc_vsig = 0;
	p->icc_tcam_idx = tcam->itc_tcam_idx;

	list_insert_head(chg, p);

	return (true);
}

/*
 * ice_adj_prof_priorities - within a VSIG, ensure that for each PTG only
 * the highest-priority (most recently added) profile's TCAM entry is
 * enabled; all others sharing the same PTG are disabled.
 */
static bool
ice_adj_prof_priorities(ice_t *ice, ice_block_t blk, uint16_t vsig,
    list_t *chg)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	ulong_t ptgs_used[ICE_XLT1_CNT / BT_NBIPUL] = { 0 };
	ice_vsig_prof_t *t;
	uint16_t idx = vsig & ICE_VSIG_IDX_M;

	for (t = list_head(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst); t != NULL;
	    t = list_next(&xlt2->ix2_vsig_tbl[idx].ive_prop_lst, t)) {
		uint16_t i;

		for (i = 0; i < t->ivp_tcam_count; i++) {
			bool used = BT_TEST(ptgs_used, t->ivp_tcam[i].itc_ptg);

			if (used && t->ivp_tcam[i].itc_in_use) {
				if (!ice_prof_tcam_ena_dis(ice, blk, false,
				    vsig, &t->ivp_tcam[i], chg)) {
					return (false);
				}
			} else if (!used && !t->ivp_tcam[i].itc_in_use) {
				if (!ice_prof_tcam_ena_dis(ice, blk, true,
				    vsig, &t->ivp_tcam[i], chg)) {
					return (false);
				}
			}

			BT_SET(ptgs_used, t->ivp_tcam[i].itc_ptg);
		}
	}

	return (true);
}

/*
 * ice_add_prof_id_vsig - add the profile indicated by the given handle to
 * a VSIG, allocating and writing its TCAM entries.
 */
static bool
ice_add_prof_id_vsig(ice_t *ice, ice_block_t blk, uint16_t vsig, uint64_t hdl,
    bool rev, list_t *chg)
{
	uint8_t vl_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t dc_msk[ICE_TCAM_KEY_VAL_SZ] = { 0xff, 0xff, 0x00, 0x00, 0x00 };
	uint8_t nm_msk[ICE_TCAM_KEY_VAL_SZ] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	ice_prof_map_t *map;
	ice_vsig_prof_t *t;
	uint16_t vsig_idx, i;

	if (ice_has_prof_vsig(ice, blk, vsig, hdl))
		return (false);

	t = kmem_zalloc(sizeof (*t), KM_SLEEP);

	for (map = list_head(&es->ie_prof_map); map != NULL;
	    map = list_next(&es->ie_prof_map, map)) {
		if (map->ipm_profile_cookie == hdl)
			break;
	}

	if (map == NULL) {
		kmem_free(t, sizeof (*t));
		return (false);
	}

	t->ivp_profile_cookie = map->ipm_profile_cookie;
	t->ivp_prof_id = map->ipm_prof_id;
	t->ivp_tcam_count = map->ipm_ptg_cnt;

	for (i = 0; i < map->ipm_ptg_cnt; i++) {
		ice_chs_chg_t *p;
		uint16_t tcam_idx;

		p = kmem_zalloc(sizeof (*p), KM_SLEEP);

		if (!ice_alloc_tcam_ent(ice, blk, true, &tcam_idx)) {
			kmem_free(p, sizeof (*p));
			kmem_free(t, sizeof (*t));
			return (false);
		}

		t->ivp_tcam[i].itc_ptg = map->ipm_ptg[i];
		t->ivp_tcam[i].itc_prof_id = map->ipm_prof_id;
		t->ivp_tcam[i].itc_tcam_idx = tcam_idx;
		t->ivp_tcam[i].itc_in_use = true;

		p->icc_type = ICE_TCAM_ADD;
		p->icc_add_tcam_idx = true;
		p->icc_prof_id = t->ivp_tcam[i].itc_prof_id;
		p->icc_ptg = t->ivp_tcam[i].itc_ptg;
		p->icc_vsig = vsig;
		p->icc_tcam_idx = t->ivp_tcam[i].itc_tcam_idx;

		if (!ice_tcam_write_entry(ice, blk,
		    t->ivp_tcam[i].itc_tcam_idx, t->ivp_tcam[i].itc_prof_id,
		    t->ivp_tcam[i].itc_ptg, vsig, 0, 0, vl_msk, dc_msk,
		    nm_msk)) {
			kmem_free(p, sizeof (*p));
			kmem_free(t, sizeof (*t));
			return (false);
		}

		list_insert_head(chg, p);
	}

	vsig_idx = vsig & ICE_VSIG_IDX_M;
	if (rev) {
		list_insert_tail(&xlt2->ix2_vsig_tbl[vsig_idx].ive_prop_lst,
		    t);
	} else {
		list_insert_head(&xlt2->ix2_vsig_tbl[vsig_idx].ive_prop_lst,
		    t);
	}

	return (true);
}

/*
 * ice_create_prof_id_vsig - allocate a brand new VSIG containing a single
 * VSI and a single profile.
 */
static bool
ice_create_prof_id_vsig(ice_t *ice, ice_block_t blk, uint16_t vsi,
    uint64_t hdl, list_t *chg)
{
	ice_chs_chg_t *p;
	uint16_t new_vsig;

	new_vsig = ice_vsig_alloc(ice, blk);
	if (new_vsig == ICE_DEFAULT_VSIG)
		return (false);

	if (!ice_move_vsi(ice, blk, vsi, new_vsig, chg))
		return (false);

	if (!ice_add_prof_id_vsig(ice, blk, new_vsig, hdl, false, chg))
		return (false);

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);
	p->icc_type = ICE_VSIG_ADD;
	p->icc_vsi = vsi;
	p->icc_orig_vsig = ICE_DEFAULT_VSIG;
	p->icc_vsig = new_vsig;

	list_insert_head(chg, p);

	return (true);
}

/*
 * ice_create_vsig_from_lst - allocate a brand new VSIG containing a single
 * VSI and the given list of profiles (added in reverse order, since the
 * list is itself ordered newest-first).
 */
static bool
ice_create_vsig_from_lst(ice_t *ice, ice_block_t blk, uint16_t vsi,
    list_t *lst, uint16_t *new_vsig, list_t *chg)
{
	ice_vsig_prof_t *t;
	uint16_t vsig;

	vsig = ice_vsig_alloc(ice, blk);
	if (vsig == ICE_DEFAULT_VSIG)
		return (false);

	if (!ice_move_vsi(ice, blk, vsi, vsig, chg))
		return (false);

	for (t = list_head(lst); t != NULL; t = list_next(lst, t)) {
		if (!ice_add_prof_id_vsig(ice, blk, vsig,
		    t->ivp_profile_cookie, true, chg)) {
			return (false);
		}
	}

	*new_vsig = vsig;

	return (true);
}

/*
 * The (4096-byte) package update buffer being built, matching the on-wire
 * ice_pkg_buf_hdr_t/ice_pkg_sect_t layout used by ice_ddp.c's read-side
 * parser. ipbb_reserved tracks how many section-table slots have been
 * reserved (via ice_pkg_buf_reserve_section()) so far.
 */
typedef struct ice_pkg_buf_build {
	uint8_t		ipbb_data[ICE_PKG_BUF_LEN];
	uint16_t	ipbb_reserved;
} ice_pkg_buf_build_t;

static ice_pkg_buf_build_t *
ice_pkg_buf_alloc(void)
{
	ice_pkg_buf_build_t *bld;
	ice_pkg_buf_hdr_t *hdr;

	bld = kmem_zalloc(sizeof (*bld), KM_SLEEP);
	hdr = (ice_pkg_buf_hdr_t *)bld->ipbb_data;
	LE_OUT16(&hdr->ipbh_data_end, sizeof (*hdr));

	return (bld);
}

static void
ice_pkg_buf_free(ice_pkg_buf_build_t *bld)
{
	kmem_free(bld, sizeof (*bld));
}

/*
 * ice_pkg_buf_reserve_section - reserve room in the section table for
 * "count" additional sections. Must be called (once) before any sections
 * are allocated.
 */
static bool
ice_pkg_buf_reserve_section(ice_pkg_buf_build_t *bld, uint16_t count)
{
	ice_pkg_buf_hdr_t *hdr = (ice_pkg_buf_hdr_t *)bld->ipbb_data;
	uint16_t data_end;

	if (LE_IN16(&hdr->ipbh_size) > 0)
		return (false);

	if ((uint32_t)bld->ipbb_reserved + count > ICE_MAX_S_COUNT)
		return (false);

	bld->ipbb_reserved += count;

	data_end = LE_IN16(&hdr->ipbh_data_end) +
	    count * sizeof (ice_pkg_sect_t);
	LE_OUT16(&hdr->ipbh_data_end, data_end);

	return (true);
}

/*
 * ice_pkg_buf_alloc_section - allocate "size" bytes for a new section of
 * the given type, 4-byte aligned, returning a pointer to the section's
 * data (or NULL on failure).
 */
static void *
ice_pkg_buf_alloc_section(ice_pkg_buf_build_t *bld, uint32_t type,
    uint16_t size)
{
	ice_pkg_buf_hdr_t *hdr = (ice_pkg_buf_hdr_t *)bld->ipbb_data;
	ice_pkg_sect_t	*sects;
	uint16_t	sect_count, data_end;

	if (type == 0 || size == 0)
		return (NULL);

	data_end = P2ROUNDUP(LE_IN16(&hdr->ipbh_data_end), 4);

	if ((uint32_t)data_end + size > ICE_MAX_S_DATA_END)
		return (NULL);

	sect_count = LE_IN16(&hdr->ipbh_size);
	if (sect_count >= bld->ipbb_reserved)
		return (NULL);

	sects = (ice_pkg_sect_t *)(bld->ipbb_data + sizeof (*hdr));
	LE_OUT16(&sects[sect_count].ips_offset, data_end);
	LE_OUT16(&sects[sect_count].ips_size, size);
	LE_OUT32(&sects[sect_count].ips_type, type);

	LE_OUT16(&hdr->ipbh_data_end, data_end + size);
	LE_OUT16(&hdr->ipbh_size, sect_count + 1);

	return (bld->ipbb_data + data_end);
}

static uint16_t
ice_pkg_buf_get_active_sections(ice_pkg_buf_build_t *bld)
{
	ice_pkg_buf_hdr_t *hdr = (ice_pkg_buf_hdr_t *)bld->ipbb_data;

	return (LE_IN16(&hdr->ipbh_size));
}

/*
 * Return how much data has been written to bld. This is needed when
 * updating the package data, as the command doesn't accept trailing
 * padding apparently.
 */
static uint16_t
ice_pkg_buf_get_data_end(ice_pkg_buf_build_t *bld)
{
	ice_pkg_buf_hdr_t *hdr = (ice_pkg_buf_hdr_t *)bld->ipbb_data;

	return (LE_IN16(&hdr->ipbh_data_end));
}

/*
 * ice_prof_bld_es - append extraction-sequence table update sections for
 * every ICE_PTG_ES_ADD change-list entry that requests one (icc_add_prof).
 */
static bool
ice_prof_bld_es(ice_t *ice, ice_block_t blk, ice_pkg_buf_build_t *bld,
    list_t *chgs)
{
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;
	uint16_t vec_size = es->ie_fvw * sizeof (ice_fv_word_t);
	ice_chs_chg_t *tmp;

	for (tmp = list_head(chgs); tmp != NULL; tmp = list_next(chgs, tmp)) {
		uint8_t *p;
		uint16_t off;

		if (tmp->icc_type != ICE_PTG_ES_ADD || !tmp->icc_add_prof)
			continue;

		off = tmp->icc_prof_id * es->ie_fvw;

		p = ice_pkg_buf_alloc_section(bld, es->ie_sid,
		    2 * sizeof (uint16_t) + vec_size);
		if (p == NULL)
			return (false);

		LE_OUT16(p, 1);
		p += sizeof (uint16_t);

		LE_OUT16(p, (uint16_t)tmp->icc_prof_id);
		p += sizeof (uint16_t);

		bcopy(&es->ie_t[off], p, vec_size);
	}

	return (true);
}

/*
 * ice_prof_bld_tcam - append profile ID TCAM update sections for every
 * ICE_TCAM_ADD change-list entry that requests one (icc_add_tcam_idx).
 */
static bool
ice_prof_bld_tcam(ice_t *ice, ice_block_t blk, ice_pkg_buf_build_t *bld,
    list_t *chgs)
{
	ice_prof_tcam_t *prof = &ice->ice_blk[blk].ibi_prof;
	ice_chs_chg_t *tmp;

	for (tmp = list_head(chgs); tmp != NULL; tmp = list_next(chgs, tmp)) {
		uint8_t *p;

		if (tmp->icc_type != ICE_TCAM_ADD || !tmp->icc_add_tcam_idx)
			continue;

		p = ice_pkg_buf_alloc_section(bld, prof->ipt_sid,
		    sizeof (uint16_t) + sizeof (ice_prof_tcam_entry_t));
		if (p == NULL)
			return (false);

		LE_OUT16(p, 1);
		bcopy(&prof->ipt_t[tmp->icc_tcam_idx], p + 2,
		    sizeof (ice_prof_tcam_entry_t));
	}

	return (true);
}

/*
 * ice_prof_bld_xlt1 - append XLT1 (PTYPE -> PTG) update sections for every
 * ICE_PTG_ES_ADD change-list entry that requests one (icc_add_ptg).
 */
static bool
ice_prof_bld_xlt1(ice_t *ice, ice_block_t blk, ice_pkg_buf_build_t *bld,
    list_t *chgs)
{
	ice_xlt1_t *xlt1 = &ice->ice_blk[blk].ibi_xlt1;
	ice_chs_chg_t *tmp;

	for (tmp = list_head(chgs); tmp != NULL; tmp = list_next(chgs, tmp)) {
		uint8_t *p;

		if (tmp->icc_type != ICE_PTG_ES_ADD || !tmp->icc_add_ptg)
			continue;

		p = ice_pkg_buf_alloc_section(bld, xlt1->ix1_sid,
		    2 * sizeof (uint16_t) + sizeof (uint8_t));
		if (p == NULL)
			return (false);

		LE_OUT16(p, 1);
		LE_OUT16(p + 2, tmp->icc_ptype);
		p[4] = tmp->icc_ptg;
	}

	return (true);
}

/*
 * ice_prof_bld_xlt2 - append XLT2 (VSI -> VSIG) update sections for every
 * ICE_VSIG_ADD/ICE_VSI_MOVE/ICE_VSIG_REM change-list entry.
 */
static bool
ice_prof_bld_xlt2(ice_t *ice, ice_block_t blk, ice_pkg_buf_build_t *bld,
    list_t *chgs)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	ice_chs_chg_t *tmp;

	for (tmp = list_head(chgs); tmp != NULL; tmp = list_next(chgs, tmp)) {
		uint8_t *p;

		switch (tmp->icc_type) {
		case ICE_VSIG_ADD:
		case ICE_VSI_MOVE:
		case ICE_VSIG_REM:
			break;
		default:
			continue;
		}

		p = ice_pkg_buf_alloc_section(bld, xlt2->ix2_sid,
		    2 * sizeof (uint16_t) + sizeof (uint16_t));
		if (p == NULL)
			return (false);

		LE_OUT16(p, 1);
		LE_OUT16(p + 2, tmp->icc_vsi);
		LE_OUT16(p + 4, tmp->icc_vsig);
	}

	return (true);
}

/*
 * ice_upd_prof_hw - build a package-update buffer from the accumulated
 * change list (in ES, TCAM, XLT1, XLT2 order) and push it to hardware via
 * the AQ "update package" command.
 */
static bool
ice_upd_prof_hw(ice_t *ice, ice_block_t blk, list_t *chgs)
{
	ice_pkg_buf_build_t *b;
	ice_chs_chg_t *tmp;
	uint16_t xlt1 = 0, xlt2 = 0, tcam = 0, es = 0, sects, pkg_sects;
	bool ret = false;

	for (tmp = list_head(chgs); tmp != NULL; tmp = list_next(chgs, tmp)) {
		switch (tmp->icc_type) {
		case ICE_PTG_ES_ADD:
			if (tmp->icc_add_ptg)
				xlt1++;
			if (tmp->icc_add_prof)
				es++;
			break;
		case ICE_TCAM_ADD:
			tcam++;
			break;
		case ICE_VSIG_ADD:
		case ICE_VSI_MOVE:
		case ICE_VSIG_REM:
			xlt2++;
			break;
		default:
			break;
		}
	}

	sects = xlt1 + xlt2 + tcam + es;
	if (sects == 0)
		return (true);

	b = ice_pkg_buf_alloc();

	if (!ice_pkg_buf_reserve_section(b, sects))
		goto done;

	if (es != 0 && !ice_prof_bld_es(ice, blk, b, chgs))
		goto done;

	if (tcam != 0 && !ice_prof_bld_tcam(ice, blk, b, chgs))
		goto done;

	if (xlt1 != 0 && !ice_prof_bld_xlt1(ice, blk, b, chgs))
		goto done;

	if (xlt2 != 0 && !ice_prof_bld_xlt2(ice, blk, b, chgs))
		goto done;

	pkg_sects = ice_pkg_buf_get_active_sections(b);
	if (pkg_sects == 0 || pkg_sects != sects)
		goto done;

	/*
	 * The tables this command updates (XLT1, XLT2, profile ID TCAM, and
	 * the ES/field-vector table) are a device-wide hardware resource
	 * shared across every PF, so we must hold the change lock across
	 * the AQ command, mirroring the FreeBSD driver's ice_update_pkg().
	 * Without this, the update can be rejected (or race with another
	 * PF's update) since we never actually own the resource we're
	 * modifying.
	 */
	if (!ice_cmd_acquire_change_lock(ice, true))
		goto done;

	ret = ice_cmd_update_pkg(ice, b->ipbb_data,
	    ice_pkg_buf_get_data_end(b), true);

	if (!ice_cmd_release_change_lock(ice))
		ret = false;

done:
	ice_pkg_buf_free(b);
	return (ret);
}

/*
 * ice_add_vsi_flow - add the given VSI to the given (already-existing)
 * VSIG and push the resulting hardware table change.
 */
bool
ice_add_vsi_flow(ice_t *ice, ice_block_t blk, uint16_t vsi, uint16_t vsig)
{
	list_t chg;
	ice_chs_chg_t *d;
	bool ret;

	if ((vsig & ICE_VSIG_IDX_M) == ICE_DEFAULT_VSIG)
		return (false);

	list_create(&chg, sizeof (ice_chs_chg_t),
	    offsetof(ice_chs_chg_t, icc_node));

	ret = ice_move_vsi(ice, blk, vsi, vsig, &chg);
	if (ret)
		ret = ice_upd_prof_hw(ice, blk, &chg);

	while ((d = list_remove_head(&chg)) != NULL)
		kmem_free(d, sizeof (*d));
	list_destroy(&chg);

	return (ret);
}

/*
 * ice_add_prof_id_flow - associate a VSI with a flow profile.
 *
 * If the VSI is not yet part of any (non-default) VSIG, a new (or
 * existing, exactly-matching) VSIG is found/created for it. If the VSI is
 * already part of a VSIG, either the profile is added directly to that
 * VSIG (if the VSI is its only member), or a new VSIG combining the
 * existing profile set plus the new profile is found/created and the VSI
 * moved to it.
 */
bool
ice_add_prof_id_flow(ice_t *ice, ice_block_t blk, uint16_t vsi, uint64_t hdl)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	list_t union_lst, chg;
	ice_vsig_prof_t *d1;
	ice_chs_chg_t *d;
	bool ret = false;
	uint16_t vsig;

	list_create(&union_lst, sizeof (ice_vsig_prof_t),
	    offsetof(ice_vsig_prof_t, ivp_node));
	list_create(&chg, sizeof (ice_chs_chg_t),
	    offsetof(ice_chs_chg_t, icc_node));

	if (!ice_get_prof(ice, blk, hdl, &chg))
		goto done;

	if (!ice_vsig_find_vsi(xlt2, vsi, &vsig))
		goto done;

	if (vsig != ICE_DEFAULT_VSIG) {
		uint16_t or_vsig = vsig;
		uint16_t ref;
		bool only_vsi;

		if (ice_has_prof_vsig(ice, blk, vsig, hdl))
			goto done;

		if (!ice_vsig_get_ref(ice, blk, vsig, &ref))
			goto done;
		only_vsi = (ref == 1);

		if (!ice_get_profs_vsig(ice, blk, vsig, &union_lst))
			goto done;

		if (!ice_add_prof_to_lst(ice, blk, &union_lst, hdl))
			goto done;

		if (ice_find_dup_props_vsig(ice, blk, &union_lst, &vsig)) {
			if (!ice_move_vsi(ice, blk, vsi, vsig, &chg))
				goto done;

			if (only_vsi &&
			    !ice_rem_vsig(ice, blk, or_vsig, &chg)) {
				goto done;
			}
		} else if (only_vsi) {
			if (!ice_add_prof_id_vsig(ice, blk, vsig, hdl, false,
			    &chg)) {
				goto done;
			}

			if (!ice_adj_prof_priorities(ice, blk, vsig, &chg))
				goto done;
		} else {
			if (!ice_create_vsig_from_lst(ice, blk, vsi,
			    &union_lst, &vsig, &chg)) {
				goto done;
			}

			if (!ice_adj_prof_priorities(ice, blk, vsig, &chg))
				goto done;
		}
	} else {
		if (ice_find_prof_vsig(ice, blk, hdl, &vsig)) {
			if (!ice_move_vsi(ice, blk, vsi, vsig, &chg))
				goto done;
		} else {
			if (!ice_create_prof_id_vsig(ice, blk, vsi, hdl,
			    &chg)) {
				goto done;
			}
		}
	}

	ret = ice_upd_prof_hw(ice, blk, &chg);

done:
	while ((d = list_remove_head(&chg)) != NULL)
		kmem_free(d, sizeof (*d));
	list_destroy(&chg);

	while ((d1 = list_remove_head(&union_lst)) != NULL)
		kmem_free(d1, sizeof (*d1));
	list_destroy(&union_lst);

	return (ret);
}

/*
 * ice_rem_flow_all - remove every VSIG association for the given profile
 * (used when a profile itself is being removed).
 */
static bool
ice_rem_flow_all(ice_t *ice, ice_block_t blk, uint64_t id)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	list_t chg;
	ice_chs_chg_t *d;
	bool ret = true;
	uint16_t i;

	list_create(&chg, sizeof (ice_chs_chg_t),
	    offsetof(ice_chs_chg_t, icc_node));

	for (i = 1; i < ICE_MAX_VSIGS; i++) {
		if (!xlt2->ix2_vsig_tbl[i].ive_in_use)
			continue;

		if (!ice_has_prof_vsig(ice, blk, i, id))
			continue;

		if (!ice_rem_prof_id_vsig(ice, blk, i, id, &chg)) {
			ret = false;
			goto done;
		}
	}

	ret = ice_upd_prof_hw(ice, blk, &chg);

done:
	while ((d = list_remove_head(&chg)) != NULL)
		kmem_free(d, sizeof (*d));
	list_destroy(&chg);

	return (ret);
}

/*
 * ice_rem_prof_id_flow - remove a VSI's association with a flow profile,
 * the inverse of ice_add_prof_id_flow().
 */
bool
ice_rem_prof_id_flow(ice_t *ice, ice_block_t blk, uint16_t vsi, uint64_t hdl)
{
	ice_xlt2_t *xlt2 = &ice->ice_blk[blk].ibi_xlt2;
	list_t chg, copy;
	ice_vsig_prof_t *d1;
	ice_chs_chg_t *d;
	bool ret = false;
	uint16_t vsig;

	list_create(&copy, sizeof (ice_vsig_prof_t),
	    offsetof(ice_vsig_prof_t, ivp_node));
	list_create(&chg, sizeof (ice_chs_chg_t),
	    offsetof(ice_chs_chg_t, icc_node));

	if (!ice_vsig_find_vsi(xlt2, vsi, &vsig) || vsig == ICE_DEFAULT_VSIG)
		goto done;

	{
		bool last_profile =
		    ice_vsig_prof_id_count(ice, blk, vsig) == 1;
		bool only_vsi;
		uint16_t ref;

		if (!ice_vsig_get_ref(ice, blk, vsig, &ref))
			goto done;
		only_vsi = (ref == 1);

		if (only_vsi) {
			if (last_profile) {
				if (!ice_rem_vsig(ice, blk, vsig, &chg))
					goto done;
			} else {
				if (!ice_rem_prof_id_vsig(ice, blk, vsig, hdl,
				    &chg)) {
					goto done;
				}

				if (!ice_adj_prof_priorities(ice, blk, vsig,
				    &chg)) {
					goto done;
				}
			}
		} else {
			if (!ice_get_profs_vsig(ice, blk, vsig, &copy))
				goto done;

			if (!ice_rem_prof_from_list(&copy, hdl))
				goto done;

			if (list_is_empty(&copy)) {
				if (!ice_move_vsi(ice, blk, vsi,
				    ICE_DEFAULT_VSIG, &chg)) {
					goto done;
				}
			} else if (ice_find_dup_props_vsig(ice, blk, &copy,
			    &vsig)) {
				if (!ice_move_vsi(ice, blk, vsi, vsig, &chg))
					goto done;
			} else {
				if (!ice_create_vsig_from_lst(ice, blk, vsi,
				    &copy, &vsig, &chg)) {
					goto done;
				}

				if (!ice_adj_prof_priorities(ice, blk, vsig,
				    &chg)) {
					goto done;
				}
			}
		}
	}

	ret = ice_upd_prof_hw(ice, blk, &chg);

done:
	while ((d = list_remove_head(&chg)) != NULL)
		kmem_free(d, sizeof (*d));
	list_destroy(&chg);

	while ((d1 = list_remove_head(&copy)) != NULL)
		kmem_free(d1, sizeof (*d1));
	list_destroy(&copy);

	return (ret);
}

/*
 * ice_rem_prof - remove a previously-registered flow profile (added via
 * ice_add_prof()), first tearing down any VSIG associations it still has.
 */
bool
ice_rem_prof(ice_t *ice, ice_block_t blk, uint64_t id)
{
	ice_es_t *es = &ice->ice_blk[blk].ibi_es;
	ice_prof_map_t *pmap;

	for (pmap = list_head(&es->ie_prof_map); pmap != NULL;
	    pmap = list_next(&es->ie_prof_map, pmap)) {
		if (pmap->ipm_profile_cookie == id)
			break;
	}

	if (pmap == NULL)
		return (false);

	if (!ice_rem_flow_all(ice, blk, pmap->ipm_profile_cookie))
		return (false);

	(void) ice_prof_dec_ref(ice, blk, pmap->ipm_prof_id);

	list_remove(&es->ie_prof_map, pmap);
	kmem_free(pmap, sizeof (*pmap));

	return (true);
}
