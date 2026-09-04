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

#include "ice.h"
#include "ice_ddp.h"
#include "ice_flow.h"

/*
 * Much like ice_flow.h, this contains enough of ice_flow.c from the
 * FreeBSD driver to setup RSS. It's worth noting (in case of future
 * changes) that we create and use a single RSS profile for all VSIs.
 *
 * The FreeBSD driver allows for different VSIs to have different
 * profiles (essentially which fields in the packet are used to hash),
 * though to conserve resources, VSIs that are hashing the same fields
 * will share the same profile. In the FreeBSD driver, this is done
 * by the use of VSI groups (or VSIGs) -- basically each VSIG has a profile
 * associated with it, and all VSIs in the group use the VSIG profile.
 *
 * In our case, we currently have a single VSIG and all VSIs are a
 * member of it. If we want to have more flexibility with RSS (or other
 * pieces of the switching mechanism on the NIC), we will need to
 * add similar functionality.
 */

/* Size of known protocol header fields */
#define	ICE_FLOW_FLD_SZ_ETH_TYPE	2
#define	ICE_FLOW_FLD_SZ_VLAN		2
#define	ICE_FLOW_FLD_SZ_IPV4_ADDR	4
#define	ICE_FLOW_FLD_SZ_IPV6_ADDR	16
#define	ICE_FLOW_FLD_SZ_IP_DSCP		1
#define	ICE_FLOW_FLD_SZ_IP_TTL		1
#define	ICE_FLOW_FLD_SZ_IP_PROT		1
#define	ICE_FLOW_FLD_SZ_PORT		2
#define	ICE_FLOW_FLD_SZ_TCP_FLAGS	1
#define	ICE_FLOW_FLD_SZ_ICMP_TYPE	1
#define	ICE_FLOW_FLD_SZ_ICMP_CODE	1
#define	ICE_FLOW_FLD_SZ_ARP_OPER	2
#define	ICE_FLOW_FLD_SZ_GRE_KEYID	4

/* Describe properties of a protocol header field */
typedef struct ice_flow_field_info {
	enum ice_flow_seg_hdr hdr;
	s16 off;	/* Offset from start of a protocol header, in bits */
	u16 size;	/* Size of fields in bits */
} ice_flow_field_info_t;

#define	ICE_FLOW_FLD_INFO(_hdr, _offset_bytes, _size_bytes) { \
	.hdr = _hdr, \
	.off = (_offset_bytes) * NBBY, \
	.size = (_size_bytes) * NBBY, \
}

/* Table containing properties of supported protocol header fields */
static const ice_flow_field_info_t ice_flds_info[ICE_FLOW_FIELD_IDX_MAX] = {
	/* Ether */
	/* ICE_FLOW_FIELD_IDX_ETH_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, 0, ETHERADDRL),
	/* ICE_FLOW_FIELD_IDX_ETH_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, ETHERADDRL, ETHERADDRL),
	/* ICE_FLOW_FIELD_IDX_S_VLAN */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_VLAN, 12, ICE_FLOW_FLD_SZ_VLAN),
	/* ICE_FLOW_FIELD_IDX_C_VLAN */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_VLAN, 14, ICE_FLOW_FLD_SZ_VLAN),
	/* ICE_FLOW_FIELD_IDX_ETH_TYPE */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ETH, 0, ICE_FLOW_FLD_SZ_ETH_TYPE),
	/* IPv4 / IPv6 */
	/* ICE_FLOW_FIELD_IDX_IPV4_DSCP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 1, ICE_FLOW_FLD_SZ_IP_DSCP),
	/* ICE_FLOW_FIELD_IDX_IPV6_DSCP */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 0, ICE_FLOW_FLD_SZ_IP_DSCP),
	/* ICE_FLOW_FIELD_IDX_IPV4_TTL */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 8, ICE_FLOW_FLD_SZ_IP_TTL),
	/* ICE_FLOW_FIELD_IDX_IPV4_PROT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 9, ICE_FLOW_FLD_SZ_IP_PROT),
	/* ICE_FLOW_FIELD_IDX_IPV6_TTL */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 7, ICE_FLOW_FLD_SZ_IP_TTL),
	/* ICE_FLOW_FIELD_IDX_IPV4_PROT */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_NONE, 6, ICE_FLOW_FLD_SZ_IP_PROT),
	/* ICE_FLOW_FIELD_IDX_IPV4_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 12, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV4_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV4, 16, ICE_FLOW_FLD_SZ_IPV4_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV6_SA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 8, ICE_FLOW_FLD_SZ_IPV6_ADDR),
	/* ICE_FLOW_FIELD_IDX_IPV6_DA */
	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_IPV6, 24, ICE_FLOW_FLD_SZ_IPV6_ADDR),
	/* Transport */
	/* ICE_FLOW_FIELD_IDX_TCP_SRC_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 0, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_TCP_DST_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 2, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_UDP_SRC_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_UDP, 0, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_UDP_DST_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_UDP, 2, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_SCTP, 0, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_SCTP_DST_PORT */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_SCTP, 2, ICE_FLOW_FLD_SZ_PORT),
 	/* ICE_FLOW_FIELD_IDX_TCP_FLAGS */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_TCP, 13, ICE_FLOW_FLD_SZ_TCP_FLAGS),
 	/* ARP */
 	/* ICE_FLOW_FIELD_IDX_ARP_SIP */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 14, ICE_FLOW_FLD_SZ_IPV4_ADDR),
 	/* ICE_FLOW_FIELD_IDX_ARP_DIP */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 24, ICE_FLOW_FLD_SZ_IPV4_ADDR),
 	/* ICE_FLOW_FIELD_IDX_ARP_SHA */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 8, ETHERADDRL),
 	/* ICE_FLOW_FIELD_IDX_ARP_DHA */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 18, ETHERADDRL),
 	/* ICE_FLOW_FIELD_IDX_ARP_OP */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ARP, 6, ICE_FLOW_FLD_SZ_ARP_OPER),
 	/* ICMP */
 	/* ICE_FLOW_FIELD_IDX_ICMP_TYPE */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ICMP, 0, ICE_FLOW_FLD_SZ_ICMP_TYPE),
 	/* ICE_FLOW_FIELD_IDX_ICMP_CODE */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_ICMP, 1, ICE_FLOW_FLD_SZ_ICMP_CODE),
 	/* GRE */
 	/* ICE_FLOW_FIELD_IDX_GRE_KEYID */
 	ICE_FLOW_FLD_INFO(ICE_FLOW_SEG_HDR_GRE, 12, ICE_FLOW_FLD_SZ_GRE_KEYID),
};

#define	ICE_FLOW_RSS_SEG_HDR_L3_MASKS \
	(ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_IPV6)

#define	ICE_FLOW_RSS_SEG_HDR_L4_MASKS \
	(ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_SCTP)

#define	ICE_FLOW_RSS_SEG_HDR_VAL_MASKS \
	(ICE_FLOW_RSS_SEG_HDR_L3_MASKS | \
	 ICE_FLOW_RSS_SEG_HDR_L4_MASKS)

static bool
ice_flow_set_rss_seg_info(ice_flow_sec_info_t *segs, size_t n,
    const ice_rss_hash_cfg_t *cfg)
{
	ice_flow_seg_info_t	*seg;
	uint64_t		val;

	ASSERT3U(n, >, 0);
	seg = &segs[n - 1];

	for (uint_t i = 0; i < ICE_FLOW_FLD_IDX_MAX; i++) {
		if (((1ULL << i) & cfg->irhc_fields) == 0)
			continue;

		seg->fields[i].iffi_type = ICE_FLOW_FLD_TYPE_REG;
		seg->fields[i].iffi_src = ICE_FLOW_FLD_OFF_INVAL;
		seg->fields[i].iffi_entry = ICE_FLOW_FLD_OFF_INVAL;
		seg->fields[i].iffi_xtrct = ICE_FLOW_FLD_OFF_INVAL;

		seg->ifsi_headers |= ice_flds_info[i].hdr;
	}

	seg->ifsi_headers |= cfg->irhc_headers;

	switch (cfg->irhc_hdr_type) {
	case ICE_RSS_INNER_HEADERS_W_OUTER_IPV4:
		segs[ICE_RSS_OUTER_HEADERS].ifsi_headers |=
		    ICE_FLOW_SEG_HDR_IPV4 |
		    ICE_FLOW_SEG_HDR_IPV_FRAG |
		    ICE_FLOW_SEG_HDR_IPV_OTHER;
		break;
	case ICE_RSS_INNER_HEADERS_W_OUTER_IPV6:
		segs[ICE_RSS_OUTER_HEADERS].ifsi_headers |=
		    ICE_FLOW_SEG_HDR_IPV6 |
		    ICE_FLOW_SEG_HDR_IPV_FRAG |
		    ICE_FLOW_SEG_HDR_IPV_OTHER;
		break;
	case ICE_RSS_INNER_HEADERS_W_OUTER_IPV4_GRE:
		segs[ICE_RSS_OUTER_HEADERS].ifsi_headers |=
		    ICE_FLOW_SEG_HDR_IPV4 |
		    ICE_FLOW_SEG_HDR_GRE |
		    ICE_FLOW_SEG_HDR_IPV_OTHER;
		break;
	case ICE_RSS_INNER_HEADERS_W_OUTER_IPV6_GRE:
		segs[ICE_RSS_OUTER_HEADERS].ifsi_headers |=
		    ICE_FLOW_SEG_HDR_IPV6 |
		    ICE_FLOW_SEG_HDR_GRE |
		    ICE_FLOW_SEG_HDR_IPV_OTHER;
		break;
	default:
		break;
	}

	if (seg->ifsi_headers & ~ICE_FLOW_RSS_SEG_HDR_VAL_MASKS)
		return (false);

	// TODO other checks

	return (true);
}

static uint64_t
ice_flow_gen_profid(const ice_rss_hash_cfg_t *cfg,
    const ice_flow_seg_info_t *seg)
{
	uint64_t id;

	id = cfg->irhc_headers;

	id |= (uint64_t)seg->ifsi_headers << 32;
	id &= ~(3ULL << 62);

	id |= ((uint64_t)(cfg->irhc_hdr_type & 0x3)) << 62;

	return (id);
}

static bool
ice_add_rss_cfg_sync(ice_vsi_t *vsi, const ice_rss_hash_cfg_t *cfg)
{
	ice_flow_seg_info_t	*segs;
	size_t			nseg;
	bool			ret = false;

	nseg = (cfg->irhc_hdr_type == ICE_RSS_OUTER_HEADERS) ?
	    ICE_FLOW_SEG_SINGLE : ICE_FLOW_SEG_MAX;

	segs = kmem_zalloc(nseg * sizeof (*segs), KM_SLEEP);

	if (!ice_flow_set_rss_seg_info(segs, nseg, cfg))
		goto done;

	
done:
	kmem_free(segs, nseg * sizeof (*segs));
	return (ret);
}
