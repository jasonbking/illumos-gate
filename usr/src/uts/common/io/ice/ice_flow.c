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
#include "ice_ddp.h"

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
	ice_flow_seg_hdr_t hdr;
	int16_t off;	/* Offset from start of a protocol header, in bits */
	uint16_t size;	/* Size of fields in bits */
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

/*
 * Bitmaps indicating relevant packet types for a particular protocol header
 *
 * Packet types for packets with an Outer/First/Single MAC header
 */
static const uint32_t ice_ptypes_mac_ofos[] = {
        0xFDC00846, 0xBFBF7F7E, 0xF70001DF, 0xFEFDFDFB,
        0x0000077E, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last MAC VLAN header */
static const uint32_t ice_ptypes_macvlan_il[] = {
        0x00000000, 0xBC000000, 0x000001DF, 0xF0000000,
        0x0000077E, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single non-frag IPv4 header,
 * does NOT include IPV4 other PTYPEs
 */
static const uint32_t ice_ptypes_ipv4_ofos[] = {
        0x1D800000, 0x04000800, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single non-frag IPv4 header,
 * includes IPV4 other PTYPEs
 */
static const uint32_t ice_ptypes_ipv4_ofos_all[] = {
        0x1D800000, 0x04000800, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv4 header */
static const uint32_t ice_ptypes_ipv4_il[] = {
        0xE0000000, 0xB807700E, 0x80000003, 0xE01DC03B,
        0x0000000E, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single non-frag IPv6 header,
 * does NOT include IVP6 other PTYPEs
 */
static const uint32_t ice_ptypes_ipv6_ofos[] = {
        0x00000000, 0x00000000, 0x76000000, 0x10002000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single non-frag IPv6 header,
 * includes IPV6 other PTYPEs
 */
static const uint32_t ice_ptypes_ipv6_ofos_all[] = {
        0x00000000, 0x00000000, 0x76000000, 0x10002000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv6 header */
static const uint32_t ice_ptypes_ipv6_il[] = {
        0x00000000, 0x03B80770, 0x000001DC, 0x0EE00000,
        0x00000770, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single
 * non-frag IPv4 header - no L4
 */
static const uint32_t ice_ptypes_ipv4_ofos_no_l4[] = {
        0x10800000, 0x04000800, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv4 header - no L4 */
static const uint32_t ice_ptypes_ipv4_il_no_l4[] = {
        0x60000000, 0x18043008, 0x80000002, 0x6010c021,
        0x00000008, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * Packet types for packets with an Outer/First/Single
 * non-frag IPv6 header - no L4
 */
static const uint32_t ice_ptypes_ipv6_ofos_no_l4[] = {
        0x00000000, 0x00000000, 0x42000000, 0x10002000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last IPv6 header - no L4 */
static const uint32_t ice_ptypes_ipv6_il_no_l4[] = {
        0x00000000, 0x02180430, 0x0000010c, 0x086010c0,
        0x00000430, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First ARP header */
static const uint32_t ice_ptypes_arp_of[] = {
        0x00000800, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/*
 * UDP Packet types for non-tunneled packets or tunneled
 * packets with inner UDP.
 */
static const uint32_t ice_ptypes_udp_il[] = {
        0x81000000, 0x20204040, 0x04000010, 0x80810102,
        0x00000040, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last TCP header */
static const uint32_t ice_ptypes_tcp_il[] = {
        0x04000000, 0x80810102, 0x10000040, 0x02040408,
        0x00000102, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last SCTP header */
static const uint32_t ice_ptypes_sctp_il[] = {
        0x08000000, 0x01020204, 0x20000081, 0x04080810,
        0x00000204, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First ICMP header */
static const uint32_t ice_ptypes_icmp_of[] = {
        0x10000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last ICMP header */
static const uint32_t ice_ptypes_icmp_il[] = {
        0x00000000, 0x02040408, 0x40000102, 0x08101020,
        0x00000408, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Outermost/First GRE header */
static const uint32_t ice_ptypes_gre_of[] = {
        0x00000000, 0xBFBF7800, 0x000001DF, 0xFEFDE000,
        0x0000017E, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

/* Packet types for packets with an Innermost/Last MAC header */
static const uint32_t ice_ptypes_mac_il[] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

typedef struct ice_flow_prof_params {
	ice_block_t	ifpp_blk;
	uint16_t	ifpp_entry_length;
	uint8_t		ifpp_es_cnt;
	ice_flow_prof_t	*ifpp_prof;
	ice_fv_word_t	ifpp_es[ICE_MAX_FV_WORDS];
	uint32_t	ifpp_ptypes[ICE_FLOW_PTYPE_MAX / sizeof (uint32_t)];
} ice_flow_prof_params_t;

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

	/*
	 * Since we're currently statically generating the resulting
	 * config, these checks shouldn't fail. These would turn into
	 * errors if we get more dynamic on generating these configs.
	 */
	VERIFY0(seg->ifsi_headers & ~ICE_FLOW_RSS_SEG_HDR_VAL_MASKS);

	val = seg->ifsi_headers & ICE_FLOW_RSS_SEG_HDR_L3_MASKS;
	if (val != 0)
		VERIFY(IS_P2(val));

	val = seg->ifsi_headers & ICE_FLOW_RSS_SEG_HDR_L4_MASKS;
	if (val != 0)
		VERIFY(IS_P2(val));

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

static inline
ice_flow_seg_and(uint32_t *dst, const uint32_t *src, size_t len)
{
	for (uint_t i = 0; i < len; i++)
		dst[i] &= src[i];
}

static void
ice_flow_proc_seg_hdrs(ice_flow_prof_params_t *params)
{
	ice_flow_prof_t *prof = params->ifpp_prof;
	uint32_t	*ptypes = params->ifpp_ptypes;
	uint_t		i;

	(void) memset(params->ifpp_ptypes, 0xff, sizeof (params->ifpp_ptypes));

	for (i = 0; i < prof->ifp_segs_cnt; i++) {
		const uint32_t	*src = NULL;
		uint32_t	hdrs;

		hdrs = prof->ifp_segs[i].ifsi_hdrs;

		if (hdrs & ICE_FLOW_SEG_HDR_ETH) {
			src = (i == 0) ?
			    ice_ptypes_mac_ofos : ice_ptypes_mac_il;
			ice_flow_seg_and(ptypes, src, 32);
		}

		if (i > 0 && (hdrs & ICE_FLOW_SEG_HDR_VLAN) != 0) {
			src = ice_ptypes_macvlan_il;
			ice_flow_seg_and(ptypes, src, 32);
		}

		if (i == 0 && (hdrs & ICE_FLOW_SEG_HDR_ARP) != 0) {
			src = ice_ptypes_arp_of;
			ice_flow_seg_and(ptypes, src, 32);
		}

		if ((hdrs & ICE_FLOW_SEG_HDR_IPV4) != 0 &&
		    (hdrs & ICE_FLOW_SEG_HDR_IPV_OTHER) != 0) {
			src = (i > 0) ?
			    ice_ptypes_ipv4_il : ice_types_ipv4_ofos_all;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_IPV6) != 0 &&
		    (hdrs & ICE_FLOW_SEG_HDR_IPV_OTHER) != 0) {
			src = (i > 0) ?
			    ice_ptypes_ipv6_il : ice_ptypes_ipv6_ofos_all;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_IPV4) != 0 &&
		    (hdrs & ICE_FLOW_SEG_HDRS_L4_MASK_NO_OTHER) == 0) {
			src = (i == 0) ? ice_ptypes_ipv4_ofos_no_l4 :
			    ice_ptypes_ipv4_il_no_l4;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_IPV4) != 0) {
			src = (i == 0) ?
			    ice_ptypes_ipv4_ofos : ice_ptypes_ipv4_il;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_IPV6) != 0 &&
		    (hdrs & ICE_FLOW_SEG_HDRS_L4_MASK_NO_OTHER) == 0) {
			src = (i == 0) ? ice_ptypes_ipv6_ofos_no_l4 :
			    ice_ptypes_ipv6_il_no_l4;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_IPV6) != 0) {
			src = (i == 0) ?
			    ice_ptypes_ipv6_ofos : ice_ptypes_ipv6_il;
			ice_flow_seg_and(ptypes, src, 32);
		}
	
		if ((hdrs & ICE_FLOW_SEG_HDR_UDP) != 0) {
			src = ice_ptypes_udp_il;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_TCP) != 0) {
			src = ice_ptypes_tcp_il;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_SCTP) != 0) {
			src = ice_ptypes_sctp_il;
			ice_flow_seg_and(ptypes, src, 32);
		}

		if ((hdrs & ICE_FLOW_SEG_HDR_ICMP) != 0) {
			src = (i == 0) ?
			    ice_ptypes_icmp_of : ice_ptypes_icmp_il;
			ice_flow_seg_and(ptypes, src, 32);
		} else if ((hdrs & ICE_FLOW_SEG_HDR_GRE) != 0 && (1 == 0)) {
			src = ice_ptypes_gre_of;
			ice_flow_seg_and(ptypes, src, 32);
		}
	}
}

static bool
ice_flow_xtract_fld(ice_t *ice, ice_flow_prof_params_t *params, uint_t seg,
    ice_flow_field_t fld)
{
	ice_flow_fld_info_t	*flds;
	ice_flow_seg_xtrct_t	*xt;
	ice_flow_field_t	sib = ICE_FLOW_FIELD_IDX_MAX;
	ice_prot_id_t		prod_id = ICE_PROT_ID_INVAL;
	uint32_t		cnt, i;
	uint16_t		ese_bits;

	flds = params->ifpp_prof->ifp_segs[seg].ifsi_fields;

	switch (fld) {
	case ICE_FLOW_FIELD_IDX_ETH_DA:
	case ICE_FLOW_FIELD_IDX_ETH_SA:
	case ICE_FLOW_FIELD_IDX_S_VLAN:
	case ICE_FLOW_FIELD_IDX_C_VLAN:
		prot_id = (seg == 0) ? ICE_PROT_MAC_OF_OR_S : ICE_PROT_MAC_IL;
		break;
	case ICE_FLOW_FIELD_IDX_ETH_TYPE:
		prot_id = (seg == 0) ? ICE_PROT_ETYPE_OL : ICE_PROT_ETYPE_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_DSCP:
		prot_id = (seg == 0) ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_DSCP:
		prot_id = (seg == 0) ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_TTL:
	case ICE_FLOW_FIELD_IDX_IPV4_PROT:
		prot_id = (seg == 0) ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;
		/* TTL and PROT share the same extraction seq. entry.
		 * Each is considered a sibling to the other in terms of sharing
		 * the same extraction sequence entry.
		 */
		if (fld == ICE_FLOW_FIELD_IDX_IPV4_TTL)
			sib = ICE_FLOW_FIELD_IDX_IPV4_PROT;
		else
			sib = ICE_FLOW_FIELD_IDX_IPV4_TTL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_TTL:
	case ICE_FLOW_FIELD_IDX_IPV6_PROT:
		prot_id = (seg == 0) ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;
		/* TTL and PROT share the same extraction seq. entry.
		 * Each is considered a sibling to the other in terms of sharing
		 * the same extraction sequence entry.
		 */
		if (fld == ICE_FLOW_FIELD_IDX_IPV6_TTL)
			sib = ICE_FLOW_FIELD_IDX_IPV6_PROT;
		else
			sib = ICE_FLOW_FIELD_IDX_IPV6_TTL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV4_SA:
	case ICE_FLOW_FIELD_IDX_IPV4_DA:
		prot_id = (seg == 0) ? ICE_PROT_IPV4_OF_OR_S : ICE_PROT_IPV4_IL;
		break;
	case ICE_FLOW_FIELD_IDX_IPV6_SA:
	case ICE_FLOW_FIELD_IDX_IPV6_DA:
		prot_id = (seg == 0) ? ICE_PROT_IPV6_OF_OR_S : ICE_PROT_IPV6_IL;
		break;
			case ICE_FLOW_FIELD_IDX_TCP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_TCP_DST_PORT:
	case ICE_FLOW_FIELD_IDX_TCP_FLAGS:
		prot_id = ICE_PROT_TCP_IL;
		break;
	case ICE_FLOW_FIELD_IDX_UDP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_UDP_DST_PORT:
		prot_id = ICE_PROT_UDP_IL_OR_S;
		break;
	case ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT:
	case ICE_FLOW_FIELD_IDX_SCTP_DST_PORT:
		prot_id = ICE_PROT_SCTP_IL;
		break;
	case ICE_FLOW_FIELD_IDX_ARP_SIP:
	case ICE_FLOW_FIELD_IDX_ARP_DIP:
	case ICE_FLOW_FIELD_IDX_ARP_SHA:
	case ICE_FLOW_FIELD_IDX_ARP_DHA:
	case ICE_FLOW_FIELD_IDX_ARP_OP:
		prot_id = ICE_PROT_ARP_OF;
		break;
	case ICE_FLOW_FIELD_IDX_ICMP_TYPE:
	case ICE_FLOW_FIELD_IDX_ICMP_CODE:
		/* ICMP type and code share the same extraction seq. entry */
		prot_id =
		    (params->prof->segs[seg].hdrs & ICE_FLOW_SEG_HDR_IPV4) ?
			ICE_PROT_ICMP_IL : ICE_PROT_ICMPV6_IL;
		sib = (fld == ICE_FLOW_FIELD_IDX_ICMP_TYPE) ?
			ICE_FLOW_FIELD_IDX_ICMP_CODE :
			ICE_FLOW_FIELD_IDX_ICMP_TYPE;
		break;
	case ICE_FLOW_FIELD_IDX_GRE_KEYID:
		prot_id = ICE_PROT_GRE_OF;
		break;
	default:
		return ICE_ERR_NOT_IMPL;
        }

	/*
	 * Each extraction sequence entry is a word in size, and extracts
	 * a word-aligned offset from a protocol header.
	 */
	ese_bits = ICE_FLOW_FV_EXTRACT_SZ * NBBY;

	xt = &flds[fld].iffi_xtrct;

	xt->ifsx_prot_id = prot_id;
	xt->ifsx_off = (ice_flds_info[fld].off / ese_bits) *
	    ICE_FLOW_FV_EXTRACT_SZ;
	xt->ifsx_disp = ice_flds_info[fld].off % ese_bits;
	xt->ifsx_idx = params->ifpp_es_cnt;

	/*
	 * Adjust the next field-entry index after accomodating the number of
	 * entries this field consumes.
	 */
	cnt = xt->ifsx_disp + ice_flds_info[fld].size;
	cnt /= ese_bits;

	/* Fill in the extraction sequence entries needed for this field */
	off = xt->ifsx_off;
	for (i = 0; i < cnt; i++) {
		/*
		 * Only consume an extraction sequence entry if there is no
		 * sibling field associated with this field or the sibling entry
		 * already extracts the word shared with this field.
		 */
		if (sib == IEC_FLOW_FIELD_IDX_MAX ||
		    xt->ifsx_prot_id == ICE_PROT_ID_INVAL ||
		    xt->ifsx_off != off) {
			uint8_t idx;

			/*
			 * Make sure the number of extraction sequences
			 * required does not exceed the block's capability
			 */
			if (params->ifpp_es_cnt >= fv_words)
				return (false);

			/* some blocks require a reversed field vector layout */
			if (xxxx[RSS].es.reverse)
				idx = fv_words - params->ifpp_es_cnt - 1;
			else
				idx = params->ifpp_es_cnt;

			params->ifpp_es[idx].ifp_prot_id = prot_id;
			params->ifpp_es[idx].ifp_off = off;
			params->ifpp_es_cnt++;
		}

		off += ICE_FLOW_FV_EXTRACT_SZ;
	}

	return (true);
}

static bool
ice_flow_create_xtrct_seq(ice_t *ice, ice_flow_prof_params_t *params)
{
	ice_flow_prof_t *prof = params->ifpp_prof;
	uint_t		i;

	for (i = 0; i < prof->ifp_segs_cnt; i++) {
		uint32_t		match;
		ice_flow_field_t	j;

		match = prof->ifp_segs[i].ifsi_match;
		for (j = 0; j < ICE_FLOW_FIELD_IDX_MAX; j++) {
			if (((1ULL << j) & match) == 0)
				continue;

			if (!ice_flow_xtract_fld(ice, params, i, j))
				return (false);

			match &= ~(1ULL << j);
		}
	}

	return (true);
}

static bool
ice_flow_proc_segs(ice_t *ice, ice_flow_prof_params_t *params)
{
	ice_flow_proc_seg_hdrs(params);

	if (!ice_flow_create_xtrct_seq(ice, params))
		return (false);

	VERIFY3S(params->iffp_blk, ==, ICE_BLK_RSS);
	return (true);
}

static bool
ice_flow_add_prof(ice_t *ice, ice_blk_t blk, ice_flow_dir_t dir,
    uint64_t prof_id, ice_flow_seg_info_t *segs, uint8_t nseg,
    ice_flow_action_t *act, uint8_t nact, ice_flow_profile_t **profp)
{
	ice_flow_params_t	*params;
	uint_t			i;

	/*
	 * Since we're currently statically generating these profiles
	 * (i.e. it's not dynamic or derived from user input), we
	 * assert that the parameters are well formed.
	 *
	 * If we ever want to dynamically generate profiles, well
	 * want to define errors to return if any of these
	 * values are invalid.
	 */
	VERIFY3U(nseg, <=, ICE_FLOW_SEG_MAX);
	VERIFY3U(nseg, >, 0);

	/* Validate headers */
	for (uint_t i = 0; i < nseg; i++) {
		uint32_t mask;

		mask = segs[i]->ifsi_headers & ICE_FLOW_SEG_HDRS_L3_MASK;
		if (mask != 0)
			VERIFY(ISP2(mask));

		mask = segs[i]->ifsi_headers & ICE_FLOW_SEG_HDRS_L4_MASK;
		if (mask != 0)
			VERIFY(ISP2(mask));
	}

	params = kmem_zalloc(sizeof (*params), KM_SLEEP);
	params->ifpp_prof = kmem_zalloc(sizeof (*params->ifpp_prof, KM_SLEEP));

	/* Init extraction sequence to all invalid */
	for (i = 0; i < ICE_MAX_FV_WORDS; i++) {
		params->ifpp_es[i].ifw_prot_id = ICE_PROT_INVALID;
		params->ifpp_es[i].ifw_off = ICE_FV_OFFSET_INVAL;
	}

	params->ifpp_blk = ICE_BLK_RSS;
	params->ifpp_prof->ifp_id = prof_id;
	params->ifpp_prof->ifp_dir = dir;
	params->ifpp_segs_cnt = nseg;

	for (i = 0; i < nseg; i++) {
		bcopy(&segs[i], &params->ifpp_prof->ifp_segs[i],
		    sizeof (segs[i]));
	}


}

static bool
ice_add_rss_cfg_sync(ice_vsi_t *vsi, const ice_rss_hash_cfg_t *cfg)
{
	ice_t			*ice = vsi->ivsi_ice;
	ice_flow_seg_info_t	*segs;
	ice_flow_prof_t		*prof = NULL;
	uint8_t			nseg;
	uint64_t		flow_id;
	bool			ret = false;

	nseg = (cfg->irhc_hdr_type == ICE_RSS_OUTER_HEADERS) ?
	    ICE_FLOW_SEG_SINGLE : ICE_FLOW_SEG_MAX;

	segs = kmem_zalloc(nseg * sizeof (*segs), KM_SLEEP);

	if (!ice_flow_set_rss_seg_info(segs, nseg, cfg))
		goto done;

	flow_id = ice_flow_gen_profid(cfg, &segs[nseg - 1]);

	if (!ice_flow_add_prof(ice, ICE_BLK_RSS, ICE_FLOW_RX, flowid,
	    segs, nseg, NULL, 0, &prof)) {
		goto done;
	}

	if (!ice_flow_assoc_prof(ice, ICE_BLK_RSS, prof, vsi)) {
		ice_flow_rem_prof(ice, prof);
		ret = false;
		goto done;
	}

	
done:
	kmem_free(segs, nseg * sizeof (*segs));
	return (ret);
}
