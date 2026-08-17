/* SPDX-License-Identifier: BSD-3-Clause */
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

/* This comes from FreeBSD's ice_type.h */

#include <sys/types.h>

#ifndef _ICE_RX_HWCKSUM_H
#define	_ICE_RX_HWCKSUM_H

#ifdef __cplusplus
extern "C" {
#endif

struct ice_rx_ptype_decoded {
        uint32_t known:1;
        uint32_t outer_ip:1;
        uint32_t outer_ip_ver:2;
        uint32_t outer_frag:1;
        uint32_t tunnel_type:3;
        uint32_t tunnel_end_prot:2;
        uint32_t tunnel_end_frag:1;
        uint32_t inner_prot:4;
        uint32_t payload_layer:3;
};

enum ice_rx_ptype_outer_ip {
        ICE_RX_PTYPE_OUTER_L2   = 0,
        ICE_RX_PTYPE_OUTER_IP   = 1,
};

enum ice_rx_ptype_outer_ip_ver {
        ICE_RX_PTYPE_OUTER_NONE = 0,
        ICE_RX_PTYPE_OUTER_IPV4 = 1,
        ICE_RX_PTYPE_OUTER_IPV6 = 2,
};

enum ice_rx_ptype_outer_fragmented {
        ICE_RX_PTYPE_NOT_FRAG   = 0,
        ICE_RX_PTYPE_FRAG       = 1,
};

enum ice_rx_ptype_tunnel_type {
        ICE_RX_PTYPE_TUNNEL_NONE                = 0,
        ICE_RX_PTYPE_TUNNEL_IP_IP               = 1,
        ICE_RX_PTYPE_TUNNEL_IP_GRENAT           = 2,
        ICE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC       = 3,
        ICE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN  = 4,
};

enum ice_rx_ptype_tunnel_end_prot {
        ICE_RX_PTYPE_TUNNEL_END_NONE    = 0,
        ICE_RX_PTYPE_TUNNEL_END_IPV4    = 1,
        ICE_RX_PTYPE_TUNNEL_END_IPV6    = 2,
};

enum ice_rx_ptype_inner_prot {
        ICE_RX_PTYPE_INNER_PROT_NONE            = 0,
        ICE_RX_PTYPE_INNER_PROT_UDP             = 1,
        ICE_RX_PTYPE_INNER_PROT_TCP             = 2,
        ICE_RX_PTYPE_INNER_PROT_SCTP            = 3,
        ICE_RX_PTYPE_INNER_PROT_ICMP            = 4,
};

enum ice_rx_ptype_payload_layer {
        ICE_RX_PTYPE_PAYLOAD_LAYER_NONE = 0,
        ICE_RX_PTYPE_PAYLOAD_LAYER_PAY2 = 1,
        ICE_RX_PTYPE_PAYLOAD_LAYER_PAY3 = 2,
        ICE_RX_PTYPE_PAYLOAD_LAYER_PAY4 = 3,
};

extern const struct ice_rx_ptype_decoded ice_ptype_lkup[1024];

#ifdef __cplusplus
}
#endif

#endif /* _ICE_RX_HWCKSUM_H */
