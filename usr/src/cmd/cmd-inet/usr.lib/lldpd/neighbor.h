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
 * Copyright 2023 Jason King
 */

#ifndef _NEIGHBOR_H
#define	_NEIGHBOR_H

#include <inttypes.h>
#include <libdlpi.h>
#include <liblldp.h>
#include <libuutil.h>
#include <time.h>

#include "buf.h"
#include "timer.h"
#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct agent;

typedef struct neighbor {
	uu_list_node_t		nb_node;

	lldp_timer_t		nb_timer;
	time_t			nb_time;
	uint16_t		nb_ttl;

	uint8_t			nb_src[DLPI_PHYSADDR_MAX];
	size_t			nb_srclen;

	uint8_t			nb_dst[DLPI_PHYSADDR_MAX];
	size_t			nb_dstlen;

	uint8_t			nb_pdu[LLDP_PDU_MAX];
	size_t			nb_pdu_len;

	tlv_list_t		nb_core_tlvs;
	tlv_list_t		nb_org_tlvs;
	tlv_list_t		nb_unknown_tlvs;
} neighbor_t;

void		neighbor_init(void);
void		neighbor_fini(void);

neighbor_t	*neighbor_new(void);
void		neighbor_free(neighbor_t *);
uu_list_t	*neighbor_list_new(struct agent *);
neighbor_t	*neighbor_get(const lldp_chassis_t *, const lldp_port_t *);

int		neighbor_cmp_msap(const neighbor_t *, const neighbor_t *);
bool		neighbor_same(const neighbor_t *, const neighbor_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NEIGHBOR_H */
