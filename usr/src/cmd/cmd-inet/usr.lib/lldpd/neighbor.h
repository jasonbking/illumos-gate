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
 * Copyright 2022 Jason King
 */

#ifndef _NEIGHBOR_H
#define	_NEIGHBOR_H

#include <inttypes.h>
#include <libdlpi.h>
#include <liblldp.h>
#include <libuutil.h>
#include <time.h>

#include "timer.h"

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

	lldp_chassis_t		nb_chassis;
	lldp_port_t		nb_port;

	char			*nb_sysname;
	char			*nb_sysdesc;
	char			*nb_portdesc;
	lldp_cap_t		nb_cap;
	lldp_cap_t		nb_encap;
} neighbor_t;

void		neighbor_init(void);
void		neighbor_fini(void);

neighbor_t	*neighbor_new(void);
void		neighbor_free(neighbor_t *);
uu_list_t	*neighbor_list_new(struct agent *);

#ifdef __cplusplus
}
#endif

#endif /* _NEIGHBOR_H */
