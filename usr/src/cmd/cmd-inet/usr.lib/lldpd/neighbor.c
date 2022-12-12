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

#include <sys/sysmacros.h>
#include <stddef.h>
#include <string.h>
#include <umem.h>

#include "agent.h"
#include "neighbor.h"
#include "log.h"
#include "util.h"

static uu_list_pool_t	*nb_pool;

neighbor_t *
neighbor_new(void)
{
	neighbor_t *nb;

	nb = umem_zalloc(sizeof (*nb), UMEM_DEFAULT);
	if (nb == NULL)
		return (NULL);

	uu_list_node_init(nb, &nb->nb_node, nb_pool);
	return (nb);
}

void
neighbor_free(neighbor_t *nb)
{
	if (nb == NULL)
		return;

	uu_list_node_fini(nb, &nb->nb_node, nb_pool);
	umem_free(nb, sizeof (*nb));
}

uu_list_t *
neighbor_list_new(agent_t *a)
{
	return (uu_list_create(nb_pool, a, UU_LIST_DEBUG));
}

static int
chassis_cmp(const lldp_chassis_t *l, const lldp_chassis_t *r)
{
	int ret;

	if (l->llc_type < r->llc_type)
		return (-1);
	if (l->llc_type > r->llc_type)
		return (1);

	ret = memcmp(l->llc_id, r->llc_id, MIN(l->llc_len, r->llc_len));
	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	if (l->llc_len < r->llc_len)
		return (-1);
	if (l->llc_len > r->llc_len)
		return (1);
	return (0);
}

static int
port_cmp(const lldp_port_t *l, const lldp_port_t *r)
{
	int ret;

	if (l->llp_type < r->llp_type)
		return (-1);
	if (l->llp_type > r->llp_type)
		return (1);

	ret = memcmp(l->llp_id, r->llp_id, MIN(l->llp_len, r->llp_len));
	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	if (l->llp_len < r->llp_len)
		return (-1);
	if (l->llp_len > r->llp_len)
		return (1);
	return (0);
}

int
neighbor_cmp_msap(const neighbor_t *l, const neighbor_t *r)
{
	int ret;

	ret = chassis_cmp(&l->nb_chassis, &r->nb_chassis);
	if (ret != 0)
		return (ret);
	return (port_cmp(&l->nb_port, &r->nb_port));
}

static int
neighbor_cmp_msap_uu(const void *a, const void *b, void *private __unused)
{
	return (neighbor_cmp_msap(a, b));
}

bool
neighbor_cmp(const neighbor_t *l, const neighbor_t *r)
{
	/* TODO */
	return (true);
}

void
neighbor_init(void)
{
	log_trace(log, "creating neighbor list pool", LOG_T_END);

	nb_pool = uu_list_pool_create("neighbors", sizeof (neighbor_t),
	    offsetof(neighbor_t, nb_node), neighbor_cmp_msap_uu,
	    UU_LIST_POOL_DEBUG);
	if (nb_pool == NULL)
		panic("failed to create neighbor list pool");
}

void
neighbor_fini(void)
{
	log_trace(log, "destroying neighbor list pool", LOG_T_END);
	uu_list_pool_destroy(nb_pool);
}
