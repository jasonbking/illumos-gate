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

#include <sys/debug.h>
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
chassis_cmp(const tlv_t *l, const tlv_t *r)
{
	buf_t lb = l->tlv_buf;
	buf_t rb = r->tlv_buf;
	uint8_t l_stype, r_stype;
	int ret;

	/*
	 * We should never instantiate a neighbor_t (especially off the wire)
	 * with an invalid PDU, so these should always succeed.
	 */
	VERIFY3U(l->tlv_type, ==, LLDP_TLV_CHASSIS_ID);
	VERIFY3U(r->tlv_type, ==, LLDP_TLV_CHASSIS_ID);

	VERIFY(buf_get8(&lb, &l_stype));
	VERIFY(buf_get8(&rb, &r_stype));

	if (l_stype < r_stype)
		return (-1);
	if (l_stype > r_stype)
		return (1);

	ret = memcmp(lb.b_ptr, rb.b_ptr, MIN(buf_len(&lb), buf_len(&rb)));
	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	if (buf_len(&lb) < buf_len(&rb))
		return (-1);
	if (buf_len(&lb) > buf_len(&rb))
		return (1);
	return (0);
}

static int
port_cmp(const tlv_t *l, const tlv_t *r)
{
	buf_t lb = l->tlv_buf;
	buf_t rb = r->tlv_buf;
	uint8_t l_stype, r_stype;
	int ret;

	/*
	 * We should never instantiate a neighbor_t (especially off the wire)
	 * with an invalid PDU, so these should always succeed.
	 */
	VERIFY3U(l->tlv_type, ==, LLDP_TLV_PORT_ID);
	VERIFY3U(r->tlv_type, ==, LLDP_TLV_PORT_ID);

	VERIFY(buf_get8(&lb, &l_stype));
	VERIFY(buf_get8(&rb, &r_stype));

	if (l_stype < r_stype)
		return (-1);
	if (l_stype > r_stype)
		return (1);

	ret = memcmp(lb.b_ptr, rb.b_ptr, MIN(buf_len(&lb), buf_len(&rb)));
	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	if (buf_len(&lb) < buf_len(&rb))
		return (-1);
	if (buf_len(&lb) > buf_len(&rb))
		return (1);

	return (0);
}

int
neighbor_cmp_msap(const neighbor_t *l, const neighbor_t *r)
{
	tlv_t *l_tlv, *r_tlv;
	int ret;

	/* Chassis ID */
	l_tlv = tlv_list_get((tlv_list_t *)&l->nb_tlvs, 0);
	r_tlv = tlv_list_get((tlv_list_t *)&r->nb_tlvs, 0);
	ret = chassis_cmp(l_tlv, r_tlv);
	if (ret != 0)
		return (ret);

	/* Port ID */
	l_tlv = tlv_list_get((tlv_list_t *)&l->nb_tlvs, 1);
	r_tlv = tlv_list_get((tlv_list_t *)&r->nb_tlvs, 1);
	return (port_cmp(l_tlv, r_tlv));
}

static int
neighbor_cmp_msap_uu(const void *a, const void *b, void *private __unused)
{
	return (neighbor_cmp_msap(a, b));
}

bool
neighbor_same(const neighbor_t *l, const neighbor_t *r)
{
	int ret;

	if (l->nb_pdu_len != r->nb_pdu_len)
		return (false);

	ret = memcmp(l->nb_pdu, r->nb_pdu, l->nb_pdu_len);
	return ((ret == 0) ? true : false);
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
