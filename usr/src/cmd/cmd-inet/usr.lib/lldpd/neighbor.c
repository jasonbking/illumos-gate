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
static umem_cache_t	*nb_cache;

neighbor_t *
neighbor_new(void)
{
	neighbor_t *nb;

	nb = umem_cache_alloc(nb_cache, UMEM_DEFAULT);
	if (nb == NULL)
		return (NULL);

	/*
	 * neighbor_free() finis the list node, so it must be (re)initialized
	 * on every allocation, not just when the cache constructs the object.
	 */
	uu_list_node_init(nb, &nb->nb_node, nb_pool);

	return (nb);
}

void
neighbor_free(neighbor_t *nb)
{
	if (nb == NULL)
		return;

	uu_list_node_fini(nb, &nb->nb_node, nb_pool);

	/*
	 * The rxInfoAge timer is only initialized once the neighbor is added
	 * to an agent's list (update_objects()). lldp_timer_init() always
	 * sets lt_clock, so use that to tell if there's anything to fini.
	 */
	if (nb->nb_timer.lt_clock != NULL)
		lldp_timer_fini(&nb->nb_timer);
	(void) memset(&nb->nb_timer, '\0', sizeof (nb->nb_timer));

	nb->nb_time = 0;
	nb->nb_ttl = 0;

	(void) memset(nb->nb_src, '\0', sizeof (nb->nb_src));
	(void) memset(nb->nb_dst, '\0', sizeof (nb->nb_dst));
	(void) memset(nb->nb_pdu, '\0', sizeof (nb->nb_pdu));
	nb->nb_pdu_len = 0;

	tlv_list_free(&nb->nb_core_tlvs);
	tlv_list_free(&nb->nb_org_tlvs);
	tlv_list_free(&nb->nb_unknown_tlvs);

	umem_cache_free(nb_cache, nb);
}

uu_list_t *
neighbor_list_new(agent_t *a)
{
	return (uu_list_create(nb_pool, a, UU_LIST_DEBUG | UU_LIST_SORTED));
}

static int
nb_ctor(void *buf, void *cbdata __unused, int flags __unused)
{
	neighbor_t *nb = buf;

	(void) memset(nb, '\0', sizeof (*nb));
	tlv_list_init(&nb->nb_core_tlvs);
	tlv_list_init(&nb->nb_org_tlvs);
	tlv_list_init(&nb->nb_unknown_tlvs);
	return (0);
}

static void
nb_dtor(void *buf, void *cbdata __unused)
{
	neighbor_t *nb = buf;

	/* neighbor_free() has already released the timer and list node */
	tlv_list_free(&nb->nb_core_tlvs);
	tlv_list_free(&nb->nb_org_tlvs);
	tlv_list_free(&nb->nb_unknown_tlvs);
}

/*
 * Compare two Chassis ID or Port ID TLV values (subtype, then id).
 */
static int
id_cmp(buf_t lb, buf_t rb)
{
	uint8_t l_stype, r_stype;
	int ret;

	/*
	 * We should never instantiate a neighbor_t (especially off the wire)
	 * with an invalid PDU, and the door server validates cursors, so
	 * these should always succeed.
	 */
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
chassis_cmp(const tlv_t *l, const tlv_t *r)
{
	VERIFY3U(l->tlv_type, ==, LLDP_TLV_CHASSIS_ID);
	VERIFY3U(r->tlv_type, ==, LLDP_TLV_CHASSIS_ID);
	return (id_cmp(l->tlv_buf, r->tlv_buf));
}

static int
port_cmp(const tlv_t *l, const tlv_t *r)
{
	VERIFY3U(l->tlv_type, ==, LLDP_TLV_PORT_ID);
	VERIFY3U(r->tlv_type, ==, LLDP_TLV_PORT_ID);
	return (id_cmp(l->tlv_buf, r->tlv_buf));
}

int
neighbor_cmp_msap(const neighbor_t *l, const neighbor_t *r)
{
	tlv_t *l_tlv, *r_tlv;
	int ret;

	/* Chassis ID */
	l_tlv = tlv_list_get((tlv_list_t *)&l->nb_core_tlvs, NB_TLV_CHASSIS);
	r_tlv = tlv_list_get((tlv_list_t *)&r->nb_core_tlvs, NB_TLV_CHASSIS);
	ret = chassis_cmp(l_tlv, r_tlv);
	if (ret != 0)
		return (ret);

	/* Port ID */
	l_tlv = tlv_list_get((tlv_list_t *)&l->nb_core_tlvs, NB_TLV_PORT);
	r_tlv = tlv_list_get((tlv_list_t *)&r->nb_core_tlvs, NB_TLV_PORT);
	return (port_cmp(l_tlv, r_tlv));
}

/*
 * Compare a neighbor's MSAP against raw Chassis ID and Port ID TLV values
 * (e.g. from a door cursor). Both values must be at least 2 bytes.
 */
int
neighbor_cmp_msap_raw(const neighbor_t *nb, const uint8_t *chassis,
    uint16_t chassis_len, const uint8_t *port, uint16_t port_len)
{
	const tlv_t	*t;
	buf_t		b;
	int		ret;

	VERIFY3U(chassis_len, >=, 2);
	VERIFY3U(port_len, >=, 2);

	t = tlv_list_get((tlv_list_t *)&nb->nb_core_tlvs, NB_TLV_CHASSIS);
	buf_init(&b, (uint8_t *)chassis, chassis_len);
	ret = id_cmp(t->tlv_buf, b);
	if (ret != 0)
		return (ret);

	t = tlv_list_get((tlv_list_t *)&nb->nb_core_tlvs, NB_TLV_PORT);
	buf_init(&b, (uint8_t *)port, port_len);
	return (id_cmp(t->tlv_buf, b));
}

static int
neighbor_cmp_msap_uu(const void *a, const void *b, void *private __unused)
{
	return (neighbor_cmp_msap(a, b));
}

/*
 * Returns true if the information in two PDUs from the same MSAP is
 * identical. The value of the TTL TLV is excluded from the comparison:
 * a change in TTL alone just refreshes the existing information (see
 * rx_process_frame()), it isn't a change in the neighbor's information.
 */
bool
neighbor_same(const neighbor_t *l, const neighbor_t *r)
{
	const tlv_t	*lt, *rt;
	size_t		loff, roff, ttl_end;

	if (l->nb_pdu_len != r->nb_pdu_len)
		return (false);

	lt = tlv_list_get((tlv_list_t *)&l->nb_core_tlvs, NB_TLV_TTL);
	rt = tlv_list_get((tlv_list_t *)&r->nb_core_tlvs, NB_TLV_TTL);

	loff = buf_cptr(&lt->tlv_buf) - l->nb_pdu;
	roff = buf_cptr(&rt->tlv_buf) - r->nb_pdu;
	if (loff != roff || buf_len(&lt->tlv_buf) != buf_len(&rt->tlv_buf))
		return (false);

	ttl_end = loff + buf_len(&lt->tlv_buf);
	VERIFY3U(ttl_end, <=, l->nb_pdu_len);

	/* Everything before the TTL value (incl. the TTL TLV header) ... */
	if (memcmp(l->nb_pdu, r->nb_pdu, loff) != 0)
		return (false);

	/* ... and everything after it */
	return (memcmp(l->nb_pdu + ttl_end, r->nb_pdu + ttl_end,
	    l->nb_pdu_len - ttl_end) == 0);
}

void
neighbor_init(void)
{
	/*
	 * Note that we need to create the list pool prior to the umem
	 * cache since we pre want to init the uu_list_node_t in the
	 * cached objects.
	 */
	nb_pool = uu_list_pool_create("neighbors", sizeof (neighbor_t),
	    offsetof(neighbor_t, nb_node), neighbor_cmp_msap_uu,
	    UU_LIST_POOL_DEBUG);
	if (nb_pool == NULL)
		panic("failed to create neighbor list pool");

	log_trace(log, "creating neighbor cache", LOG_T_END);

	nb_cache = umem_cache_create("lldp neighbors", sizeof (neighbor_t),
	    sizeof (uint8_t), nb_ctor, nb_dtor, NULL, NULL, NULL, 0);
	if (nb_cache == NULL)
		panic("failed to create neighbor cache");
}

void
neighbor_fini(void)
{
	log_trace(log, "destroying neighbor cache", LOG_T_END);
	umem_cache_destroy(nb_cache);

	log_trace(log, "destroying neighbor list pool", LOG_T_END);
	uu_list_pool_destroy(nb_pool);
}
