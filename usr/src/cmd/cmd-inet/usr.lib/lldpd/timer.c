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

#include <inttypes.h>
#include <stddef.h>
#include <sys/debug.h>
#include <sys/time.h>

#include "agent.h"
#include "log.h"
#include "timer.h"
#include "util.h"

/*
 * The LLDP specification documents four timers:
 *  - rxInfoTTL (LLDP_TIMER_NEIGHBOR)
 *	An instance of this timer exists for each neighbor and represents
 *	the amount of time until the neighbor entry is expired (sans update).
 *  - tooManyNeighborsTimer (LLDP_TIMER_TOO_MANY)
 *	When an agent (link) reaches the maximum number of allowed neighbors,
 *	this ... until removed.
 *  - txTTR (LLDP_TIMER_TX)
 *	This timer determine when the next PDU should be transmitted.
 *  - txShutdownWhile (LLDP_TIMER_SHUT)
 *	Delays reinitialization.
 */
static uu_list_pool_t *clock_pool;

static const char *lldp_timer_str(lldp_timer_type_t);

void
lldp_timers_sysinit(void)
{
	clock_pool = uu_list_pool_create("clocks", sizeof (lldp_timer_t),
	    offsetof(lldp_timer_t, lt_node), NULL, UU_LIST_POOL_DEBUG);
	if (clock_pool == NULL)
		panic("cannot create clock pool");
}

void
lldp_timers_sysfini(void)
{
	uu_list_pool_destroy(clock_pool);
}

bool
lldp_timer_init(lldp_clock_t *clk, lldp_timer_type_t type, lldp_timer_t *t,
    void *parent, lldp_timer_func_t func)
{
	log_t *log_parent;

	VERIFY3P(clk, !=, NULL);
	VERIFY3P(parent, !=, NULL);
	VERIFY3P(func, !=, NULL);

	if (type == LLDP_TIMER_NEIGHBOR) {
		neighbor_t *nb = parent;
		log_parent = &nb->nb_log;
	} else {
		agent_t *a = parent;
		log_parent = &a->log;
	}

	(void) memset(t, '\0', sizeof (*t));

	if (!log_child(log_parent, &t->lt_log,
	    LOG_T_STRING, "timer", lldp_timer_str(type),
	    LOG_T_END)) {
		return (false);
	}

	uu_list_node_init(t, &t->lt_node, clock_pool);
	t->lt_clock = clk;
	t->lt_parent = parent;
	t->lt_type = type;
	t->lt_func = func;
	return (true);
}

void
lldp_timer_fini(lldp_timer_t *t)
{
	uu_avl_node_fini(t, &t->lt_node, timer_pool);
}

void
lldp_timer_set(lldp_timer_t *t, uint16_t amt)
{
	t->lt_lastset = gethrtime();
	t->lt_ttl = amt;
}

bool
lldp_clock_init(agent_t *a, lldp_clock_t *clk)
{
	clk->lc_agent = a;
	clk->lc_timers = uu_list_create(clock_pool, a, UU_AVL_DEBUG);
	if (clk->lts_timers == NULL) {
		log_uuerr(a->log, "failed to initialize timer tree");
		return (false);
	}
	return (true);
}

void
lldp_timers_fini(lldp_clock_t *clk)
{
	uu_list_destroy(clk->lc_timers);
	clk->lc_timers = NULL;
}

void
lldp_clock_tick(lldp_clock_t *clk, timestruc_t *tick)
{
	uint32_t msec = 1000;

	if (agent_num_neighors(clk->lc_agent) > 1) {
		msec -= 200 + arc4random_uniform(401);
	}

	if (amt >= 1000) {
		tick->tv_sec = 1;
		amt -= 1000;
	}
	tick->tv_nsec = MSEC2NSEC(amt);
}

void
lldp_clock_tock(lldp_clock_t *clk)
{
	clk->lc_agent->tx_tick = true;

	log_trace(clk->lc_agent->log, "tick", LOG_T_END);

	for (lldp_timer_t *t = uu_list_first(clk->lc_timers); t != NULL;
	    t = uu_list_next(clk->lc_timers)) {
		if (t->lt_ttl == 0)
			continue;

		if (--t->lt_ttl != 0)
			continue;

		log_trace(t->lt_log, "firing timer", LOG_T_END);
		t->lt_func(t->lt_parent);
	}
}

static const char *
lldp_timer_str(lldp_timer_type_t type)
{
	switch (type) {
	case LLDP_TIMER_NEIGHBOR:
		return ("rxInfoTTL");
	case LLDP_TIMER_TX:
		return ("txTTR");
	case LLDP_TIMER_SHUT:
		return ("txShutdownWhile");
	case LLDP_TIMER_TOO_MANY:
		return ("tooManyNeighbors");
	default:
		panic("unknown timer type");
	}
}
