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
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/time.h>

#include "agent.h"
#include "log.h"
#include "timer.h"
#include "util.h"

/*
 * Each agent (port) gets it's own clock (lldp_clock_t). The work of the
 * clock is broken up into two pieces -- lldp_clock_tick() which determines
 * the absolute time when the clock fires, and lldp_clock_tock() which is
 * called when the clock fires (to decrement each timer associated with
 * this clock).
 */
static uu_list_pool_t *clock_pool;

void
lldp_timers_sysinit(void)
{
	clock_pool = uu_list_pool_create("clocks", sizeof (lldp_timer_t),
	    offsetof(lldp_timer_t, lt_node), NULL, UU_LIST_POOL_DEBUG);
	if (clock_pool == NULL)
		panic("cannot create clock pool");

	log_trace(log, "created timer list pool", LOG_T_END);
}

void
lldp_timers_sysfini(void)
{
	uu_list_pool_destroy(clock_pool);
}

void
lldp_timer_init(lldp_clock_t *clk, lldp_timer_t *t, const char *name,
    void *parent, log_t *plog, const char *flagname, bool *flagp)
{
	VERIFY3P(clk, !=, NULL);
	VERIFY3P(parent, !=, NULL);
	VERIFY3P(plog, !=, NULL);
	VERIFY3P(name, !=, NULL);

	(void) memset(t, '\0', sizeof (*t));

	uu_list_node_init(t, &t->lt_node, clock_pool);

	(void) log_child(plog, &t->lt_log,
	    LOG_T_STRING, "timer", name,
	    LOG_T_END);

	t->lt_clock = clk;
	t->lt_parent = parent;
	t->lt_name = name;
	t->lt_flagp = flagp;
	t->lt_flagname = flagname;
}

void
lldp_timer_fini(lldp_timer_t *t)
{
	log_fini(t->lt_log);
	uu_list_node_fini(t, &t->lt_node, clock_pool);
}

void
lldp_timer_set(lldp_timer_t *t, uint16_t amt)
{
	t->lt_lastset = gethrtime();
	t->lt_val = amt;
	log_debug(t->lt_log, "setting timer",
	    LOG_T_UINT32, "value", (uint32_t)amt,
	    LOG_T_END);
}

uint16_t
lldp_timer_val(const lldp_timer_t *t)
{
	return (t->lt_val);
}

bool
lldp_clock_init(agent_t *a, lldp_clock_t *clk)
{
	clk->lc_agent = a;
	clk->lc_timers = uu_list_create(clock_pool, a, UU_LIST_DEBUG);
	if (clk->lc_timers == NULL) {
		log_uuerr(a->a_log, LOG_L_ERROR,
		    "failed to initialize timer tree");
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
	struct timeval now = { 0 };
	uint32_t msec = 1000;

	TRACE_ENTER(clk->lc_agent->a_log);

	VERIFY0(gettimeofday(&now, NULL));

	/*
	 * As recommended by 802.1ab, when there's more than one neighbor
	 * for an agent, we introduce some deliberate jitter into the clock
	 * to minimize sychronization.
	 */
	if (uu_list_numnodes(clk->lc_agent->a_neighbors) > 1) {
		msec -= 200 + arc4random_uniform(401);
	}

	tick->tv_nsec = USEC2NSEC(now.tv_usec) + MSEC2NSEC(msec);
	if (tick->tv_nsec > NANOSEC) {
		tick->tv_sec = now.tv_sec + 1;
		tick->tv_nsec -= NANOSEC;
	}

	TRACE_RETURN(clk->lc_agent->a_log);
}

void
lldp_clock_tock(lldp_clock_t *clk)
{
	TRACE_ENTER(clk->lc_agent->a_log);

	clk->lc_agent->a_ttr.ttr_tick = true;

	for (lldp_timer_t *t = uu_list_first(clk->lc_timers); t != NULL;
	    t = uu_list_next(clk->lc_timers, t)) {
		/*
		 * A timer already at 0 has already fired, skip it.
		 */
		if (t->lt_val == 0)
			continue;

		/*
		 * If we decrement the timer, and still have time remaining,
		 * nothing is needed. Continue to the next timer.
		 */
		if (--t->lt_val != 0)
			continue;

		/*
		 * If we get here, t has transitioned from 1 -> 0, and
		 * we should fire the timer (i.e. set the flag corresponding
		 * to this timer).
		 */
		log_debug(t->lt_log, "timer fired", LOG_T_END);
		if (t->lt_flagp != NULL) {
			*t->lt_flagp = true;
			log_debug(t->lt_log, "flag set",
			    LOG_T_STRING, "flag", t->lt_flagname,
			    LOG_T_END);
		}
	}

	TRACE_RETURN(clk->lc_agent->a_log);
}
