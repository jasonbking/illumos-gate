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
 * Each agent (port) gets it's own clock (lldp_clock_t), which ticks once a
 * second. Each tick decrements every timer associated with the clock (and
 * fires any that reach zero).
 *
 * The clock keeps an absolute deadline for its next tick in terms of
 * gethrtime(), which is monotonic and unaffected by changes to the system
 * time (NTP steps, date(1), etc). Each deadline is computed from the
 * previous deadline, not from when the previous tick was processed, so
 * scheduling and processing latency don't accumulate into drift. The
 * agent thread waits for the deadline with cond_reltimedwait() (see
 * lldp_clock_reltime()), and calls lldp_clock_advance() whenever it wakes
 * to process every tick that has come due -- including any that were
 * missed if the thread was delayed for longer than a tick.
 *
 * A timer is associated with its clock (placed on lc_timers) from
 * lldp_timer_init() until lldp_timer_fini(). A clock and its timers are only
 * manipulated by the owning agent's thread, or while that thread isn't
 * running (agent creation/destruction).
 */
static uu_list_pool_t *clock_pool;

static void lldp_clock_tock(lldp_clock_t *);

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

	/* Attach to the clock so lldp_clock_tock() counts it down */
	VERIFY0(uu_list_insert_before(clk->lc_timers, NULL, t));
}

/*
 * Detach a timer from its clock and release its resources. It is safe to
 * call this on a zeroed timer that was never initialized.
 */
void
lldp_timer_fini(lldp_timer_t *t)
{
	if (t->lt_clock == NULL)
		return;

	uu_list_remove(t->lt_clock->lc_timers, t);
	uu_list_node_fini(t, &t->lt_node, clock_pool);
	log_fini(t->lt_log);

	t->lt_clock = NULL;
	t->lt_log = NULL;
	t->lt_val = 0;
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
	clk->lc_deadline = 0;
	clk->lc_timers = uu_list_create(clock_pool, a, UU_LIST_DEBUG);
	if (clk->lc_timers == NULL) {
		log_uuerr(a->a_log, LOG_L_ERROR,
		    "failed to initialize timer tree");
		return (false);
	}
	return (true);
}

void
lldp_clock_fini(lldp_clock_t *clk)
{
	if (clk->lc_timers == NULL)
		return;

	/* Every timer should have been lldp_timer_fini()ed by now */
	VERIFY3U(uu_list_numnodes(clk->lc_timers), ==, 0);
	uu_list_destroy(clk->lc_timers);
	clk->lc_timers = NULL;
}

/*
 * The length of the next tick. As recommended by 802.1ab, when there's more
 * than one neighbor for an agent, we introduce some deliberate jitter
 * (+/- 200ms, uniformly distributed) into the clock to minimize
 * synchronization. Since the jitter has a mean of zero and each tick is
 * scheduled from the previous deadline, it doesn't change the long-term
 * rate of the clock.
 */
static hrtime_t
clock_period(const lldp_clock_t *clk)
{
	hrtime_t msec = 1000;

	if (uu_list_numnodes(clk->lc_agent->a_neighbors) > 1)
		msec = msec - 200 + arc4random_uniform(401);

	return (MSEC2NSEC(msec));
}

/*
 * Start the clock: the first tick is one period from now.
 */
void
lldp_clock_start(lldp_clock_t *clk)
{
	clk->lc_deadline = gethrtime() + clock_period(clk);
}

/*
 * Set *rel to the time remaining until the next tick (zero if it's already
 * due), suitable for cond_reltimedwait().
 */
void
lldp_clock_reltime(const lldp_clock_t *clk, timestruc_t *rel)
{
	hrtime_t left = clk->lc_deadline - gethrtime();

	if (left < 0)
		left = 0;

	rel->tv_sec = left / NANOSEC;
	rel->tv_nsec = left % NANOSEC;
}

/*
 * Process every tick that has come due, and schedule the next. Returns the
 * number of ticks processed (zero if woken before the deadline).
 */
uint_t
lldp_clock_advance(lldp_clock_t *clk)
{
	hrtime_t	now = gethrtime();
	uint_t		n = 0;

	while (now >= clk->lc_deadline) {
		/*
		 * Timers are 16 bits, so after UINT16_MAX ticks every timer
		 * has necessarily expired; there's nothing more to catch up
		 * on, so just restart the schedule from now.
		 */
		if (n == UINT16_MAX) {
			clk->lc_deadline = now + clock_period(clk);
			break;
		}

		lldp_clock_tock(clk);
		clk->lc_deadline += clock_period(clk);
		n++;
	}

	if (n > 1) {
		log_warn(clk->lc_agent->a_log,
		    "agent fell behind its clock; processed missed ticks",
		    LOG_T_UINT32, "ticks", n,
		    LOG_T_END);
	}

	return (n);
}

/*
 * Process a single tick. This runs every second, so it deliberately doesn't
 * log anything unless a timer actually expires.
 */
static void
lldp_clock_tock(lldp_clock_t *clk)
{
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
}
