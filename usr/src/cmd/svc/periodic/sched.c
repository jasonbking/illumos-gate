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
 * Copyright 2026 Jason King
 */

#include <stdlib.h>
#include <time.h>
#include <sys/debug.h>

#include "periodic.h"

static int64_t periodic_next_run(const periodic_data_t *);
static int64_t periodic_first_run(const periodic_data_t *, bool, int64_t);
static int64_t scheduled_next_run(const scheduled_data_t *);

int64_t
svc_next_run(const periodic_svc_t *svc)
{
	const scheduled_data_t	*s;
	int64_t			next = INT64_MAX;

	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		return (periodic_next_run(svc->ps_u.psu_periodic));
	case PST_SCHEDULED:
		/*
		 * A scheduled service may have multiple schedules; it
		 * next runs at the earliest of them.
		 */
		VERIFY3P(svc->ps_u.psu_scheduled, !=, NULL);
		for (s = svc->ps_u.psu_scheduled; s != NULL; s = s->ss_next) {
			int64_t t = scheduled_next_run(s);

			if (t < next) {
				next = t;
			}
		}
		return (next);
	default:
		/* We should never have an unknown service type */
		panic("Invalid service type %d", svc->ps_type);
	}

	return (0);
}

/*
 * When svc should first run after coming online at now:
 *
 * - Not persistent, or never scheduled before: after delay (i.e. as soon as
 *   it comes online, by default).
 * - Persistent, and its prior schedule is still in the future: continue it.
 * - Persistent, and one or more runs were missed while it was down:
 *   - recover: run as soon as possible; later runs follow period and
 *     jitter from that run (see periodic_next_run()).
 *   - otherwise: skip the missed runs and continue the prior schedule.
 */
int64_t
svc_first_run(const periodic_svc_t *svc, int64_t now)
{
	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		return (periodic_first_run(svc->ps_u.psu_periodic,
		    svc->ps_exec.pe_recover, now));
	case PST_SCHEDULED:
		/* TODO: the first run of each schedule */
		return (svc_next_run(svc));
	default:
		panic("Invalid service type %d", svc->ps_type);
	}
}

static int64_t
periodic_first_run(const periodic_data_t *p, bool recover, int64_t now)
{
	int64_t next, period, missed;

	if (!p->ps_persistent) {
		return (now + (int64_t)p->ps_delay);
	}

	/*
	 * The prior schedule: the saved next run, or one period after the
	 * last run.
	 */
	period = (int64_t)p->ps_period;
	if (p->ps_next_run != 0) {
		next = p->ps_next_run;
	} else if (p->ps_last_run != 0) {
		next = p->ps_last_run + period;
	} else {
		/* Never scheduled */
		return (now + (int64_t)p->ps_delay);
	}

	if (next >= now) {
		return (next);
	}

	if (recover) {
		return (now);
	}

	/*
	 * Skip the missed runs: the first time on the prior schedule that is
	 * not in the past. period is > 0 (checked when loaded).
	 */
	missed = (now - next) / period + (((now - next) % period) != 0);
	if (missed > (INT64_MAX - next) / period) {
		return (INT64_MAX);
	}
	return (next + missed * period);
}

/*
 * When a periodic service should next run after its last run: period plus
 * up to jitter after it.
 */
static int64_t
periodic_next_run(const periodic_data_t *p)
{
	int64_t last_run = p->ps_last_run;
	int64_t jitter = 0;

	if (p->ps_jitter > 0) {
		jitter = arc4random_uniform(p->ps_jitter);
	}

	if (last_run == 0) {
		time_t now;

		VERIFY3S(time(&now), >, 0);
		return (now + jitter);
	}

	return (last_run + p->ps_period + jitter);
}

static int64_t
scheduled_next_run(const scheduled_data_t *s)
{
	/*
	 * The minimum frequency is 1 and should be validated when we
	 * load a service.
	 */
	VERIFY3U(s->ss_frequency, >, 0);


	return (0);
}
