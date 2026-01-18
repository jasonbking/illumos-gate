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

static int64_t periodic_next_run(const periodic_data_t *, int64_t);
static int64_t scheduled_next_run(const scheduled_data_t *, int64_t);

int64_t
svc_next_run(const periodic_svc_t *svc)
{
	switch (svc->ps_type) {
	case PST_PERIODIC:
		return (periodic_next_run(&svc->ps_u.psu_periodic,
		    svc->ps_exec.pe_last_run));
	case PST_SCHEDULED:
		return (scheduled_next_run(&svc->ps_u.psu_scheduled,
		    svc->ps_exec.pe_last_run));
		break;
	default:
		/* We should never have an unknown service type */
		panic("Invalid service type %d", svc->ps_type);
	}

	return (0);
}

static int64_t
periodic_next_run(const periodic_data_t *p, int64_t last_run)
{
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
scheduled_next_run(const scheduled_data_t *s, int64_t last_run)
{
	/*
	 * The minimum frequency is 1 and should be validated when we
	 * load a service.
	 */
	VERIFY3U(s->ss_frequency, >, 0);


	return (0);
}
