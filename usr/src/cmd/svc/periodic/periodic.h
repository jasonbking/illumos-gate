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

#ifndef _SVC_PERIODIC_H
#define	_SVC_PERIODIC_H

#include <inttypes.h>
#include <stdbool.h>
#include <libintl.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	_(x) gettext(x)

struct method_context;

typedef struct periodic_exec {
	char			*pe_exec;
	int64_t			pe_timeout_secs;
	struct method_context	*pe_method_ctx;

	int64_t			pe_last_run;
	int64_t			pe_next_run;
	bool			pe_recover;
} periodic_exec_t;

typedef struct periodic_data {
	uint64_t	ps_delay;
	uint64_t	ps_delay;
	uint64_t	ps_period;
	uint32_t	ps_jitter;
	bool		ps_persistent;
} periodic_data_t;

typedef enum scheduled_ival {
	SI_YEAR,
	SI_MONTH,
	SI_WEEK,
	SI_DAY,
	SI_DAY_OF_MONTH,
	SI_HOUR,
	SI_MINUTE,
} scheduled_ival_t;

typedef struct scheduled_data {
	scheduled_ival_t	ss_interval;
	uint64_t		ss_frequency;
	char			*ss_timezone;
	uint64_t		ss_year;
	int64_t			ss_week_of_year;
	int64_t			ss_month;
	int64_t			ss_day_of_month;
	int64_t			ss_weekday_of_month;
	int64_t			ss_day;
	int64_t			ss_hour;
	int64_t			ss_minute;
} scheduled_data_t;

typedef enum periodic_svctype {
	PST_PERIODIC,
	PST_SCHEDULED,
} periodic_svctype_t;

typedef struct periodic_svc {
	mutex_t			ps_lock;
	char			*ps_fmri;
	periodic_exec_t		ps_exec;
	periodic_svctype_t	ps_type;
	union {
		periodic_data_t		psu_periodic;
		scheduled_data_t	psu_scheduled;
	} ps_u;
} periodic_svc_t;

periodic_svc_t *periodic_svc_get(const char *);
void periodic_svc_add(periodic_svc_t *);
void periodic_svc_rele(periodic_svc_t *);

void log(const char *, ...) __PRINTFLIKE(0);
void panic(const char *, ...) __PRINTFLIKE(0);

int64_t svc_next_run(const periodic_svc_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SVC_PERIODIC_H */
