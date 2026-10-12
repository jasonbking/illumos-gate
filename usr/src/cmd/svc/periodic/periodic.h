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
#include <librestart.h>
#include <libuutil.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	_(x) gettext(x)

struct method_context;
struct periodic_svc;

typedef struct periodic_exec {
	char			*pe_exec;
	int64_t			pe_timeout_secs;
	struct method_context	*pe_method_ctx;

	bool			pe_recover;
} periodic_exec_t;

typedef struct periodic_data {
	uint64_t	ps_delay;
	uint64_t	ps_n;
	uint64_t	ps_period;
	uint32_t	ps_jitter;
	bool		ps_persistent;

	int64_t		ps_last_run;
	int64_t		ps_next_run;
} periodic_data_t;

typedef enum scheduled_ival {
	SI_YEAR,
	SI_MONTH,
	SI_WEEK,
	SI_DAY,
	SI_HOUR,
	SI_MINUTE,
} scheduled_ival_t;

/*
 * 'Not set' values for the optional calendar fields of a schedule (year,
 * week_of_year, month, day_of_month, weekday_of_month, day, hour, and
 * minute). None of them can legitimately take these values.
 */
#define	SCHED_IVAL_NONE	INT64_MAX	/* int64_t fields */
#define	SCHED_UVAL_NONE	UINT64_MAX	/* uint64_t fields (year) */

typedef struct scheduled_data {
	struct scheduled_data	*ss_next;
	char			*ss_name;
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

	int64_t			ss_last_run;
	int64_t			ss_next_run;
} scheduled_data_t;

/*
 * The auxiliary state (restarter/auxiliary_state) of an online or degraded
 * instance: running while its method runs, otherwise scheduled. PA_NONE
 * means neither (e.g. the instance isn't online).
 */
typedef enum periodic_aux {
	PA_NONE,
	PA_SCHEDULED,
	PA_RUNNING,
} periodic_aux_t;

typedef enum periodic_svctype {
	PST_PERIODIC,
	PST_SCHEDULED,
} periodic_svctype_t;

typedef struct periodic_svc {
	uu_avl_node_t		ps_avl;		/* protected by svcs_lock */
	mutex_t			ps_lock;
	char			*ps_fmri;
	periodic_exec_t		ps_exec;
	bool			ps_running;
	restarter_instance_state_t ps_state;	/* current SMF state */
	periodic_svctype_t	ps_type;
	union {
		periodic_data_t		*psu_periodic;
		scheduled_data_t	*psu_scheduled;
	} ps_u;
} periodic_svc_t;

extern size_t max_fmri_len;

periodic_svc_t *periodic_svc_get(const char *);
void periodic_svc_add(periodic_svc_t *);
void periodic_svc_del(periodic_svc_t *);
void periodic_svc_rele(periodic_svc_t *);

bool init_scf(void);
void fini_scf(void);
bool get_service(periodic_svc_t *);
bool get_restarter_state(periodic_svc_t *, restarter_instance_state_t *,
    restarter_instance_state_t *);
restarter_str_t admin_request_reason(periodic_svc_t *);
bool save_run_times(periodic_svc_t *);
bool get_aux_state(periodic_svc_t *, periodic_aux_t *);
bool set_aux_state(periodic_svc_t *, periodic_aux_t);
void svc_set_running(periodic_svc_t *, bool);
void free_service(periodic_svc_t *);

void logmsg(const char *, ...) __PRINTFLIKE(1);
void panic(const char *, ...) __PRINTFLIKE(1) __NORETURN;

int64_t svc_next_run(const periodic_svc_t *);
int64_t svc_first_run(const periodic_svc_t *, int64_t);

#ifdef __cplusplus
}
#endif

#endif /* _SVC_PERIODIC_H */
