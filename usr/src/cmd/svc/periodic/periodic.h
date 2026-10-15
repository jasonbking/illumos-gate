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

#include <sys/types.h>
#include <inttypes.h>
#include <port.h>
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

/*
 * The largest period or delay we accept (about 100 years), and the largest
 * saved run or boot time. These keep the scheduling arithmetic in sched.c
 * from overflowing.
 */
#define	PERIODIC_TIME_MAX	((int64_t)100 * 365 * 24 * 60 * 60)
#define	RUN_TIME_MAX		(INT64_MAX / 4)

typedef struct periodic_data {
	uint64_t	ps_delay;
	uint64_t	ps_n;
	uint64_t	ps_period;
	uint32_t	ps_jitter;
	bool		ps_persistent;

	int64_t		ps_last_run;
	int64_t		ps_next_run;
	int64_t		ps_base;	/* next regular run (not saved) */
} periodic_data_t;

/* Why a service's schedule is being (re)started; see sched.c */
typedef enum periodic_start {
	PSTART_ONLINE,		/* it has just come online */
	PSTART_RESUME,		/* we're resuming an online instance */
} periodic_start_t;

/*
 * The units of time a schedule works in: the possible intervals, and the
 * granularity of each calendar field. Ordered from smallest to largest.
 */
typedef enum sched_unit {
	SU_MINUTE,
	SU_HOUR,
	SU_DAY,
	SU_WEEK,
	SU_MONTH,
	SU_YEAR,
	SU_NUM
} sched_unit_t;

/*
 * The levels the calendar fields of a schedule are grouped into, from
 * largest to smallest. The fields within a level are mutually exclusive
 * (apart from weekday_of_month, which qualifies day).
 */
typedef enum sched_level {
	SL_YEAR,
	SL_MONTH,
	SL_DAY,
	SL_HOUR,
	SL_MINUTE,
	SL_NUM
} sched_level_t;

/* The calendar fields of a schedule */
typedef enum sched_field {
	SF_YEAR,
	SF_MONTH,
	SF_WEEK,	/* week_of_year */
	SF_MDAY,	/* day_of_month */
	SF_WDAY,	/* day (of the week) */
	SF_WOM,		/* weekday_of_month */
	SF_HOUR,
	SF_MINUTE,
	SF_NUM
} sched_field_t;

#define	SF_BIT(f)	(1U << (f))

typedef struct sched_unit_info {
	const char	*su_name;	/* as an interval property value */
	sched_level_t	su_level;	/* the level an interval of it is at */
} sched_unit_info_t;

typedef struct sched_field_info {
	const char	*sf_name;	/* property name */
	sched_level_t	sf_level;
	sched_unit_t	sf_unit;
	size_t		sf_offset;	/* of its int64_t in scheduled_data_t */
	bool		sf_qualifier;	/* only qualifies another field */
} sched_field_info_t;

/* Indexed by sched_unit_t and sched_field_t; in sched.c */
extern const sched_unit_info_t sched_units[SU_NUM];
extern const sched_field_info_t sched_fields[SF_NUM];

/*
 * The 'not set' value of each calendar field. None of them can legitimately
 * take this value.
 */
#define	SCHED_IVAL_NONE	INT64_MAX

typedef struct scheduled_data {
	struct scheduled_data	*ss_next;
	char			*ss_name;
	sched_unit_t		ss_interval;
	uint64_t		ss_frequency;
	char			*ss_timezone;

	/* The calendar fields; see sched_fields[] */
	int64_t			ss_year;	/* a count in SMF */
	int64_t			ss_week_of_year;
	int64_t			ss_month;
	int64_t			ss_day_of_month;
	int64_t			ss_weekday_of_month;
	int64_t			ss_day;
	int64_t			ss_hour;
	int64_t			ss_minute;

	bool			ss_recover;

	int64_t			ss_last_run;
	int64_t			ss_next_run;
	int64_t			ss_base;	/* next regular run */
	int64_t			ss_offset;	/* into window; -1 if unknown */
} scheduled_data_t;

/*
 * Limits on schedules, which keep the calendar arithmetic in sched.c
 * within range.
 */
#define	SCHED_YEAR_MIN		1970
#define	SCHED_YEAR_MAX		9999
#define	SCHED_FREQUENCY_MAX	1000000

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
	/*
	 * Log for restarter messages about this instance and output from its
	 * runs. As with svc.startd, the path is derived from the FMRI (never
	 * read from restarter/logfile) and is set for the life of svc.
	 */
	char			*ps_logfile;
	periodic_exec_t		ps_exec;
	bool			ps_running;
	restarter_instance_state_t ps_state;	/* current SMF state */
	/*
	 * Non-fatal faults of its runs in a row, and whether a run (rather
	 * than an administrator) degraded it; see exec.c. Saved in the
	 * periodic_restarter property group.
	 */
	uint_t			ps_fault_count;
	bool			ps_fault_degraded;
	/*
	 * The timer that fires at its next run time, while it is online
	 * (see svc_schedule() in periodic.c). Main thread only.
	 */
	bool			ps_timer_created;
	timer_t			ps_timer;
	port_notify_t		ps_timer_pn;
	/* boot_time as of when its run times were last saved */
	int64_t			ps_saved_boot;
	periodic_svctype_t	ps_type;
	union {
		periodic_data_t		*psu_periodic;
		scheduled_data_t	*psu_scheduled;
	} ps_u;
} periodic_svc_t;

/*
 * Instance logs, named as svc.startd names them (restarter_insert_inst()):
 * LOG_PREFIX, then <service>:<instance> with each '/' replaced by '-', then
 * LOG_SUFFIX. svc.periodicd depends on filesystem/local, so unlike
 * svc.startd it never needs the early (/etc/svc/volatile) location.
 */
#define	LOG_PREFIX	"/var/svc/log/"
#define	LOG_SUFFIX	".log"

extern size_t max_fmri_len;
extern int64_t boot_time;	/* when this system or zone booted */
extern int evport;		/* the main loop's event port */
extern char *my_fmri;		/* our own instance's FMRI */

extern mutex_t tz_lock;

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
bool save_faults(periodic_svc_t *);
bool get_aux_state(periodic_svc_t *, periodic_aux_t *);
bool set_aux_state(periodic_svc_t *, periodic_aux_t);
void svc_set_running(periodic_svc_t *, bool);
void update_state(periodic_svc_t *, restarter_instance_state_t,
    restarter_error_t, restarter_str_t);
void svc_unschedule(periodic_svc_t *);
void free_service(periodic_svc_t *);
char *svc_logfile(const char *);
bool note_logfile(periodic_svc_t *);
bool note_run(periodic_svc_t *, pid_t, ctid_t, int64_t);
bool clear_run(periodic_svc_t *);

int expand_method_tokens(const char *, scf_instance_t *, scf_snapshot_t *,
    char **);

void exec_init(void);
void exec_refresh(void);
int exec_start(periodic_svc_t *);
bool exec_running(const char *);
bool exec_kill(const char *, int);
bool exec_port_event(const port_event_t *);

void logmsg(const char *, ...) __PRINTFLIKE(1);
void panic(const char *, ...) __PRINTFLIKE(1) __NORETURN;

int64_t svc_next_run(const periodic_svc_t *);
int64_t *sched_field(scheduled_data_t *, sched_field_t);
uint_t sched_fields_set(const scheduled_data_t *);
void svc_first_run(periodic_svc_t *, periodic_start_t, int64_t);
void svc_mark_run(periodic_svc_t *, int64_t);
void svc_after_run(periodic_svc_t *, int64_t);

#ifdef __cplusplus
}
#endif

#endif /* _SVC_PERIODIC_H */
