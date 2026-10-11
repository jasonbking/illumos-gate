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

#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <librestart.h>
#include <libscf.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <umem.h>
#include <unistd.h>

#include "periodic.h"

#define	PG_TYPE_SCHEDULE	"schedule"
#define	PG_TYPE_PERIODIC	"periodic"

/* The method property group that holds the exec string and method context */
#define	START_METHOD		"start"

/* As with svc.startd, run with the config as of the last refresh */
#define	SNAPSHOT_RUNNING	"running"

/*
 * How many times we try to bind to the SCF repository. The value was copied
 * from inetd given the lack of any better guidance on a value. That is to
 * say it's an arbitrary number.
 */
#define	BIND_SCF_TRIES		10

/*
 * How many times get_service() reloads a service after losing its
 * connection to the repository (e.g. because svc.configd restarted).
 */
#define	LOAD_SCF_TRIES		3

#define	IVAL_YEAR		"year"
#define	IVAL_MONTH		"month"
#define	IVAL_WEEK		"week"
#define	IVAL_DAY		"day"
#define	IVAL_DAY_OF_MONTH	"day_of_month"
#define	IVAL_HOUR		"hour"
#define	IVAL_MINUTE		"minute"
#define	MAX_IVAL_LEN		(sizeof (IVAL_DAY_OF_MONTH) + 1)

struct names {
	const char *full;
	const char *abb;
};

static struct names months[] = {
	{ "January", "Jan" },
	{ "February", "Feb" },
	{ "March", "Mar" },
	{ "April", "Apr" },
	{ "May", "May" },
	{ "June", "Jun" },
	{ "July", "Jul" },
	{ "August", "Aug" },
	{ "September", "Sep" },
	{ "October", "Oct" },
	{ "November", "Nov" },
	{ "December", "Dec" },
};

static struct names days[] = {
	{ "Sunday", "Sun" },
	{ "Monday", "Mon" },
	{ "Tuesday", "Tue" },
	{ "Wednesday", "Wed" },
	{ "Thursday", "Thu" },
	{ "Friday", "Fri" },
	{ "Saturday", "Sat" },
};

struct proptbl {
	const char 	*pt_name;
	size_t		pt_offset;
	scf_error_t	(*pt_parse)(scf_value_t *, void *, bool *);
	bool		pt_required;
};

static scf_error_t parse_ival(scf_value_t *, void *, bool *);
static scf_error_t parse_str(scf_value_t *, void *, bool *);
static scf_error_t parse_count(scf_value_t *, void *, bool *);
static scf_error_t parse_int(scf_value_t *, void *, bool *);
static scf_error_t parse_bool(scf_value_t *, void *, bool *);
static scf_error_t parse_week_of_year(scf_value_t *, void *, bool *);
static scf_error_t parse_month(scf_value_t *, void *, bool *);
static scf_error_t parse_day_of_month(scf_value_t *, void *, bool *);
static scf_error_t parse_weekday_of_month(scf_value_t *, void *, bool *);
static scf_error_t parse_day(scf_value_t *, void *, bool *);
static scf_error_t parse_hour(scf_value_t *, void *, bool *);
static scf_error_t parse_minute(scf_value_t *, void *, bool *);
static scf_error_t parse_time(scf_value_t *, void *, bool *);
static scf_error_t parse_jitter(scf_value_t *, void *, bool *);

static struct proptbl sched_tbl[] = {
    { "interval", offsetof(scheduled_data_t, ss_interval), parse_ival, true },
    { "frequency", offsetof(scheduled_data_t, ss_frequency), parse_count,
	false },
    { "timezone", offsetof(scheduled_data_t, ss_timezone), parse_str, false },
    { "year", offsetof(scheduled_data_t, ss_year), parse_count, false },
    { "week_of_year", offsetof(scheduled_data_t, ss_week_of_year),
	parse_week_of_year, false },
    { "month", offsetof(scheduled_data_t, ss_month), parse_month, false },
    { "day_of_month", offsetof(scheduled_data_t, ss_day_of_month),
	parse_day_of_month, false },
    { "weekday_of_month", offsetof(scheduled_data_t, ss_weekday_of_month),
	parse_weekday_of_month, false },
    { "day", offsetof(scheduled_data_t, ss_day), parse_day, false },
    { "hour", offsetof(scheduled_data_t, ss_hour), parse_hour, false },
    { "minute", offsetof(scheduled_data_t, ss_minute), parse_minute, false },
    { "last_run", offsetof(scheduled_data_t, ss_last_run), parse_time, false },
    { "next_run", offsetof(scheduled_data_t, ss_next_run), parse_time, false },
};

static struct proptbl periodic_tbl[] = {
    { "delay", offsetof(periodic_data_t, ps_delay), parse_time, false },
    { "period", offsetof(periodic_data_t, ps_period), parse_time, true },
    { "jitter", offsetof(periodic_data_t, ps_jitter), parse_jitter, false },
    { "persistent", offsetof(periodic_data_t, ps_persistent), parse_bool,
	false },
    { "last_run", offsetof(periodic_data_t, ps_last_run), parse_time, false },
    { "next_run", offsetof(periodic_data_t, ps_next_run), parse_time, false },
};

static struct proptbl exec_tbl[] = {
    { SCF_PROPERTY_EXEC, offsetof(periodic_exec_t, pe_exec), parse_str,
	true },
    { SCF_PROPERTY_TIMEOUT, offsetof(periodic_exec_t, pe_timeout_secs),
	parse_count, false },
};

scf_handle_t *rep_hdl;
scf_service_t *service;
scf_instance_t *inst;
scf_transaction_t *xact;
scf_transaction_entry_t *entry;
scf_propertygroup_t *pg;
scf_property_t *prop;
scf_value_t *val;
scf_iter_t *iter;
scf_snapshot_t *snap;
char *fmri;

/* Buffer for property group names; includes space for the NUL */
static char *pg_name;
static size_t max_name_len;

static bool
bind_handle(void)
{
	uint_t	i;
	int	ret;

	for (i = 0; i < BIND_SCF_TRIES; i++) {
		ret = scf_handle_bind(rep_hdl);
		if (ret == 0 || scf_error() == SCF_ERROR_IN_USE) {
			return (true);
		}
		if (i + 1 < BIND_SCF_TRIES) {
			(void) sleep(1);
		}
	}

	fprintf(stderr, _("failed to bind SCF handle: %s\n"),
	    scf_strerror(scf_error()));

	return (false);
}

bool
init_scf(void)
{
	rep_hdl = scf_handle_create(SCF_VERSION);
	if (rep_hdl == NULL) {
		fprintf(stderr,
		    _("failed to create SCF repository handle: %s\n"),
		    scf_strerror(scf_error()));
		return (false);
	}

	if (!bind_handle()) {
		scf_handle_destroy(rep_hdl);
		rep_hdl = NULL;
		return (false);
	}

	fmri = umem_zalloc(max_fmri_len, UMEM_NOFAIL);

	max_name_len = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	pg_name = umem_zalloc(max_name_len, UMEM_NOFAIL);

	iter = scf_iter_create(rep_hdl);
	if (iter == NULL) {
		fprintf(stderr, _("failed to create SCF iter object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	inst = scf_instance_create(rep_hdl);
	if (inst == NULL) {
		fprintf(stderr, _("failed to create SCF instance object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	xact = scf_transaction_create(rep_hdl);
	if (xact == NULL) {
		fprintf(stderr,
		    _("failed to create SCF transaction object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	entry = scf_entry_create(rep_hdl);
	if (entry == NULL) {
		fprintf(stderr, _("failed to create SCF entry object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	pg = scf_pg_create(rep_hdl);
	if (pg == NULL) {
		fprintf(stderr,
		    _("failed to create SCF property group object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	prop = scf_property_create(rep_hdl);
	if (prop == NULL) {
		fprintf(stderr, _("failed to create SCF property object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	val = scf_value_create(rep_hdl);
	if (val == NULL) {
		fprintf(stderr, _("failed to create SCF value object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	snap = scf_snapshot_create(rep_hdl);
	if (snap == NULL) {
		fprintf(stderr,
		    _("failed to create SCF snapshot object: %s\n"),
		    scf_strerror(scf_error()));
		goto failed;
	}

	return (true);

failed:
	fini_scf();
	return (false);
}

void
fini_scf(void)
{
	(void) scf_handle_unbind(rep_hdl);

	umem_free(fmri, max_fmri_len);
	fmri = NULL;

	if (pg_name != NULL) {
		umem_free(pg_name, max_name_len);
		pg_name = NULL;
	}

	scf_snapshot_destroy(snap);
	snap = NULL;

	scf_value_destroy(val);
	val = NULL;

	scf_property_destroy(prop);
	prop = NULL;

	scf_pg_destroy(pg);
	pg = NULL;

	scf_entry_destroy(entry);
	entry = NULL;

	scf_transaction_destroy(xact);
	xact = NULL;

	scf_instance_destroy(inst);
	inst = NULL;

	scf_iter_destroy(iter);
	iter = NULL;

	scf_handle_destroy(rep_hdl);
	rep_hdl = NULL;
}

static bool
ival_str_to_val(const char *str, scheduled_ival_t *ivp)
{
	if (strcmp(str, IVAL_YEAR) == 0) {
		*ivp = SI_YEAR;
	} else if (strcmp(str, IVAL_MONTH) == 0) {
		*ivp = SI_MONTH;
	} else if (strcmp(str, IVAL_WEEK) == 0) {
		*ivp = SI_WEEK;
	} else if (strcmp(str, IVAL_DAY) == 0) {
		*ivp = SI_DAY;
	} else if (strcmp(str, IVAL_DAY_OF_MONTH) == 0) {
		*ivp = SI_DAY_OF_MONTH;
	} else if (strcmp(str, IVAL_HOUR) == 0) {
		*ivp = SI_HOUR;
	} else if (strcmp(str, IVAL_MINUTE) == 0) {
		*ivp = SI_MINUTE;
	} else {
		return (false);
	}
	return (true);
}

static scf_error_t
parse_ival(scf_value_t *v, void *vp, bool *validp)
{
	ssize_t			len;
	char			buf[MAX_IVAL_LEN] = { 0 };

	*validp = false;

	len = scf_value_get_astring(v, buf, sizeof (buf));
	if (len < 0) {
		return (scf_error());
	}
	if (len >= sizeof (buf)) {
		goto done;
	}

	if (!ival_str_to_val(buf, vp)) {
		goto done;
	}

	*validp = true;

done:
	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_count(scf_value_t *v, void *vp, bool *validp)
{
	*validp = false;

	if (scf_value_get_count(v, vp) != 0) {
		return (scf_error());
	}

	*validp = true;
	return (SCF_ERROR_NONE);
}

static bool
validate_week_of_year(int64_t val)
{
	if (val == INT64_MIN) {
		return (true);
	}
	if (val >= -53 && val <= -1) {
		return (true);
	}
	if (val >= 1 && val <= 53) {
		return (true);
	}
	return (false);
}

static scf_error_t
parse_week_of_year(scf_value_t *v, void *vp, bool *validp)
{
	int64_t *ip = vp;
	scf_error_t e;

	*validp = false;

	e = parse_int(v, vp, validp);
	if (e != SCF_ERROR_NONE) {
		return (e);
	}

	if (validate_week_of_year(*ip)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
parse_named(const char *str, const struct names *names, size_t n, int64_t *vp)
{
	if (str == NULL) {
		*vp = INT64_MIN;
		return (true);
	}

	for (size_t i = 0; i < n; i++) {
		if (strcasecmp(str, names[i].full) == 0 ||
		    strcasecmp(str, names[i].abb) == 0) {
			*vp = i + 1;
			return (true);
		}
	}

	char *endptr;
	long val;
	int64_t max = n;

	errno = 0;
	val = strtol(str, &endptr, 10);
	if (errno != 0) {
		return (false);
	}

	if (val < -max || val > max || val == 0) {
		return (false);
	}

	*vp = val;
	return (true);
}

static bool
month_to_val(const char *str, int64_t *vp)
{
	if (!parse_named(str, months, ARRAY_SIZE(months), vp)) {
		return (false);
	}

	return (parse_named(str, months, ARRAY_SIZE(months), vp));
}

static scf_error_t
parse_month(scf_value_t *v, void *vp, bool *validp)
{
	ssize_t		len;
	/* Large enough for the longest name ("September") + NUL */
	char		buf[10];

	*validp = false;

	len = scf_value_get_astring(v, buf, sizeof (buf));
	if (len < 0) {
		return (scf_error());
	}

	/* Size is too large -- i.e. invalid value */
	if (len >= sizeof (buf)) {
		return (SCF_ERROR_NONE);
	}

	if (month_to_val(buf, vp)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
validate_day_of_month(int64_t v)
{
	if (((v >= 1) && (v <= 31)) || ((v >= -31 && v <= -1))) {
		return (true);
	}
	return (false);
}

static scf_error_t
parse_day_of_month(scf_value_t *v, void *vp, bool *validp)
{
	int64_t		*ip = vp;
	scf_error_t	e;

	*validp = false;

	e = parse_int(v, vp, validp);
	if (e != SCF_ERROR_NONE) {
		return (e);
	}

	if (validate_day_of_month(*ip)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
validate_weekday_of_month(int64_t v)
{
	if (((v >= 1) && (v <= 5)) || ((v >= -5) && (v <= -1))) {
		return (true);
	}
	return (false);
}

static scf_error_t
parse_weekday_of_month(scf_value_t *v, void *vp, bool *validp)
{
	int64_t		*ip = vp;
	scf_error_t	e;

	*validp = false;

	e = parse_int(v, vp, validp);
	if (e != SCF_ERROR_NONE) {
		return (e);
	}

	if (validate_weekday_of_month(*ip)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
day_to_val(const char *str, int64_t *vp)
{
	return (parse_named(str, days, ARRAY_SIZE(days), vp));
}

static scf_error_t
parse_day(scf_value_t *v, void *vp, bool *validp)
{
	ssize_t	len;
	char	buf[10];

	*validp = false;

	len = scf_value_get_astring(v, buf, sizeof (buf));
	if (len < 0) {
		return (scf_error());
	}

	/* Size is too large -- i.e. invalid value */
	if (len >= sizeof (buf)) {
		return (SCF_ERROR_NONE);
	}

	if (day_to_val(buf, vp)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
validate_hour(int64_t v)
{
	if ((v >= -24) && (v <= 23)) {
		return (true);
	}
	return (false);
}

static scf_error_t
parse_hour(scf_value_t *v, void *vp, bool *validp)
{
	int64_t		*ip = vp;
	scf_error_t	e;

	*validp = false;

	e = parse_int(v, vp, validp);
	if (e != SCF_ERROR_NONE) {
		return (e);
	}

	if (validate_hour(*ip)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static bool
validate_minute(int64_t v)
{
	if ((v >= -60) && (v <= 59)) {
		return (true);
	}
	return (false);
}

static scf_error_t
parse_minute(scf_value_t *v, void *vp, bool *validp)
{
	int64_t		*ip = vp;
	scf_error_t	e;

	*validp = false;

	e = parse_int(v, vp, validp);
	if (e != SCF_ERROR_NONE) {
		return (e);
	}

	if (validate_minute(*ip)) {
		*validp = true;
	}

	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_str(scf_value_t *v, void *vp, bool *validp)
{
	char	*s;
	ssize_t len, ret;

	*validp = false;

	len = scf_value_get_astring(v, NULL, 0);
	if (len < 0) {
		return (scf_error());
	}

	s = calloc(1, len + 1);
	if (s == NULL) {
		return (SCF_ERROR_NO_MEMORY);
	}

	ret = scf_value_get_astring(v, s, len + 1);
	if (ret < 0) {
		free(s);
		return (scf_error());
	}

	/* The value shouldn't change between invocations */
	VERIFY3S(ret, ==, len);

	/* Free any previous value (e.g. from before a refresh) */
	free(*(char **)vp);
	*(char **)vp = s;
	*validp = true;

	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_int(scf_value_t *v, void *vp, bool *validp)
{
	*validp = false;

	if (scf_value_get_integer(v, vp) != 0) {
		return (scf_error());
	}

	*validp = true;
	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_time(scf_value_t *v, void *vp, bool *validp)
{
	/* We ignore the nanosecond portion of the time */
	int32_t ns = 0;

	*validp = false;

	if (scf_value_get_time(v, vp, &ns) != 0) {
		return (scf_error());
	}

	*validp = true;
	return (SCF_ERROR_NONE);
}

/*
 * ps_jitter is a uint32_t (it's passed to arc4random_uniform()), so read the
 * time into an int64_t and make sure it fits.
 */
static scf_error_t
parse_jitter(scf_value_t *v, void *vp, bool *validp)
{
	uint32_t	*jp = vp;
	int64_t		secs;
	scf_error_t	e;

	*validp = false;

	e = parse_time(v, &secs, validp);
	if (e != SCF_ERROR_NONE || !*validp) {
		return (e);
	}

	if (secs < 0 || secs > UINT32_MAX) {
		*validp = false;
		return (SCF_ERROR_NONE);
	}

	*jp = (uint32_t)secs;
	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_bool(scf_value_t *v, void *vp, bool *validp)
{
	bool	*bp = vp;
	uint8_t val = 0;

	*validp = false;

	if (scf_value_get_boolean(v, &val) != 0) {
		return (scf_error());
	}

	*bp = (val == 0) ? false : true;

	*validp = true;

	return (SCF_ERROR_NONE);
}

static bool
get_values(const scf_propertygroup_t *pg, const struct proptbl *tbl, uint_t n,
    void *s)
{
	ssize_t	len = 0;

	len = scf_pg_to_fmri(pg, fmri, max_fmri_len);
	if (len < 0) {
		logmsg(_("failed to get fmri from property group: %s"),
		    scf_strerror(scf_error()));
		return (false);
	}
	VERIFY3S(len, <, max_fmri_len);

	for (uint_t i = 0; i < n; i++, tbl++) {
		uint8_t		*dest = (uint8_t *)s + tbl->pt_offset;
		scf_error_t	e;
		bool		valid;

		if (scf_pg_get_property(pg, tbl->pt_name, prop) < 0) {
			if (scf_error() != SCF_ERROR_NOT_FOUND) {
				logmsg(_("%s: failed to get %s property: %s"),
				    fmri, tbl->pt_name,
				    scf_strerror(scf_error()));
				return (false);
			}
			if (tbl->pt_required) {
				logmsg(_("%s: missing required %s property"),
				    fmri, tbl->pt_name);
				return (false);
			}
			continue;
		}

		if (scf_property_get_value(prop, val) < 0) {
			logmsg(_("%s: failed getting value of %s property: %s"),
			    fmri, tbl->pt_name, scf_strerror(scf_error()));
			return (false);
		}

		e = tbl->pt_parse(val, dest, &valid);
		if (e != SCF_ERROR_NONE) {
			logmsg(_("%s: failed parsing value of %s property: %s"),
			    fmri, tbl->pt_name, scf_strerror(e));
			return (false);
		}

		if (!valid) {
			logmsg(_("%s: %s property's value is invalid"), fmri,
			    tbl->pt_name);
			return (false);
		}
	}

	return (true);
}

bool
get_scheduled_data(const scf_propertygroup_t *pg, scheduled_data_t *s)
{
	return (get_values(pg, sched_tbl, ARRAY_SIZE(sched_tbl), s));
}

bool
get_periodic_data(const scf_propertygroup_t *pg, periodic_data_t *p)
{
	return (get_values(pg, periodic_tbl, ARRAY_SIZE(periodic_tbl), p));
}

static void
free_scheduled_data(scheduled_data_t *s)
{
	while (s != NULL) {
		scheduled_data_t *next = s->ss_next;

		if (s->ss_name != NULL) {
			umem_free(s->ss_name, strlen(s->ss_name) + 1);
		}
		/* Allocated by parse_str() */
		free(s->ss_timezone);
		umem_free(s, sizeof (*s));

		s = next;
	}
}

static void
free_periodic_data(periodic_data_t *p)
{
	if (p != NULL) {
		umem_free(p, sizeof (*p));
	}
}

static void
svc_free_data(periodic_svc_t *svc)
{
	switch (svc->ps_type) {
	case PST_PERIODIC:
		free_periodic_data(svc->ps_u.psu_periodic);
		svc->ps_u.psu_periodic = NULL;
		break;
	case PST_SCHEDULED:
		free_scheduled_data(svc->ps_u.psu_scheduled);
		svc->ps_u.psu_scheduled = NULL;
		break;
	}
}

static void
free_exec(periodic_exec_t *pe)
{
	/* Allocated by parse_str() */
	free(pe->pe_exec);
	pe->pe_exec = NULL;

	if (pe->pe_method_ctx != NULL) {
		restarter_free_method_context(pe->pe_method_ctx);
		pe->pe_method_ctx = NULL;
	}
}

/*
 * Load the exec string, timeout, and method context of the start method from
 * the current property group (pg), following what svc.startd does in
 * method_run(). snapp is the snapshot pg was read from, or NULL if it came
 * from the current (editing) properties.
 */
static bool
get_exec(const char *svc_fmri, scf_snapshot_t *snapp, periodic_exec_t *pe)
{
	mc_error_t *mc_err;

	if (!get_values(pg, exec_tbl, ARRAY_SIZE(exec_tbl), pe)) {
		return (false);
	}

	/*
	 * timeout_seconds is a count, but as with svc.startd, both 0 and -1
	 * mean no timeout. We use 0 for no timeout.
	 */
	if (pe->pe_timeout_secs < 0) {
		pe->pe_timeout_secs = 0;
	}

	/* There is nothing for :kill to signal when a periodic task starts */
	if (restarter_is_kill_method(pe->pe_exec) >= 0 ||
	    restarter_is_kill_proc_method(pe->pe_exec) >= 0) {
		logmsg(_("%s: '%s' is not a valid %s method"), svc_fmri,
		    pe->pe_exec, START_METHOD);
		return (false);
	}

	/* :true never runs anything, so it needs no method context */
	if (restarter_is_null_method(pe->pe_exec)) {
		return (true);
	}

	mc_err = restarter_get_method_context(RESTARTER_METHOD_CONTEXT_VERSION,
	    inst, snapp, START_METHOD, pe->pe_exec, &pe->pe_method_ctx);
	if (mc_err != NULL) {
		logmsg(_("%s: failed to get %s method context: %s"), svc_fmri,
		    START_METHOD, mc_err->msg);
		restarter_mc_error_destroy(mc_err);
		pe->pe_method_ctx = NULL;
		return (false);
	}

	return (true);
}

/*
 * Set *matchp to whether the current property group (pg) is named name.
 */
static bool
pg_name_is(const char *svc_fmri, const char *name, bool *matchp)
{
	ssize_t len;

	len = scf_pg_get_name(pg, pg_name, max_name_len);
	if (len < 0) {
		logmsg(_("%s: failed to get property group name: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}
	VERIFY3S(len, <, max_name_len);

	*matchp = (strcmp(pg_name, name) == 0);
	return (true);
}

/*
 * Copy the name of the current property group (pg) into a newly allocated
 * string.
 */
static bool
get_pg_name(const char *svc_fmri, char **namep)
{
	ssize_t len;

	len = scf_pg_get_name(pg, pg_name, max_name_len);
	if (len < 0) {
		logmsg(_("%s: failed to get property group name: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}
	VERIFY3S(len, <, max_name_len);

	*namep = umem_alloc(len + 1, UMEM_NOFAIL);
	(void) strlcpy(*namep, pg_name, len + 1);
	return (true);
}

/*
 * Free everything get_service() loaded for svc.
 */
void
free_service(periodic_svc_t *svc)
{
	svc_free_data(svc);
	free_exec(&svc->ps_exec);
}

static bool load_service(periodic_svc_t *);

/*
 * Returns true if the repository connection is broken. A load can fail
 * part way through for many reasons, and scf_error() may be left over from
 * an earlier, expected failure (e.g. a missing optional property), so check
 * the connection directly rather than trusting it.
 */
static bool
connection_broken(const char *svc_fmri)
{
	if (scf_handle_decode_fmri(rep_hdl, svc_fmri, NULL, NULL, inst, NULL,
	    NULL, 0) == 0) {
		return (false);
	}

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
	case SCF_ERROR_NOT_BOUND:
		return (true);
	default:
		return (false);
	}
}

/*
 * Load svc from the repository (see load_service()). As inetd does, if the
 * connection to the repository was lost, rebind and try again.
 */
bool
get_service(periodic_svc_t *svc)
{
	for (uint_t i = 0; i < LOAD_SCF_TRIES; i++) {
		if (load_service(svc)) {
			return (true);
		}

		if (!connection_broken(svc->ps_fmri)) {
			return (false);
		}

		logmsg(_("%s: lost connection to repository, rebinding"),
		    svc->ps_fmri);
		(void) scf_handle_unbind(rep_hdl);
		if (!bind_handle()) {
			return (false);
		}
	}

	logmsg(_("%s: failed to load service after %u attempts"), svc->ps_fmri,
	    LOAD_SCF_TRIES);
	return (false);
}

/*
 * Load the periodic or scheduled data for svc from the repository. A
 * periodic service has exactly one property group of type 'periodic'. A
 * scheduled service has one or more property groups of type 'schedule',
 * each of which becomes an entry in the psu_scheduled list (in iteration
 * order) with ss_name set to the property group's name. A service may not
 * mix the two types.
 *
 * On success, any previously loaded data for svc is freed and replaced. On
 * failure, svc is left unchanged.
 */
static bool
load_service(periodic_svc_t *svc)
{
	periodic_data_t		*periodic = NULL;
	scheduled_data_t	*sched = NULL;
	scheduled_data_t	**tailp = &sched;
	periodic_exec_t		exec = { 0 };
	bool			have_start = false;
	scf_snapshot_t		*snapp = snap;
	int			ret;

	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	/*
	 * As svc.startd does, use the running snapshot so that changes take
	 * effect on refresh, falling back to the current properties if the
	 * instance doesn't have one yet.
	 */
	if (scf_instance_get_snapshot(inst, SNAPSHOT_RUNNING, snapp) != 0) {
		snapp = NULL;
	}

	if (scf_iter_instance_pgs_composed(iter, inst, snapp) != 0) {
		logmsg(_("%s: failed to iterate property groups: %s"),
		    svc->ps_fmri, scf_strerror(scf_error()));
		return (false);
	}

	while ((ret = scf_iter_next_pg(iter, pg)) == 1) {
		ssize_t	n;
		char	pg_type[10];

		n = scf_pg_get_type(pg, pg_type, sizeof (pg_type));
		if (n < 0) {
			logmsg(_("%s: failed to get property group type: %s"),
			    svc->ps_fmri, scf_strerror(scf_error()));
			goto fail;
		}
		if (n >= sizeof (pg_type)) {
			/* Can't be a pg we're interested in */
			continue;
		}

		if (strcmp(pg_type, PG_TYPE_SCHEDULE) == 0) {
			scheduled_data_t *s;

			if (periodic != NULL) {
				logmsg(_("%s: service cannot have both %s and "
				    "%s property groups"), svc->ps_fmri,
				    PG_TYPE_PERIODIC, PG_TYPE_SCHEDULE);
				goto fail;
			}

			/*
			 * Link it in before filling it in so the failure
			 * path frees it.
			 */
			s = umem_zalloc(sizeof (*s), UMEM_NOFAIL);
			*tailp = s;
			tailp = &s->ss_next;

			if (!get_pg_name(svc->ps_fmri, &s->ss_name)) {
				goto fail;
			}
			if (!get_scheduled_data(pg, s)) {
				goto fail;
			}
		} else if (strcmp(pg_type, PG_TYPE_PERIODIC) == 0) {
			if (sched != NULL) {
				logmsg(_("%s: service cannot have both %s and "
				    "%s property groups"), svc->ps_fmri,
				    PG_TYPE_PERIODIC, PG_TYPE_SCHEDULE);
				goto fail;
			}
			if (periodic != NULL) {
				logmsg(_("%s: service has more than one %s "
				    "property group"), svc->ps_fmri,
				    PG_TYPE_PERIODIC);
				goto fail;
			}

			periodic = umem_zalloc(sizeof (*periodic),
			    UMEM_NOFAIL);
			if (!get_periodic_data(pg, periodic)) {
				goto fail;
			}
		} else if (strcmp(pg_type, SCF_GROUP_METHOD) == 0) {
			bool is_start;

			if (!pg_name_is(svc->ps_fmri, START_METHOD,
			    &is_start)) {
				goto fail;
			}
			if (!is_start) {
				continue;
			}

			/*
			 * The composed view merges same-named service and
			 * instance property groups, so this shouldn't happen,
			 * but be certain we only ever load one start method.
			 */
			if (have_start) {
				logmsg(_("%s: service has more than one %s "
				    "method property group"), svc->ps_fmri,
				    START_METHOD);
				goto fail;
			}
			have_start = true;

			if (!get_exec(svc->ps_fmri, snapp, &exec)) {
				goto fail;
			}
		}
	}

	if (ret < 0) {
		logmsg(_("%s: error iterating property groups: %s"),
		    svc->ps_fmri, scf_strerror(scf_error()));
		goto fail;
	}

	if (periodic == NULL && sched == NULL) {
		logmsg(_("%s: missing %s or %s property group"), svc->ps_fmri,
		    PG_TYPE_PERIODIC, PG_TYPE_SCHEDULE);
		goto fail;
	}

	if (!have_start) {
		logmsg(_("%s: missing %s method property group"), svc->ps_fmri,
		    START_METHOD);
		goto fail;
	}

	svc_free_data(svc);

	free_exec(&svc->ps_exec);
	svc->ps_exec.pe_exec = exec.pe_exec;
	svc->ps_exec.pe_timeout_secs = exec.pe_timeout_secs;
	svc->ps_exec.pe_method_ctx = exec.pe_method_ctx;

	if (periodic != NULL) {
		svc->ps_type = PST_PERIODIC;
		svc->ps_u.psu_periodic = periodic;
	} else {
		svc->ps_type = PST_SCHEDULED;
		svc->ps_u.psu_scheduled = sched;
	}

	return (true);

fail:
	free_exec(&exec);
	free_periodic_data(periodic);
	free_scheduled_data(sched);
	return (false);
}
