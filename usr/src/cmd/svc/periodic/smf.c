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

#include <sys/ccompile.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <librestart.h>
#include <libscf.h>
#include <libscf_priv.h>
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

/* The method property group that holds the exec string and method context */
#define	START_METHOD		"start"

/* As with svc.startd, run with the config as of the last refresh */
#define	SNAPSHOT_RUNNING	"running"

/*
 * The property group, on each instance, where we record when it last ran
 * and when it next runs. This is runtime state, not configuration, so it is
 * always read from and written to the instance directly, never through a
 * snapshot. It is persistent so that last_run survives a reboot (needed for
 * persistent and recover). As with svc.startd's restarter property group,
 * it is of type framework.
 *
 * A periodic service uses the properties last_run and next_run. Each
 * schedule of a scheduled service uses <schedule name>_last_run and
 * <schedule name>_next_run.
 */
#define	PG_PERIODIC_RESTARTER	"periodic_restarter"
#define	PROP_LAST_RUN		"last_run"
#define	PROP_NEXT_RUN		"next_run"
#define	PROP_BOOT_TIME		"boot_time"

/*
 * The fault state of an instance (see exec.c), also kept in
 * periodic_restarter so that it survives restarts of svc.periodicd.
 */
#define	PROP_FAULT_COUNT	"fault_count"
#define	PROP_FAULT_DEGRADED	"fault_degraded"

/* Values of restarter/auxiliary_state while an instance is online */
#define	AUX_RUNNING		"running"
#define	AUX_SCHEDULED		"scheduled"

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

/* Longer than the longest interval name in sched_units[] ("minute") */
#define	MAX_IVAL_LEN		16

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

/*
 * Parse an SCF value into the field at vp, setting *validp to whether the
 * value is acceptable.
 */
typedef scf_error_t parse_fn_t(scf_value_t *, void *, bool *);

struct proptbl {
	const char	*pt_name;
	size_t		pt_offset;
	parse_fn_t	*pt_parse;
	bool		pt_required;
};

static parse_fn_t parse_ival;
static parse_fn_t parse_year;
static parse_fn_t parse_str;
static parse_fn_t parse_count;
static parse_fn_t parse_int;
static parse_fn_t parse_bool;
static parse_fn_t parse_week_of_year;
static parse_fn_t parse_month;
static parse_fn_t parse_day_of_month;
static parse_fn_t parse_weekday_of_month;
static parse_fn_t parse_day;
static parse_fn_t parse_hour;
static parse_fn_t parse_minute;
static parse_fn_t parse_time;
static parse_fn_t parse_jitter;

static struct proptbl sched_tbl[] = {
    { "interval", offsetof(scheduled_data_t, ss_interval), parse_ival, true },
    { "frequency", offsetof(scheduled_data_t, ss_frequency), parse_count,
	false },
    { "timezone", offsetof(scheduled_data_t, ss_timezone), parse_str, false },
    { "recover", offsetof(scheduled_data_t, ss_recover), parse_bool, false },
};

/*
 * The parser for each calendar field of a schedule. Their names and where
 * they're stored come from sched_fields[].
 */
static parse_fn_t *const sched_field_parse[SF_NUM] = {
	[SF_YEAR] =	parse_year,
	[SF_MONTH] =	parse_month,
	[SF_WEEK] =	parse_week_of_year,
	[SF_MDAY] =	parse_day_of_month,
	[SF_WDAY] =	parse_day,
	[SF_WOM] =	parse_weekday_of_month,
	[SF_HOUR] =	parse_hour,
	[SF_MINUTE] =	parse_minute,
};

static struct proptbl periodic_tbl[] = {
    { "delay", offsetof(periodic_data_t, ps_delay), parse_time, false },
    { "period", offsetof(periodic_data_t, ps_period), parse_time, true },
    { "jitter", offsetof(periodic_data_t, ps_jitter), parse_jitter, false },
    { "persistent", offsetof(periodic_data_t, ps_persistent), parse_bool,
	false },
};

/* recover is in the periodic pg, but applies to the start method */
static struct proptbl recover_tbl[] = {
    { "recover", offsetof(periodic_exec_t, pe_recover), parse_bool, false },
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

/*
 * Buffers for property group and property names; max_name_len includes
 * space for the NUL.
 */
static char *pg_name;
static char *prop_name;
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
	prop_name = umem_zalloc(max_name_len, UMEM_NOFAIL);

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
	if (prop_name != NULL) {
		umem_free(prop_name, max_name_len);
		prop_name = NULL;
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
ival_str_to_val(const char *str, sched_unit_t *ivp)
{
	for (uint_t u = 0; u < SU_NUM; u++) {
		if (strcmp(str, sched_units[u].su_name) == 0) {
			*ivp = u;
			return (true);
		}
	}
	return (false);
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

/*
 * year is stored as a count, but kept as an int64_t like the other calendar
 * fields. Any year beyond SCHED_YEAR_MAX is invalid (see
 * get_scheduled_data()), so all such values become SCHED_YEAR_MAX + 1 rather
 * than risk not fitting.
 */
static scf_error_t
parse_year(scf_value_t *v, void *vp, bool *validp)
{
	uint64_t	year;
	scf_error_t	e;

	e = parse_count(v, &year, validp);
	if (e != SCF_ERROR_NONE || !*validp) {
		return (e);
	}

	*(int64_t *)vp = (year > SCHED_YEAR_MAX) ? SCHED_YEAR_MAX + 1 :
	    (int64_t)year;
	return (SCF_ERROR_NONE);
}

static bool
validate_week_of_year(int64_t val)
{
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

/*
 * Parse str as either one of names (full or abbreviated, in any case), which
 * gives its 1-based position, or as a number in [1, n] or [-n, -1].
 */
static bool
parse_named(const char *str, const struct names *names, size_t n, int64_t *vp)
{
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
	if (errno != 0 || endptr == str || *endptr != '\0') {
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

/*
 * Set the fields of a new schedule that may be missing from its property
 * group: frequency defaults to 1, and the calendar fields to 'not set'.
 * (timezone is NULL, meaning the system's timezone.)
 */
static void
sched_init(scheduled_data_t *s)
{
	s->ss_frequency = 1;
	s->ss_offset = -1;
	for (uint_t f = 0; f < SF_NUM; f++) {
		*sched_field(s, f) = SCHED_IVAL_NONE;
	}
}

/*
 * With a frequency greater than 1, a schedule must be anchored: every level
 * from year down to its interval must be set. E.g. every 2 days needs year,
 * month (or week_of_year), and day (or day_of_month); every 2 weeks needs
 * year and month (or week_of_year). Levels smaller than the interval are
 * optional. Log every missing level, and return false if any are.
 */
static bool
sched_check_levels(const scheduled_data_t *s)
{
	uint_t		set = sched_fields_set(s);
	sched_level_t	ilevel = sched_units[s->ss_interval].su_level;
	/* Big enough for every level's names, plus separators */
	char		missing[128] = { 0 };

	for (uint_t l = SL_YEAR; l <= ilevel; l++) {
		bool	lset = false;
		bool	first = true;

		for (uint_t f = 0; f < SF_NUM; f++) {
			if (sched_fields[f].sf_level == l &&
			    !sched_fields[f].sf_qualifier &&
			    (set & SF_BIT(f)) != 0) {
				lset = true;
			}
		}
		if (lset) {
			continue;
		}

		/* List the level's fields; property names aren't translated */
		if (missing[0] != '\0') {
			(void) strlcat(missing, ", ", sizeof (missing));
		}
		for (uint_t f = 0; f < SF_NUM; f++) {
			if (sched_fields[f].sf_level != l ||
			    sched_fields[f].sf_qualifier) {
				continue;
			}
			if (!first) {
				(void) strlcat(missing, " or ",
				    sizeof (missing));
			}
			VERIFY3U(strlcat(missing, sched_fields[f].sf_name,
			    sizeof (missing)), <, sizeof (missing));
			first = false;
		}
	}

	if (missing[0] == '\0') {
		return (true);
	}

	logmsg(_("%s: a frequency greater than 1 with an interval of %s "
	    "also requires: %s"), fmri, sched_units[s->ss_interval].su_name,
	    missing);
	return (false);
}

bool
get_scheduled_data(const scf_propertygroup_t *pg, scheduled_data_t *s)
{
	struct proptbl	cal_tbl[SF_NUM];
	bool		ret = true;

	for (uint_t f = 0; f < SF_NUM; f++) {
		cal_tbl[f].pt_name = sched_fields[f].sf_name;
		cal_tbl[f].pt_offset = sched_fields[f].sf_offset;
		cal_tbl[f].pt_parse = sched_field_parse[f];
		cal_tbl[f].pt_required = false;
	}

	if (!get_values(pg, sched_tbl, ARRAY_SIZE(sched_tbl), s) ||
	    !get_values(pg, cal_tbl, ARRAY_SIZE(cal_tbl), s)) {
		return (false);
	}

	/* Try to note all errors instead of just the first one encountered */

	if (s->ss_frequency == 0 || s->ss_frequency > SCHED_FREQUENCY_MAX) {
		logmsg(_("%s: frequency must be between 1 and %d"), fmri,
		    SCHED_FREQUENCY_MAX);
		ret = false;
	}

	if (s->ss_year != SCHED_IVAL_NONE &&
	    (s->ss_year < SCHED_YEAR_MIN || s->ss_year > SCHED_YEAR_MAX)) {
		logmsg(_("%s: year must be between %d and %d"), fmri,
		    SCHED_YEAR_MIN, SCHED_YEAR_MAX);
		ret = false;
	}

	/* week_of_year and month are mutually exclusive */
	if (s->ss_week_of_year != SCHED_IVAL_NONE &&
	    s->ss_month != SCHED_IVAL_NONE) {
		logmsg(_("%s: month and week_of_year cannot both be set"),
		    fmri);
		ret = false;
	}

	/* day and day_of_month are mutually exclusive */
	if (s->ss_day != SCHED_IVAL_NONE &&
	    s->ss_day_of_month != SCHED_IVAL_NONE) {
		logmsg(_("%s: day and day_of_month cannot both be set"),
		    fmri);
		ret = false;
	}

	/* weekday_of_month requires day to be set */
	if (s->ss_weekday_of_month != SCHED_IVAL_NONE &&
	    s->ss_day == SCHED_IVAL_NONE) {
		logmsg(_("%s: weekday_of_month requires day to be set"),
		    fmri);
		ret = false;
	}

	if (s->ss_frequency > 1 && !sched_check_levels(s)) {
		ret = false;
	}

	return (ret);
}

bool
get_periodic_data(const scf_propertygroup_t *pg, periodic_data_t *p)
{
	if (!get_values(pg, periodic_tbl, ARRAY_SIZE(periodic_tbl), p)) {
		return (false);
	}

	/*
	 * period and delay are read as (signed) times; a negative value would
	 * be huge as a uint64_t, and a period of 0 would run continuously.
	 */
	if ((int64_t)p->ps_period <= 0 ||
	    (int64_t)p->ps_period > PERIODIC_TIME_MAX) {
		logmsg(_("%s: period must be greater than 0 and at most %lld"),
		    fmri, (longlong_t)PERIODIC_TIME_MAX);
		return (false);
	}
	if ((int64_t)p->ps_delay < 0 ||
	    (int64_t)p->ps_delay > PERIODIC_TIME_MAX) {
		logmsg(_("%s: delay must be between 0 and %lld"), fmri,
		    (longlong_t)PERIODIC_TIME_MAX);
		return (false);
	}

	return (true);
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
	mc_error_t	*mc_err;
	char		*expanded;

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

	/*
	 * Expand the method tokens (%s, %i, %f, %m, %r and %{prop}), as
	 * svc.startd's libscf_get_method() does. We do it when the
	 * configuration is loaded rather than for each run; the properties
	 * come from the same snapshot either way.
	 */
	if (expand_method_tokens(pe->pe_exec, inst, snapp, &expanded) != 0) {
		logmsg(_("%s: could not expand method tokens of \"%s\": %s"),
		    svc_fmri, pe->pe_exec, expanded);
		free(expanded);
		return (false);
	}
	free(pe->pe_exec);
	pe->pe_exec = expanded;

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

static bool load_service(periodic_svc_t *, void *);

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
 * Run op on svc. As inetd does, if it fails because the connection to the
 * repository was lost, rebind and try again.
 */
static bool
with_rebind(periodic_svc_t *svc, bool (*op)(periodic_svc_t *, void *),
    void *arg, const char *what)
{
	for (uint_t i = 0; ; i++) {
		if (op(svc, arg)) {
			return (true);
		}

		if (!connection_broken(svc->ps_fmri)) {
			return (false);
		}

		/* Only rebind if we'll try again */
		if (i + 1 >= LOAD_SCF_TRIES) {
			break;
		}

		logmsg(_("%s: lost connection to repository, rebinding"),
		    svc->ps_fmri);
		(void) scf_handle_unbind(rep_hdl);
		if (!bind_handle()) {
			return (false);
		}
	}

	logmsg(_("%s: failed to %s after %u attempts"), svc->ps_fmri, what,
	    LOAD_SCF_TRIES);
	return (false);
}

/*
 * The reason to record when an administrative degrade or maintenance
 * request moves svc to a new state. As svc.startd (event_from_tty()) and
 * inetd do, that's service_request if another service asked for it, and
 * administrative_request if it came from a command line (or we can't tell).
 */
restarter_str_t
admin_request_reason(periodic_svc_t *svc)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) == 0 &&
	    restarter_inst_ractions_from_tty(inst) == 0) {
		return (restarter_str_service_request);
	}
	return (restarter_str_administrative_request);
}

/*
 * Load svc from the repository (see load_service()).
 */
bool
get_service(periodic_svc_t *svc)
{
	return (with_rebind(svc, load_service, NULL, _("load service")));
}

/*
 * Read the restarter state property name (state or next_state) from the
 * restarter property group in pg. Returns 0 on success, ENOENT if the
 * property is missing, ECONNABORTED if the repository connection was lost,
 * or EINVAL if the value can't be read.
 */
static int
read_state_prop(const char *svc_fmri, const char *name,
    restarter_instance_state_t *statep)
{
	/* Larger than any SCF_STATE_STRING_* */
	char	buf[32];
	ssize_t	len;

	if (scf_pg_get_property(pg, name, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    (len = scf_value_get_astring(val, buf, sizeof (buf))) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (ECONNABORTED);
		default:
			logmsg(_("%s: failed to read %s/%s: %s"), svc_fmri,
			    SCF_PG_RESTARTER, name, scf_strerror(scf_error()));
			return (EINVAL);
		}
	}

	if ((size_t)len >= sizeof (buf)) {
		logmsg(_("%s: invalid %s/%s value"), svc_fmri,
		    SCF_PG_RESTARTER, name);
		return (EINVAL);
	}

	*statep = restarter_string_to_state(buf);
	return (0);
}

typedef struct rstate {
	restarter_instance_state_t	rs_state;
	restarter_instance_state_t	rs_next;
} rstate_t;

/*
 * Read svc's current SMF state from its restarter property group, directly
 * from the instance. This follows svc.startd's libscf_read_states() and
 * restarter_insert_inst():
 *
 * - No restarter property group, or neither property: uninitialized/none.
 * - Only one of state and next_state present: maintenance/none (the
 *   repository is inconsistent).
 * - Either value unreadable: uninitialized/none.
 */
static bool
load_restarter_state(periodic_svc_t *svc, void *arg)
{
	rstate_t	*rs = arg;
	int		sret, nret;

	rs->rs_state = RESTARTER_STATE_UNINIT;
	rs->rs_next = RESTARTER_STATE_NONE;

	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			return (true);
		}
		logmsg(_("%s: failed to get %s property group: %s"),
		    svc->ps_fmri, SCF_PG_RESTARTER, scf_strerror(scf_error()));
		return (false);
	}

	sret = read_state_prop(svc->ps_fmri, SCF_PROPERTY_STATE,
	    &rs->rs_state);
	nret = read_state_prop(svc->ps_fmri, SCF_PROPERTY_NEXT_STATE,
	    &rs->rs_next);

	if (sret == ECONNABORTED || nret == ECONNABORTED) {
		return (false);
	}

	if (sret == 0 && nret == 0) {
		return (true);
	}

	if (sret == ENOENT && nret == ENOENT) {
		rs->rs_state = RESTARTER_STATE_UNINIT;
	} else if (sret == EINVAL || nret == EINVAL) {
		rs->rs_state = RESTARTER_STATE_UNINIT;
	} else {
		logmsg(_("%s: only one of %s/%s and %s/%s exists; "
		    "treating as maintenance"), svc->ps_fmri, SCF_PG_RESTARTER,
		    SCF_PROPERTY_STATE, SCF_PG_RESTARTER,
		    SCF_PROPERTY_NEXT_STATE);
		rs->rs_state = RESTARTER_STATE_MAINT;
	}
	rs->rs_next = RESTARTER_STATE_NONE;

	return (true);
}

/*
 * Get svc's current and next SMF states as recorded in the repository.
 */
bool
get_restarter_state(periodic_svc_t *svc, restarter_instance_state_t *statep,
    restarter_instance_state_t *nextp)
{
	rstate_t rs;

	if (!with_rebind(svc, load_restarter_state, &rs,
	    _("read restarter state"))) {
		return (false);
	}

	*statep = rs.rs_state;
	*nextp = rs.rs_next;
	return (true);
}

/*
 * Build the name of a schedule's run time property in prop_name.
 */
static bool
sched_prop_name(const char *svc_fmri, const char *sched, const char *suffix)
{
	int n;

	n = snprintf(prop_name, max_name_len, "%s_%s", sched, suffix);
	if (n < 0 || (size_t)n >= max_name_len) {
		logmsg(_("%s: schedule name %s is too long for its %s "
		    "property"), svc_fmri, sched, suffix);
		return (false);
	}
	return (true);
}

/*
 * Read the time property name from pg into *tp, leaving *tp alone if the
 * property doesn't exist (i.e. it has never been set). A value that can't
 * be read is logged and ignored, treating it as never set, so that bad
 * runtime state doesn't take the service out of service. Only a lost
 * repository connection is a failure, so the load can be retried.
 */
static bool
read_time_prop(const char *svc_fmri, const char *name, int64_t *tp)
{
	int64_t	secs;
	int32_t	ns;

	if (scf_pg_get_property(pg, name, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_time(val, &secs, &ns) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (true);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (false);
		default:
			logmsg(_("%s: ignoring bad %s/%s property: %s"),
			    svc_fmri, PG_PERIODIC_RESTARTER, name,
			    scf_strerror(scf_error()));
			return (true);
		}
	}

	if (secs < 0 || secs > RUN_TIME_MAX) {
		logmsg(_("%s: ignoring out of range %s/%s value %lld"),
		    svc_fmri, PG_PERIODIC_RESTARTER, name, (longlong_t)secs);
		return (true);
	}

	*tp = secs;
	return (true);
}

/*
 * Read the count property name from pg into *np, as read_time_prop() does
 * for times.
 */
static bool
read_count_prop(const char *svc_fmri, const char *name, uint_t *np)
{
	uint64_t n;

	if (scf_pg_get_property(pg, name, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_count(val, &n) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (true);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (false);
		default:
			logmsg(_("%s: ignoring bad %s/%s property: %s"),
			    svc_fmri, PG_PERIODIC_RESTARTER, name,
			    scf_strerror(scf_error()));
			return (true);
		}
	}

	if (n > UINT_MAX) {
		logmsg(_("%s: ignoring out of range %s/%s value %llu"),
		    svc_fmri, PG_PERIODIC_RESTARTER, name, (u_longlong_t)n);
		return (true);
	}

	*np = (uint_t)n;
	return (true);
}

/*
 * Read the boolean property name from pg into *bp, as read_time_prop()
 * does for times.
 */
static bool
read_bool_prop(const char *svc_fmri, const char *name, bool *bp)
{
	uint8_t b;

	if (scf_pg_get_property(pg, name, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_boolean(val, &b) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (true);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (false);
		default:
			logmsg(_("%s: ignoring bad %s/%s property: %s"),
			    svc_fmri, PG_PERIODIC_RESTARTER, name,
			    scf_strerror(scf_error()));
			return (true);
		}
	}

	*bp = (b != 0);
	return (true);
}

/*
 * Read the last and next run times and the fault state for a newly loaded
 * periodic or scheduled service from the instance (inst) itself, not a
 * snapshot. A missing property group or property means it has never run
 * (or never faulted).
 */
static bool
read_run_times(const char *svc_fmri, periodic_data_t *p, scheduled_data_t *s,
    int64_t *bootp, uint_t *faultsp, bool *fdegradedp)
{
	if (scf_instance_get_pg(inst, PG_PERIODIC_RESTARTER, pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (true);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (false);
		default:
			logmsg(_("%s: failed to get %s property group: %s"),
			    svc_fmri, PG_PERIODIC_RESTARTER,
			    scf_strerror(scf_error()));
			return (false);
		}
	}

	if (!read_time_prop(svc_fmri, PROP_BOOT_TIME, bootp) ||
	    !read_count_prop(svc_fmri, PROP_FAULT_COUNT, faultsp) ||
	    !read_bool_prop(svc_fmri, PROP_FAULT_DEGRADED, fdegradedp)) {
		return (false);
	}

	if (p != NULL) {
		return (read_time_prop(svc_fmri, PROP_LAST_RUN,
		    &p->ps_last_run) &&
		    read_time_prop(svc_fmri, PROP_NEXT_RUN, &p->ps_next_run));
	}

	for (; s != NULL; s = s->ss_next) {
		if (!sched_prop_name(svc_fmri, s->ss_name, PROP_LAST_RUN) ||
		    !read_time_prop(svc_fmri, prop_name, &s->ss_last_run)) {
			return (false);
		}
		if (!sched_prop_name(svc_fmri, s->ss_name, PROP_NEXT_RUN) ||
		    !read_time_prop(svc_fmri, prop_name, &s->ss_next_run)) {
			return (false);
		}
	}

	return (true);
}

/*
 * Add setting the time property name to t to the transaction xact. The
 * entry and value are attached to xact, and freed by
 * scf_transaction_destroy_children().
 */
static bool
tx_set_time(const char *svc_fmri, const char *name, int64_t t)
{
	scf_transaction_entry_t	*e;
	scf_value_t		*v;

	if ((e = scf_entry_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF entry: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_transaction_property_new(xact, e, name, SCF_TYPE_TIME) != 0 &&
	    scf_transaction_property_change_type(xact, e, name,
	    SCF_TYPE_TIME) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri,
		    PG_PERIODIC_RESTARTER, name, scf_strerror(scf_error()));
		scf_entry_destroy(e);
		return (false);
	}
	/* e now belongs to xact */

	if ((v = scf_value_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF value: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_value_set_time(v, t, 0) != 0 ||
	    scf_entry_add_value(e, v) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri,
		    PG_PERIODIC_RESTARTER, name, scf_strerror(scf_error()));
		scf_value_destroy(v);
		return (false);
	}
	/* v now belongs to e */

	return (true);
}

/*
 * Add setting the astring property name of pgname to str to the transaction
 * xact, as tx_set_time() does for times.
 */
static bool
tx_set_astring(const char *svc_fmri, const char *pgname, const char *name,
    const char *str)
{
	scf_transaction_entry_t	*e;
	scf_value_t		*v;

	if ((e = scf_entry_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF entry: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_transaction_property_new(xact, e, name,
	    SCF_TYPE_ASTRING) != 0 &&
	    scf_transaction_property_change_type(xact, e, name,
	    SCF_TYPE_ASTRING) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri, pgname,
		    name, scf_strerror(scf_error()));
		scf_entry_destroy(e);
		return (false);
	}
	/* e now belongs to xact */

	if ((v = scf_value_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF value: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_value_set_astring(v, str) != 0 ||
	    scf_entry_add_value(e, v) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri, pgname,
		    name, scf_strerror(scf_error()));
		scf_value_destroy(v);
		return (false);
	}
	/* v now belongs to e */

	return (true);
}

/*
 * Commit a transaction on pg whose changes are added by fill(). As inetd
 * does, if someone else changed the property group first, get the latest
 * version and try again. pgname is only used for messages.
 */
static bool
tx_commit(periodic_svc_t *svc, const char *pgname,
    bool (*fill)(periodic_svc_t *, void *), void *arg)
{
	int ret;

	for (;;) {
		if (scf_transaction_start(xact, pg) != 0) {
			logmsg(_("%s: failed to start transaction on %s: %s"),
			    svc->ps_fmri, pgname, scf_strerror(scf_error()));
			return (false);
		}

		if (!fill(svc, arg)) {
			scf_transaction_destroy_children(xact);
			scf_transaction_reset(xact);
			return (false);
		}

		ret = scf_transaction_commit(xact);
		if (ret < 0) {
			logmsg(_("%s: failed to commit %s: %s"), svc->ps_fmri,
			    pgname, scf_strerror(scf_error()));
		}

		scf_transaction_destroy_children(xact);
		scf_transaction_reset(xact);

		if (ret != 0) {
			return (ret == 1);
		}

		if (scf_pg_update(pg) < 0) {
			logmsg(_("%s: failed to update %s: %s"), svc->ps_fmri,
			    pgname, scf_strerror(scf_error()));
			return (false);
		}
	}
}

/*
 * Add all of svc's run times to the transaction xact.
 */
static bool
tx_set_run_times(periodic_svc_t *svc, void *arg __unused)
{
	const scheduled_data_t *s;

	if (!tx_set_time(svc->ps_fmri, PROP_BOOT_TIME, boot_time)) {
		return (false);
	}

	if (svc->ps_type == PST_PERIODIC) {
		const periodic_data_t *p = svc->ps_u.psu_periodic;

		return (tx_set_time(svc->ps_fmri, PROP_LAST_RUN,
		    p->ps_last_run) &&
		    tx_set_time(svc->ps_fmri, PROP_NEXT_RUN, p->ps_next_run));
	}

	for (s = svc->ps_u.psu_scheduled; s != NULL; s = s->ss_next) {
		if (!sched_prop_name(svc->ps_fmri, s->ss_name, PROP_LAST_RUN) ||
		    !tx_set_time(svc->ps_fmri, prop_name, s->ss_last_run)) {
			return (false);
		}
		if (!sched_prop_name(svc->ps_fmri, s->ss_name, PROP_NEXT_RUN) ||
		    !tx_set_time(svc->ps_fmri, prop_name, s->ss_next_run)) {
			return (false);
		}
	}

	return (true);
}

/*
 * Get svc's periodic_restarter property group (from inst, which must
 * already refer to svc) into pg, creating it (persistent, so flags of 0) if
 * needed. If someone else creates it between our get and add, the add
 * fails with EXISTS, so get it again.
 */
static bool
get_periodic_pg(periodic_svc_t *svc)
{
	while (scf_instance_get_pg(inst, PG_PERIODIC_RESTARTER, pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto fail;
		}
		if (scf_instance_add_pg(inst, PG_PERIODIC_RESTARTER,
		    SCF_GROUP_FRAMEWORK, 0, pg) == 0) {
			return (true);
		}
		if (scf_error() != SCF_ERROR_EXISTS) {
			goto fail;
		}
	}
	return (true);

fail:
	logmsg(_("%s: failed to get or create %s property group: %s"),
	    svc->ps_fmri, PG_PERIODIC_RESTARTER, scf_strerror(scf_error()));
	return (false);
}

/*
 * Write svc's last and next run times to its periodic_restarter property
 * group, creating it if needed.
 */
static bool
store_run_times(periodic_svc_t *svc, void *arg __unused)
{
	if (svc->ps_type == PST_PERIODIC ?
	    svc->ps_u.psu_periodic == NULL : svc->ps_u.psu_scheduled == NULL) {
		/* Nothing loaded, so nothing to save */
		return (true);
	}

	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (!get_periodic_pg(svc)) {
		return (false);
	}

	if (!tx_commit(svc, PG_PERIODIC_RESTARTER, tx_set_run_times, NULL)) {
		return (false);
	}
	svc->ps_saved_boot = boot_time;
	return (true);
}

/*
 * Save svc's last and next run times to the repository.
 */
bool
save_run_times(periodic_svc_t *svc)
{
	return (with_rebind(svc, store_run_times, NULL,
	    _("save run times")));
}

static bool tx_set_num(const char *, const char *, const char *, scf_type_t,
    int64_t);

static bool
tx_set_faults(periodic_svc_t *svc, void *arg __unused)
{
	return (tx_set_num(svc->ps_fmri, PG_PERIODIC_RESTARTER,
	    PROP_FAULT_COUNT, SCF_TYPE_COUNT, svc->ps_fault_count) &&
	    tx_set_num(svc->ps_fmri, PG_PERIODIC_RESTARTER,
	    PROP_FAULT_DEGRADED, SCF_TYPE_BOOLEAN, svc->ps_fault_degraded));
}

static bool
store_faults(periodic_svc_t *svc, void *arg __unused)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (!get_periodic_pg(svc)) {
		return (false);
	}

	return (tx_commit(svc, PG_PERIODIC_RESTARTER, tx_set_faults, NULL));
}

/*
 * Save svc's fault state (ps_fault_count and ps_fault_degraded) to the
 * repository, so that it survives a restart of svc.periodicd.
 */
bool
save_faults(periodic_svc_t *svc)
{
	if (!with_rebind(svc, store_faults, NULL, _("save fault state"))) {
		logmsg(_("%s: couldn't save fault state"), svc->ps_fmri);
		return (false);
	}
	return (true);
}

/*
 * Read svc's auxiliary state (restarter/auxiliary_state) directly from the
 * instance. Anything other than running or scheduled (including a missing
 * property group or property, or a transition reason written by
 * restarter_set_states()) is PA_NONE. Only a lost repository connection is
 * a failure.
 */
static bool
load_aux_state(periodic_svc_t *svc, void *arg)
{
	periodic_aux_t	*auxp = arg;
	/* Larger than AUX_RUNNING or AUX_SCHEDULED */
	char		buf[32];
	ssize_t		len;

	*auxp = PA_NONE;

	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0 ||
	    scf_pg_get_property(pg, SCF_PROPERTY_AUX_STATE, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    (len = scf_value_get_astring(val, buf, sizeof (buf))) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (true);
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			return (false);
		default:
			logmsg(_("%s: failed to read %s/%s: %s"), svc->ps_fmri,
			    SCF_PG_RESTARTER, SCF_PROPERTY_AUX_STATE,
			    scf_strerror(scf_error()));
			return (true);
		}
	}

	if ((size_t)len >= sizeof (buf)) {
		return (true);
	}

	if (strcmp(buf, AUX_RUNNING) == 0) {
		*auxp = PA_RUNNING;
	} else if (strcmp(buf, AUX_SCHEDULED) == 0) {
		*auxp = PA_SCHEDULED;
	}

	return (true);
}

bool
get_aux_state(periodic_svc_t *svc, periodic_aux_t *auxp)
{
	return (with_rebind(svc, load_aux_state, auxp,
	    _("read auxiliary state")));
}

static bool
tx_set_aux_state(periodic_svc_t *svc, void *arg)
{
	periodic_aux_t aux = *(periodic_aux_t *)arg;

	return (tx_set_astring(svc->ps_fmri, SCF_PG_RESTARTER,
	    SCF_PROPERTY_AUX_STATE,
	    (aux == PA_RUNNING) ? AUX_RUNNING : AUX_SCHEDULED));
}

/*
 * Write svc's auxiliary state. svc.periodicd is the only writer of the
 * restarter property group of the instances it manages, which it otherwise
 * updates through restarter_set_states().
 */
static bool
store_aux_state(periodic_svc_t *svc, void *arg)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	/*
	 * restarter_set_states() creates the restarter property group, and
	 * we only set the auxiliary state after that.
	 */
	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		logmsg(_("%s: failed to get %s property group: %s"),
		    svc->ps_fmri, SCF_PG_RESTARTER, scf_strerror(scf_error()));
		return (false);
	}

	return (tx_commit(svc, SCF_PG_RESTARTER, tx_set_aux_state, arg));
}

/*
 * Return the path of the log for the instance fmri, allocated with
 * umem_alloc(), or NULL if fmri isn't a valid instance FMRI. As in svc.startd
 * (restarter_insert_inst()), the name is <service>:<instance> with each '/'
 * replaced by '-', so svc:/site/backup:default logs to
 * /var/svc/log/site-backup:default.log.
 */
char *
svc_logfile(const char *fmri)
{
	const char	*scope, *svc_name, *inst_name, *pgn, *propn;
	char		*buf, *path, *c;
	size_t		len;

	len = strlen(fmri) + 1;
	buf = umem_alloc(len, UMEM_NOFAIL);
	(void) strlcpy(buf, fmri, len);

	if (scf_parse_svc_fmri(buf, &scope, &svc_name, &inst_name, &pgn,
	    &propn) != 0 || svc_name == NULL || inst_name == NULL ||
	    pgn != NULL || propn != NULL) {
		umem_free(buf, len);
		return (NULL);
	}

	len = strlen(LOG_PREFIX) + strlen(svc_name) + 1 + strlen(inst_name) +
	    strlen(LOG_SUFFIX) + 1;
	path = umem_alloc(len, UMEM_NOFAIL);
	(void) snprintf(path, len, "%s%s:%s%s", LOG_PREFIX, svc_name,
	    inst_name, LOG_SUFFIX);
	umem_free(buf, strlen(fmri) + 1);

	for (c = path + strlen(LOG_PREFIX); *c != '\0'; c++) {
		if (*c == '/') {
			*c = '-';
		}
	}

	return (path);
}

static bool
tx_set_logfile(periodic_svc_t *svc, void *arg __unused)
{
	return (tx_set_astring(svc->ps_fmri, SCF_PG_RESTARTER,
	    SCF_PROPERTY_LOGFILE, svc->ps_logfile));
}

/*
 * Write svc's log path to restarter/logfile, creating the restarter
 * property group if needed, as svc.startd's libscf_note_method_log() does.
 */
static bool
store_logfile(periodic_svc_t *svc, void *arg __unused)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	while (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto fail;
		}
		if (scf_instance_add_pg(inst, SCF_PG_RESTARTER,
		    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg) == 0) {
			break;
		}
		if (scf_error() != SCF_ERROR_EXISTS) {
			goto fail;
		}
	}

	return (tx_commit(svc, SCF_PG_RESTARTER, tx_set_logfile, NULL));

fail:
	logmsg(_("%s: failed to get %s property group: %s"), svc->ps_fmri,
	    SCF_PG_RESTARTER, scf_strerror(scf_error()));
	return (false);
}

/*
 * Record where svc logs, so that svcs -l and svcs -L can find it.
 * svc.startd does this each time it runs a method, and only warns if it
 * fails; the log itself works either way. Any value an administrator set
 * is overwritten: the property reports the log, it doesn't choose it.
 */
bool
note_logfile(periodic_svc_t *svc)
{
	if (svc->ps_logfile == NULL) {
		return (false);
	}

	if (!with_rebind(svc, store_logfile, NULL, _("note log location"))) {
		logmsg(_("%s: couldn't note log location"), svc->ps_fmri);
		return (false);
	}
	return (true);
}

/*
 * Set svc's auxiliary state to running or scheduled.
 */
bool
set_aux_state(periodic_svc_t *svc, periodic_aux_t aux)
{
	VERIFY(aux == PA_RUNNING || aux == PA_SCHEDULED);

	return (with_rebind(svc, store_aux_state, &aux,
	    _("set auxiliary state")));
}

/*
 * Add setting the count, time or boolean (per type) property name of pgname
 * to n to the transaction xact, as tx_set_time() does.
 */
static bool
tx_set_num(const char *svc_fmri, const char *pgname, const char *name,
    scf_type_t type, int64_t n)
{
	scf_transaction_entry_t	*e;
	scf_value_t		*v;

	VERIFY(type == SCF_TYPE_COUNT || type == SCF_TYPE_TIME ||
	    type == SCF_TYPE_BOOLEAN);

	if ((e = scf_entry_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF entry: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_transaction_property_new(xact, e, name, type) != 0 &&
	    scf_transaction_property_change_type(xact, e, name, type) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri, pgname,
		    name, scf_strerror(scf_error()));
		scf_entry_destroy(e);
		return (false);
	}
	/* e now belongs to xact */

	if ((v = scf_value_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF value: %s"), svc_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (type == SCF_TYPE_COUNT) {
		scf_value_set_count(v, (uint64_t)n);
	} else if (type == SCF_TYPE_BOOLEAN) {
		scf_value_set_boolean(v, n != 0);
	} else if (scf_value_set_time(v, n, 0) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri, pgname,
		    name, scf_strerror(scf_error()));
		scf_value_destroy(v);
		return (false);
	}

	if (scf_entry_add_value(e, v) != 0) {
		logmsg(_("%s: failed to set %s/%s: %s"), svc_fmri, pgname,
		    name, scf_strerror(scf_error()));
		scf_value_destroy(v);
		return (false);
	}
	/* v now belongs to e */

	return (true);
}

typedef struct run_note {
	pid_t	rn_pid;
	ctid_t	rn_ctid;
	int64_t	rn_start;
} run_note_t;

static bool
tx_set_run(periodic_svc_t *svc, void *arg)
{
	const run_note_t *rn = arg;

	if (rn->rn_ctid != -1 &&
	    !tx_set_num(svc->ps_fmri, SCF_PG_RESTARTER, SCF_PROPERTY_CONTRACT,
	    SCF_TYPE_COUNT, rn->rn_ctid)) {
		return (false);
	}

	return (tx_set_num(svc->ps_fmri, SCF_PG_RESTARTER,
	    SCF_PROPERTY_START_PID, SCF_TYPE_COUNT, rn->rn_pid) &&
	    tx_set_num(svc->ps_fmri, SCF_PG_RESTARTER,
	    SCF_PROPERTY_START_METHOD_TIMESTAMP, SCF_TYPE_TIME, rn->rn_start));
}

static bool
store_run(periodic_svc_t *svc, void *arg)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	while (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto fail;
		}
		if (scf_instance_add_pg(inst, SCF_PG_RESTARTER,
		    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg) == 0) {
			break;
		}
		if (scf_error() != SCF_ERROR_EXISTS) {
			goto fail;
		}
	}

	return (tx_commit(svc, SCF_PG_RESTARTER, tx_set_run, arg));

fail:
	logmsg(_("%s: failed to get %s property group: %s"), svc->ps_fmri,
	    SCF_PG_RESTARTER, scf_strerror(scf_error()));
	return (false);
}

/*
 * Record a run of svc's start method that has just started: its contract
 * (restarter/contract; ctid is -1 if unknown), its pid (start_pid), and
 * when it started (start_method_timestamp). As with svc.startd, these are
 * informational, so failure is only logged.
 */
bool
note_run(periodic_svc_t *svc, pid_t pid, ctid_t ctid, int64_t start)
{
	run_note_t rn = { .rn_pid = pid, .rn_ctid = ctid, .rn_start = start };

	if (!with_rebind(svc, store_run, &rn, _("note run"))) {
		logmsg(_("%s: couldn't record run in repository"),
		    svc->ps_fmri);
		return (false);
	}
	return (true);
}

static bool
tx_clear_contract(periodic_svc_t *svc, void *arg __unused)
{
	scf_transaction_entry_t *e;

	if ((e = scf_entry_create(rep_hdl)) == NULL) {
		logmsg(_("%s: failed to create SCF entry: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_transaction_property_delete(xact, e,
	    SCF_PROPERTY_CONTRACT) != 0) {
		scf_entry_destroy(e);
		/* Nothing to delete is fine; commit the empty transaction */
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			return (true);
		}
		logmsg(_("%s: failed to delete %s/%s: %s"), svc->ps_fmri,
		    SCF_PG_RESTARTER, SCF_PROPERTY_CONTRACT,
		    scf_strerror(scf_error()));
		return (false);
	}
	/* e now belongs to xact */

	return (true);
}

static bool
store_clear_run(periodic_svc_t *svc, void *arg __unused)
{
	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		logmsg(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			return (true);
		}
		logmsg(_("%s: failed to get %s property group: %s"),
		    svc->ps_fmri, SCF_PG_RESTARTER, scf_strerror(scf_error()));
		return (false);
	}

	return (tx_commit(svc, SCF_PG_RESTARTER, tx_clear_contract, NULL));
}

/*
 * Remove restarter/contract once svc's run has finished (or if it was left
 * behind by a run that a previous svc.periodicd couldn't finish).
 */
bool
clear_run(periodic_svc_t *svc)
{
	if (!with_rebind(svc, store_clear_run, NULL, _("clear run"))) {
		logmsg(_("%s: couldn't remove contract from repository"),
		    svc->ps_fmri);
		return (false);
	}
	return (true);
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
load_service(periodic_svc_t *svc, void *arg __unused)
{
	periodic_data_t		*periodic = NULL;
	scheduled_data_t	*sched = NULL;
	scheduled_data_t	**tailp = &sched;
	periodic_exec_t		exec = { 0 };
	bool			have_start = false;
	int64_t			saved_boot = 0;
	uint_t			faults = 0;
	bool			fdegraded = false;
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

		if (strcmp(pg_type, SCF_GROUP_SCHEDULE) == 0) {
			scheduled_data_t *s;

			if (periodic != NULL) {
				logmsg(_("%s: service cannot have both %s and "
				    "%s property groups"), svc->ps_fmri,
				    SCF_GROUP_PERIODIC, SCF_GROUP_SCHEDULE);
				goto fail;
			}

			/*
			 * Link it in before filling it in so the failure
			 * path frees it.
			 */
			s = umem_zalloc(sizeof (*s), UMEM_NOFAIL);
			sched_init(s);
			*tailp = s;
			tailp = &s->ss_next;

			if (!get_pg_name(svc->ps_fmri, &s->ss_name)) {
				goto fail;
			}
			if (!get_scheduled_data(pg, s)) {
				goto fail;
			}
		} else if (strcmp(pg_type, SCF_GROUP_PERIODIC) == 0) {
			if (sched != NULL) {
				logmsg(_("%s: service cannot have both %s and "
				    "%s property groups"), svc->ps_fmri,
				    SCF_GROUP_PERIODIC, SCF_GROUP_SCHEDULE);
				goto fail;
			}
			if (periodic != NULL) {
				logmsg(_("%s: service has more than one %s "
				    "property group"), svc->ps_fmri,
				    SCF_GROUP_PERIODIC);
				goto fail;
			}

			periodic = umem_zalloc(sizeof (*periodic),
			    UMEM_NOFAIL);
			if (!get_periodic_data(pg, periodic) ||
			    !get_values(pg, recover_tbl,
			    ARRAY_SIZE(recover_tbl), &exec)) {
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
		    SCF_GROUP_PERIODIC, SCF_GROUP_SCHEDULE);
		goto fail;
	}

	if (!have_start) {
		logmsg(_("%s: missing %s method property group"), svc->ps_fmri,
		    START_METHOD);
		goto fail;
	}

	if (!read_run_times(svc->ps_fmri, periodic, sched, &saved_boot,
	    &faults, &fdegraded)) {
		goto fail;
	}

	svc_free_data(svc);

	free_exec(&svc->ps_exec);
	svc->ps_exec.pe_exec = exec.pe_exec;
	svc->ps_exec.pe_timeout_secs = exec.pe_timeout_secs;
	svc->ps_exec.pe_method_ctx = exec.pe_method_ctx;
	svc->ps_exec.pe_recover = exec.pe_recover;
	svc->ps_saved_boot = saved_boot;
	svc->ps_fault_count = faults;
	svc->ps_fault_degraded = fdegraded;

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
