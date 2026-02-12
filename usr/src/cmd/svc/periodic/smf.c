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
#include <libscf.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <umem.h>

#include "periodic.h"

#define	PG_TYPE_SCHEDULE	"scheduled"
#define	PG_TYPE_PERIODIC	"periodic"

/*
 * How many times we try to bind to the SCF repository. The value was copied
 * from inetd given the lack of any better guidance on a value. That is to
 * say it's an arbitrary number.
 */
#define	BIND_SCF_TRIES		10

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
	{ "Februrary", "Feb" },
	{ "March", "Mar" },
	{ "April", "Apr" },
	{ "May", "May" },
	{ "June", "Jun" },
	{ "July", "Jul" },
	{ "August", "Aug" },
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

static struct proptbl sched_tbl[] = {
    { "
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
};

static struct proptbl periodic_tbl[] = {
    { "delay", offsetof(periodic_data_t, ps_delay), parse_time, false },
    { "period", offsetof(periodic_data_t, ps_period), parse_time, true },
    { "jitter", offsetof(periodic_data_t, ps_jitter), parse_time, false },
    { "persistent", offsetof(periodic_data_t, ps_persistent), parse_bool,
	false },
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
char *fmri;

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
		    _("failed to create SCF repository handle: %s"),
		    scf_strerror(scf_error()));
		return (false);
	}

	if (!bind_handle()) {
		scf_handle_destroy(rep_hdl);
		rep_hdl = NULL;
		return (false);
	}

	fmri = umem_zalloc(max_fmri_len, UMEM_NOFAIL);

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
	char		buf[9];

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
	if (((v >= 1) && (v <= 7)) || ((v >= -7) && (v <= -1))) {
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

	if (len > sizeof (buf)) {
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
		log(_("failed to get fmri from property group: %s"),
		    scf_strerror(scf_error()));
		return (false);
	}
	VERIFY3S(n, <, max_fmri_len);

	for (uint_t i = 0; i < n; i++, tbl++) {
		uint8_t		*dest = (uint8_t *)s + tbl->pt_offset;
		scf_error_t	e;
		bool		valid;

		if (scf_pg_get_property(pg, tbl->pt_name, prop) < 0) {
			if (tbl->pt_required) {
				log(_("%s: missing required %s property"),
				    fmri, tbl->pt_name);
				return (false);
			}
			continue;
		}

		if (scf_property_get_value(prop, val) < 0) {
			log(_("%s: failed getting value of %s property: %s"),
			    fmri, tbl->pt_name, scf_strerror(scf_error()));
			return (false);
		}

		e = tbl->pt_parse(val, dest, &valid);
		if (e != SCF_ERROR_NONE) {
			log(_("%s: failed parsing value of %s property: %s"),
			    fmri, tbl->pt_name, scf_strerror(e));
			return (false);
		}

		if (!valid) {
			log(_("%s: %s property's value is invalid"), fmri,
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

bool
get_service(periodic_svc_t *svc)
{
	int ret;

	if (scf_handle_decode_fmri(rep_hdl, svc->ps_fmri, NULL, NULL, inst,
	    NULL, NULL, 0) != 0) {
		log(_("%s: failed to decode fmri: %s"), svc->ps_fmri,
		    scf_strerror(scf_error()));
		return (false);
	}

	if (scf_iter_instance_pgs_composed(iter, inst, NULL) != 0) {
		log(_("%s: failed to iterate property groups: %s"),
		    svc->ps_fmri, scf_strerror(scf_error()));
		return (false);
	}

	while ((ret = scf_iter_next_pg(iter, pg)) == 1) {
		char	*name;
		ssize_t	n;
		char	pg_type[10];

		n = scf_pg_get_type(pg, pg_type, sizeof (pg_type));
		if (n < 0) {
			log(_("%s: failed to get property group type: %s"),
			    svc->ps_fmri, scf_strerror(scf_error()));
			return (false);
		}
		if (n >= sizeof (pg_type)) {
			/* Can't be a pg we're interested in */
			continue;
		}

		if (strcmp(pg_type, PG_TYPE_SCHEDULE) == 0) {
			if (!get_scheduled_data(pg, &svc->ps_u.psu_scheduled)) {
				return (false);
			}
			/* TODO -- get more bits */
		} else if (strcmp(pg_type, PG_TYPE_PERIODIC) == 0) {
			if (!get_periodic_data(pg, &svc->ps_u.psu_periodic)) {
				return (false);
			}
			/* TODO -- get more bits */
		} else {
			continue;
		}
	}

	if (ret < 0) {
		log(_("%s: error iterating property groups: %s"),
		    svc->ps_fmri, scf_strerror(scf_error()));
		return (false);
	}

	/* TODO get common bits for service */

	return (true);
}

