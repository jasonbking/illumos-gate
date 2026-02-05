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

#include "periodic.h"

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

struct proptbl {
	const char 	*pt_name;
	size_t		pt_offset;
	scf_error_t	(*pt_parse)(scf_value_t *, void *, bool *);
	bool		pt_required;
};

static struct proptbl sched_tbl[] = {
    { "interval", offsetof(scheduled_data_t, ss_interval), parse_ival, true },
    { "frequency", offsetof(scheduled_data_t, ss_frequency), parse_count, false },
    { "timezone", offsetof(scheduled_data_t, ss_timezone), parse_str, false },
    { "year", offsetof(scheduled_data_t, ss_year), parse_count, false },
};

scf_handle_t *rep_hdl;
scf_instance_t *inst;
scf_transaction_t *xact;
scf_transaction_entry_t *entry;
scf_propertygroup_t *pg;
scf_property_t *prop;
scf_value_t *val;

static bool bind_handle(void);

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

void
fini_scf(void)
{
	(void) scf_handle_unbind(rep_hdl);

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

	scf_handle_destroy(rep_hdl);
	rep_hdl = NULL;
}

bool
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

bool
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
	return (false);
}

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

bool
parse_month(const char *str, int64_t *vp)
{
	return (parse_named(str, months, ARRAY_SIZE(months), vp));
}

bool
parse_day(const char *str, int64_t *vp)
{
	return (parse_named(str, days, ARRAY_SIZE(days), vp));
}

static scf_error_t
parse_ival(scf_value_t *v, void *vp, bool *validp)
{
	ssize_t			len;
	char			buf[IVAL_MAX_LEN] = { 0 };

	*validp = false;

	len = scf_value_get_astring(v, buf, sizeof (buf));
	if (len < 0) {
		return (scf_error());
	}
	if (len >= IVAL_MAX_LEN) {
		goto done;
	}

	if (!ival_str_to_val(buf, vp)) {
		goto done;
	}

	*validp = true;

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

	ret = scf_value_get_string(v, s, len + 1);
	if (ret < 0) {
		free(s);
		return (scf_error());
	}

	/* The value shouldn't change between invocations */
	VERIFY3S(ret, ==, len);

	*vp = s;
	*validp = true;

	return (SCF_ERROR_NONE);
}

static scf_error_t
parse_month(scf_value_t *v, void *vp, bool *validp)
{
	/* TODO */
}
