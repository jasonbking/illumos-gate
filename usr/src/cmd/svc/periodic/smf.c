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

#include <sys/sysmacros.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "periodic.h"

#define	IVAL_YEAR		"year"
#define	IVAL_MONTH		"month"
#define	IVAL_WEEK		"week"
#define	IVAL_DAY		"day"
#define	IVAL_DAY_OF_MONTH	"day_of_month"
#define	IVAL_HOUR		"hour"
#define	IVAL_MINUTE		"minute"

struct names {
	const char *full;
	const char *abb;
};

bool
ival_str_to_val(const char *str, scheduled_ival_t *ivp)
{
	if (strcmp(str, IVAL_YEAR) == 0) {
		*ivp = ST_YEAR;
	} else if (strcmp(str, IVAL_MONTH) == 0) {
		*ivp = ST_MONTH;
	} else if (strcmp(str, IVAL_WEEK) == 0) {
		*ivp = ST_WEEK;
	} else if (strcmp(str, IVAL_DAY) == 0) {
		*ivp = ST_DAY;
	} else if (strcmp(str, IVAL_DAY_OF_MONTH) == 0) {
		*ivp = ST_DAY_OF_MONTH;
	} else if (strcmp(str, IVAL_HOUR) == 0) {
		*ivp = ST_HOUR;
	} else if (strcmp(str, IVAL_MINUTE) == 0) {
		*ivp = ST_MINUTE;
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
