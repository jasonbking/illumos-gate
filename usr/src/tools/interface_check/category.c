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
 * Copyright 2024 Jason King
 */

#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include "category.h"

static regex_t re_cat_version;
static regex_t re_cat_plain_1;
static regex_t re_cat_plain_2;
static regex_t re_cat_private;

void
category_init(void)
{
	VERIFY0(regcomp(&re_cat_version,
	    "^((SUNW|ILLUMOS)_)([0-9]+)\\.([0-9]+)(\\.([0-9]+))?",
	    REG_EXTENDED));
	VERIFY0(regcomp(&re_cat_plain_1, "^SYSVABI_1.[23]$", REG_EXTENDED));
	VERIFY0(regcomp(&re_cat_plain_2, "^SISCD_2.3[ab]*$", REG_EXTENDED));
	VERIFY0(regcomp(&re_cat_private, "^(SUNW|ILLUMOS)private(_[0-9.]+)?$",
	    REG_EXTENDED));
}

static uint_t
parse_num(const char *s, int start, int end)
{
	/* This should be big enough for any version numbers we encounter */
	char		buf[16] = { 0 };
	unsigned long	v;
	uint_t		i;

	/* Copy the section of s containing the number into buf */
	VERIFY3S(end - start, <, sizeof (buf) - 1);
	i = 0;
	while (start < end)
		buf[i++] = s[start++];

	errno = 0;
	v = strtoul(buf, NULL, 10);
	VERIFY(v != 0 || errno == 0);
	VERIFY3U(v, <=, UINT_MAX);
	return (v);
}

static inline bool
matched(const regmatch_t *pm)
{
	return ((pm->rm_eo == -1 || (pm->rm_eo == pm->rm_so)) ? false : true);
}

void
parse_category(const char *vstr, const char *soname, category_t *c)
{
	regmatch_t pmatch[7] = { 0 };

	(void) memset(c, '\0', sizeof (*c));
	if (regexec(&re_cat_version, vstr, 7, pmatch, 0) == 0) {
		c->c_type = CT_NUMBERED;

		/* Major number */
		VERIFY(matched(&pmatch[3]));
		c->c_ver[c->c_num++] = parse_num(vstr, pmatch[3].rm_so,
		    pmatch[3].rm_eo);

		/* Minor number */
		VERIFY(matched(&pmatch[4]));
		c->c_ver[c->c_num++] = parse_num(vstr, pmatch[4].rm_so,
		    pmatch[4].rm_eo);

		/* Micro number, may not be present */
		if (matched(&pmatch[6])) {
			c->c_ver[c->c_num++] = parse_num(vstr, pmatch[6].rm_so,
			    pmatch[6].rm_eo);
		}
		return;
	}

	if (regexec(&re_cat_plain_1, vstr, 0, NULL, 0) == 0 ||
	    regexec(&re_cat_plain_2, vstr, 0, NULL, 0) == 0) {
		c->c_type = CT_PLAIN;
		return;
	}

	if (soname != NULL && strcmp(vstr, soname) == 0) {
		c->c_type = CT_SONAME;
		return;
	}

	if (regexec(&re_cat_private, vstr, 0, NULL, 0) == 0) {
		c->c_type = CT_PRIVATE;
		return;
	}

	c->c_type = CT_UNKNOWN;
}
