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
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <umem.h>
#include <sys/debug.h>

#include "str.h"

bool
cgetline(FILE *f, custr_t *cus, uint_t *linenp)
{
	const char	*p, *cp;
	int		c;
	bool		lnext;

again:
	if (feof(f))
		return (false);

	custr_reset(cus);

	lnext = false;
	while ((c = fgetc(f)) != -1) {
		if (!lnext && c == '\\') {
			lnext = true;
			continue;
		}

		fcustr_appendc(cus, c);

		if (c == '\n') {
			(*linenp)++;

			if (!lnext) {
				/* remove the trailing \n */
				fcustr_rtrunc(cus, 0);
				break;
			}
		}

		lnext = false;
	}

	/* Handle a corner case == a \ as the very last character of the file */
	if (feof(f) && c == '\\') {
		fcustr_appendc(cus, c);
		(*linenp)++;
	}

	if (ferror(f))
		return (false);

	/* Strip comments (i.e. everything starting at '#') */
	p = custr_cstr(cus);
	cp = strchr(p, '#');
	if (cp != NULL) {
		size_t idx;

		idx = (size_t)(uintptr_t)(cp - p);
		fcustr_trunc(cus, idx);
	}

	trimws(cus);

	/* Empty line */
	if (custr_len(cus) == 0)
		goto again;

	return (true);
}

void
trimws(custr_t *cus)
{
	const char	*p = custr_cstr(cus);
	size_t		len;
	size_t		n;

	/* Trailing whitespace */
	n = 0;
	len = custr_len(cus);
	if (len == 0)
		return;

	while (len > 0 && isspace(p[--len])) {
		n++;
	}
	if (n > 0)
		fcustr_rtrunc(cus, n);

	/* Leading whitespace */
	n = 0;
	len = custr_len(cus);
	while (n < len && isspace(p[n])) {
		n++;
	}
	if (n > 0)
		fcustr_trunc(cus, n);
}

custr_t *
fcustr_alloc(void)
{
	custr_t *cus;

	VERIFY0(custr_alloc(&cus));
	return (cus);
}

void
fcustr_append(custr_t *cus, const char *s)
{
	VERIFY0(custr_append(cus, s));
}

void
fcustr_appendc(custr_t *cus, int c)
{
	VERIFY0(custr_appendc(cus, c));
}

void
fcustr_trunc(custr_t *cus, size_t idx)
{
	VERIFY0(custr_trunc(cus, idx));
}

void
fcustr_rtrunc(custr_t *cus, size_t idx)
{
	VERIFY0(custr_rtrunc(cus, idx));
}
