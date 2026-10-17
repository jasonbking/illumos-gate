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

/*
 * Strip any trailing whitespace from buf (in place), returning the new length.
 */
static size_t
rtrim(char *buf, size_t len)
{
	while (len > 0 && isspace((unsigned char)buf[len - 1]))
		buf[--len] = '\0';
	return (len);
}

/*
 * Read the next logical line from f into cus. This follows the same rules
 * as onbld_elfmod::GetLine() in the original perl implementation:
 *
 *  - A backslash at the end of a line indicates the following line is a
 *    continuation of this line if the backslash is the only character on
 *    the line, or if it is preceded by whitespace. Continued lines are
 *    joined with a single space. Backslashes anywhere else are left alone
 *    (they are significant in regular expressions).
 *
 *  - The '#' character starts a comment if it is the first character on
 *    the line, or if it is preceded by whitespace.
 *
 *  - Leading and trailing whitespace is removed, and empty lines are
 *    skipped.
 *
 * *linenp is incremented for every physical line read. Returns false at
 * EOF (or on a read error) when no further logical line is available.
 */
bool
cgetline(FILE *f, custr_t *cus, uint_t *linenp)
{
	char	*buf = NULL;
	size_t	bufsz = 0;
	ssize_t	n;
	bool	cont = true;

	custr_reset(cus);

	while (cont && (n = getline(&buf, &bufsz, f)) >= 0) {
		size_t	len = (size_t)n;
		char	*p;

		(*linenp)++;

		/* chomp */
		if (len > 0 && buf[len - 1] == '\n')
			buf[--len] = '\0';

		/* A lone backslash: keep reading with cont unchanged. */
		if (strcmp(buf, "\\") == 0)
			continue;

		/* A trailing backslash preceded by whitespace continues. */
		cont = false;
		if (len >= 2 && buf[len - 1] == '\\' &&
		    isspace((unsigned char)buf[len - 2])) {
			buf[--len] = '\0';
			len = rtrim(buf, len);
			cont = true;
		}

		/* Lines starting with '#' are comments. */
		if (buf[0] == '#') {
			cont = true;
			continue;
		}

		/* Strip a comment that is preceded by whitespace. */
		for (p = buf; *p != '\0'; p++) {
			if (*p == '#' && p > buf &&
			    isspace((unsigned char)p[-1])) {
				*p = '\0';
				len = (size_t)(p - buf);
				break;
			}
		}

		len = rtrim(buf, len);

		if (len > 0) {
			p = buf;
			while (isspace((unsigned char)*p))
				p++;

			if (custr_len(cus) > 0)
				fcustr_appendc(cus, ' ');
			fcustr_append(cus, p);
		}

		/*
		 * If the result is still empty, act as if a continuation is
		 * present and read another line.
		 */
		if (custr_len(cus) == 0)
			cont = true;
	}

	free(buf);

	if (ferror(f))
		return (false);

	return (custr_len(cus) > 0);
}

/*
 * Remove leading and trailing whitespace from cus.
 */
void
trimws(custr_t *cus)
{
	const char	*p = custr_cstr(cus);
	size_t		len = custr_len(cus);
	size_t		start, end;
	char		*copy;

	if (len == 0)
		return;

	start = 0;
	while (start < len && isspace((unsigned char)p[start]))
		start++;

	end = len;
	while (end > start && isspace((unsigned char)p[end - 1]))
		end--;

	if (start == 0 && end == len)
		return;

	if (start == end) {
		custr_reset(cus);
		return;
	}

	copy = umem_alloc(end - start + 1, UMEM_NOFAIL);
	(void) memcpy(copy, p + start, end - start);
	copy[end - start] = '\0';

	custr_reset(cus);
	fcustr_append(cus, copy);
	umem_free(copy, end - start + 1);
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
