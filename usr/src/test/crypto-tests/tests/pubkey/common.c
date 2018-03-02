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
 * Copyright 2018, Joyent, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"

#define	WIDTH	80

static const char *red = "";
static const char *green = "";
static const char *none = "";

void
init_term(void)
{
	if (isatty(STDOUT_FILENO) == 0 || getenv("TEST_NOCOLOR") != NULL)
		return;

	red = "\x1b[31m";
	green = "\x1b[32m";
	none = "\x1b[0m";
}

static void
printbuf(size_t indent, const uint8_t *buf, char *name, size_t size)
{
	size_t i, col;

	(void) printf("%*s%s: ", (int) indent, "", name);
	indent += strlen(name) + 2;

	for (i = 0, col = indent; i < size; i++) {
		if (col + 2 >= WIDTH) {
			(void) printf("\n%*s", (int)indent, "");
			col = indent;
		}
		if (col > indent) {
			(void) fputc(' ', stdout);
			col++;
		}
		(void) printf("%02x", buf[i]);
		col += 2;
	}
	(void) fputc('\n', stdout);
}

int
bufcmp(size_t indent, const char *name, const uint8_t *src, size_t srclen,
    const uint8_t *cmp, size_t cmplen)
{
	char cmpstr[32];
	char origstr[32];

	(void) snprintf(cmpstr, sizeof (cmpstr), "calc%s%s",
	    (name != NULL) ? " " : "", (name != NULL) ? name : "");
	(void) snprintf(origstr, sizeof (origstr), "orig%s%s",
	    (name != NULL) ? " " : "", (name != NULL) ? name : "");

	if (srclen != cmplen) {
		(void) printf("%sFAIL%s - mismatched length\n", red, none);
		(void) printf("%*s%s len: %zu\n", (int)indent, "", cmpstr,
		    cmplen);
		(void) printf("%*s%s len: %zu\n", (int)indent, "", origstr,
		    srclen);
		(void) fputc('\n', stdout);
		return (1);
	}

	if (memcmp(cmp, src, srclen) != 0) {
		(void) printf("%sFAIL%s - mismatched result\n", red, none);
		printbuf(indent, cmp, cmpstr, srclen);
		printbuf(indent, src, origstr, srclen);
		(void) fputc('\n', stdout);
		return (1);
	}

	(void) printf("%sSUCCESS%s\n", green, none);
	return (0);
}

void
divider(void)
{
	(void) fprintf(stderr, "\n------------------------------\n\n");
}
