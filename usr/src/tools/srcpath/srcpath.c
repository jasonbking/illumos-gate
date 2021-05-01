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
 * Copyright 2023 Jason King
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <err.h>

int
main(int argc, char **argv)
{
	const char *srcvar = "CODEMGR_WS";
	char *p, *src, *src_resolved;
	size_t srclen;
	char srcbuf[PATH_MAX] = { 0 };
	char pathbuf[PATH_MAX] = { 0 };

	if (argc < 2) {
		(void) fprintf(stderr, "Usage: %s path\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	src = getenv(srcvar);
	if (src == NULL)
		errx(EXIT_FAILURE, "$%s not set", srcvar);

	if ((src_resolved = realpath(src, srcbuf)) == NULL)
		err(EXIT_FAILURE, "failed to resolve $SRC");

	if ((p = realpath(argv[1], pathbuf)) == NULL)
		err(EXIT_FAILURE, "failed to resolve '%s'", argv[1]);	

	srclen = strlen(src_resolved);

	if (strncmp(src_resolved, p, srclen) == 0) {
		if (p[srclen] == '/')
			p++;
		(void) printf("%s\n", p + srclen);
	} else {
		(void) printf("%s\n", p);
	}

	return (0);
}
