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

#include <sys/types.h>
#include <time.h>
#include "header.h"

/*
 * In the future, it might be nicer to have the license text in a file thats
 * added via elfwrap during the build process.
 */
static const char cddl[] =
    "#\n"
    "# CDDL HEADER START\n"
    "#\n"
    "# This file and its contents are supplied under the terms of the\n"
    "# Common Development and Distribution License (\"CDDL\"), version 1.0.\n"
    "# You may only use this file in accordance with the terms of version\n"
    "# 1.0 of the CDDL.\n"
    "#\n"
    "# A full copy of the text of the CDDL should have accompanied this\n"
    "# source.  A copy of the CDDL is also available via the Internet at\n"
    "# http://www.illumos.org/license/CDDL.\n"
    "#\n"
    "# CDDL HEADER END\n"
    "#\n";

void
print_header(FILE *f, int argc, char **argv)
{
	time_t now;

	now = time(NULL);

	(void) fwrite(cddl, sizeof (cddl) - 1, 1, f);
	(void) fputc('\n', f);
	(void) fprintf(f, "# Date:    %s", ctime(&now));
	(void) fprintf(f, "# Command: ");
	for (int i = 0; i < argc; i++) {
		if (i > 0)
			(void) fputc(' ', f);
		(void) fprintf(f, "%s", argv[i]);
	}
	(void) fputc('\n', f);

	(void) fputc('\n', f);
}
