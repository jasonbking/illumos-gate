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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <upanic.h>
#include <libuutil.h>
#include <sys/debug.h>
#include "util.h"

static char panicbuf[256];

#define	NOMEM_MSG	"out of memory\0"

void __NORETURN
nomem(void)
{
	upanic(NOMEM_MSG, sizeof (NOMEM_MSG));
}

void __NORETURN
panic(const char *msg, ...)
{
	va_list ap;
	int len;

	va_start(ap, msg);
	len = snprintf(panicbuf, sizeof (panicbuf), msg, ap);
	va_end(ap);

	if (len > sizeof (panicbuf) - 1)
		len = sizeof (panicbuf) - 1;

	upanic(panicbuf, len);
}

char *
xstrdup(const char *s)
{
	char *ns = strdup(s);

	if (ns == NULL)
		nomem();

	return (ns);
}

uu_list_walk_t *
xuu_list_walk_start(uu_list_t *l, uint_t flags)
{
	uu_list_walk_t *wk;

	wk = uu_list_walk_start(l, flags);
	if (wk == NULL) {
		uint32_t e = uu_error();

		/* Any other error is a bug by the caller */
		VERIFY3U(e, ==, UU_ERROR_NO_MEMORY);
		nomem();
	}

	return (wk);
}
