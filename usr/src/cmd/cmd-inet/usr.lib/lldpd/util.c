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
#include <string.h>
#include <upanic.h>
#include "util.h"

static char panicbuf[256];

/*
 * Iterate through a list, invoking cb on each item. Stop iteration if
 * cb returns != 0. Returns 0 if entire list was successfully iterated, or
 * the return value of cb.
 */
int
list_foreach(list_t *l, int (*cb)(list_t *, void *, void *), void *arg)
{
	void *o = list_head(l);

	while (o != NULL) {
		void *next = list_next(l, o);
		int ret = cb(l, o, arg);

		if (ret != 0)
			return (ret);

		o = next;
	}

	return (0);
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
