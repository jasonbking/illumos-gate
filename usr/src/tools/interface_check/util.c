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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <umem.h>
#include <sys/debug.h>

#ifdef __CHECKER__
/* Smatch doesn't understand the gcc builtin, so we have to help it out */
bool __builtin_mul_overflow(size_t, size_t, size_t *);
#endif

/*
 * Once we feel that the oldest supported snapshot of illumos for
 * building contains upanic(2), it would probably be useful to update
 * this to utilize it. For now, we just use abort.
 */
int
nomem_callback(void)
{
	(void) fprintf(stderr, "ERROR: out of memory\n");

	abort();

	/*
	 * Technically we should never get here, but keep the compilers
	 * happy.
	 */
	return(UMEM_CALLBACK_EXIT(EXIT_FAILURE));
}

void *
zalloc(size_t n)
{
	return (umem_zalloc(n, UMEM_NOFAIL));
}

void *
xcalloc(size_t n, size_t elsize)
{
	size_t sz;

	VERIFY(!__builtin_mul_overflow(n, elsize, &sz));
	return (zalloc(sz));
}

void
arrayfree(void *p, size_t n, size_t elsize)
{
	size_t sz;

	if (p == NULL) {
		VERIFY0(n);
		return;
	}

	VERIFY(!__builtin_mul_overflow(n, elsize, &sz));
	umem_free(p, sz);
}

void *
xcreallocarray(void *old, size_t oldnelem, size_t newnelem, size_t elsize)
{
	void *p;
	size_t newsz;

	VERIFY(!__builtin_mul_overflow(newnelem, elsize, &newsz));
	p = zalloc(newsz);

	if (old == NULL) {
		VERIFY0(oldnelem);
		return (p);
	}

	size_t oldsz;

	VERIFY(!__builtin_mul_overflow(oldnelem, elsize, &oldsz));
	(void) memcpy(p, old, oldsz);
	umem_free(old, oldsz);

	return (p);
}

char *
xstrdup(const char *s)
{
	if (s == NULL)
		return (NULL);

	size_t n = strlen(s) + 1;
	char *p = zalloc(n);

	(void) strlcpy(p, s, n);
	return (p);
}

void
strfree(char *s)
{
	if (s == NULL)
		return;

	size_t len = strlen(s);

	umem_free(s, len + 1);
}
