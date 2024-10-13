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

#ifndef _UTIL_H
#define	_UTIL_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

int nomem_callback(void);

void *zalloc(size_t);
void *xcalloc(size_t, size_t);
void *xcreallocarray(void *, size_t, size_t, size_t);
void arrayfree(void *, size_t, size_t);
char *xstrdup(const char *);
void strfree(char *);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_H */
