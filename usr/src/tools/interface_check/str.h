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

#ifndef _IFCHK_STR_H
#define	_IFCHK_STR_H

#include <inttypes.h>
#include <libcustr.h>
#include <stdio.h>
#include <stdbool.h>

/* Some utilities working on custr_ts and files */

#ifdef __cplusplus
extern "C" {
#endif

bool cgetline(FILE *, custr_t *, uint_t *);
void trimws(custr_t *);

struct custr;

struct custr *fcustr_alloc(void);
void fcustr_append(struct custr *, const char *);
void fcustr_appendc(struct custr *, int);
void fcustr_trunc(struct custr *, size_t);
void fcustr_rtrunc(struct custr *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _IFCHK_STR_H */
