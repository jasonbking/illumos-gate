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

#ifndef _EXCEPTIONS_H
#define	_EXCEPTIONS_H

#include <stdio.h>
#include <regex.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct exception {
	char	*e_verb;
	char	**e_patterns;
	regex_t	*e_regexes;
	uint_t	e_n;
	uint_t	e_sz;
} exception_t;

typedef struct exceptions {
	exception_t	*es_exceptions;
	uint_t		es_n;
	uint_t		es_size;
} exceptions_t;

exception_t *get_exception(exceptions_t *, const char *);
bool is_exception(const char *, const char *, exceptions_t *);
exceptions_t *load_exceptions(FILE *, const char *);
char *find_exception_file(int, const char *);
void exceptions_free(exceptions_t *);

#ifdef __cplusplus
}
#endif

#endif /* _EXCEPTIONS_H*/
