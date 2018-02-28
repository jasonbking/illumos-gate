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

#ifndef _COMMON_H
#define	_COMMON_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_term(void);
int bufcmp(size_t, const char *, const uint8_t *, size_t, const uint8_t *,
    size_t);

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_H */
