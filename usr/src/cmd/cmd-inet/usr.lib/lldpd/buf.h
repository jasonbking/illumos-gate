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
 * Copyright 2022 Jason King
 */

#ifndef _BUF_H
#define	_BUF_H

#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct buf {
	uint8_t		*b_data;
	uint16_t	b_idx;
	uint16_t	b_size;
	bool		b_err;
} buf_t;

void buf_init(buf_t *, size_t);
void buf_fini(buf_t *);

#ifdef __cplusplus
}
#endif

#endif /* _BUF_H */
