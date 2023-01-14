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
	uint8_t		*b_ptr;
	uint16_t	b_len;
} buf_t;

void buf_init(buf_t *, uint8_t *, uint16_t);
bool buf_get8(buf_t *, uint8_t *);
bool buf_get16(buf_t *, uint16_t *);
bool buf_take(buf_t *restrict, uint16_t, buf_t *restrict);
bool buf_truncate(buf_t *, uint16_t);

bool buf_put8(buf_t *, uint8_t);
bool buf_put16(buf_t *, uint16_t);
bool buf_ptrstr(buf_t *, const char *);
bool buf_putbytes(buf_t *, void *, uint16_t);

static inline uint8_t *
buf_ptr(buf_t *b)
{
	return (b->b_ptr);
}

static inline uint16_t
buf_len(const buf_t *b)
{
	return (b->b_len);
}

#ifdef __cplusplus
}
#endif

#endif /* _BUF_H */
