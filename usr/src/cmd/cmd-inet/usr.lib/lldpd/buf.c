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
 * Copyright 2023 Jason King
 */

#include <string.h>
#include "buf.h"

void
buf_init(buf_t *b, uint8_t *ptr, uint16_t len)
{
	b->b_ptr = ptr;
	b->b_len = len;
}

bool
buf_get8(buf_t *b, uint8_t *vp)
{
	if (b->b_len < sizeof (*vp))
		return (false);

	*vp = b->b_ptr[0];
	b->b_ptr++;
	b->b_len--;
	return (true);
}

bool
buf_get16(buf_t *b, uint16_t *vp)
{
	if (b->b_len < sizeof (*vp))
		return (false);

	*vp = ((uint16_t)b->b_ptr[0]) << 8 | b->b_ptr[1];
	b->b_ptr += sizeof (*vp);
	b->b_len -= sizeof (*vp);
	return (true);
}

bool
buf_take(buf_t *restrict src, uint16_t amt, buf_t *restrict dst)
{
	if (src->b_len < amt)
		return (false);

	dst->b_ptr = src->b_ptr;
	dst->b_len = amt;
	src->b_ptr += amt;
	src->b_len -= amt;
	return (true);
}

bool
buf_put8(buf_t *b, uint8_t v)
{
	if (b->b_len < sizeof (uint8_t))
		return (false);
	b->b_ptr[0] = v;
	b->b_ptr++;
	b->b_len--;
	return (true);
}

bool
buf_put16(buf_t *b, uint16_t v)
{
	if (b->b_len < sizeof (uint16_t))
		return (false);
	b->b_ptr[0] = (v >> 8) & 0xff;
	b->b_ptr[1] = v & 0xff;
	b->b_ptr += sizeof (uint16_t);
	b->b_len -= sizeof (uint16_t);
	return (true);
}

bool
buf_putstr(buf_t *b, const char *s)
{
	size_t len = strlen(s);

	if (b->b_len < len)
		return (false);

	(void) memcpy(b->b_ptr, s, len);
	b->b_ptr += len;
	b->b_len -= len;
	return (true);
}

bool
buf_putbytes(buf_t *b, const void *p, uint16_t n)
{
	if (b->b_len < n)
		return (false);
	(void) memcpy(b->b_ptr, p, n);
	b->b_ptr += n;
	b->b_len -= n;
	return (true);
}

bool
buf_truncate(buf_t *b, uint16_t amt)
{
	if (b->b_len < amt)
		return (false);
	b->b_len = amt;
	return (true);
}

bool
buf_skip(buf_t *b, uint16_t amt)
{
	if (b->b_len < amt)
		return (false);
	b->b_ptr += amt;
	b->b_len -= amt;
	return (true);
}
