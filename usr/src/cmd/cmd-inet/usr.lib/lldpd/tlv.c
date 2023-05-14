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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/debug.h>
#include "tlv.h"

/* We grow the tlv list in increments of CHUNK_SIZE */
#define	CHUNK_SIZE	8

void
tlv_list_init(tlv_list_t *l)
{
	l->tlvl_list = NULL;
	l->tlvl_n = 0;
	l->tlvl_size = 0;
}

void
tlv_list_free(tlv_list_t *l)
{
	free(l->tlvl_list);
	tlv_list_init(l);
}

bool
tlv_list_add(tlv_list_t *l, tlv_t *t)
{
	if (l->tlvl_n == l->tlvl_size) {
		tlv_t *new_list = NULL;
		size_t new_sz = l->tlvl_size + CHUNK_SIZE;

		new_list = recallocarray(l->tlvl_list, l->tlvl_size,
		    new_sz, sizeof (tlv_t));
		if (new_list == NULL)
			return (false);

		l->tlvl_list = new_list;
		l->tlvl_size = new_sz;
	}

	(void) memcpy(&l->tlvl_list[l->tlvl_n++], t, sizeof (*t));
	return (true);
}

tlv_t *
tlv_list_get(tlv_list_t *l, uint_t idx)
{
	VERIFY3U(idx, <, l->tlvl_n);
	return (&l->tlvl_list[idx]);
}
