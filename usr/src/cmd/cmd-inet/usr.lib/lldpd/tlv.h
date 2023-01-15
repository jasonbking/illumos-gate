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

#ifndef _TLV_H
#define	_TLV_H

#include <liblldp.h>
#include "buf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tlv {
	lldp_tlv_type_t	tlv_type;
	buf_t		tlv_buf;
} tlv_t;

typedef struct tlv_list {
	tlv_t		*tlvl_list;
	uint_t		tlvl_n;
	uint_t		tlvl_size;
} tlv_list_t;

tlv_list_t *tlv_list_new(void);
void tlv_list_free(tlv_list_t *);
tlv_t *tlv_list_get(tlv_list_t *, uint_t);
bool tlv_list_add(tlv_list_t *, tlv_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TLV_H */
