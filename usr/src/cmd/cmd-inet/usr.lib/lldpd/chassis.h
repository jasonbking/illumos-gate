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
 * Copyright 2026 Jason King
 */

#ifndef _CHASSIS_H
#define	_CHASSIS_H

#include <stdbool.h>
#include <libdladm.h>
#include <liblldp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct log;

void chassis_set_topo(const char *);
void chassis_init(struct log *, dladm_handle_t);
lldp_chassis_id_src_t chassis_select(struct log *, lldp_chassis_id_src_t,
    const char *, lldp_chassis_t *);

/* Exposed for testing */
bool chassis_str_junk(const char *);
bool chassis_uuid_junk(const uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CHASSIS_H */
