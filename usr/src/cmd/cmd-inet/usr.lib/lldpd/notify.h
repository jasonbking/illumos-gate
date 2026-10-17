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

#ifndef _NOTIFY_H
#define	_NOTIFY_H

#include <stdint.h>
#include <liblldp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct log;

void notify_init(void);
void notify_fini(void);
void notify_change(void);
int notify_wait(uint32_t, uint_t, uint32_t *);
void notify_publish(struct log *, const char *, uint32_t, uint32_t,
    const lldp_agent_stats_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NOTIFY_H */
