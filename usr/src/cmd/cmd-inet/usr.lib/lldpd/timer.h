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

#ifndef _LLDP_TIMER_H
#define	_LLDP_TIMER_H

#include <libuutil.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

struct agent;
struct log;

typedef struct lldp_clock {
	struct agent	*lc_agent;
	uu_list_t	*lc_timers;
} lldp_clock_t;

typedef struct lldp_timer {
	uu_list_node_t		lt_node;
	lldp_clock_t		*lt_clock;
	void			*lt_parent;
	const char		*lt_name;
	struct log		*lt_log;

	hrtime_t		lt_lastset;
	uint16_t		lt_val;
	bool			*lt_flagp;
	const char		*lt_flagname;
} lldp_timer_t;

void lldp_timers_sysinit(void);
void lldp_timers_sysfini(void);

bool		lldp_clock_init(struct agent *, lldp_clock_t *);
void		lldp_clock_fini(lldp_clock_t *);
void		lldp_clock_tick(lldp_clock_t *, timestruc_t *);
void		lldp_clock_tock(lldp_clock_t *);

void lldp_timer_init(lldp_clock_t *, lldp_timer_t *, const char *, void *,
    struct log *, const char *, bool *);
void lldp_timer_fini(lldp_timer_t *);

void lldp_timer_set(lldp_timer_t *, uint16_t);
uint16_t lldp_timer_val(const lldp_timer_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_TIMER_H */
