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

#ifndef _LLDPD_H
#define	_LLDPD_H

#include <sys/param.h>
#include <synch.h>
#include <libdladm.h>
#include <liblldp.h>
#include <libscf.h>
#include <stdbool.h>

#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	LLDP_FMRI	"svc:/network/lldpd"

/*
 * Once initialized, lldpd runs as netadm (see lldp_drop_privs()), like other
 * network management daemons.
 */
#define	LLDPD_UID	UID_NETADM
#define	LLDPD_GID	GID_NETADM
#define	LLDP_SVC_FMRI	LLDP_FMRI ":default"

typedef struct fd_cb {
	void	(*fc_fn)(int, void *);
	void	*fc_arg;
} fd_cb_t;

bool schedule_fd(int, fd_cb_t *);
void cancel_fd(int);

/* Only used from the main thread */
extern dladm_handle_t dl_handle;

void lldp_set_log_level(log_level_t);

#ifdef __cplusplus
}
#endif

#endif /* _LLDPD_H */
