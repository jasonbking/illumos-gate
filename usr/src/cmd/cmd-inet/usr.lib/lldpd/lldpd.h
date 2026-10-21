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

/*
 * Once initialized, lldpd runs as netadm (see lldp_drop_privs()), like other
 * network management daemons.
 */
#define	LLDPD_UID	UID_NETADM
#define	LLDPD_GID	GID_NETADM

typedef struct fd_cb {
	void	(*fc_fn)(int, void *);
	void	*fc_arg;
} fd_cb_t;

bool schedule_fd(int, fd_cb_t *);
void cancel_fd(int);

/* Only used from the main thread */
extern dladm_handle_t dl_handle;

void lldp_set_log_level(log_level_t);
void lldp_priv_bracket(bool);

/*
 * Requests (from lldp_rcm, via the door) about a link that's being
 * reconfigured. See lldp_link_request().
 */
typedef enum lldp_link_op {
	LLDP_LINK_OP_OFFLINE,	/* Release the link (e.g. for DR) */
	LLDP_LINK_OP_ONLINE,	/* Undo LLDP_LINK_OP_OFFLINE */
	LLDP_LINK_OP_REMOVE,	/* The link is gone; destroy its agent */
} lldp_link_op_t;

int lldp_link_request(lldp_link_op_t, datalink_id_t);

#ifdef __cplusplus
}
#endif

#endif /* _LLDPD_H */
