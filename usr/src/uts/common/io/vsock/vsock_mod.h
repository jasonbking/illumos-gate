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
 * Copyright 2021 Jason King
 */

#ifndef _VSOCK_MOD_H
#define	_VSOCK_MOD_H

/*
 * API endpoints for VSOCK guest backends
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vsock_guest_ops {
	int vgo_foo;
} vsock_guest_ops_t;

int vsock_attach_guest(uint64_t, const vsock_guest_ops_t *);
int vsock_detach_guest(void);

#ifdef __cplusplus
}
#endif

#endif /* _VSOCK_MOD_H */
