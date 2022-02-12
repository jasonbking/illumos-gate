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

#ifndef _PDU_H
#define	_PDU_H

#ifdef __cplusplus
extern "C" {
#endif

struct agent;
struct buf;
struct log;
struct neighbor;

void make_pdu(struct agent *, struct buf *);
void make_shutdown_pdu(struct agent *, struct buf *);
bool process_pdu(struct log *, struct buf *, struct neighbor **);

#ifdef __cplusplus
}
#endif

#endif /* _PDU_H */
