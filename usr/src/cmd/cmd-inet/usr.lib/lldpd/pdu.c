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

#include "agent.h"
#include "buf.h"
#include "log.h"
#include "neighbor.h"
#include "pdu.h"

void
make_pdu(agent_t *a, buf_t *buf)
{
}

void
make_shutdown_pdu(agent_t *a, buf_t *buf)
{
}

bool
process_pdu(log_t *log, buf_t *buf, neighbor_t **)
{
	return false;
}
