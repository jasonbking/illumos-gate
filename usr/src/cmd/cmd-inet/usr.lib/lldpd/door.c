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

/*
 * The door server. See lldp_door.h (in liblldp) for the protocol.
 */

#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <libscf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <umem.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <lldp_door.h>

#include "agent.h"
#include "door.h"
#include "log.h"
#include "neighbor.h"
#include "timer.h"
#include "tlv.h"

static int door_fd = -1;

/* Log for the door server threads (which don't otherwise have one) */
static log_t *door_log;

/*
 * Each door server thread gets its own reply buffer (allocated on first
 * use). door_return() copies the reply out before the thread can service
 * another call, so it's safe to reuse.
 */
static __thread uint8_t *door_reply_buf;

CTASSERT(LLDP_DOOR_REC_OFF + LLDP_DOOR_NBR_RECLEN(LLDP_PDU_MAX) <=
    LLDP_DOOR_REPLY_MAX);

static inline int
map_errno(int e)
{
	if (e == EACCES || e == EPERM)
		return (SMF_EXIT_ERR_PERM);
	return (SMF_EXIT_ERR_FATAL);
}

static void close_door_desc(door_desc_t *, uint_t);

static bool
cursor_valid(const lldp_door_cursor_t *c)
{
	/* An empty cursor means 'from the beginning' */
	if (c->ldc_link[0] == '\0')
		return (true);

	if (strnlen(c->ldc_link, sizeof (c->ldc_link)) == sizeof (c->ldc_link))
		return (false);

	/* Same bounds process_pdu() applies to received TLVs */
	if (c->ldc_chassis_len < 2 ||
	    c->ldc_chassis_len > LLDP_CHASSIS_MAX + 1)
		return (false);
	if (c->ldc_port_len < 2 || c->ldc_port_len > LLDP_PORT_MAX + 1)
		return (false);

	return (true);
}

static void
cursor_set(lldp_door_cursor_t *c, const agent_t *a, const neighbor_t *nb)
{
	const tlv_t *chassis, *port;

	chassis = tlv_list_get((tlv_list_t *)&nb->nb_core_tlvs,
	    NB_TLV_CHASSIS);
	port = tlv_list_get((tlv_list_t *)&nb->nb_core_tlvs, NB_TLV_PORT);

	(void) memset(c, '\0', sizeof (*c));
	(void) strlcpy(c->ldc_link, a->a_name, sizeof (c->ldc_link));

	c->ldc_chassis_len = buf_len(&chassis->tlv_buf);
	(void) memcpy(c->ldc_chassis, buf_cptr(&chassis->tlv_buf),
	    c->ldc_chassis_len);

	c->ldc_port_len = buf_len(&port->tlv_buf);
	(void) memcpy(c->ldc_port, buf_cptr(&port->tlv_buf), c->ldc_port_len);
}

/*
 * Add the neighbors of a to the reply, skipping any at or before the cursor
 * (if non-NULL). Returns false if the reply filled before all of a's
 * remaining neighbors could be added.
 */
static bool
door_agent_neighbors(agent_t *a, const lldp_door_cursor_t *cur,
    uint8_t *buf, size_t buflen, size_t *offp)
{
	lldp_door_reply_t	*rep = (lldp_door_reply_t *)buf;
	neighbor_t		*nb;
	bool			ret = true;

	mutex_enter(&a->a_lock);

	for (nb = uu_list_first(a->a_neighbors); nb != NULL;
	    nb = uu_list_next(a->a_neighbors, nb)) {
		lldp_door_nbr_t	rec = { 0 };
		size_t		reclen;

		/* Skip anything at or before the cursor */
		if (cur != NULL &&
		    neighbor_cmp_msap_raw(nb, cur->ldc_chassis,
		    cur->ldc_chassis_len, cur->ldc_port,
		    cur->ldc_port_len) <= 0) {
			continue;
		}

		reclen = LLDP_DOOR_NBR_RECLEN(nb->nb_pdu_len);
		if (*offp + reclen > buflen) {
			ret = false;
			break;
		}

		rec.ldn_reclen = reclen;
		rec.ldn_pdu_len = nb->nb_pdu_len;
		rec.ldn_ttl = lldp_timer_val(&nb->nb_timer);
		(void) strlcpy(rec.ldn_link, a->a_name, sizeof (rec.ldn_link));

		(void) memset(buf + *offp, '\0', reclen);
		(void) memcpy(buf + *offp, &rec, sizeof (rec));
		(void) memcpy(buf + *offp + sizeof (rec), nb->nb_pdu,
		    nb->nb_pdu_len);
		*offp += reclen;

		rep->ldrp_count++;
		cursor_set(&rep->ldrp_next, a, nb);
	}

	mutex_exit(&a->a_lock);
	return (ret);
}

/*
 * LLDP_DOOR_CMD_NEIGHBORS. Returns the size of the reply.
 */
static size_t
door_neighbors(const lldp_door_req_t *req, uint8_t *buf, size_t buflen)
{
	lldp_door_reply_t		*rep = (lldp_door_reply_t *)buf;
	const lldp_door_cursor_t	*cur = &req->ldrq_cursor;
	bool				have_cursor, one;
	size_t				off = LLDP_DOOR_REC_OFF;
	agent_t				*a;

	if (!cursor_valid(cur)) {
		rep->ldrp_error = EINVAL;
		return (sizeof (*rep));
	}

	have_cursor = cur->ldc_link[0] != '\0';
	one = req->ldrq_link[0] != '\0';

	/* If nothing is returned, the cursor doesn't move */
	rep->ldrp_next = *cur;

	mutex_enter(&agent_list_lock);

	if (one) {
		agent_t key = { .a_name = (char *)req->ldrq_link };

		a = uu_list_find(agent_list, &key, NULL, NULL);
		if (a == NULL) {
			rep->ldrp_error = ENOENT;
			off = sizeof (*rep);
			goto done;
		}

		if (have_cursor && strcmp(cur->ldc_link, a->a_name) != 0) {
			rep->ldrp_error = EINVAL;
			off = sizeof (*rep);
			goto done;
		}
	} else {
		/* The agent list is sorted by name */
		a = uu_list_first(agent_list);
		while (have_cursor && a != NULL &&
		    strcmp(a->a_name, cur->ldc_link) < 0) {
			a = uu_list_next(agent_list, a);
		}
	}

	while (a != NULL) {
		bool resume = have_cursor &&
		    strcmp(a->a_name, cur->ldc_link) == 0;

		if (!door_agent_neighbors(a, resume ? cur : NULL, buf, buflen,
		    &off)) {
			rep->ldrp_flags |= LLDP_DOOR_F_MORE;
			break;
		}

		a = one ? NULL : uu_list_next(agent_list, a);
	}

done:
	mutex_exit(&agent_list_lock);
	return (off);
}

static void
lldp_door_server(void *cookie __unused, char *argp, size_t argsz,
    door_desc_t *dp, uint_t ndesc)
{
	lldp_door_reply_t	*rep;
	lldp_door_req_t		req;
	size_t			len = sizeof (*rep);

	close_door_desc(dp, ndesc);

	log = door_log;

	if (door_reply_buf == NULL)
		door_reply_buf = umem_alloc(LLDP_DOOR_REPLY_MAX, UMEM_NOFAIL);

	rep = (lldp_door_reply_t *)door_reply_buf;
	(void) memset(rep, '\0', sizeof (*rep));
	rep->ldrp_version = LLDP_DOOR_VERSION;

	if (argp == NULL || argsz != sizeof (req)) {
		rep->ldrp_error = EINVAL;
		goto done;
	}

	/* Copy out the request; we can't assume argp is aligned */
	(void) memcpy(&req, argp, sizeof (req));
	req.ldrq_link[sizeof (req.ldrq_link) - 1] = '\0';

	if (req.ldrq_version != LLDP_DOOR_VERSION) {
		rep->ldrp_error = ENOTSUP;
		goto done;
	}

	switch (req.ldrq_cmd) {
	case LLDP_DOOR_CMD_NEIGHBORS:
		len = door_neighbors(&req, door_reply_buf, LLDP_DOOR_REPLY_MAX);
		break;
	default:
		rep->ldrp_error = EINVAL;
		break;
	}

	if (rep->ldrp_error != 0) {
		log_debug(log, "door request failed",
		    LOG_T_UINT32, "cmd", req.ldrq_cmd,
		    LOG_T_STRING, "link", req.ldrq_link,
		    LOG_T_INT32, "error", rep->ldrp_error,
		    LOG_T_END);
	}

done:
	VERIFY0(door_return((char *)door_reply_buf, len, NULL, 0));
}

void
lldp_create_door(const char *path)
{
	const char	*dpath;
	sigset_t	set, oset;
	int		fd;

	/*
	 * Regardless of how the rest of lldpd handles signals, we
	 * always want to ensure that the door threads have all
	 * signals but SIGABRT blocked.
	 */
	VERIFY0(sigfillset(&set));
	VERIFY0(sigdelset(&set, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &set, &oset));

	(void) log_child(log, &door_log,
	    LOG_T_STRING, "component", "door",
	    LOG_T_END);

	door_fd = door_create(lldp_door_server, NULL, DOOR_REFUSE_DESC);
	if (door_fd == -1) {
		log_fatal(SMF_EXIT_ERR_FATAL, log, "failed to create door fd",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_END);
	}

	/*
	 * Precendence (seems most reasonable):
	 *	LLDP_DOOR environment variable
	 *	SMF config
	 *	built-in default
	 *
	 * liblldp honors the same environment variable.
	 */
	dpath = getenv(LLDP_DOOR_ENV);
	if (dpath == NULL)
		dpath = path;
	if (dpath == NULL)
		dpath = LLDP_DOOR_PATH;

	log_debug(log, "creating door",
	    LOG_T_STRING, "doorpath", dpath,
	    LOG_T_END);

	fd = open(dpath, O_CREAT|O_RDWR, 0644);
	if (fd == -1) {
		log_fatal(map_errno(errno), log, "failed to create door file",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}

	if (close(fd) < 0) {
		log_fatal(SMF_EXIT_ERR_PERM, log, "failed to close door file",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}

	(void) fdetach(dpath);

	if (fattach(door_fd, dpath) < 0) {
		log_fatal(map_errno(errno), log, "failed to attach door",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}
}

static void
close_door_desc(door_desc_t *dp, uint_t n)
{
	for (uint_t i = 0; i < n; i++, dp++) {
		if ((dp->d_attributes & DOOR_DESCRIPTOR) == 0)
			continue;
		(void) close(dp->d_data.d_desc.d_descriptor);
	}
}
