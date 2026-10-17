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
#include <priv.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ucred.h>
#include <umem.h>
#include <unistd.h>
#include <zone.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <lldp_door.h>

#include "agent.h"
#include "config.h"
#include "door.h"
#include "log.h"
#include "neighbor.h"
#include "timer.h"
#include "tlv.h"
#include "util.h"

static int door_fd = -1;
static char *door_path;

/* Log for the door server threads (which don't otherwise have one) */
static log_t *door_log;

/*
 * Each door server thread gets its own reply buffer (allocated on first
 * use). door_return() copies the reply out before the thread can service
 * another call, so it's safe to reuse.
 */
static __thread uint8_t *door_reply_buf;

/* Any neighbor's PDU (which is < 64K, see buf_t) must fit in a reply */
CTASSERT(LLDP_DOOR_REC_OFF + LLDP_DOOR_NBR_RECLEN(UINT16_MAX) <=
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
		/* Either the hardware or (renamed) datalink name */
		a = agent_find(req->ldrq_link);
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

/*
 * Fills in an agent's record (of a command with one fixed-size record per
 * agent) at rec, which is zeroed and 8-byte aligned.
 */
typedef void (*door_agent_rec_f)(agent_t *, void *rec);

/*
 * A command returning one fixed-size record (reclen bytes, a multiple of 8)
 * per agent: every agent's (or just ldrq_link's), ordered by agent name,
 * resuming after the agent named by the cursor. Returns the size of the
 * reply.
 */
static size_t
door_agent_records(const lldp_door_req_t *req, uint8_t *buf, size_t buflen,
    size_t reclen, door_agent_rec_f fill)
{
	lldp_door_reply_t		*rep = (lldp_door_reply_t *)buf;
	const lldp_door_cursor_t	*cur = &req->ldrq_cursor;
	size_t				off = LLDP_DOOR_REC_OFF;
	agent_t				*a;
	bool				one;

	VERIFY0(reclen % 8);

	if (strnlen(cur->ldc_link, sizeof (cur->ldc_link)) ==
	    sizeof (cur->ldc_link) || cur->ldc_chassis_len != 0 ||
	    cur->ldc_port_len != 0) {
		rep->ldrp_error = EINVAL;
		return (sizeof (*rep));
	}

	one = req->ldrq_link[0] != '\0';

	/* If nothing is returned, the cursor doesn't move */
	rep->ldrp_next = *cur;

	mutex_enter(&agent_list_lock);

	if (one) {
		a = agent_find(req->ldrq_link);
		if (a == NULL) {
			rep->ldrp_error = ENOENT;
			off = sizeof (*rep);
			goto done;
		}

		/* The only agent was already returned */
		if (cur->ldc_link[0] != '\0')
			a = NULL;
	} else {
		/* The agent list is sorted by name; resume after the cursor */
		a = uu_list_first(agent_list);
		while (cur->ldc_link[0] != '\0' && a != NULL &&
		    strcmp(a->a_name, cur->ldc_link) <= 0) {
			a = uu_list_next(agent_list, a);
		}
	}

	while (a != NULL) {
		if (off + reclen > buflen) {
			rep->ldrp_flags |= LLDP_DOOR_F_MORE;
			break;
		}

		(void) memset(buf + off, '\0', reclen);
		fill(a, buf + off);
		off += reclen;
		rep->ldrp_count++;

		(void) memset(&rep->ldrp_next, '\0', sizeof (rep->ldrp_next));
		(void) strlcpy(rep->ldrp_next.ldc_link, a->a_name,
		    sizeof (rep->ldrp_next.ldc_link));

		a = one ? NULL : uu_list_next(agent_list, a);
	}

done:
	mutex_exit(&agent_list_lock);
	return (off);
}

/* LLDP_DOOR_CMD_STATS */
static void
door_stats_rec(agent_t *a, void *arg)
{
	lldp_door_stats_t *rec = arg;

	(void) strlcpy(rec->lds_link, a->a_name, sizeof (rec->lds_link));
	rec->lds_linkid = a->a_linkid;
	mutex_enter(&a->a_lock);
	rec->lds_stats = a->a_stats;
	mutex_exit(&a->a_lock);
}

/* LLDP_DOOR_CMD_AGENTS */
static void
door_agents_rec(agent_t *a, void *arg)
{
	agent_get_info(a, arg);
}

/*
 * LLDP_DOOR_CMD_SYSTEM. Returns the size of the reply.
 */
static size_t
door_system(const lldp_door_req_t *req, uint8_t *buf, size_t buflen)
{
	lldp_door_reply_t	*rep = (lldp_door_reply_t *)buf;
	lldp_system_info_t	*si;
	lldp_agent_info_t	ai;

	CTASSERT(LLDP_DOOR_REC_OFF + sizeof (*si) <= LLDP_DOOR_REPLY_MAX);
	VERIFY3U(buflen, >=, LLDP_DOOR_REC_OFF + sizeof (*si));

	if (req->ldrq_link[0] != '\0') {
		rep->ldrp_error = EINVAL;
		return (sizeof (*rep));
	}

	si = (lldp_system_info_t *)(buf + LLDP_DOOR_REC_OFF);
	(void) memset(si, '\0', sizeof (*si));

	mutex_enter(&lldp_config_lock);
	si->lsi_chassis = lldp_config->lcfg_chassis;
	si->lsi_chassis_type = lldp_config->lcfg_chassis_type;
	si->lsi_chassis_src = lldp_config->lcfg_chassis_src;
	if (lldp_config->lcfg_sysname != NULL) {
		(void) strlcpy(si->lsi_sysname, lldp_config->lcfg_sysname,
		    sizeof (si->lsi_sysname));
	}
	if (lldp_config->lcfg_sysdesc != NULL) {
		(void) strlcpy(si->lsi_sysdesc, lldp_config->lcfg_sysdesc,
		    sizeof (si->lsi_sysdesc));
	}
	si->lsi_syscap = lldp_config->lcfg_syscap;
	si->lsi_encap = lldp_config->lcfg_encap;
	mutex_exit(&lldp_config_lock);

	mutex_enter(&agent_list_lock);
	for (agent_t *a = uu_list_first(agent_list); a != NULL;
	    a = uu_list_next(agent_list, a)) {
		agent_get_info(a, &ai);
		si->lsi_agents++;
		if (ai.lai_state == LLDP_AGENT_ACTIVE)
			si->lsi_active++;
		si->lsi_neighbors += ai.lai_neighbors;
	}
	mutex_exit(&agent_list_lock);

	rep->ldrp_count = 1;
	return (LLDP_DOOR_REC_OFF + sizeof (*si));
}

/*
 * The link commands change what lldpd is doing (and are only meant for the
 * lldp RCM module, which runs in rcm_daemon), so the caller must be in our
 * zone and be allowed to configure datalinks. The read-only commands are
 * open to anyone, like 'dladm show-link'.
 */
static int
door_check_link_privs(uint32_t cmd)
{
	ucred_t			*uc = NULL;
	const priv_set_t	*eset;
	int			ret = 0;

	if (door_ucred(&uc) != 0) {
		ret = errno;
		log_syserr(log, "failed to get door caller credentials", ret);
		return (ret);
	}

	if (ucred_getzoneid(uc) != getzoneid()) {
		ret = EPERM;
	} else if ((eset = ucred_getprivset(uc, PRIV_EFFECTIVE)) == NULL ||
	    !priv_ismember(eset, PRIV_SYS_DL_CONFIG)) {
		ret = EPERM;
	}

	if (ret != 0) {
		log_warn(log, "door caller not permitted to make request",
		    LOG_T_UINT32, "cmd", cmd,
		    LOG_T_INT32, "pid", (int32_t)ucred_getpid(uc),
		    LOG_T_UINT32, "euid", (uint32_t)ucred_geteuid(uc),
		    LOG_T_INT32, "zoneid", (int32_t)ucred_getzoneid(uc),
		    LOG_T_END);
	}

	ucred_free(uc);
	return (ret);
}

/*
 * LLDP_DOOR_CMD_LINK_*: hand the request to the main thread (which does
 * all opening and closing of links), and wait for it to complete. Returns
 * the size of the reply.
 */
static size_t
door_link_op(const lldp_door_req_t *req, lldp_door_reply_t *rep)
{
	lldp_link_op_t	op;
	int		ret;

	switch (req->ldrq_cmd) {
	case LLDP_DOOR_CMD_LINK_OFFLINE:
		op = LLDP_LINK_OP_OFFLINE;
		break;
	case LLDP_DOOR_CMD_LINK_ONLINE:
		op = LLDP_LINK_OP_ONLINE;
		break;
	case LLDP_DOOR_CMD_LINK_REMOVE:
		op = LLDP_LINK_OP_REMOVE;
		break;
	default:
		rep->ldrp_error = EINVAL;
		return (sizeof (*rep));
	}

	if ((ret = door_check_link_privs(req->ldrq_cmd)) != 0) {
		rep->ldrp_error = ret;
		return (sizeof (*rep));
	}

	ret = lldp_link_request(op, (datalink_id_t)req->ldrq_linkid);
	log_debug(log, "link request",
	    LOG_T_UINT32, "cmd", req->ldrq_cmd,
	    LOG_T_UINT32, "linkid", req->ldrq_linkid,
	    LOG_T_INT32, "error", ret,
	    LOG_T_END);

	rep->ldrp_error = ret;
	return (sizeof (*rep));
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
	case LLDP_DOOR_CMD_STATS:
		len = door_agent_records(&req, door_reply_buf,
		    LLDP_DOOR_REPLY_MAX, sizeof (lldp_door_stats_t),
		    door_stats_rec);
		break;
	case LLDP_DOOR_CMD_SYSTEM:
		len = door_system(&req, door_reply_buf, LLDP_DOOR_REPLY_MAX);
		break;
	case LLDP_DOOR_CMD_AGENTS:
		len = door_agent_records(&req, door_reply_buf,
		    LLDP_DOOR_REPLY_MAX, LLDP_DOOR_AGENT_RECLEN,
		    door_agents_rec);
		break;
	case LLDP_DOOR_CMD_LINK_OFFLINE:
	case LLDP_DOOR_CMD_LINK_ONLINE:
	case LLDP_DOOR_CMD_LINK_REMOVE:
		len = door_link_op(&req, rep);
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

	/*
	 * Remove any door left attached by a previous instance first, so
	 * that we open (and chown) the file itself rather than that door.
	 */
	(void) fdetach(dpath);

	fd = open(dpath, O_CREAT|O_RDWR, 0644);
	if (fd == -1) {
		log_fatal(map_errno(errno), log, "failed to create door file",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}

	/*
	 * lldpd drops to LLDPD_UID/LLDPD_GID once initialized (see
	 * lldp_drop_privs()); it must own the file to fdetach() the door
	 * at shutdown. The owner is recorded when the door is attached, so
	 * this must happen before fattach().
	 */
	if (geteuid() == 0 && fchown(fd, LLDPD_UID, LLDPD_GID) != 0) {
		log_fatal(map_errno(errno), log, "failed to chown door file",
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

	door_path = xstrdup(dpath);

	if (fattach(door_fd, dpath) < 0) {
		log_fatal(map_errno(errno), log, "failed to attach door",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}
}

/*
 * Stop accepting door calls: detach the door from the filesystem and
 * revoke it. Calls already in progress are allowed to complete.
 */
void
lldp_destroy_door(void)
{
	if (door_fd < 0)
		return;

	if (door_path != NULL)
		(void) fdetach(door_path);
	(void) door_revoke(door_fd);
	door_fd = -1;
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
