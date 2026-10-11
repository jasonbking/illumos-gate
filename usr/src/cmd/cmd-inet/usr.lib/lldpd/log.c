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
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright 2023 Jason King
 */

#include <atomic.h>
#include <errno.h>
#include <netdb.h>
#include <libcustr.h>
#include <libdlpi.h>
#include <libscf.h>
#include <libnvpair.h>
#include <libuutil.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <synch.h>
#include <syslog.h>
#include <thread.h>
#include <time.h>
#include <unistd.h>
#include <umem.h>
#include <wchar.h>

#include "buf.h"
#include "log.h"
#include "tlv.h"
#include "util.h"

struct log_key;
struct log_stream;
struct log;

typedef struct log_stream {
	uu_list_node_t	ls_node;
	char		*ls_name;
	log_fmt_type_t	ls_fmt;
	log_level_t	ls_level;
	log_stream_f	ls_func;
	void		*ls_arg;
} log_stream_t;

typedef struct log_key {
	uu_list_node_t	lk_node;
	char		*lk_name;
	log_type_t	lk_type;
	uintptr_t	lk_data;
	size_t		lk_len;
} log_key_t;

struct log {
	mutex_t		l_lock;
	struct log	*l_parent;
	uu_list_t	*l_keys;
	uu_list_t	*l_streams;
	char		*l_name;
	char		l_host[MAXHOSTNAMELEN + 1];
	custr_t		*l_bunyan;	/* Rendered bunyan message */
	custr_t		*l_syslog;	/* Rendered RFC 5424 message */
};

/*
 * State for rendering a single message. Each format is rendered at most
 * once per message, and only if a stream (on the log or any of its parents)
 * that wants the message uses that format. Each rendering walks its own
 * copy of the caller's arguments.
 */
typedef struct log_render {
	log_t		*lr_src;
	log_level_t	lr_level;
	const char	*lr_msg;
	struct timeval	lr_tv;
	va_list		lr_ap;
	uint_t		lr_tried;	/* Formats we've attempted to render */
	uint_t		lr_ok;		/* Formats successfully rendered */
	size_t		lr_syslog_hdrlen; /* Length of the RFC 5424 header */
} log_render_t;

typedef bool (*arg_cb_t)(void *, const char *, log_type_t, uintptr_t, size_t);

#define	ISO_TIMELEN		25

/* Size of the buffer used to render (non-string) key values as text */
#define	LOG_VALBUF		1024

/*
 * RFC 5424 limits and settings for the syslog format.
 *
 * Structured data IDs other than the IANA-registered ones must be of the
 * form name@<private enterprise number>. 32473 is the enterprise number
 * reserved for use in documentation (RFC 5612); replace it if a registered
 * one is available.
 */
#define	SYSLOG_FACILITY		LOG_DAEMON
#define	SYSLOG_PEN		"32473"
#define	SYSLOG_HOSTNAME_MAX	255
#define	SYSLOG_APPNAME_MAX	48
#define	SYSLOG_SDNAME_MAX	32
#define	SYSLOG_PARAMNAME_MAX	32

#define	FD_MUTEX_HASH_SIZE	64
static mutex_t		fd_mutex[FD_MUTEX_HASH_SIZE];
static uu_list_pool_t	*key_pool;
static uu_list_pool_t	*stream_pool;
static umem_cache_t	*key_cache;

static const int bunyan_version = 0;

__thread log_t *log;

static bool log_key_add_one(void *, const char *, log_type_t, uintptr_t,
    size_t);
static bool log_make_bunyan(log_t *, const struct timeval *, log_level_t,
    const char *, va_list *);
static bool log_make_syslog(log_t *, const struct timeval *, log_level_t,
    const char *, va_list *, size_t *);
static void key_tlv_copy(log_key_t *, const tlv_t *);
static bool log_walk_arglist(va_list *, arg_cb_t, void *);

static inline uint_t
log_fd_hash(int fd)
{
	return (fd % FD_MUTEX_HASH_SIZE);
}

static void
log_fd_lock(int fd)
{
	mutex_t *m = &fd_mutex[log_fd_hash(fd)];
	mutex_enter(m);
}

static void
log_fd_unlock(int fd)
{
	mutex_t *m = &fd_mutex[log_fd_hash(fd)];
	mutex_exit(m);
}

static void
log_key_fini(log_key_t *k)
{
	if (k->lk_len > 0)
		umem_free((void *)k->lk_data, k->lk_len);

	uu_free(k->lk_name);

	k->lk_name = NULL;
	k->lk_type = 0;
	k->lk_data = 0;
	k->lk_len = 0;
	umem_cache_free(key_cache, k);
}

static void
log_stream_fini(log_stream_t *ls)
{
	uu_free(ls->ls_name);
	umem_free(ls, sizeof (*ls));
}

static log_t *
log_init_common(const char *name)
{
	log_t *l;

	VERIFY3P(name, !=, NULL);

	l = umem_zalloc(sizeof (*l), UMEM_NOFAIL);

	VERIFY0(mutex_init(&l->l_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));

	l->l_name = xstrdup(name);

	l->l_keys = uu_list_create(key_pool, NULL, UU_LIST_DEBUG);
	if (l->l_keys == NULL)
		nomem();

	l->l_streams = uu_list_create(stream_pool, NULL, UU_LIST_DEBUG);
	if (l->l_streams == NULL)
		nomem();

	if (custr_alloc(&l->l_bunyan) != 0)
		nomem();

	if (custr_alloc(&l->l_syslog) != 0)
		nomem();

	return (l);
}

void
log_init(const char *name, log_t **lp)
{
	log_t		*l = NULL;

	VERIFY3P(name, !=, NULL);

	l = log_init_common(name);

	VERIFY0(gethostname(l->l_host, sizeof (l->l_host)));
	l->l_host[sizeof (l->l_host) - 1] = '\0';

	*lp = l;
}

void
log_fini(log_t *lp)
{
	log_key_t *key = NULL;
	log_stream_t *stream = NULL;
	void *cookie;

	if (lp == NULL)
		return;

	cookie = NULL;
	while ((key = uu_list_teardown(lp->l_keys, &cookie)) != NULL)
		log_key_fini(key);

	cookie = NULL;
	while ((stream = uu_list_teardown(lp->l_streams, &cookie)) != NULL)
		log_stream_fini(stream);

	uu_free(lp->l_name);
	VERIFY0(mutex_destroy(&lp->l_lock));

	custr_free(lp->l_bunyan);
	custr_free(lp->l_syslog);

	umem_free(lp, sizeof (*lp));
}

int
log_child(log_t *parent, log_t **childp, ...)
{
	log_t		*child;
	log_key_t	*k;
	uu_list_walk_t	*wk;
	va_list 	ap;

	child = log_init_common(parent->l_name);

	(void) strlcpy(child->l_host, parent->l_host, sizeof (child->l_host));

	wk = uu_list_walk_start(parent->l_keys, 0);
	while ((k = uu_list_walk_next(wk)) != NULL) {
		if (!log_key_add_one(child, k->lk_name, k->lk_type, k->lk_data,
		    k->lk_len)) {
			nomem();
		}
	}
	uu_list_walk_end(wk);

	va_start(ap, childp);
	if (!log_walk_arglist(&ap, log_key_add_one, child))
		nomem();
	va_end(ap);

	child->l_parent = parent;
	*childp = child;

	return (0);
}

/*
 * Destination: write the complete message to a file descriptor.
 */
void
log_stream_fd(log_level_t lvl __unused, const log_msg_t *m, void *arg)
{
	uintptr_t	fd = (uintptr_t)arg;
	const char	*msg = m->lm_msg;
	size_t		msglen = m->lm_len;
	size_t		off = 0;
	ssize_t		ret = 0;
	static int	maxbuf = -1;

	if (maxbuf == -1)
		maxbuf = getpagesize();

	log_fd_lock(fd);
	while (off != msglen) {
		/*
		 * Write up to a page of data at a time. If for some reason an
		 * individual write fails, move on and try to still write a new
		 * line at least...
		 */
		ret = write(fd, msg + off, MIN(msglen - off, maxbuf));
		if (ret < 0)
			break;

		off += ret;
	}

	log_fd_unlock(fd);
}

static int
log_syslog_sev(log_level_t level)
{
	if (level >= LOG_L_FATAL)
		return (LOG_CRIT);
	if (level >= LOG_L_ERROR)
		return (LOG_ERR);
	if (level >= LOG_L_WARN)
		return (LOG_WARNING);
	if (level >= LOG_L_INFO)
		return (LOG_INFO);
	return (LOG_DEBUG);
}

static pthread_once_t log_syslog_once = PTHREAD_ONCE_INIT;

static void
log_syslog_open(void)
{
	openlog(getprogname(), LOG_PID | LOG_NDELAY, SYSLOG_FACILITY);
}

/*
 * Destination: send the message body to syslog(3C). syslog(3C) supplies
 * the timestamp, hostname, program name and pid, so only the body (which
 * for LFMT_SYSLOG is the structured data and message) is sent.
 */
void
log_stream_syslog(log_level_t level, const log_msg_t *m, void *arg)
{
	int facility = (int)(uintptr_t)arg;

	/* LOG_KERN (0) is reserved for the kernel */
	if (facility == 0)
		facility = SYSLOG_FACILITY;

	(void) pthread_once(&log_syslog_once, log_syslog_open);

	syslog(facility | log_syslog_sev(level), "%.*s",
	    (int)MIN(m->lm_bodylen, INT_MAX), m->lm_body);
}

int
log_stream_add(log_t *l, const char *name, log_fmt_type_t fmt,
    log_level_t level, log_stream_f func, void *arg)
{
	log_stream_t *ls;
	log_stream_t templ = {
		.ls_name = (char *)name,
	};

	if (name == NULL)
		return (EINVAL);

	switch (fmt) {
	case LFMT_SYSLOG:
	case LFMT_BUNYAN:
		break;
	default:
		return (EINVAL);
	}

	ls = umem_zalloc(sizeof (*ls), UMEM_NOFAIL);
	uu_list_node_init(ls, &ls->ls_node, stream_pool);
	ls->ls_name = xstrdup(name);
	ls->ls_level = level;
	ls->ls_fmt = fmt;
	ls->ls_func = func;
	ls->ls_arg = arg;

	mutex_enter(&l->l_lock);
	if (uu_list_find(l->l_streams, &templ, NULL, NULL) != NULL) {
		mutex_exit(&l->l_lock);
		uu_free(ls->ls_name);
		umem_free(ls, sizeof (*ls));
		return (EEXIST);
	}

	VERIFY0(uu_list_insert_after(l->l_streams, uu_list_last(l->l_streams),
	    ls));

	mutex_exit(&l->l_lock);
	return (0);
}

int
log_stream_remove(log_t *l, const char *name)
{
	log_stream_t *stream;
	log_stream_t templ = {
		.ls_name = (char *)name,
	};

	mutex_enter(&l->l_lock);
	stream = uu_list_find(l->l_streams, &templ, NULL, NULL);
	if (stream != NULL)
		uu_list_remove(l->l_streams, stream);
	mutex_exit(&l->l_lock);

	if (stream == NULL)
		return (ENOENT);

	log_stream_fini(stream);
	return (0);
}

static bool
log_walk_arglist(va_list *ap, arg_cb_t cb, void *arg)
{
	log_type_t type;

	while ((type = va_arg(*ap, int)) != _LOG_T_END) {
		const char	*name = va_arg(*ap, char *);
		uintptr_t	val = 0;
		size_t		vallen = 0;

		switch (type) {
		case LOG_T_STRING:
			val = (uintptr_t)va_arg(*ap, char *);
			vallen = strlen((const char *)val) + 1;
			break;
		case LOG_T_POINTER:
			val = (uintptr_t)va_arg(*ap, void *);
			break;
		case LOG_T_BOOLEAN:
			val = (uintptr_t)va_arg(*ap, int);
			break;
		case LOG_T_INT32:
		case LOG_T_UINT32:
		case LOG_T_XINT32:
			val = (uintptr_t)va_arg(*ap, uint32_t);
			break;
		case LOG_T_INT64:
		case LOG_T_UINT64:
		case LOG_T_XINT64:
			val = (uintptr_t)va_arg(*ap, uint64_t);
			break;
		case LOG_T_MAC:
			val = (uintptr_t)va_arg(*ap, uint8_t *);
			vallen = ETHERADDRL;
			break;
		case LOG_T_IPV4:
			val = (uintptr_t)va_arg(*ap, in_addr_t);
			break;
		case LOG_T_IPV6:
			val = (uintptr_t)va_arg(*ap, in6_addr_t *);
			break;
		case LOG_T_CHASSIS:
		case LOG_T_PORT:
			val = (uintptr_t)va_arg(*ap, tlv_t *);
			vallen = sizeof (tlv_t) +
			    buf_len(&((const tlv_t *)val)->tlv_buf);
			break;
		default:
			panic("unexpected type");
		}

		if (!cb(arg, name, type, val, vallen))
			return (false);
	}

	return (true);
}

static log_key_t *
log_key_create(const char *name, log_type_t type, uintptr_t arg, size_t len)
{
	const void *p = (const void *)arg;
	log_key_t *k;

	VERIFY3S(type, !=, _LOG_T_END);

	k = umem_cache_alloc(key_cache, UMEM_NOFAIL);

	k->lk_name = uu_strdup(name);
	if (k->lk_name == NULL) {
		log_key_fini(k);
		return (NULL);
	}

	k->lk_type = type;

	switch (type) {
	case _LOG_T_END:
		panic("invalid type");
		break;
	case LOG_T_STRING:
		ASSERT3U(len, >, 0);
		ASSERT(((const char *)p)[len - 1] == '\0');
		k->lk_len = len;
		k->lk_data = (uintptr_t)umem_zalloc(len, UMEM_NOFAIL);
		(void) memcpy((void *)k->lk_data, p, len);
		return (k);
	case LOG_T_POINTER:
	case LOG_T_BOOLEAN:
	case LOG_T_INT32:
	case LOG_T_UINT32:
	case LOG_T_XINT32:
	case LOG_T_INT64:
	case LOG_T_UINT64:
	case LOG_T_XINT64:
		k->lk_data = arg;
		k->lk_len = 0;
		return (k);
	case LOG_T_MAC:
		k->lk_data = (uintptr_t)umem_zalloc(len, UMEM_NOFAIL);
		(void) memcpy((void *)k->lk_data, p, len);
		k->lk_len = len;
		return (k);
	case LOG_T_IPV4:
		k->lk_data = arg;
		k->lk_len = 0;
		return (k);
	case LOG_T_IPV6:
		k->lk_data = (uintptr_t)umem_zalloc(sizeof (in6_addr_t),
		    UMEM_NOFAIL);
		(void) memcpy((void *)k->lk_data, p, sizeof (in6_addr_t));
		k->lk_len = sizeof (in6_addr_t);
		return (k);
	case LOG_T_CHASSIS:
	case LOG_T_PORT:
		key_tlv_copy(k, (const tlv_t *)arg);
		break;
	}

	return (k);
}

static bool
log_key_add_one(void *arg, const char *name, log_type_t type, uintptr_t val,
    size_t vallen)
{
	log_t		*l = arg;
	log_key_t	*k;
	log_key_t	*ok;
	log_key_t	templ = {
		.lk_name = (char *)name,
	};
	uu_list_index_t	idx;

	VERIFY3S(type, !=, _LOG_T_END);

	k = log_key_create(name, type, val, vallen);
	if (k == NULL)
		return (false);

	mutex_enter(&l->l_lock);
	ok = uu_list_find(l->l_keys, &templ, NULL, &idx);
	if (ok != NULL)
		log_key_fini(ok);
	uu_list_insert(l->l_keys, k, idx);
	mutex_exit(&l->l_lock);

	return (true);
}

int
log_key_add(log_t *l, ...)
{
	va_list ap;
	bool ret;

	va_start(ap, l);
	ret = log_walk_arglist(&ap, log_key_add_one, l);
	va_end(ap);

	return (ret ? 0 : -1);
}

/*
 * Render the message in the given format (if not already done), and fill in
 * *m. Returns false if the message couldn't be rendered in that format.
 */
static bool
log_render(log_render_t *r, log_fmt_type_t fmt, log_msg_t *m)
{
	log_t	*l = r->lr_src;
	custr_t	*cus;
	size_t	bodyoff = 0;

	ASSERT(MUTEX_HELD(&l->l_lock));

	if ((r->lr_tried & fmt) == 0) {
		va_list	ap;
		bool	ok = false;

		va_copy(ap, r->lr_ap);
		switch (fmt) {
		case LFMT_BUNYAN:
			ok = log_make_bunyan(l, &r->lr_tv, r->lr_level,
			    r->lr_msg, &ap);
			break;
		case LFMT_SYSLOG:
			ok = log_make_syslog(l, &r->lr_tv, r->lr_level,
			    r->lr_msg, &ap, &r->lr_syslog_hdrlen);
			break;
		}
		va_end(ap);

		r->lr_tried |= fmt;
		if (ok)
			r->lr_ok |= fmt;
	}

	if ((r->lr_ok & fmt) == 0)
		return (false);

	switch (fmt) {
	case LFMT_BUNYAN:
		cus = l->l_bunyan;
		break;
	case LFMT_SYSLOG:
		cus = l->l_syslog;
		bodyoff = r->lr_syslog_hdrlen;
		break;
	default:
		return (false);
	}

	m->lm_fmt = fmt;
	m->lm_msg = custr_cstr(cus);
	m->lm_len = custr_len(cus);
	m->lm_body = m->lm_msg + bodyoff;
	m->lm_bodylen = m->lm_len - bodyoff;

	/* The body excludes the trailing newline */
	if (m->lm_bodylen > 0 && m->lm_body[m->lm_bodylen - 1] == '\n')
		m->lm_bodylen--;

	return (true);
}

static void
log_run_streams(log_render_t *r, log_t *l)
{
	uu_list_walk_t	*wk;
	log_stream_t	*stream;

	ASSERT(MUTEX_HELD(&l->l_lock));

	wk = uu_list_walk_start(l->l_streams, 0);
	if (wk == NULL)
		nomem();

	while ((stream = uu_list_walk_next(wk)) != NULL) {
		log_msg_t m;

		if (stream->ls_level > r->lr_level)
			continue;

		if (!log_render(r, stream->ls_fmt, &m))
			continue;

		stream->ls_func(r->lr_level, &m, stream->ls_arg);
	}

	uu_list_walk_end(wk);

	if (l->l_parent == NULL)
		return;

	mutex_enter(&l->l_parent->l_lock);
	log_run_streams(r, l->l_parent);
	mutex_exit(&l->l_parent->l_lock);
}

void
log_vlvl(log_t *l, log_level_t level, const char *msg, va_list ap)
{
	log_render_t r = {
		.lr_src = l,
		.lr_level = level,
		.lr_msg = msg,
	};

	VERIFY0(gettimeofday(&r.lr_tv, NULL));
	va_copy(r.lr_ap, ap);

	mutex_enter(&l->l_lock);
	log_run_streams(&r, l);
	mutex_exit(&l->l_lock);

	va_end(r.lr_ap);
}

void
log_lvl(log_t *l, log_level_t level, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, level, msg, ap);
	va_end(ap);
}

void
log_fatal(int eval, log_t *l, const char *msg, ...)
{
	extern int start_pipe_fd;

	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_FATAL, msg, ap);

	membar_consumer();
	if (start_pipe_fd >= 0) {
		(void) write(start_pipe_fd, &eval, sizeof (eval));
		(void) close(start_pipe_fd);
	}

	exit(eval);
}

void
log_error(log_t *l, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_ERROR, msg, ap);
	va_end(ap);
}

void
log_warn(log_t *l, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_WARN, msg, ap);
	va_end(ap);
}

void
log_info(log_t *l, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_INFO, msg, ap);
	va_end(ap);
}

void
log_debug(log_t *l, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_DEBUG, msg, ap);
	va_end(ap);
}

void
log_trace(log_t *l, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_vlvl(l, LOG_L_TRACE, msg, ap);
	va_end(ap);
}

void
log_syserr(log_t *l, const char *msg, int eval)
{
	log_error(l, msg,
	    LOG_T_INT32, "err", eval,
	    LOG_T_STRING, "errmsg", strerror(eval),
	    LOG_T_END);
}

void
log_fatal_syserr(log_t *l, const char *msg, int eval)
{
	log_fatal(SMF_EXIT_ERR_FATAL, l, msg,
	    LOG_T_INT32, "err", eval,
	    LOG_T_STRING, "errmsg", strerror(eval),
	    LOG_T_END);
}

void
log_dlerr(log_t *l, const char *msg, int eval)
{
	log_error(l, msg,
	    LOG_T_INT32, "err", eval,
	    LOG_T_STRING, "errmsg", dlpi_strerror(eval),
	    LOG_T_END);
}

void
log_fatal_dladm_err(log_t *l, const char *msg, dladm_status_t st)
{
	char buf[DLADM_STRSIZE] = { 0 };

	log_fatal(SMF_EXIT_ERR_FATAL, l, msg,
	    LOG_T_INT32, "err", st,
	    LOG_T_STRING, "errmsg", dladm_status2str(st, buf),
	    LOG_T_END);
}

void
log_uuerr(log_t *l, log_level_t lvl, const char *msg)
{
	log_lvl(l, lvl, msg,
	    LOG_T_INT32, "err", uu_error(),
	    LOG_T_STRING, "errmsg", uu_strerror(uu_error()),
	    LOG_T_END);
}

void
log_fatal_uuerr(int eval, log_t *l, const char *msg)
{
	log_fatal(eval, l, msg,
	    LOG_T_INT32, "err", uu_error(),
	    LOG_T_STRING, "errmsg", uu_strerror(uu_error()),
	    LOG_T_END);
}

void
log_fatal_scferr(int eval, log_t *l, const char *msg)
{
	log_fatal(eval, l, msg,
	    LOG_T_INT32, "err", scf_error(),
	    LOG_T_STRING, "errmsg", scf_strerror(scf_error()),
	    LOG_T_END);
}

/*
 * Format tv as an ISO 8601 / RFC 3339 UTC timestamp with millisecond
 * precision (e.g. 2026-10-11T12:34:56.789Z). Used by both formats.
 */
static bool
log_iso_time(const struct timeval *tv, char *buf)
{
	struct tm tm;

	if (gmtime_r(&tv->tv_sec, &tm) == NULL)
		return (false);

	VERIFY3U(strftime(buf, ISO_TIMELEN, "%FT%T", &tm), ==, 19);
	(void) snprintf(&buf[19], 6, ".%03dZ", (int)(tv->tv_usec / 1000));
	return (true);
}

static bool
bunyan_add_str(custr_t *cus, const char *str)
{
	mbstate_t	mbr;
	wchar_t		c;
	size_t		sz;

	(void) memset(&mbr, '\0', sizeof (mbr));

	VERIFY0(custr_appendc(cus, '"'));
	while ((sz = mbrtowc(&c, str, MB_CUR_MAX, &mbr)) > 0) {
		switch (c) {
		case '"':
			VERIFY0(custr_append(cus, "\\\""));
			break;
		case '\n':
			VERIFY0(custr_append(cus, "\\n"));
			break;
		case '\r':
			VERIFY0(custr_append(cus, "\\r"));
			break;
		case '\\':
			VERIFY0(custr_append(cus, "\\\\"));
			break;
		case '\f':
			VERIFY0(custr_append(cus, "\\f"));
			break;
		case '\t':
			VERIFY0(custr_append(cus, "\\t"));
			break;
		case '\b':
			VERIFY0(custr_append(cus, "\\b"));
			break;
		default:
			if ((c >= 0x00 && c <= 0x1f) ||
			    (c > 0x7f && c <= 0xffff)) {
				VERIFY0(custr_append_printf(cus, "\\u%04x",
				    (int)(0xffff & c)));
			} else if (c >= 0x20 && c <= 0x7f) {
				VERIFY0(custr_appendc(cus, (int)(0xff & c)));
			}
			break;
		}
		str += sz;
	}

	if (sz == (size_t)-1 || sz == (size_t)-2) {
		/* Read an invalid multibyte character, return failure */
		return (false);
	}

	VERIFY0(custr_appendc(cus, '"'));
	return (true);
}

/*
 * Format a chassis or port id key (whose value is the TLV) as text.
 */
static void
log_id_str(log_type_t type, const tlv_t *t, char *buf, size_t buflen)
{
	buf_t	b = t->tlv_buf;
	uint8_t	subtype;
	size_t	len;

	buf[0] = '\0';

	/* The TLV value is the id subtype followed by the id */
	if (!buf_get8(&b, &subtype))
		return;

	if (type == LOG_T_CHASSIS) {
		lldp_chassis_t c = { 0 };

		len = MIN(buf_len(&b), sizeof (c.llc_id));
		c.llc_type = subtype;
		c.llc_len = len;
		(void) memcpy(c.llc_id, buf_cptr(&b), len);
		(void) lldp_chassis_str(&c, buf, buflen);
	} else {
		lldp_port_t p = { 0 };

		len = MIN(buf_len(&b), sizeof (p.llp_id));
		p.llp_type = subtype;
		p.llp_len = len;
		(void) memcpy(p.llp_id, buf_cptr(&b), len);
		(void) lldp_port_str(&p, buf, buflen);
	}
}

/*
 * Return the value of a key as text. Strings are returned as-is; anything
 * else is formatted into buf. If quotep is non-NULL, it is set to whether
 * the value should be a string (vs. a number or boolean) in JSON.
 */
static const char *
log_val_str(log_type_t type, uintptr_t data, char *buf, size_t buflen,
    bool *quotep)
{
	const uint8_t	*p;
	bool		quote = true;

	buf[0] = '\0';

	switch (type) {
	case LOG_T_STRING:
		if (quotep != NULL)
			*quotep = true;
		return ((const char *)data);
	case LOG_T_POINTER:
		(void) snprintf(buf, buflen, "%p", (void *)data);
		break;
	case LOG_T_BOOLEAN:
		(void) strlcpy(buf, (data != 0) ? "true" : "false", buflen);
		quote = false;
		break;
	case LOG_T_INT32:
		(void) snprintf(buf, buflen, "%" PRId32, (int32_t)data);
		quote = false;
		break;
	case LOG_T_UINT32:
		(void) snprintf(buf, buflen, "%" PRIu32, (uint32_t)data);
		quote = false;
		break;
	case LOG_T_XINT32:
		(void) snprintf(buf, buflen, "0x%" PRIx32, (uint32_t)data);
		break;
	case LOG_T_INT64:
		(void) snprintf(buf, buflen, "%" PRId64, (int64_t)data);
		quote = false;
		break;
	case LOG_T_UINT64:
		(void) snprintf(buf, buflen, "%" PRIu64, (uint64_t)data);
		quote = false;
		break;
	case LOG_T_XINT64:
		(void) snprintf(buf, buflen, "0x%" PRIx64, (uint64_t)data);
		break;
	case LOG_T_MAC:
		p = (const uint8_t *)data;
		(void) snprintf(buf, buflen,
		    "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		    p[0], p[1], p[2], p[3], p[4], p[5]);
		break;
	case LOG_T_IPV4: {
		struct in_addr in4 = { .s_addr = (in_addr_t)data };

		if (inet_ntop(AF_INET, &in4, buf, buflen) == NULL)
			(void) strlcpy(buf, "?", buflen);
		break;
	}
	case LOG_T_IPV6:
		if (inet_ntop(AF_INET6, (const in6_addr_t *)data, buf,
		    buflen) == NULL) {
			(void) strlcpy(buf, "?", buflen);
		}
		break;
	case LOG_T_CHASSIS:
	case LOG_T_PORT:
		log_id_str(type, (const tlv_t *)data, buf, buflen);
		break;
	default:
		panic("invalid key type");
	}

	if (quotep != NULL)
		*quotep = quote;
	return (buf);
}

static bool
log_bunyan_key(void *arg, const char *name, log_type_t type, uintptr_t data,
    size_t len __unused)
{
	custr_t		*cus = arg;
	char		buf[LOG_VALBUF];
	const char	*val;
	bool		quote;

	VERIFY0(custr_append(cus, ", "));

	if (!bunyan_add_str(cus, name))
		return (false);
	VERIFY0(custr_append(cus, ": "));

	val = log_val_str(type, data, buf, sizeof (buf), &quote);
	if (quote)
		return (bunyan_add_str(cus, val));

	VERIFY0(custr_append(cus, val));
	return (true);
}

static bool
log_make_bunyan(log_t *l, const struct timeval *tv, log_level_t level,
    const char *msg, va_list *ap)
{
	custr_t		*cus = l->l_bunyan;
	log_key_t	*k;
	uu_list_walk_t	*wk = NULL;
	char		timebuf[ISO_TIMELEN] = { 0 };

	if (!log_iso_time(tv, timebuf))
		return (false);

	custr_reset(cus);

	VERIFY0(custr_append(cus, "{ "));

	/* Mandatory fields */

	/*
	 * For the first key, we don't want the separator. Since JSON
	 * doesn't like a trailing separator, we do this one manually.
	 */
	VERIFY0(custr_append_printf(cus, "\"v\": %" PRIu32, bunyan_version));

	if (!log_bunyan_key(cus, "level", LOG_T_UINT32, (uintptr_t)level,
	    sizeof (uintptr_t)))
		goto fail;

	if (!log_bunyan_key(cus, "name", LOG_T_STRING, (uintptr_t)l->l_name,
	    strlen(l->l_name) + 1))
		goto fail;

	if (!log_bunyan_key(cus, "hostname", LOG_T_STRING, (uintptr_t)l->l_host,
	    strlen(l->l_host) + 1))
		goto fail;

	if (!log_bunyan_key(cus, "pid", LOG_T_INT32, (uintptr_t)getpid(),
	    sizeof (uintptr_t)))
		goto fail;

	if (!log_bunyan_key(cus, "tid", LOG_T_UINT32, (uintptr_t)thr_self(),
	    sizeof (uintptr_t)))
		goto fail;

	if (!log_bunyan_key(cus, "time", LOG_T_STRING, (uintptr_t)timebuf,
	    strlen(timebuf) + 1))
		goto fail;

	if (!log_bunyan_key(cus, "msg", LOG_T_STRING, (uintptr_t)msg,
	    strlen(msg) + 1))
		goto fail;

	wk = uu_list_walk_start(l->l_keys, 0);
	if (wk == NULL)
		nomem();

	while ((k = uu_list_walk_next(wk)) != NULL) {
		if (!log_bunyan_key(cus, k->lk_name, k->lk_type, k->lk_data,
		    k->lk_len))
			goto fail;
	}

	uu_list_walk_end(wk);
	wk = NULL;

	if (!log_walk_arglist(ap, log_bunyan_key, cus))
		goto fail;

	VERIFY0(custr_append(cus, " }\n"));
	return (true);

fail:
	if (wk != NULL)
		uu_list_walk_end(wk);
	custr_reset(cus);
	return (false);
}

/*
 * RFC 5424 helpers.
 *
 * Header fields and structured data names are restricted to printable
 * US-ASCII (33-126), and names additionally exclude '=', ']', and '"'.
 * Anything else is replaced with '_'. An empty header field is written as
 * the NILVALUE ('-').
 */
static void
syslog_add_name(custr_t *cus, const char *s, size_t max, bool sdname)
{
	size_t n;

	for (n = 0; s[n] != '\0' && n < max; n++) {
		unsigned char c = s[n];

		if (c < 33 || c > 126 ||
		    (sdname && (c == '=' || c == ']' || c == '"'))) {
			c = '_';
		}
		VERIFY0(custr_appendc(cus, c));
	}

	if (n == 0)
		VERIFY0(custr_appendc(cus, sdname ? '_' : '-'));
}

/*
 * Add a structured data parameter value (or the free-form message). '"',
 * '\', and ']' are escaped in parameter values as RFC 5424 requires. Control
 * characters are replaced with spaces so that each message stays on a
 * single line.
 */
static void
syslog_add_text(custr_t *cus, const char *s, bool sdvalue)
{
	for (; *s != '\0'; s++) {
		unsigned char c = *s;

		if (sdvalue && (c == '"' || c == '\\' || c == ']'))
			VERIFY0(custr_appendc(cus, '\\'));
		else if (c < 0x20 || c == 0x7f)
			c = ' ';

		VERIFY0(custr_appendc(cus, c));
	}
}

static bool
log_syslog_key(void *arg, const char *name, log_type_t type, uintptr_t data,
    size_t len __unused)
{
	custr_t		*cus = arg;
	char		buf[LOG_VALBUF];
	const char	*val;

	val = log_val_str(type, data, buf, sizeof (buf), NULL);

	VERIFY0(custr_appendc(cus, ' '));
	syslog_add_name(cus, name, SYSLOG_PARAMNAME_MAX, true);
	VERIFY0(custr_append(cus, "=\""));
	syslog_add_text(cus, val, true);
	VERIFY0(custr_appendc(cus, '"'));
	return (true);
}

/*
 * Render the message as an RFC 5424 syslog message:
 *
 *	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID params] MSG
 *
 * The keys (the log's own and those passed with the message), along with
 * the thread id and log level, are included as parameters of a single
 * structured data element. MSGID is unused (NILVALUE). *hdrlenp is set to
 * the length of the header (everything before the structured data), which
 * transports such as syslog(3C) that supply their own header omit.
 */
static bool
log_make_syslog(log_t *l, const struct timeval *tv, log_level_t level,
    const char *msg, va_list *ap, size_t *hdrlenp)
{
	custr_t		*cus = l->l_syslog;
	log_key_t	*k;
	uu_list_walk_t	*wk;
	char		timebuf[ISO_TIMELEN] = { 0 };
	const size_t	pen_len = strlen("@" SYSLOG_PEN);

	if (!log_iso_time(tv, timebuf))
		return (false);

	custr_reset(cus);

	/* Header */
	VERIFY0(custr_append_printf(cus, "<%d>1 %s ",
	    SYSLOG_FACILITY | log_syslog_sev(level), timebuf));
	syslog_add_name(cus, l->l_host, SYSLOG_HOSTNAME_MAX, false);
	VERIFY0(custr_appendc(cus, ' '));
	syslog_add_name(cus, l->l_name, SYSLOG_APPNAME_MAX, false);
	VERIFY0(custr_append_printf(cus, " %d - ", (int)getpid()));

	*hdrlenp = custr_len(cus);

	/* Structured data */
	VERIFY0(custr_appendc(cus, '['));
	syslog_add_name(cus, l->l_name, SYSLOG_SDNAME_MAX - pen_len, true);
	VERIFY0(custr_append(cus, "@" SYSLOG_PEN));

	(void) log_syslog_key(cus, "tid", LOG_T_UINT32, (uintptr_t)thr_self(),
	    0);
	(void) log_syslog_key(cus, "level", LOG_T_UINT32, (uintptr_t)level,
	    0);

	wk = uu_list_walk_start(l->l_keys, 0);
	if (wk == NULL)
		nomem();
	while ((k = uu_list_walk_next(wk)) != NULL) {
		(void) log_syslog_key(cus, k->lk_name, k->lk_type, k->lk_data,
		    k->lk_len);
	}
	uu_list_walk_end(wk);

	if (!log_walk_arglist(ap, log_syslog_key, cus)) {
		custr_reset(cus);
		return (false);
	}

	VERIFY0(custr_append(cus, "] "));

	/* Message */
	syslog_add_text(cus, msg, false);
	VERIFY0(custr_appendc(cus, '\n'));

	return (true);
}

static int
log_key_cmp(const void *a, const void *b, void *dummy __unused)
{
	const log_key_t *l = a;
	const log_key_t *r = b;
	int ret = strcmp(l->lk_name, r->lk_name);

	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	return (0);
}

static int
log_stream_cmp(const void *a, const void *b, void *dummy __unused)
{
	const log_stream_t *l = a;
	const log_stream_t *r = b;
	int ret = strcmp(l->ls_name, r->ls_name);

	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	return (0);
}

static int
key_ctor(void *buf, void *cbdata __unused, int flags __unused)
{
	log_key_t *k = buf;

	(void) memset(buf, '\0', sizeof (log_key_t));
	uu_list_node_init(k, &k->lk_node, key_pool);
	return (0);
}

static void
key_dtor(void *buf, void *cbdata __unused)
{
	log_key_t *k = buf;

	uu_list_node_fini(k, &k->lk_node, key_pool);
}

static void
key_tlv_copy(log_key_t *k, const tlv_t *src)
{
	tlv_t	*new;
	size_t	len;

	len = sizeof (*new) + buf_len(&src->tlv_buf);
	new = umem_zalloc(len, UMEM_NOFAIL);

	new->tlv_type = src->tlv_type;
	(void) memcpy(new + 1, buf_cptr(&src->tlv_buf), buf_len(&src->tlv_buf));
	buf_init(&new->tlv_buf, (uint8_t *)(new + 1), buf_len(&src->tlv_buf));

	k->lk_data = (uintptr_t)new;
	k->lk_len = len;
}

void
log_sysinit(void)
{
	for (uint_t i = 0; i < ARRAY_SIZE(fd_mutex); i++) {
		VERIFY0(mutex_init(&fd_mutex[i], USYNC_THREAD|LOCK_ERRORCHECK,
		    NULL));
	}

	key_pool = uu_list_pool_create("log-keys", sizeof (log_key_t),
	    offsetof(log_key_t, lk_node), log_key_cmp, UU_LIST_POOL_DEBUG);
	if (key_pool == NULL) {
		panic("failed to create log key list pool: %s",
		    uu_strerror(uu_error()));
	}

	stream_pool = uu_list_pool_create("log-streams",
	    sizeof (log_stream_t), offsetof(log_stream_t, ls_node),
	    log_stream_cmp, UU_LIST_POOL_DEBUG);
	if (stream_pool == NULL) {
		panic("failed to create log stream list pool: %s",
		    uu_strerror(uu_error()));
	}

	key_cache = umem_cache_create("log keys", sizeof (log_key_t),
	    0, key_ctor, key_dtor, NULL, NULL, NULL, 0);
	if (key_cache == NULL) {
		panic("failed to create log key cache: %s", strerror(errno));
	}
}

void
log_sysfini(void)
{
	umem_cache_destroy(key_cache);
	uu_list_pool_destroy(stream_pool);
	uu_list_pool_destroy(key_pool);

	for (uint_t i = 0; i < ARRAY_SIZE(fd_mutex); i++)
		VERIFY0(mutex_destroy(&fd_mutex[i]));
}
