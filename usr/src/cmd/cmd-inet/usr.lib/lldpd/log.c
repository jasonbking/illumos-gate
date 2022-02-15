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
 * Copyright 2022 Jason King
 */

#include <errno.h>
#include <netdb.h>
#include <libdlpi.h>
#include <libnvpair.h>
#include <libuutil.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <synch.h>
#include <thread.h>
#include <time.h>
#include <unistd.h>
#include <umem.h>

#include "log.h"
#include "util.h"

struct log_key;
struct log_stream;
struct log;

typedef struct log_stream {
	uu_list_node_t	ls_node;
	char		*ls_name;
	log_level_t	ls_level;
	log_stream_f	ls_func;
	void		*ls_arg;
	uint_t		ls_count;
} log_stream_t;

typedef struct log_key {
	uu_list_node_t	lk_node;
	char		*lk_name;
	log_type_t	lk_type;
	void		*lk_data;
	size_t		lk_len;
} log_key_t;

struct log {
	mutex_t		l_lock;
	uu_list_t	*l_keys;
	uu_list_t	*l_streams;
	char		*l_name;
	char		l_host[MAXHOSTNAMELEN + 1];
};

#define	FD_MUTEX_HASH_SIZE	64
static mutex_t		fd_mutex[FD_MUTEX_HASH_SIZE];
static uu_list_pool_t	*key_pool;
static uu_list_pool_t	*stream_pool;
static umem_cache_t	*key_cache;

#ifdef notyet
static const int log_version = 0;
#endif

__thread log_t *log;

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
	if (k->lk_type == LOG_T_OBJ) {
		uu_list_t *list = k->lk_data;
		log_key_t *ok = NULL;
		void *cookie = NULL;

		while ((ok = uu_list_teardown(list, &cookie)) != NULL)
			log_key_fini(ok);

		uu_list_destroy(list);
	} else {
		if (k->lk_len > 0)
			umem_free(k->lk_data, k->lk_len);
	}

	uu_free(k->lk_name);

	k->lk_name = NULL;
	k->lk_data = NULL;
	k->lk_len = 0;
	umem_cache_free(key_cache, k);
}

static void
log_stream_fini(log_stream_t *ls)
{
	uu_free(ls->ls_name);
	umem_free(ls, sizeof (*ls));
}

void
log_init(const char *name, log_t **lp)
{
	log_t		*l = NULL;

	VERIFY3P(name, !=, NULL);

	l = umem_zalloc(sizeof (*l), UMEM_NOFAIL);

	VERIFY0(mutex_init(&l->l_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));
	VERIFY0(gethostname(l->l_host, sizeof (l->l_host)));
	l->l_host[sizeof (l->l_host) - 1] = '\0';

	l->l_name = xstrdup(name);
	l->l_keys = uu_list_create(key_pool, NULL, UU_LIST_DEBUG);
	if (l->l_keys == NULL)
		nomem();

	l->l_streams = uu_list_create(stream_pool, NULL, UU_LIST_DEBUG);
	if (l->l_streams == NULL)
		nomem();

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
	umem_free(lp, sizeof (*lp));
}

int
log_stream_fd(nvlist_t *nvl, const char *js, void *arg)
{
	uintptr_t	fd = (uintptr_t)arg;
	size_t		jslen = strlen(js);
	off_t		off = 0;
	ssize_t		ret = 0;
	static int	maxbuf = -1;

	if (maxbuf == -1)
		maxbuf = getpagesize();

	log_fd_lock(fd);
	while (off != jslen) {
		/*
		 * Write up to a page of data at a time. If for some reason an
		 * individual write fails, move on and try to still write a new
		 * line at least...
		 */

		ret = write(fd, js + off, MIN(jslen - off, maxbuf));
		if (ret < 0)
			break;

		off += ret;
	}

	if (ret < 0) {
		(void) write(fd, "\n", 1);
	} else {
		ret = write(fd, "\n", 1);
	}
	log_fd_unlock(fd);

	return (ret < 0 ? 1 : 0);
}

int
log_stream_add(log_t *l, const char *name, log_level_t level, log_stream_f func,
    void *arg)
{
	log_stream_t *ls;
	log_stream_t templ = {
		.ls_name = (char *)name,
	};

	if (name == NULL)
		return (EINVAL);

	ls = umem_zalloc(sizeof (*ls), UMEM_NOFAIL);
	ls->ls_name = xstrdup(name);
	ls->ls_level = level;
	ls->ls_func = func;
	ls->ls_arg = arg;
	ls->ls_count = 0;

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

static log_key_t *
log_key_create(const char *name, log_type_t type, const void *arg)
{
	log_key_t *k;
	void *cookie = NULL;
	size_t len = 0;

	VERIFY3S(type, !=, _LOG_T_END);

	k = umem_cache_alloc(key_cache, UMEM_DEFAULT);
	if (k == NULL)
		return (NULL);

	k->lk_name = uu_strdup(name);
	if (k->lk_name == NULL) {
		log_key_fini(k);
		return (NULL);
	}

	switch (type) {
	case _LOG_T_END:
		panic("invalid type");
		break;
	case LOG_T_STRING:
		k->lk_len = strlen(arg) + 1;
		k->lk_data = umem_zalloc(k->lk_len, UMEM_NOFAIL);
		(void) memcpy(k->lk_data, arg, k->lk_len);
		return (k);
	case LOG_T_POINTER:
	case LOG_T_BOOLEAN:
	case LOG_T_INT32:
	case LOG_T_UINT32:
	case LOG_T_XINT32:
	case LOG_T_INT64:
	case LOG_T_UINT64:
	case LOG_T_XINT64:
		k->lk_data = (void *)arg;
		k->lk_len = 0;
		return (k);
	case LOG_T_MAC:
		len = ETHERADDRL;
		k->lk_data = umem_zalloc(len, UMEM_NOFAIL);
		(void) memcpy(k->lk_data, arg, len);
		k->lk_len = len;
		return (k);
	case LOG_T_IPV4:
		(void) memcpy(&k->lk_data, arg, sizeof (in_addr_t));
		k->lk_len = 0;
		return (k);
	case LOG_T_IPV6:
		k->lk_data = umem_zalloc(sizeof (in6_addr_t), UMEM_NOFAIL);
		(void) memcpy(k->lk_data, arg, sizeof (in6_addr_t));
		k->lk_data = (void *)(uintptr_t)sizeof (in6_addr_t);
		return (k);
	case LOG_T_OBJ:
		break;
	}

	uu_list_t *ol = uu_list_create(key_pool, k, UU_LIST_DEBUG);
	uu_list_walk_t *wk;
	log_key_t *ok;

	wk = uu_list_walk_start((void *)arg, 0);
	if (wk == NULL)
		nomem();

	while ((ok = uu_list_walk_next(wk)) != NULL) {
		log_key_t *nk = log_key_create(ok->lk_name, ok->lk_type,
		    ok->lk_data);

		if (nk == NULL)
			goto fail;

		(void) uu_list_insert_after(ol, uu_list_last(ol), nk);
	}

	k->lk_data = ol;
	k->lk_len = 0;
	return (k);

fail:
	while ((ok = uu_list_teardown(ol, &cookie)) != NULL)
		log_key_fini(ok);

	uu_list_destroy(ol);
	log_key_fini(k);
	return (NULL);
}

static int
log_key_add_one(log_t *l, const char *name, log_type_t type, const void *arg)
{
	log_key_t	*k;
	log_key_t	*ok;
	log_key_t	templ = {
		.lk_name = (char *)name,
	};
	uu_list_index_t	idx;

	if (type == _LOG_T_END)
		return (EINVAL);

	k = log_key_create(name, type, arg);
	if (k == NULL)
		return (ENOMEM);

	mutex_enter(&l->l_lock);
	ok = uu_list_find(l->l_keys, &templ, NULL, &idx);
	if (ok != NULL)
		log_key_fini(ok);
	uu_list_insert(l->l_keys, k, idx);
	mutex_exit(&l->l_lock);

	return (0);
}

static int
log_key_vadd(log_t *l, va_list *ap)
{
	log_type_t type;
	void *data = NULL;

	while ((type = va_arg(*ap, int)) != _LOG_T_END) {
		const char *name = va_arg(*ap, char *);
		int ret;

		switch (type) {
		case _LOG_T_END:
			break;
		case LOG_T_STRING:
		case LOG_T_POINTER:
		case LOG_T_BOOLEAN:
		case LOG_T_INT32:
		case LOG_T_UINT32:
		case LOG_T_XINT32:
		case LOG_T_INT64:
		case LOG_T_UINT64:
		case LOG_T_XINT64:
		case LOG_T_MAC:
		case LOG_T_IPV4:
		case LOG_T_IPV6:
		case LOG_T_OBJ:
			break;
		}

		ret = log_key_add_one(l, name, type, data);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

int
log_key_add(log_t *l, ...)
{
	va_list ap;
	int ret;

	va_start(ap, l);
	ret = log_key_vadd(l, &ap);
	va_end(ap);

	return (ret);
}

void
log_syserr(log_t *l, const char *msg, int eval)
{
	log_error(l, msg,
	    LOG_T_INT32, "err", eval,
	    LOG_T_STRING, "errstr", strerror(eval),
	    LOG_T_END);
}

void
log_dlerr(log_t *l, const char *msg, int eval)
{
	log_error(l, msg,
	    LOG_T_INT32, "err", eval,
	    LOG_T_STRING, "errstr", dlpi_strerror(eval),
	    LOG_T_END);
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

void
log_sysinit(void)
{
	for (uint_t i = 0; i < ARRAY_SIZE(fd_mutex); i++) {
		VERIFY0(mutex_init(&fd_mutex[i], USYNC_THREAD|LOCK_ERRORCHECK,
		    NULL));
	}

	key_pool = uu_list_pool_create("log keys", sizeof (log_key_t),
	    offsetof(log_key_t, lk_node), log_key_cmp, UU_LIST_POOL_DEBUG);
	VERIFY3P(key_pool, !=, NULL);

	stream_pool = uu_list_pool_create("log streams", sizeof (log_stream_t),
	    offsetof(log_stream_t, ls_node), log_stream_cmp,
	    UU_LIST_POOL_DEBUG);
	VERIFY3P(stream_pool, !=, NULL);

	key_cache = umem_cache_create("log keys", sizeof (log_key_t),
	    0, key_ctor, key_dtor, NULL, NULL, NULL, 0);
	VERIFY3P(key_cache, !=, NULL);
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
