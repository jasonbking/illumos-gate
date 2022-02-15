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

#ifndef _LOG_H
#define	_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is very much based off the bunyan logger in SmartOS.
 */
typedef struct log log_t;
typedef struct logobj logobj_t;

struct nvlist;

typedef enum log_level {
	LOG_L_TRACE =	10,
	LOG_L_DEBUG =	20,
	LOG_L_INFO =	30,
	LOG_L_WARN =	40,
	LOG_L_ERROR =	50,
	LOG_L_FATAL =	60,
} log_level_t;

/*
 * This looks a bit odd, but by defining LOG_T_END as NULL, we can use
 * gcc's __sentinel attribute to flag a final LOG_T_END (gcc explicitly wants
 * a pointer type with value 0 to terminate a list, so merely passing 0
 * won't work.
 */
#define	LOG_T_END	NULL
typedef enum log_type {
	_LOG_T_END =	0,
	LOG_T_STRING,
	LOG_T_POINTER,
	LOG_T_BOOLEAN,
	LOG_T_INT32,
	LOG_T_UINT32,
	LOG_T_XINT32,	/* as hex */
	LOG_T_INT64,
	LOG_T_UINT64,
	LOG_T_XINT64,	/* as hex */
	LOG_T_MAC,
	LOG_T_IPV4,
	LOG_T_IPV6,
	LOG_T_OBJ,
} log_type_t;

void log_sysinit(void);
void log_sysfini(void);

void log_init(const char *, log_t **);
int log_child(const log_t *, log_t **, ...) __sentinel(0);
void log_fini(log_t *);

typedef int (*log_stream_f)(struct nvlist *, const char *, void *);
int log_stream_fd(struct nvlist *, const char *, void *);
int log_stream_syslog(struct nvlist *, const char *, void *);

int log_stream_add(log_t *, const char *, log_level_t, log_stream_f, void *);

int log_key_add(log_t *, ...) __sentinel(0);
int log_key_remove(log_t *, const char *);

void log_lvl(log_t *, log_level_t, const char *, ...) __sentinel(0);
void log_trace(log_t *, const char *, ...) __sentinel(0);
void log_debug(log_t *, const char *, ...) __sentinel(0);
void log_info(log_t *, const char *, ...) __sentinel(0);
void log_warn(log_t *, const char *, ...) __sentinel(0);
void log_error(log_t *, const char *, ...) __sentinel(0);
void log_fatal(log_t *, const char *, ...) __sentinel(0);

void log_syserr(log_t *, const char *, int);
void log_dlerr(log_t *, const char *, int);
void log_uuerr(log_t *, const char *);

int logobj_init(logobj_t *, ...) __sentinel(0);
int logobj_key_add(logobj_t *, ...) __sentinel(0);
int logobj_key_remove(logobj_t *, const char *);
void logobj_fini(logobj_t *);

extern __thread log_t *log;

#define	TRACE_ENTER(_l)				\
	log_trace((_l), "function enter",	\
	    LOG_T_STRING, "function", __func__,	\
	    LOG_T_END);

#define	TRACE_RETURN(_l)			\
	log_trace((_l), "function return",	\
	    LOG_T_STRING, "function", __func__,	\
	    LOG_T_END);

#ifdef __cplusplus
}
#endif

#endif /* _LOG_H */
