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
 * Copyright 2026 Jason King
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <errno.h>
#include <librestart.h>
#include <libscf.h>
#include <libuutil.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <umem.h>
#include <unistd.h>
#include <upanic.h>

#include "periodic.h"

static void nomem_cb(void);
static void go_background(void);
static void init_done(int, int, char *, ...);
static void start_sig_thread(int);
static int event_handler(restarter_event_t *);
static char *event_get_instance(restarter_event_t *);

static bool do_refresh;
static bool do_exit;

/*
 * This size should be large enough for any panic messages, but is otherwise
 * an arbitrary size.
 */
char panicbuf[256];

pthread_t sig_thread;
char *my_fmri;
int evport;
restarter_event_handle_t evt_hdl;

/* This includes the space for the terminating NUL byte */
size_t max_fmri_len;

int
main(int argc, const char * const argv[])
{
	void *status;

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	umem_nofail_callback(nomem_cb);

	(void) textdomain(TEXT_DOMAIN);
	(void) setlocale(LC_ALL, "");

	go_backgroud();

	while (!do_exit) {
	}

	(void) pthread_join(sig_thread, &status);

	return (SMF_EXIT_OK);
}

static int
event_handler(restarter_event_t *event)
{
	char			*inst_fmri;
	periodic_svc_t		*svc;
	restarter_event_type	evt_type;

	inst_fmri = event_get_instance(event);
	svc = periodic_svc_get(inst_fmri);
	if (svc == NULL) {
		/* TODO: create new service */
	}
	umem_free(inst_fmri, max_fmri_len);
	inst_fmri = NULL;

	evt_type = restarter_event_get_type(event);

	/* TODO */

	return (0);
}

static void
init(int fd)
{
	sigset_t	mask;
	sigset_t	omask;
	int		ret;

	VERIFY0(sigfillset(&mask));
	VERIFY0(sigdelset(&mask, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &mask, &omask));

	start_sig_thread(fd);

	/*
	 * scf_limit(3SCF) states that this should not change over the
	 * execution of a program (i.e. us), so it should be safe to cache
	 * for the duration of svc.periodicd.
	 */
	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;

	ret = restarter_bind_handle(RESTARTER_EVENT_VERSION, my_fmri,
	    event_handler, 0, &evt_hdl);

	/* TODO */

	if (setsid() < 0) {
		init_done(pipe_fds[0], EXIT_FAILURE,
		    _("failed to create session"));
	}
}

static void
go_background(void)
{
	int	pipe_fds[2];
	pid_t	child;

	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL) {
		uu_warn(_("Error: must be run under smf(7) (SMF_FMRI not set"));
		exit(SMF_EXIT_ERR_NOSMF);
	}

	if (pipe(pipe_fds) < 0) {
		uu_die(_("Error: failed to create pipe"));
	}

	/*
	 * In case of transitory errors, if we hit a 'retryable' failure
	 * we'll keep retrying until we reach our timeout and svc.startd
	 * kills us.
	 */
	for (;;) {
		child = fork();
		if (child >= 0) {
			break;
		}

		if (errno == EAGAIN || errno == ENOMEM) {
			(void) sleep(1);
			continue;
		}

		uu_die(_("Error: failed to fork"));
	}

	if (child > 0) {
		/* parent */

		ssize_t	n;
		int	ret;

		(void) close(pipe_fds[0]);

		do {
			n = read(pipe_fds[1], &ret, sizeof (ret));
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR) {
					continue;
				}
				uu_die(_("Error: "
				    "failed to read status from child"));
			}
		} while (n != sizeof (ret));

		(void) close(pipe_fds[1]);
		exit(ret);
	}

	/* child */
	(void) close(pipe_fds[1]);

	init(pipe_fds[0]);
	init_done(pipe_fds[0], SMF_EXIT_OK, NULL);
}

static void
init_done(int fd, int ret, const char *fmt, ...) __PRINTFLIKE(2)
{
	va_list ap;
	ssize_t n;

	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);

		if (fmt[strlen(fmt) - 1] != '\n') {
			(void) fputc('\n', stderr);
		}
	}

	do {
		n = write(fd, ret, sizeof (ret));
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			uu_die(_("Error: failed to write status to parent: %s"),
			    strerror(errno));
		}
	} while (n != sizeof (ret));

	if (ret > 0) {
		exit(ret);
	}
}

static void *
sig_thread(void *arg)
{
	ssize_t	n;
	int	fd = (uintptr_t)arg;
	char	buf[SIG2STR_MAX];

	VERIFY0(pthread_setname_np(pthread_self(), "signal"));

	for (;;) {
		struct signalfd_info info = { 0 };

		n = read(fd, &info, sizeof (info));
		if (n < 0) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
				continue;
			default:
				uu_die(_("Error: "
				    "failed to read signal info: %s"),
				    strerror(errno));
			}
		}
		if (n != sizeof (info)) {
			uu_die(_("Error: short signalfd read (read %zd bytes)"),
			    n);
		}

		switch (info.ssi_signo) {
		case 0:
			break;
		case SIGHUP:
			do_refresh = true;
			break;
		case SIGTERM:
			do_exit = true;
			break;
		default:
			(void) sig2str(info.ssi_signo, buf);

			/* XXX: this probably needs a timestamp */
			uu_warn(_("Received unexpected signal SIG%s (%u)"),
			    buf, info.ssi_signo);
			continue;
		}

		if (do_exit) {
			break;
		}
	}

	return (NULL);
}

static void
start_sig_thread(int status_fd)
{
	sigset_t	mask;
	int		fd;
	int		ret;

	VERIFY0(sigemptyset(&mask));
	VERIFY0(sigaddset(&mask, SIGHUP));
	VERIFY0(sigaddset(&mask, SIGTERM));

	fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (fd < 0) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to create signal fd: %s"),
		    strerror(errno));
	}

	ret = pthread_create(&sig_thread, NULL, sig_thread,
	    (void *)(uintptr_t)fd);
	if (ret != 0) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to create signal thread: %s"),
		    strerror(ret));
	}
}

static char *
event_get_instance(restarter_event_t *evt)
{
	char	*fmri;
	size_t	len;

	fmri = umem_zalloc(max_fmri_len, UMEM_NOFAIL);
	len = restarter_event_get_instance(event, fmri, max_fmri_len);
	VERIFY3U(len, <, max_fmri_len);

	return (fmri);
}

void
panic(const char *msg, ...) __PRINTFLIKE(0)
{
	ssize_t n;
	va_args ap;

	va_start(ap, msg);
	n = vsnprintf(panicbuf, sizeof (panicbuf), msg, ap);
	va_end(ap);

	upanic(panicbuf, n);
}

static int
nomem_cb(void)
{
	panic("out of memory");
}

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
