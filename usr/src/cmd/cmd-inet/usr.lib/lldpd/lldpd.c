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

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <paths.h>
#include <port.h>
#include <priv_utils.h>
#include <signal.h>
#include <unistd.h>
#include <umem.h>

#include <liblldp.h>

#include "agent.h"
#include "lldpd.h"
#include "log.h"
#include "neighbor.h"
#include "timer.h"
#include "util.h"

static const char *doorpath = "/var/run/lldpd";

static bool debug;
static int evport = -1;
static int sigfd = -1;

static int lldp_daemonize(void);
static int lldp_umem_nomem_cb(void);
static int sigfd_create(void);
static void lldp_main(void);

static void __NORETURN
usage(void)
{
	(void) fprintf(stderr, "Usage: %s [-d]\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int c, pfd;

	/*
	 * For simplicity, memory allocation failures are always treated
	 * as fatal.
	 */
	umem_nofail_callback(lldp_umem_nomem_cb);

	if (getenv("LLDPD_DOORPATH") != NULL)
		doorpath = getenv("LLDPD_DOORPATH");

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			break;
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n", optopt);
			usage();
		}
	}

	if (optind > argc) {
		(void) fprintf(stderr, "Invalid parameter\n");
		usage();
	}

	closefrom(STDERR_FILENO + 1);

	if (!debug) {
		pfd = lldp_daemonize();
	} else {
		pfd = open(_PATH_DEVNULL, O_WRONLY);
	}

	log_sysinit();
	(void) log_init("lldpd", &log);

	VERIFY0(log_stream_add(log, "stderr", LOG_L_ERROR, log_stream_fd,
	    (void *)(uintptr_t)STDERR_FILENO));
	VERIFY0(log_stream_add(log, "stdout",
	    debug ? LOG_L_DEBUG : LOG_L_INFO, log_stream_fd,
	    (void *)(uintptr_t)STDOUT_FILENO));

	log_info(log, "startup...", LOG_T_END);

	evport = port_create();
	if (evport < 0) {
		int e = errno;
		log_syserr(log, "failed to create event port", e);

		(void) write(pfd, &e, sizeof (e));
		(void) close(pfd);
		return (EXIT_FAILURE);
	}
	log_trace(log, "created event port",
	    LOG_T_UINT32, "evport", evport,
	    LOG_T_END);

	sigfd = sigfd_create();
	if (sigfd < 0) {
		int e = errno;
		log_syserr(log, "failed to create signal fd", e);

		(void) write(pfd, &e, sizeof (e));
		(void) close(pfd);
		return (EXIT_FAILURE);
	}
	log_trace(log, "created signal fd",
	    LOG_T_UINT32, "sigfd", sigfd,
	    LOG_T_END);

	int rval = 0;
	(void) write(pfd, &rval, sizeof (rval));
	(void) close(pfd);

	lldp_main();

	return (0);
}

static void
lldp_main(void)
{
}

static int
lldp_daemonize(void)
{
	struct rlimit rlim;
	sigset_t set, oset;
	int estatus, pfds[2];
	pid_t child;

	/* Make sure we aren't limited in our dump size */
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		warn("unable to set core file size to unlimited");

	/* Claim as many file descriptors as the system will allow. */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
	}

	if (chdir("/") != 0)
		err(EXIT_FAILURE, "failed to chdir to /");

	/*
	 * Block all signals (except SIGABRT) while forking so the parent
	 * doesn't exit before the child signals it's ready.
	 */
	VERIFY0(sigfillset(&set));
	VERIFY0(sigdelset(&set, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &set, &oset));

	if (pipe(pfds) != 0)
		err(EXIT_FAILURE, "failed to create pipe for daemonizing");

	if ((child = fork()) == -1)
		err(EXIT_FAILURE, "failed to fork for daemonizing");

	if (child != 0) {
		/* We should be exiting shortly, allow silent failure */
		(void) close(pfds[1]);
		if (read(pfds[0], &estatus, sizeof (estatus)) ==
		    sizeof (estatus)) {
			_exit(estatus);
		}

		if (waitpid(child, &estatus, 0) == child && WIFEXITED(estatus))
			_exit(WEXITSTATUS(estatus));

		_exit(EXIT_FAILURE);
	}

	VERIFY0(close(pfds[0]));
	if (setsid() == -1)
		panic("setsid failed");

	VERIFY0(sigprocmask(SIG_SETMASK, &oset, NULL));
	(void) umask(0022);

	return (pfds[1]);
}

bool
schedule_fd(int fd, fd_cb_t *cb)
{
	if (port_associate(evport, PORT_SOURCE_FD, fd, POLLIN, cb) < 0) {
		log_syserr(log, "port associate failed", errno);
		return (false);
	}

	return (true);
}

void
cancel_fd(int fd)
{
	(void) port_dissociate(evport, PORT_SOURCE_FD, fd);
}

static int
sigfd_create(void)
{
	sigset_t set;

	VERIFY0(sigemptyset(&set));
	VERIFY0(sigaddset(&set, SIGTERM));
	VERIFY0(sigaddset(&set, SIGHUP));
	if (debug)
		VERIFY0(sigaddset(&set, SIGINT));

	return (signalfd(-1, &set, SFD_CLOEXEC));
}

static int
lldp_umem_nomem_cb(void)
{
	nomem();
	return (UMEM_CALLBACK_EXIT(EXIT_FAILURE));
}

#ifdef DEBUG
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
#else
const char *
_umem_debug_init(void)
{
	return ("guards");
}

const char *
_umem_logging_init(void)
{
	return ("fail");
}
#endif /* DEBUG */
