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
#include <pthread.h>
#include <port.h>
#include <priv_utils.h>
#include <signal.h>
#include <unistd.h>
#include <umem.h>

#include <libdladm.h>
#include <libdllink.h>
#include <liblldp.h>
#include <libscf.h>

#include "agent.h"
#include "lldpd.h"
#include "log.h"
#include "neighbor.h"
#include "timer.h"
#include "util.h"

lldp_config_t	lldp_config;
mutex_t		lldp_config_lock = ERRORCHECKMUTEX;

scf_handle_t	*rep_handle;
dladm_handle_t	dl_handle;
char		*my_fmri;

static const char *doorpath = "/var/run/lldpd";

static bool debug;
static bool quit;
static int evport = -1;
static int sigfd = -1;

static int lldp_daemonize(void);
static int lldp_umem_nomem_cb(void);
static void block_signals(sigset_t *);
static int sigfd_create(void);
static void lldp_init(int);
static void lldp_main(int);
static void lldp_create_agents(void);
static void lldp_enable_agents(void);
static void lldp_handle_sig(int, void *);

static fd_cb_t sig_cb = {
	.fc_fn = lldp_handle_sig,
};

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
	log_level_t level = LOG_L_INFO;

	/*
	 * For simplicity, memory allocation failures are always treated
	 * as fatal.
	 */
	umem_nofail_callback(lldp_umem_nomem_cb);

	if (getenv("LLDPD_DOORPATH") != NULL)
		doorpath = getenv("LLDPD_DOORPATH");

	while ((c = getopt(argc, argv, "dt")) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			level = LOG_L_DEBUG;
			break;
		case 't':
			level = LOG_L_TRACE;
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

	VERIFY0(log_stream_add(log, "stderr", LFMT_BUNYAN, LOG_L_ERROR,
	    log_stream_fd, (void *)(uintptr_t)STDERR_FILENO));
	VERIFY0(log_stream_add(log, "stdout", LFMT_BUNYAN, level,
	    log_stream_fd, (void *)(uintptr_t)STDOUT_FILENO));

	lldp_init(pfd);
	lldp_main(pfd);

	return (EXIT_SUCCESS);
}

static void
lldp_init(int pfd)
{
	dladm_status_t dlret;

	TRACE_ENTER(log);

	log_info(log, "startup...", LOG_T_END);

	/*
	 * For debugging/troubleshooting purposes, we want to be able
	 * to manually run lldpd outside of SMF.
	 */
	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL) {
		my_fmri = LLDP_FMRI;
		log_info(log,
		    "SMF_FMRI not set (not run from SMF?); using default",
		    LOG_T_STRING, "fmri", my_fmri,
		    LOG_T_END);
	}

	lldp_timers_sysinit();
	neighbor_init();
	agent_init(pfd);

	evport = port_create();
	if (evport < 0) {
		int e = errno;
		log_syserr(log, "failed to create event port", e);

		(void) write(pfd, &e, sizeof (e));
		(void) close(pfd);
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}
	log_trace(log, "created signal fd",
	    LOG_T_UINT32, "sigfd", sigfd,
	    LOG_T_END);

	rep_handle = scf_handle_create(SCF_VERSION);
	if (rep_handle == NULL) {
		uint32_t serr = scf_error();

		log_error(log, "failed to create repository handle",
		    LOG_T_UINT32, "err", serr,
		    LOG_T_STRING, "errstr", scf_strerror(serr),
		    LOG_T_END);

		(void) write(pfd, &serr, sizeof (serr));
		(void) close(pfd);
		exit(EXIT_FAILURE);
	}
	log_trace(log, "created repository handle",
	    LOG_T_POINTER, "rep_handle", (void *)rep_handle,
	    LOG_T_END);

	dlret = dladm_open(&dl_handle);
	if (dlret != DLADM_STATUS_OK) {
		char buf[DLADM_STRSIZE] = { 0 };

		log_error(log, "failed to create dlmgt handle",
		    LOG_T_UINT32, "err", dlret,
		    LOG_T_STRING, "errstr", dladm_status2str(dlret, buf),
		    LOG_T_END);

		(void) write(pfd, &dlret, sizeof (dlret));
		(void) close(pfd);
		exit(EXIT_FAILURE);
	}

	lldp_create_agents();

	/* XXX restarter */

	lldp_enable_agents();

	TRACE_RETURN(log);
}

static void
lldp_main(int pfd)
{
	int ret;

	TRACE_ENTER(log);

	ret = pthread_setname_np(pthread_self(), "main");
	if (ret < 0) {
		log_syserr(log, "failed to set thread name on main thread",
		    ret);
		exit(EXIT_FAILURE);
	}

	VERIFY(schedule_fd(sigfd, &sig_cb));

	block_signals(NULL);

	ret = 0;
	(void) write(pfd, &ret, sizeof (ret));
	VERIFY0(close(pfd));

	log_debug(log, "starting main loop", LOG_T_END);

	while (!quit) {
		port_event_t pe = { 0 };
		fd_cb_t *cb;

		ret = port_get(evport, &pe, NULL);
		if (ret < 0) {
			int e = errno;
			switch (e) {
			case EINTR:
				continue;
			case EBADF:
			case EBADFD:
				log_fatal(log, "event port fd error",
				    LOG_T_INT32, "fd", evport,
				    LOG_T_INT32, "errno", e,
				    LOG_T_STRING, "errmsg", strerror(e),
				    LOG_T_END);
			default:
				log_syserr(log, "port_get failed", e);
				break;
			}
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_FD:
			cb = pe.portev_user;
			cb->fc_fn((int)pe.portev_object, cb->fc_arg);
			break;
		default:
			log_error(log, "unexpected port event",
			    LOG_T_UINT32, "source", pe.portev_source,
			    LOG_T_XINT32, "events", pe.portev_events,
			    LOG_T_POINTER, "obj", pe.portev_object,
			    LOG_T_POINTER, "user", pe.portev_user,
			    LOG_T_END);
			break;
		}
	}

	log_info(log, "shutting down", LOG_T_END);

	TRACE_RETURN(log);
}

static int
dladm_cb(dladm_handle_t dlh, datalink_id_t did, void *arg)
{
	datalink_class_t	class;
	dladm_status_t		ret;
	char			link[MAXLINKNAMELEN] = { 0 };
	dladm_phys_attr_t	dpa = { 0 };
	agent_t			*a;

	ret = dladm_datalink_id2info(dl_handle, did, NULL, &class, NULL,
	    link, sizeof (link));
	if (ret != DLADM_STATUS_OK) {
		char buf[DLADM_STRSIZE] = { 0 };

		log_warn(log, "failed to get datalink class",
		    LOG_T_UINT32, "id", did,
		    LOG_T_UINT32, "err", ret,
		    LOG_T_STRING, "errstr", dladm_status2str(ret, buf),
		    LOG_T_END);

		/* Keep going */
		return (DLADM_WALK_CONTINUE);
	}

	char buf[32] = { 0 };

	log_debug(log, "found link",
	    LOG_T_UINT32, "id", did,
	    LOG_T_STRING, "link", link,
	    LOG_T_STRING, "class", dladm_class2str(class, buf),
	    LOG_T_UINT32, "classval", class,
	    LOG_T_END);

	/*
	 * If a datalink was renamed, 'link' is the name seen in the os
	 * while dpa.dp_dev is the hardware name (e.g. 'ixgbe0').
	 */
	ret = dladm_phys_info(dl_handle, did, &dpa, DLADM_OPT_ACTIVE);
	if (ret != DLADM_STATUS_OK) {
		char buf[DLADM_STRSIZE] = { 0 };

		log_warn(log, "failed to get phys info on datalink",
		    LOG_T_UINT32, "id", did,
		    LOG_T_STRING, "link", link,
		    LOG_T_UINT32, "err", ret,
		    LOG_T_STRING, "errstr", dladm_status2str(ret, buf),
		    LOG_T_END);

		/* Keep going */
		return (DLADM_WALK_CONTINUE);
	}

	a = agent_create(dpa.dp_dev);

	mutex_enter(&agent_list_lock);
	VERIFY0(uu_list_insert_after(agent_list, NULL, a));
	mutex_exit(&agent_list_lock);

	log_debug(log, "created agent",
	    LOG_T_STRING, "agent", dpa.dp_dev,
	    LOG_T_POINTER, "addr", a,
	    LOG_T_END);

	return (DLADM_WALK_CONTINUE);
}

static void
lldp_create_agents(void)
{
	TRACE_ENTER(log);

	/*
	 * Until the mac/aggr/dlpi issue is sorted out, we don't
	 * include aggrs in our walk.
	 */
	(void) dladm_walk_datalink_id(dladm_cb, dl_handle, NULL,
	    DATALINK_CLASS_PHYS, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

	TRACE_RETURN(log);	
}

static void
lldp_enable_agents(void)
{
	uu_list_walk_t	*wk;
	agent_t		*agent;

	TRACE_ENTER(log);

	wk = uu_list_walk_start(agent_list, 0);
	if (wk == NULL)
		nomem();

	while ((agent = uu_list_walk_next(wk)) != NULL) {
		(void) agent_enable(agent);
		agent_set_status(agent, LLDP_LINK_TXRX);
	}

	uu_list_walk_end(wk);

	TRACE_RETURN(log);
}

static void
lldp_handle_sig(int fd, void *arg __unused)
{
	signalfd_siginfo_t si = { 0 };
	ssize_t n;

	VERIFY3S(fd, ==, sigfd);
	n = read(fd, &si, sizeof (si));
	if (n < 0) {
		int e = errno;

		log_syserr(log, "failed to read signal info", e);
	} else if (n != sizeof (si)) {
		log_error(log, "short read of signal fd",
		    LOG_T_INT32, "fd", fd,
		    LOG_T_INT32, "n", n,
		    LOG_T_END);
	} else {
		log_debug(log, "received signal",
		    LOG_T_UINT32, "signo", si.ssi_signo,
		    LOG_T_UINT32, "pid", si.ssi_pid,
		    LOG_T_UINT32, "uid", si.ssi_uid,
		    LOG_T_END);

		switch (si.ssi_signo) {
		case SIGHUP:
			break;
		case SIGKILL:
			/* TODO: handle signal */
			quit = true;
			break;
		default:
			log_info(log, "ignoring signal",
			    LOG_T_UINT32, "pid", si.ssi_pid,
			    LOG_T_UINT32, "uid", si.ssi_uid,
			    LOG_T_END);
			break;
		}
	}

	VERIFY(schedule_fd(fd, &sig_cb));
}

static int
lldp_daemonize(void)
{
	struct rlimit rlim;
	sigset_t oset;
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

	if (!debug) {
		if (chdir("/") != 0)
			err(EXIT_FAILURE, "failed to chdir to /");
	}

	/*
	 * Block all signals (except SIGABRT) while forking so the parent
	 * doesn't exit before the child signals it's ready.
	 */
	block_signals(&oset);

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
	(void) umask(022);

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

static void
block_signals(sigset_t *oset)
{
	sigset_t set;

	VERIFY0(sigfillset(&set));
	VERIFY0(sigdelset(&set, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &set, oset));
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
