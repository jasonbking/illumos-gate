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

#include <sys/avl.h>
#include <sys/ccompile.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <librestart.h>
#include <libscf.h>
#include <libuutil.h>
#include <locale.h>
#include <paths.h>
#include <poll.h>
#include <port.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <synch.h>
#include <syslog.h>
#include <time.h>
#include <umem.h>
#include <unistd.h>
#include <upanic.h>

#include "periodic.h"

struct rst_req;

static int nomem_cb(void);
static void init_done(int fd, int ret, const char *fmt, ...) __PRINTFLIKE(3);
static void go_background(void);
static void init_events(int);
static void handle_signals(void);
static bool associate_fd(int);
static int event_handler(restarter_event_t *);
static char *event_get_instance(restarter_event_t *);
static void process_restarter_event(struct rst_req *);
static void svcs_init(void);
static int svc_cmp(const void *, const void *);

static bool do_refresh;
static bool do_exit;

/*
 * Restarter events arrive on a librestart thread. As inetd does, we hand
 * each one to the main loop (here via the event port) and wait for it to
 * be processed, so that all the service state is only touched by the main
 * thread.
 */
#define	PEV_RESTARTER	1

typedef struct rst_req {
	restarter_event_t	*rr_event;
	mutex_t			rr_lock;
	cond_t			rr_cv;
	bool			rr_done;
	int			rr_ret;
} rst_req_t;

/*
 * This size should be large enough for any panic messages, but is otherwise
 * an arbitrary size.
 */
char panicbuf[256];

char *my_fmri;

/* The event port the main loop waits on */
int evport = -1;

/* signalfd for SIGHUP and SIGTERM, associated with evport */
static int sigfd = -1;
restarter_event_handle_t *evt_hdl;

/* This includes the space for the terminating NUL byte */
size_t max_fmri_len;

/* All the periodic_svc_t's we manage, sorted by FMRI */
static avl_tree_t svcs;
static mutex_t svcs_lock = ERRORCHECKMUTEX;

int
main(int argc, const char * const argv[])
{
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	umem_nofail_callback(nomem_cb);

	(void) textdomain(TEXT_DOMAIN);
	(void) setlocale(LC_ALL, "");

	go_background();

	while (!do_exit) {
		port_event_t pe;

		if (port_get(evport, &pe, NULL) != 0) {
			if (errno == EINTR) {
				continue;
			}
			uu_die(_("Error: failed to get port event: %s"),
			    strerror(errno));
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_USER:
			if (pe.portev_events == PEV_RESTARTER) {
				process_restarter_event(pe.portev_user);
				break;
			}
			logmsg(_("unexpected user event %d"), pe.portev_events);
			break;
		case PORT_SOURCE_FD:
			if ((int)pe.portev_object == sigfd) {
				handle_signals();
				break;
			}
			logmsg(_("unexpected event on fd %d"),
			    (int)pe.portev_object);
			break;
		default:
			logmsg(_("unexpected event source %d"),
			    pe.portev_source);
			break;
		}

		if (do_refresh) {
			do_refresh = false;
			/* TODO: handle refresh */
		}
	}

	return (SMF_EXIT_OK);
}

/*
 * The librestart event callback. Pass the event to the main loop and wait
 * for it to be processed. If we are shutting down, the main loop stops
 * processing events and this blocks until we exit; as with inetd, the
 * unacknowledged event is redelivered when we next start.
 */
static int
event_handler(restarter_event_t *event)
{
	rst_req_t	req = { 0 };
	int		ret;

	req.rr_event = event;
	VERIFY0(mutex_init(&req.rr_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL));
	VERIFY0(cond_init(&req.rr_cv, USYNC_THREAD, NULL));

	if (port_send(evport, PEV_RESTARTER, &req) != 0) {
		logmsg(_("failed to queue restarter event: %s"),
		    strerror(errno));
		ret = EAGAIN;
		goto done;
	}

	VERIFY0(mutex_lock(&req.rr_lock));
	while (!req.rr_done) {
		(void) cond_wait(&req.rr_cv, &req.rr_lock);
	}
	ret = req.rr_ret;
	VERIFY0(mutex_unlock(&req.rr_lock));

done:
	VERIFY0(cond_destroy(&req.rr_cv));
	VERIFY0(mutex_destroy(&req.rr_lock));
	return (ret);
}

/*
 * Tell event_handler() we are done with its event.
 */
static void
ack_restarter_event(rst_req_t *req, int ret)
{
	VERIFY0(mutex_lock(&req->rr_lock));
	req->rr_ret = ret;
	req->rr_done = true;
	VERIFY0(cond_signal(&req->rr_cv));
	VERIFY0(mutex_unlock(&req->rr_lock));
}

/*
 * Start running svc on its schedule.
 * TODO: compute the next run with svc_next_run() and arm a timer.
 */
static void
svc_schedule(periodic_svc_t *svc __unused)
{
}

/*
 * Stop running svc on its schedule.
 * TODO: cancel any timer armed by svc_schedule().
 */
static void
svc_unschedule(periodic_svc_t *svc __unused)
{
}

static bool
svc_is_online(const periodic_svc_t *svc)
{
	return (svc->ps_state == RESTARTER_STATE_ONLINE ||
	    svc->ps_state == RESTARTER_STATE_DEGRADED);
}

/*
 * Move svc to new_state, recording it in the repository.
 */
static void
update_state(periodic_svc_t *svc, restarter_instance_state_t new_state,
    restarter_error_t err, restarter_str_t reason)
{
	int ret;

	ret = restarter_set_states(evt_hdl, svc->ps_fmri, svc->ps_state,
	    new_state, RESTARTER_STATE_NONE, RESTARTER_STATE_NONE, err,
	    reason);
	if (ret != 0) {
		logmsg(_("%s: failed to update state in repository: %s"),
		    svc->ps_fmri, strerror(ret));
	}

	/* As inetd does, our view of the state changes regardless */
	svc->ps_state = new_state;
}

/*
 * (Re)load the configuration of svc and take it offline, from where
 * svc.startd will send us a start event once its dependencies are met. If
 * the configuration is bad, put svc into maintenance instead.
 */
static void
svc_load_offline(periodic_svc_t *svc, restarter_str_t reason)
{
	if (!get_service(svc)) {
		update_state(svc, RESTARTER_STATE_MAINT, RERR_FAULT,
		    restarter_str_bad_repo_state);
		return;
	}
	update_state(svc, RESTARTER_STATE_OFFLINE, RERR_RESTART, reason);
}

/*
 * Reload the configuration of svc after an administrative refresh. Instances
 * that aren't (potentially) running reload their configuration when they
 * next leave the disabled or maintenance state, so there's nothing to do
 * for them.
 */
static void
svc_refresh(periodic_svc_t *svc)
{
	switch (svc->ps_state) {
	case RESTARTER_STATE_OFFLINE:
	case RESTARTER_STATE_ONLINE:
	case RESTARTER_STATE_DEGRADED:
		break;
	default:
		return;
	}

	if (!get_service(svc)) {
		svc_unschedule(svc);
		update_state(svc, RESTARTER_STATE_MAINT, RERR_FAULT,
		    restarter_str_bad_repo_state);
		return;
	}

	if (svc_is_online(svc)) {
		/* Pick up any change to the schedule */
		svc_unschedule(svc);
		svc_schedule(svc);
	}
}

/*
 * Create a periodic_svc_t for an instance we haven't seen before, starting
 * from the state svc.startd reports for it.
 */
static periodic_svc_t *
svc_create(const char *fmri, restarter_event_t *event)
{
	periodic_svc_t			*svc;
	restarter_instance_state_t	cur, next;
	size_t				len = strlen(fmri) + 1;

	svc = umem_zalloc(sizeof (*svc), UMEM_NOFAIL);
	svc->ps_fmri = umem_alloc(len, UMEM_NOFAIL);
	(void) strlcpy(svc->ps_fmri, fmri, len);
	VERIFY0(mutex_init(&svc->ps_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL));

	svc->ps_state = RESTARTER_STATE_UNINIT;
	if (restarter_event_get_current_states(event, &cur, &next) == 0 &&
	    cur != RESTARTER_STATE_NONE) {
		svc->ps_state = cur;
	}

	periodic_svc_add(svc);

	/*
	 * As inetd does, only read the configuration of instances that may
	 * be running. Disabled, uninitialized, and maintenance instances
	 * read it when they leave those states.
	 */
	switch (svc->ps_state) {
	case RESTARTER_STATE_OFFLINE:
	case RESTARTER_STATE_ONLINE:
	case RESTARTER_STATE_DEGRADED:
		if (!get_service(svc)) {
			update_state(svc, RESTARTER_STATE_MAINT, RERR_FAULT,
			    restarter_str_bad_repo_state);
		}
		break;
	default:
		break;
	}

	return (svc);
}

static void
svc_destroy(periodic_svc_t *svc)
{
	svc_unschedule(svc);
	periodic_svc_del(svc);
	free_service(svc);

	VERIFY0(mutex_destroy(&svc->ps_lock));
	umem_free(svc->ps_fmri, strlen(svc->ps_fmri) + 1);
	umem_free(svc, sizeof (*svc));
}

/*
 * Act on a restarter event for svc, modeled on inetd's
 * handle_restarter_event(). A periodic or scheduled service is online when
 * it is enabled and its dependencies are satisfied; while online, we run
 * its start method on its schedule.
 */
static void
handle_restarter_event(periodic_svc_t *svc, restarter_event_type_t type)
{
	/* Events handled the same way regardless of state */
	switch (type) {
	case RESTARTER_EVENT_TYPE_ADD_INSTANCE:
		/*
		 * svc.startd sends this for every instance we manage when
		 * either of us (re)starts. Restate our view of the instance
		 * so svc.startd's graph is up to date, and resume running it
		 * if it is online.
		 */
		update_state(svc, svc->ps_state, RERR_NONE, restarter_str_none);
		if (svc_is_online(svc)) {
			svc_schedule(svc);
		}
		return;

	case RESTARTER_EVENT_TYPE_REMOVE_INSTANCE:
		svc_destroy(svc);
		return;

	case RESTARTER_EVENT_TYPE_ADMIN_REFRESH:
		svc_refresh(svc);
		return;

	case RESTARTER_EVENT_TYPE_ADMIN_RESTART:
		/*
		 * Take it offline; svc.startd will send a start event to
		 * bring it back online.
		 */
		if (svc_is_online(svc)) {
			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_OFFLINE,
			    RERR_RESTART, restarter_str_restart_request);
		}
		return;

	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE:
	case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
	case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
		if (svc->ps_state != RESTARTER_STATE_MAINT) {
			restarter_str_t reason;

			if (type == RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE) {
				reason = restarter_str_dependency_cycle;
			} else if (type ==
			    RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY) {
				reason = restarter_str_invalid_dependency;
			} else {
				reason = restarter_str_administrative_request;
			}

			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_MAINT, RERR_RESTART,
			    reason);
		}
		return;

	default:
		break;
	}

	switch (svc->ps_state) {
	case RESTARTER_STATE_UNINIT:
		/* Ignore anything else until we know if we're enabled */
		if (type == RESTARTER_EVENT_TYPE_DISABLE ||
		    type == RESTARTER_EVENT_TYPE_ADMIN_DISABLE) {
			update_state(svc, RESTARTER_STATE_DISABLED, RERR_NONE,
			    restarter_str_disable_request);
			break;
		}
		/* FALLTHROUGH */

	case RESTARTER_STATE_DISABLED:
		if (type == RESTARTER_EVENT_TYPE_ENABLE) {
			svc_load_offline(svc, restarter_str_enable_request);
		}
		break;

	case RESTARTER_STATE_OFFLINE:
		switch (type) {
		case RESTARTER_EVENT_TYPE_START:
			update_state(svc, RESTARTER_STATE_ONLINE, RERR_NONE,
			    restarter_str_dependencies_satisfied);
			svc_schedule(svc);
			break;
		case RESTARTER_EVENT_TYPE_DISABLE:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			update_state(svc, RESTARTER_STATE_DISABLED,
			    RERR_RESTART, restarter_str_disable_request);
			break;
		default:
			break;
		}
		break;

	case RESTARTER_STATE_ONLINE:
	case RESTARTER_STATE_DEGRADED:
		switch (type) {
		case RESTARTER_EVENT_TYPE_DISABLE:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			/* TODO: deal with a method that is still running */
			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_DISABLED,
			    RERR_RESTART, restarter_str_disable_request);
			break;
		case RESTARTER_EVENT_TYPE_STOP:
		case RESTARTER_EVENT_TYPE_STOP_RESET:
			/* A dependency went away */
			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_OFFLINE,
			    RERR_RESTART, restarter_str_dependency_activity);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_DEGRADED:
		case RESTARTER_EVENT_TYPE_ADMIN_DEGRADE_IMMEDIATE:
			if (svc->ps_state == RESTARTER_STATE_ONLINE) {
				update_state(svc, RESTARTER_STATE_DEGRADED,
				    RERR_NONE,
				    restarter_str_administrative_request);
			}
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_RESTORE:
			if (svc->ps_state == RESTARTER_STATE_DEGRADED) {
				update_state(svc, RESTARTER_STATE_ONLINE,
				    RERR_NONE,
				    restarter_str_administrative_request);
			}
			break;
		default:
			break;
		}
		break;

	case RESTARTER_STATE_MAINT:
		switch (type) {
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF:
			svc_load_offline(svc, restarter_str_clear_request);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			update_state(svc, RESTARTER_STATE_DISABLED,
			    RERR_RESTART, restarter_str_disable_request);
			break;
		default:
			break;
		}
		break;

	default:
		logmsg(_("%s: instance in unexpected state %d"), svc->ps_fmri,
		    svc->ps_state);
		break;
	}
}

/*
 * Called from the main loop with an event from event_handler(). If the
 * event is for an instance we aren't managing yet, start managing it, then
 * act on the event.
 */
static void
process_restarter_event(rst_req_t *req)
{
	restarter_event_t	*event = req->rr_event;
	restarter_event_type_t	type;
	periodic_svc_t		*svc;
	char			*fmri;

	type = restarter_event_get_type(event);
	fmri = event_get_instance(event);

	svc = periodic_svc_get(fmri);
	if (svc == NULL) {
		if (type == RESTARTER_EVENT_TYPE_REMOVE_INSTANCE) {
			/* Nothing to remove */
			umem_free(fmri, max_fmri_len);
			ack_restarter_event(req, 0);
			return;
		}
		svc = svc_create(fmri, event);
	}
	umem_free(fmri, max_fmri_len);

	handle_restarter_event(svc, type);

	ack_restarter_event(req, 0);
}

static void
init(int fd)
{
	sigset_t	mask;
	sigset_t	omask;
	int		ret;
	int		nullfd;

	VERIFY0(sigfillset(&mask));
	VERIFY0(sigdelset(&mask, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &mask, &omask));

	VERIFY0(chdir("/"));

	nullfd = open(_PATH_DEVNULL, O_RDONLY);
	if (nullfd < 0) {
		init_done(fd, EXIT_FAILURE, _("failed to open %s: %s"),
		    _PATH_DEVNULL, strerror(errno));
	}
	VERIFY3S(dup2(nullfd, STDIN_FILENO), >=, 0);

	/* Make our pipefd fd 3, and close anything after that */
	fd = dup2(fd, STDERR_FILENO + 1);
	VERIFY3S(fd, >, STDERR_FILENO);

	closefrom(fd + 1);

	init_events(fd);

	/*
	 * scf_limit(3SCF) states that this should not change over the
	 * execution of a program (i.e. us), so it should be safe to cache
	 * for the duration of svc.periodicd.
	 */
	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;

	/* This must be ready before we start receiving restarter events */
	svcs_init();

	if (!init_scf()) {
		init_done(fd, EXIT_FAILURE, NULL);
	}

	ret = restarter_bind_handle(RESTARTER_EVENT_VERSION, my_fmri,
	    event_handler, 0, &evt_hdl);
	if (ret != 0) {
		init_done(fd, EXIT_FAILURE,
		    _("failed to register for restarter events: %s"),
		    strerror(ret));
	}

	/* TODO */

	if (setsid() < 0) {
		init_done(fd, EXIT_FAILURE, _("failed to create session"));
	}
}

static void
go_background(void)
{
	int	pipe_fds[2];
	pid_t	child;

	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL) {
		uu_warn(_("Error: must be run under smf(7) "
		    "(SMF_FMRI not set)"));
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
			if (n == 0) {
				uu_die(_("Error: child exited without "
				    "reporting status"));
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
init_done(int fd, int ret, const char *fmt, ...)
{
	va_list ap;
	ssize_t n;

	if (fmt != NULL) {
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);

		if (fmt[0] != '\0' && fmt[strlen(fmt) - 1] != '\n') {
			(void) fputc('\n', stderr);
		}
	}

	do {
		n = write(fd, &ret, sizeof (ret));
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

/*
 * Associate fd with the event port for read events. PORT_SOURCE_FD
 * associations are one-shot, so this must be redone after each event.
 */
static bool
associate_fd(int fd)
{
	if (port_associate(evport, PORT_SOURCE_FD, (uintptr_t)fd, POLLIN,
	    NULL) != 0) {
		return (false);
	}
	return (true);
}

/*
 * Create the event port the main loop waits on, and a signalfd for the
 * signals we handle. All signals are already blocked by init(), so they
 * are only delivered through the signalfd.
 */
static void
init_events(int status_fd)
{
	sigset_t mask;

	evport = port_create();
	if (evport < 0) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to create event port: %s"),
		    strerror(errno));
	}
	if (fcntl(evport, F_SETFD, FD_CLOEXEC) != 0) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to set close-on-exec on event port: %s"),
		    strerror(errno));
	}

	VERIFY0(sigemptyset(&mask));
	VERIFY0(sigaddset(&mask, SIGHUP));
	VERIFY0(sigaddset(&mask, SIGTERM));

	sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sigfd < 0) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to create signal fd: %s"),
		    strerror(errno));
	}

	if (!associate_fd(sigfd)) {
		init_done(status_fd, EXIT_FAILURE,
		    _("Error: failed to associate signal fd with event "
		    "port: %s"), strerror(errno));
	}
}

/*
 * Called from the main loop when the signalfd is readable. Drain all
 * pending signals, then re-arm the signalfd on the event port.
 */
static void
handle_signals(void)
{
	char buf[SIG2STR_MAX];

	for (;;) {
		struct signalfd_siginfo	info = { 0 };
		ssize_t			n;

		n = read(sigfd, &info, sizeof (info));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				break;
			}
			uu_die(_("Error: failed to read signal info: %s"),
			    strerror(errno));
		}
		if (n != sizeof (info)) {
			uu_die(_("Error: short signalfd read (read %zd bytes)"),
			    n);
		}

		switch (info.ssi_signo) {
		case SIGHUP:
			do_refresh = true;
			break;
		case SIGTERM:
			do_exit = true;
			break;
		default:
			(void) sig2str(info.ssi_signo, buf);
			logmsg(_("Received unexpected signal SIG%s (%u)"), buf,
			    info.ssi_signo);
			break;
		}
	}

	if (!associate_fd(sigfd)) {
		uu_die(_("Error: failed to re-associate signal fd with event "
		    "port: %s"), strerror(errno));
	}
}

static int
svc_cmp(const void *a, const void *b)
{
	const periodic_svc_t	*l = a;
	const periodic_svc_t	*r = b;
	int			ret;

	ret = strcmp(l->ps_fmri, r->ps_fmri);
	if (ret < 0) {
		return (-1);
	}
	if (ret > 0) {
		return (1);
	}
	return (0);
}

static void
svcs_init(void)
{
	avl_create(&svcs, svc_cmp, sizeof (periodic_svc_t),
	    offsetof(periodic_svc_t, ps_avl));
}

/*
 * Look up a service by FMRI. Returns NULL if we aren't managing it.
 */
periodic_svc_t *
periodic_svc_get(const char *fmri)
{
	periodic_svc_t	key = { 0 };
	periodic_svc_t	*svc;

	key.ps_fmri = (char *)fmri;

	VERIFY0(mutex_lock(&svcs_lock));
	svc = avl_find(&svcs, &key, NULL);
	VERIFY0(mutex_unlock(&svcs_lock));

	return (svc);
}

/*
 * Add a service. It is a programming error to add a service whose FMRI is
 * already in the tree; avl_add() will abort if that happens.
 */
void
periodic_svc_add(periodic_svc_t *svc)
{
	VERIFY3P(svc->ps_fmri, !=, NULL);

	VERIFY0(mutex_lock(&svcs_lock));
	avl_add(&svcs, svc);
	VERIFY0(mutex_unlock(&svcs_lock));
}

/*
 * Remove a service from the tree. This does not free it.
 */
void
periodic_svc_del(periodic_svc_t *svc)
{
	VERIFY0(mutex_lock(&svcs_lock));
	avl_remove(&svcs, svc);
	VERIFY0(mutex_unlock(&svcs_lock));
}

static char *
event_get_instance(restarter_event_t *evt)
{
	char	*fmri;
	size_t	len;

	fmri = umem_zalloc(max_fmri_len, UMEM_NOFAIL);
	len = restarter_event_get_instance(evt, fmri, max_fmri_len);
	VERIFY3U(len, <, max_fmri_len);

	return (fmri);
}

void
logmsg(const char *msg, ...)
{
	char		buf[64] = { 0 };
	struct tm	tm;
	time_t		now;
	va_list		ap;

	now = time(NULL);
	(void) localtime_r(&now, &tm);
	(void) strftime(buf, sizeof (buf), "%FT%T", &tm);

	flockfile(stdout);

	printf("%s ", buf);

	va_start(ap, msg);
	vprintf(msg, ap);
	va_end(ap);

	if (msg[0] != '\0' && msg[strlen(msg) - 1] != '\n') {
		(void) fputc('\n', stdout);
	}

	funlockfile(stdout);
}

void
panic(const char *msg, ...)
{
	ssize_t n;
	va_list ap;

	va_start(ap, msg);
	n = vsnprintf(panicbuf, sizeof (panicbuf), msg, ap);
	va_end(ap);

	/* Ensure message fits in panicbuf */
	if (n < 0) {
		(void) strlcpy(panicbuf, "panic (failed to format message)",
		    sizeof (panicbuf));
		n = strlen(panicbuf);
	} else if ((size_t)n >= sizeof (panicbuf)) {
		n = sizeof (panicbuf) - 1;
	}

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
