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
#include <atomic.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <paths.h>
#include <pthread.h>
#include <port.h>
#include <priv.h>
#include <priv_utils.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <umem.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>

#include <libdladm.h>
#include <libdllink.h>
#include <liblldp.h>
#include <libnvpair.h>
#include <librcm.h>
#include <libscf.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>

#include "agent.h"
#include "config.h"
#include "door.h"
#include "lldpd.h"
#include "log.h"
#include "neighbor.h"
#include "timer.h"
#include "util.h"

dladm_handle_t	dl_handle;

int start_pipe_fd = -1;


static bool debug;

/* Logging configuration (see lldp_set_log_level()) */
static log_t *root_log;
static bool use_syslog;
static bool log_level_cmdline;	/* -d or -t given */
static log_level_t cur_log_level;
static bool quit;
static int evport = -1;
static int sigfd = -1;

/* Set once lldp_drop_privs() has run; see lldp_priv_bracket() */
static bool privs_dropped;

/* syseventd(8) subscription, for links that appear after startup */
static sysevent_handle_t *sysevent_hdl;
static log_t *sysevent_log;

/*
 * Work for the main thread, posted by other threads (door server threads
 * and the sysevent handler) to the event port as PORT_SOURCE_USER events.
 * Agents are only created and destroyed, and their links only opened and
 * closed, by the main thread, which also dispatches the event port events
 * for the agents' DLPI handles; so there's no race between closing a
 * handle and receiving on it.
 *
 * If lt_wait is set, the poster waits (on lt_cv) for lt_done, and owns the
 * task; otherwise the main thread frees it once it has run. Once
 * tasks_closed is set (during shutdown), no more tasks are accepted, and
 * any that are pending are cancelled (with ECANCELED) without running.
 */
typedef struct lldp_task {
	void		(*lt_fn)(struct lldp_task *);
	datalink_id_t	lt_linkid;
	int		lt_err;
	bool		lt_wait;
	bool		lt_done;
	mutex_t		lt_lock;
	cond_t		lt_cv;
} lldp_task_t;

static mutex_t	tasks_lock = ERRORCHECKMUTEX;
static bool	tasks_closed;

static int lldp_daemonize(void);
static int lldp_umem_nomem_cb(void);
static void block_signals(sigset_t *);
static int sigfd_create(void);
static void lldp_init(void);
static void lldp_main(void);
static void lldp_fini(void);
static void lldp_drop_privs(void);
static void lldp_create_agents(void);
static bool lldp_agent_add(datalink_id_t);
static void lldp_handle_sig(int, void *);
static void lldp_task_done(lldp_task_t *);
static void lldp_tasks_drain(void);
static void lldp_sysevent_init(void);
static void lldp_sysevent_fini(void);

static fd_cb_t sig_cb = {
	.fc_fn = lldp_handle_sig,
};

static void __NORETURN
usage(void)
{
	(void) fprintf(stderr, "Usage: %s [-dst]\n"
	    "\t-d\tdebug: don't daemonize, log at debug level\n"
	    "\t-s\talso log (info and above) to syslog, in RFC 5424 "
	    "format\n"
	    "\t-t\tlog at trace level\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int c;
	log_level_t level = LOG_L_INFO;

	/*
	 * For simplicity, memory allocation failures are always treated
	 * as fatal.
	 */
	umem_nofail_callback(lldp_umem_nomem_cb);

	while ((c = getopt(argc, argv, "dst")) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			level = LOG_L_DEBUG;
			log_level_cmdline = true;
			break;
		case 's':
			use_syslog = true;
			break;
		case 't':
			level = LOG_L_TRACE;
			log_level_cmdline = true;
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

	if (!debug)
		start_pipe_fd = lldp_daemonize();

	log_sysinit();

	(void) log_init("lldpd", &log);
	root_log = log;
	cur_log_level = level;

	VERIFY0(log_stream_add(log, "stderr", LFMT_BUNYAN, LOG_L_ERROR,
	    log_stream_fd, (void *)(uintptr_t)STDERR_FILENO));
	VERIFY0(log_stream_add(log, "stdout", LFMT_BUNYAN, level,
	    log_stream_fd, (void *)(uintptr_t)STDOUT_FILENO));

	/*
	 * Any format can go to any destination; e.g. LFMT_BUNYAN to
	 * log_stream_syslog would send the JSON object to syslog instead.
	 */
	if (use_syslog) {
		VERIFY0(log_stream_add(log, "syslog", LFMT_SYSLOG, LOG_L_INFO,
		    log_stream_syslog, (void *)(uintptr_t)LOG_DAEMON));
	}

	lldp_init();
	lldp_main();
	lldp_fini();

	return (EXIT_SUCCESS);
}

/*
 * Set the level of messages logged (to stdout, which is the SMF log file
 * when run by SMF), from the daemon/log_level SMF property. Called at
 * startup and on refresh. A level given on the command line (-d, -t) takes
 * precedence. The syslog stream (-s) also follows the level, but never logs
 * below LOG_L_INFO; errors are always logged to stderr.
 */
void
lldp_set_log_level(log_level_t level)
{
	if (log_level_cmdline) {
		log_debug(root_log, "log level given on command line; "
		    "ignoring SMF log_level",
		    LOG_T_STRING, "log_level", log_level_str(level),
		    LOG_T_END);
		return;
	}

	if (level == cur_log_level)
		return;

	VERIFY0(log_stream_set_level(root_log, "stdout", level));
	if (use_syslog) {
		VERIFY0(log_stream_set_level(root_log, "syslog",
		    MAX(level, LOG_L_INFO)));
	}

	/* Logged at the higher of the two levels, so it's always seen */
	log_lvl(root_log, MAX(level, cur_log_level), "log level changed",
	    LOG_T_STRING, "old_level", log_level_str(cur_log_level),
	    LOG_T_STRING, "new_level", log_level_str(level),
	    LOG_T_END);

	cur_log_level = level;
}

static void
lldp_init(void)
{
	dladm_status_t dlret;

	TRACE_ENTER(log);

	log_info(log, "startup...", LOG_T_END);

	/* Before config_init(), which uses it to find a chassis id */
	dlret = dladm_open(&dl_handle);
	if (dlret != DLADM_STATUS_OK) {
		log_fatal_dladm_err(log, "failed to create dlmgt handle",
		    dlret);
	}

	config_init();
	lldp_timers_sysinit();
	neighbor_init();
	agent_init();

	evport = port_create();
	if (evport < 0)
		log_fatal_syserr(log, "failed to create event port", errno);

	log_trace(log, "created event port",
	    LOG_T_UINT32, "evport", evport,
	    LOG_T_END);

	sigfd = sigfd_create();
	if (sigfd < 0)
		log_fatal_syserr(log, "failed to create signal fd", errno);

	log_trace(log, "created signal fd",
	    LOG_T_UINT32, "sigfd", sigfd,
	    LOG_T_END);

	block_signals(NULL);

	lldp_create_door(NULL);

	/*
	 * Subscribe before looking for links, so a link that appears in
	 * between isn't missed (one we already have an agent for is
	 * ignored). Binding requires root, so this is done before
	 * dropping privileges.
	 */
	lldp_sysevent_init();

	lldp_create_agents();

	/* Everything that needs privileges has been done */
	lldp_drop_privs();

	TRACE_RETURN(log);
}

/*
 * Privileges
 *
 * Almost everything lldpd needs privileges for happens during
 * initialization: taking a topo snapshot, opening, binding, and configuring
 * notifications on each link's DLPI handle (net_rawaccess), subscribing to
 * sysevents, and creating the door. After that, it mostly uses descriptors
 * it already has open:
 *
 *	- sending and receiving on the DLPI handles
 *	- reading MAC properties (DLDIOC_GETMACPROP on the dladm handle,
 *	  which, unlike setting them, requires no privileges)
 *	- answering door calls
 *	- reading SMF properties (on refresh)
 *	- logging (to its stdout/stderr, and syslog)
 *
 * Once initialized, lldpd switches to LLDPD_UID/LLDPD_GID and reduces its
 * privileges to the parts of the basic set it needs: file_read and
 * file_write (to (re)open the syslog device and the SMF repository door).
 * The limit set is cleared, so nothing else can be regained.
 *
 * The one exception is net_rawaccess, which is needed to open a link's DLPI
 * handle after startup: when an agent is re-enabled, when a link that was
 * offlined (through RCM) is onlined again, or when a link appears (via
 * sysevent). It's kept in the permitted set, but not the effective set,
 * and only raised around opening a link (lldp_priv_bracket()).
 *
 * The syseventd(8) subscription for new links must be made as root, so
 * that's done before dropping privileges too (the subscription's door
 * remains usable afterwards).
 */
static void
lldp_drop_privs(void)
{
	TRACE_ENTER(log);

	if (geteuid() == 0) {
		/*
		 * P = E = basic + net_rawaccess, L cleared, uids/gids set
		 * to netadm
		 */
		if (__init_daemon_priv(PU_RESETGROUPS | PU_CLEARLIMITSET,
		    LLDPD_UID, LLDPD_GID, PRIV_NET_RAWACCESS, NULL) != 0) {
			log_fatal_syserr(log, "failed to set daemon privileges",
			    errno);
		}
	} else {
		log_warn(log, "not running as root; not changing uid",
		    LOG_T_UINT32, "euid", (uint32_t)geteuid(),
		    LOG_T_END);
	}

	/*
	 * Give up the basic privileges we don't use (and, if we weren't
	 * started as root, any extra ones we were given).
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_INFO,
	    PRIV_PROC_SESSION, PRIV_PROC_SECFLAGS, PRIV_FILE_LINK_ANY,
	    PRIV_NET_ACCESS, NULL);

	/* Only raised around opening a link; see lldp_priv_bracket() */
	if (priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_NET_RAWACCESS, NULL) != 0)
		log_syserr(log, "failed to lower net_rawaccess", errno);
	privs_dropped = true;

	log_info(log, "dropped privileges",
	    LOG_T_UINT32, "uid", (uint32_t)getuid(),
	    LOG_T_UINT32, "gid", (uint32_t)getgid(),
	    LOG_T_END);

	TRACE_RETURN(log);
}

/*
 * Raise (or lower) net_rawaccess, needed to open a link, in the effective
 * set. Until privileges are dropped (during startup), it's already
 * effective, so this does nothing.
 */
void
lldp_priv_bracket(bool on)
{
	if (!privs_dropped)
		return;

	if (priv_set(on ? PRIV_ON : PRIV_OFF, PRIV_EFFECTIVE,
	    PRIV_NET_RAWACCESS, NULL) != 0) {
		/* E.g. not started as root (so never had it) */
		log_debug(log, "failed to change net_rawaccess",
		    LOG_T_BOOLEAN, "raise", on,
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_END);
	}
}

static void
lldp_main(void)
{
	int ret, fd;

	TRACE_ENTER(log);

	ret = pthread_setname_np(pthread_self(), "main");
	if (ret != 0) {
		log_fatal_syserr(log,
		    "failed to set thread name on main thread", ret);
	}

	VERIFY(schedule_fd(sigfd, &sig_cb));

	fd = start_pipe_fd;
	start_pipe_fd = -1;
	membar_producer();

	/* We daemonized, so now signal parent we've started up */
	if (fd >= 0) {
		ret = 0;
		(void) write(fd, &ret, sizeof (ret));
		VERIFY0(close(fd));
	}

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
				/* log_fatal() is __NORETURN */
				log_fatal(SMF_EXIT_ERR_FATAL, log,
				    "event port fd error",
				    LOG_T_INT32, "fd", evport,
				    LOG_T_INT32, "err", e,
				    LOG_T_STRING, "errmsg", strerror(e),
				    LOG_T_END);
			default:
				log_syserr(log, "port_get failed", e);
				break;
			}

			/* There's no event to process */
			continue;
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_FD:
			cb = pe.portev_user;
			cb->fc_fn((int)pe.portev_object, cb->fc_arg);
			break;
		case PORT_SOURCE_USER: {
			lldp_task_t *t = pe.portev_user;

			t->lt_fn(t);
			lldp_task_done(t);
			break;
		}
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

/*
 * Orderly shutdown (after an exit signal): stop answering door calls, then
 * stop the agents. Each agent's thread sends a shutdown LLDPDU on its link
 * (if it was advertising) before exiting. All agents are asked to stop
 * before waiting on any, so they shut down in parallel.
 */
static void
lldp_fini(void)
{
	agent_t *a;

	TRACE_ENTER(log);

	/*
	 * Stop taking requests from other threads: no more new links, no
	 * more door calls, and cancel anything that was waiting on the main
	 * thread (which is done processing events).
	 */
	lldp_sysevent_fini();
	lldp_destroy_door();
	lldp_tasks_drain();

	/*
	 * Agent threads never take agent_list_lock, so it's safe to hold it
	 * while waiting for them to exit.
	 */
	mutex_enter(&agent_list_lock);
	for (a = uu_list_first(agent_list); a != NULL;
	    a = uu_list_next(agent_list, a)) {
		agent_stop(a, true);
	}
	for (a = uu_list_first(agent_list); a != NULL;
	    a = uu_list_next(agent_list, a)) {
		agent_wait(a);
	}
	mutex_exit(&agent_list_lock);

	log_info(log, "shutdown complete", LOG_T_END);

	TRACE_RETURN(log);
}

/*
 * Create (and start) an agent for the physical link did. Only called from
 * the main thread.
 */
static bool
lldp_agent_add(datalink_id_t did)
{
	datalink_class_t	class;
	dladm_status_t		ret;
	char			link[MAXLINKNAMELEN] = { 0 };
	dladm_phys_attr_t	dpa = { 0 };
	agent_t			*a;
	uu_list_index_t		idx;

	ret = dladm_datalink_id2info(dl_handle, did, NULL, &class, NULL,
	    link, sizeof (link));
	if (ret != DLADM_STATUS_OK) {
		char buf[DLADM_STRSIZE] = { 0 };

		log_warn(log, "failed to get datalink class",
		    LOG_T_UINT32, "id", did,
		    LOG_T_UINT32, "err", ret,
		    LOG_T_STRING, "errstr", dladm_status2str(ret, buf),
		    LOG_T_END);

		return (false);
	}

	if (class != DATALINK_CLASS_PHYS) {
		log_debug(log, "not a physical link; ignoring",
		    LOG_T_UINT32, "id", did,
		    LOG_T_STRING, "link", link,
		    LOG_T_END);
		return (false);
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
	 * while dpa.dp_dev is the hardware name (e.g. 'ixgbe0'). Agents are
	 * named (and their SMF property groups looked up) by hardware name.
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

		return (false);
	}

	a = agent_create(dpa.dp_dev, link, did);
	if (a == NULL) {
		log_warn(log, "failed to create agent; skipping link",
		    LOG_T_STRING, "agent", dpa.dp_dev,
		    LOG_T_STRING, "link", link,
		    LOG_T_END);
		return (false);
	}

	/* The agent list is sorted by name */
	mutex_enter(&agent_list_lock);
	VERIFY3P(uu_list_find(agent_list, a, NULL, &idx), ==, NULL);
	uu_list_insert(agent_list, a, idx);
	mutex_exit(&agent_list_lock);

	log_debug(log, "created agent",
	    LOG_T_STRING, "agent", dpa.dp_dev,
	    LOG_T_POINTER, "addr", a,
	    LOG_T_END);

	/* Agent threads are created suspended */
	agent_start(a);

	return (true);
}

static int
dladm_cb(dladm_handle_t dlh __unused, datalink_id_t did, void *arg __unused)
{
	/* Failures are logged; keep going */
	(void) lldp_agent_add(did);
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

/*
 * Post a task to the main thread. Fails (with ESHUTDOWN) once lldpd is
 * shutting down.
 */
static int
lldp_task_post(lldp_task_t *t)
{
	int ret = 0;

	mutex_enter(&tasks_lock);
	if (tasks_closed)
		ret = ESHUTDOWN;
	else if (port_send(evport, 0, t) != 0)
		ret = errno;
	mutex_exit(&tasks_lock);

	return (ret);
}

/*
 * Run fn (for linkid) on the main thread, and wait for it to finish.
 * Returns fn's result (lt_err), or why it couldn't be run.
 */
static int
lldp_task_run(void (*fn)(lldp_task_t *), datalink_id_t linkid)
{
	lldp_task_t	t = {
		.lt_fn = fn,
		.lt_linkid = linkid,
		.lt_wait = true,
	};
	int		ret;

	VERIFY0(mutex_init(&t.lt_lock, USYNC_THREAD | LOCK_ERRORCHECK, NULL));
	VERIFY0(cond_init(&t.lt_cv, USYNC_THREAD, NULL));

	if ((ret = lldp_task_post(&t)) == 0) {
		mutex_enter(&t.lt_lock);
		while (!t.lt_done)
			(void) cond_wait(&t.lt_cv, &t.lt_lock);
		ret = t.lt_err;
		mutex_exit(&t.lt_lock);
	}

	VERIFY0(cond_destroy(&t.lt_cv));
	VERIFY0(mutex_destroy(&t.lt_lock));
	return (ret);
}

/*
 * Run fn (for linkid) on the main thread, without waiting for it.
 */
static int
lldp_task_async(void (*fn)(lldp_task_t *), datalink_id_t linkid)
{
	lldp_task_t	*t = umem_zalloc(sizeof (*t), UMEM_NOFAIL);
	int		ret;

	t->lt_fn = fn;
	t->lt_linkid = linkid;

	if ((ret = lldp_task_post(t)) != 0)
		umem_free(t, sizeof (*t));
	return (ret);
}

/* Called from the main thread once a task has run (or been cancelled) */
static void
lldp_task_done(lldp_task_t *t)
{
	if (!t->lt_wait) {
		umem_free(t, sizeof (*t));
		return;
	}

	mutex_enter(&t->lt_lock);
	t->lt_done = true;
	VERIFY0(cond_signal(&t->lt_cv));
	mutex_exit(&t->lt_lock);
}

/*
 * Stop accepting tasks, and cancel any still pending. Called from the main
 * thread during shutdown, after it's stopped processing events.
 */
static void
lldp_tasks_drain(void)
{
	timespec_t	zero = { 0 };
	port_event_t	pe;

	mutex_enter(&tasks_lock);
	tasks_closed = true;
	mutex_exit(&tasks_lock);

	while (port_get(evport, &pe, &zero) == 0) {
		if (pe.portev_source != PORT_SOURCE_USER)
			continue;

		lldp_task_t *t = pe.portev_user;

		t->lt_err = ECANCELED;
		lldp_task_done(t);
	}
}

/* Task: a physical link appeared (or reappeared); create its agent */
static void
task_link_add(lldp_task_t *t)
{
	agent_t *a;

	/* Only the main thread creates or destroys agents */
	mutex_enter(&agent_list_lock);
	a = agent_find_linkid(t->lt_linkid);
	mutex_exit(&agent_list_lock);

	if (a != NULL) {
		log_debug(log, "already have an agent for new link; ignoring",
		    LOG_T_UINT32, "id", t->lt_linkid,
		    LOG_T_STRING, "agent", a->a_name,
		    LOG_T_END);
		return;
	}

	log_info(log, "new link",
	    LOG_T_UINT32, "id", t->lt_linkid,
	    LOG_T_END);

	if (!lldp_agent_add(t->lt_linkid))
		t->lt_err = EIO;
}

static agent_t *
task_agent(lldp_task_t *t)
{
	agent_t *a;

	mutex_enter(&agent_list_lock);
	a = agent_find_linkid(t->lt_linkid);
	mutex_exit(&agent_list_lock);

	if (a == NULL)
		t->lt_err = ENOENT;
	return (a);
}

/* Task: release a link that's being offlined */
static void
task_link_offline(lldp_task_t *t)
{
	agent_t *a;

	if ((a = task_agent(t)) != NULL)
		agent_offline(a);
}

/* Task: an offline was undone, or the link is back */
static void
task_link_online(lldp_task_t *t)
{
	agent_t *a;

	if ((a = task_agent(t)) != NULL && !agent_online(a))
		t->lt_err = EIO;
}

/* Task: the link has been removed */
static void
task_link_remove(lldp_task_t *t)
{
	agent_t *a;

	if ((a = task_agent(t)) == NULL)
		return;

	log_info(a->a_log, "link removed; destroying agent", LOG_T_END);

	/* Once it's off the list, no door call can find it */
	mutex_enter(&agent_list_lock);
	uu_list_remove(agent_list, a);
	mutex_exit(&agent_list_lock);

	/* The link has (normally) already been offlined and closed */
	agent_destroy(a);
}

/*
 * Handle a request (from lldp_rcm, via the door) about a link that's being
 * reconfigured. Runs on the main thread; the caller waits for the result:
 * 0, ENOENT if there's no agent for the link, or another errno value.
 */
int
lldp_link_request(lldp_link_op_t op, datalink_id_t linkid)
{
	switch (op) {
	case LLDP_LINK_OP_OFFLINE:
		return (lldp_task_run(task_link_offline, linkid));
	case LLDP_LINK_OP_ONLINE:
		return (lldp_task_run(task_link_online, linkid));
	case LLDP_LINK_OP_REMOVE:
		return (lldp_task_run(task_link_remove, linkid));
	}
	return (EINVAL);
}

/*
 * dlmgmtd posts ESC_DATALINK_PHYS_ADD when a physical link is created or
 * (after DR) reattached. Runs on a libsysevent thread; the agent is created
 * on the main thread.
 */
static void
lldp_sysevent_handler(sysevent_t *ev)
{
	nvlist_t	*nvl = NULL;
	uint64_t	id64;
	boolean_t	reconfigured = B_FALSE;
	int		ret;

	if (log == NULL)
		log = sysevent_log;

	if (strcmp(sysevent_get_class_name(ev), EC_DATALINK) != 0 ||
	    strcmp(sysevent_get_subclass_name(ev), ESC_DATALINK_PHYS_ADD) != 0)
		return;

	if (sysevent_get_attr_list(ev, &nvl) != 0) {
		log_syserr(log, "failed to get sysevent attributes", errno);
		return;
	}

	if (nvlist_lookup_uint64(nvl, RCM_NV_LINKID, &id64) != 0 ||
	    id64 > UINT32_MAX) {
		log_warn(log, "sysevent has no valid link id; ignoring",
		    LOG_T_STRING, "subclass", ESC_DATALINK_PHYS_ADD,
		    LOG_T_END);
		nvlist_free(nvl);
		return;
	}
	(void) nvlist_lookup_boolean_value(nvl, RCM_NV_RECONFIGURED,
	    &reconfigured);
	nvlist_free(nvl);

	log_debug(log, "physical link added",
	    LOG_T_UINT32, "id", (uint32_t)id64,
	    LOG_T_BOOLEAN, "reconfigured", (bool)reconfigured,
	    LOG_T_END);

	if ((ret = lldp_task_async(task_link_add, (datalink_id_t)id64)) != 0 &&
	    ret != ESHUTDOWN) {
		log_syserr(log, "failed to queue new link", ret);
	}
}

/*
 * Subscribe to new physical links. If this fails, lldpd still runs agents
 * on the links present at startup.
 */
static void
lldp_sysevent_init(void)
{
	const char *subclasses[] = { ESC_DATALINK_PHYS_ADD };

	(void) log_child(log, &sysevent_log,
	    LOG_T_STRING, "component", "sysevent",
	    LOG_T_END);

	sysevent_hdl = sysevent_bind_handle(lldp_sysevent_handler);
	if (sysevent_hdl == NULL) {
		log_warn(log, "failed to bind sysevent handle; links that "
		    "appear later won't be noticed",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_END);
		return;
	}

	if (sysevent_subscribe_event(sysevent_hdl, EC_DATALINK, subclasses,
	    ARRAY_SIZE(subclasses)) != 0) {
		log_warn(log, "failed to subscribe to datalink sysevents; "
		    "links that appear later won't be noticed",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_END);
		sysevent_unbind_handle(sysevent_hdl);
		sysevent_hdl = NULL;
		return;
	}

	log_debug(log, "subscribed to datalink sysevents", LOG_T_END);
}

static void
lldp_sysevent_fini(void)
{
	if (sysevent_hdl == NULL)
		return;

	sysevent_unsubscribe_event(sysevent_hdl, EC_DATALINK);
	sysevent_unbind_handle(sysevent_hdl);
	sysevent_hdl = NULL;
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
		char buf[SIG2STR_MAX + 3] = { 0 };

		(void) strlcat(buf, "SIG", sizeof (buf));
		(void) sig2str(si.ssi_signo, buf + 3);

		log_debug(log, "received signal",
		    LOG_T_UINT32, "signo", si.ssi_signo,
		    LOG_T_STRING, "signal", buf,
		    LOG_T_UINT32, "srcpid", si.ssi_pid,
		    LOG_T_UINT32, "srcuid", si.ssi_uid,
		    LOG_T_END);

		switch (si.ssi_signo) {
		case SIGHUP:
			config_refresh();
			break;
		case SIGINT:
		case SIGTERM:
			log_info(log, "Received exit signal",
			    LOG_T_STRING, "signal", strsignal(si.ssi_signo),
			    LOG_T_UINT32, "signo", si.ssi_signo,
			    LOG_T_END);
			quit = true;
			break;
		default:
			log_info(log, "ignoring signal",
			    LOG_T_STRING, "signal", buf,
			    LOG_T_UINT32, "signo", si.ssi_signo,
			    LOG_T_UINT32, "srcpid", si.ssi_pid,
			    LOG_T_UINT32, "srcuid", si.ssi_uid,
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
