/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Portions of this file are derived from svc.startd(8)
 * (usr/src/cmd/svc/startd/{method,env,log,wait,contract,libscf}.c) and
 * inetd(8)
 * (usr/src/cmd/cmd-inet/usr.lib/inetd/{inetd,contracts}.c). Their copyright
 * notices are carried over from the time the original files were used.
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2011 Nexenta Systems. All rights reserved.
 * Copyright (c) 2011 Gary Mills
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2017 RackTop Systems.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2026 Oxide Computer Company
 * Copyright 2026 Jason King
 */

/*
 * Copyright 2026 Jason King
 */

/*
 * Running the start method of a periodic or scheduled service.
 *
 * Each time a service is due, exec_start() runs its start method, as
 * svc.startd runs the start method of a transient service: in a new process
 * contract, through /sbin/sh -c "exec <method>", with the method context
 * from the repository, the instance's log as its standard output and error,
 * and the SMF_* environment. As periodic.xml describes, a run is in progress
 * until its contract is empty, not just until the start method's process
 * exits, and if it doesn't finish within the method's timeout_seconds, every
 * process in the contract is killed.
 *
 * Contracts
 * ---------
 *
 * The contract's only critical event is CT_PR_EV_EMPTY, which ends the run.
 * Because it is critical, the kernel queues it on the contract whether or
 * not anyone is listening, so it can't be missed however quickly the run
 * finishes, and it is still there for a later svc.periodicd that adopts the
 * contract. Hardware errors are fatal, scoped to the process group, as inetd
 * does. Every run's contract carries EXEC_COOKIE, svc_fmri set to the
 * instance, and svc_aux set to the method name, which is what svcs -p and
 * ptree -c use.
 *
 * While a run is in progress, its contract and start method pid are
 * recorded in the instance's restarter property group (restarter/contract,
 * restarter/start_pid and restarter/start_method_timestamp), and the
 * contract property is removed when the run finishes.
 *
 * If svc.periodicd exits while runs are in progress, their contracts are
 * inherited by svc.periodicd's own contract (svc.startd starts it in a
 * regent contract), and when svc.startd restarts us, transferred to our
 * new contract. exec_init() adopts each one that carries EXEC_COOKIE and
 * keeps watching it until it is empty, much as svc.startd's contract_init()
 * adopts the contracts it inherited. The start method's process is not our
 * child, so its exit status is unknown.
 *
 * Event handling
 * --------------
 *
 * Everything here runs on the main thread, from the main loop, so the list
 * of runs needs no lock. Each run's contract events endpoint is associated
 * with the main loop's event port (PORT_SOURCE_FD), as is its timeout
 * (PORT_SOURCE_TIMER, from a timer_create(3C) timer with SIGEV_PORT). The
 * main loop passes every event to exec_port_event(), which claims the ones
 * that belong to a run. Each event carries its run's ID (see event_id()), not
 * a pointer, so an event left over from a run that has finished is simply
 * not found.
 *
 * Outcomes
 * --------
 *
 * When a run finishes, the start method's exit status decides what happens
 * to the instance:
 *
 *   SMF_EXIT_OK, SMF_EXIT_NODAEMON	success
 *   SMF_EXIT_MON_DEGRADE		degraded
 *   SMF_EXIT_TEMP_DISABLE		svcadm disable -t
 *   SMF_EXIT_MON_OFFLINE		svcadm disable
 *   SMF_EXIT_ERR_CONFIG, _ERR_NOSMF,	fatal fault
 *     _ERR_PERM, _ERR_FATAL
 *   anything else (SMF_EXIT_ERR_OTHER)	non-fatal fault
 *
 * Death by a signal, and running for longer than the method's timeout, are
 * also non-fatal faults.
 *
 * As svc.startd does (update_fault_count()), we count the non-fatal faults
 * of each instance (ps_fault_count). The first moves an online instance to
 * degraded; on the FAULT_THRESHOLD'th in a row, it goes to maintenance. A
 * successful run before then resets the count and, if a run degraded the
 * instance (ps_fault_degraded), brings it back online. A fatal fault puts
 * the instance into maintenance at once. The count is reset when the
 * instance comes online. Unlike svc.startd's, which only has to last
 * through the retries of one start, the count spans runs that may be days
 * apart, so it and ps_fault_degraded are saved in the periodic_restarter
 * property group (save_faults()) and survive restarts of svc.periodicd.
 *
 * SMF_EXIT_MON_DEGRADE resets the count, as it does in svc.startd, and
 * degrades the instance as a fault does, so a later successful run brings it
 * back online. An instance an administrator degraded (svcadm mark degraded)
 * stays degraded until a run faults or exits with SMF_EXIT_MON_DEGRADE.
 */

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/debug.h>
#include <sys/procset.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <definit.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <librestart.h>
#include <libscf.h>
#include <paths.h>
#include <poll.h>
#include <port.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <time.h>
#include <umem.h>
#include <unistd.h>
#include <zone.h>

#include "periodic.h"

/* The method we run; periodic and scheduled services have no others */
#define	EXEC_METHOD	"start"

/* As svc.startd runs methods */
#define	EXEC_SHELL	"/sbin/sh"

/*
 * The exit status of a method child that couldn't exec the shell. This is
 * the value svc.startd uses.
 */
#define	EXEC_EXIT_NOEXEC	10

/* Marks the contracts of our runs ("periodic") */
#define	EXEC_COOKIE	0x706572696f646963ULL

/* As svc.startd (env.c) */
#define	DEF_PATH	"PATH=/usr/sbin:/usr/bin"

/* Non-fatal faults in a row that put an instance into maintenance */
#define	FAULT_THRESHOLD	3

/* Big enough for "%b %e %T" */
#define	LOG_DATE_SIZE	32

typedef enum exec_outcome {
	EO_SUCCESS,
	EO_DEGRADE,
	EO_TEMP_DISABLE,
	EO_DISABLE,
	EO_FAULT,	/* non-fatal fault */
	EO_FATAL,	/* fatal fault */
	EO_UNKNOWN,	/* an adopted run; we can't know how it went */
} exec_outcome_t;

typedef struct exec_run {
	struct exec_run	*er_next;
	uint64_t	er_id;		/* in its events; see event_id() */
	char		*er_fmri;
	pid_t		er_pid;		/* -1 for an adopted run */
	ctid_t		er_ctid;
	int		er_evfd;	/* the contract's events endpoint */
	bool		er_adopted;
	bool		er_timer_armed;
	bool		er_timedout;
	timer_t		er_timer;
	port_notify_t	er_pn;
} exec_run_t;

static exec_run_t *runs;

/* The global environment of every method, as svc.startd's init_env() */
static char **glob_envp;
static size_t glob_env_n;	/* slots allocated */
static size_t glob_env_cnt;	/* entries, excluding the terminating NULL */

static char zonename[ZONENAME_MAX];

static void method_done(periodic_svc_t *, exec_outcome_t);
static void method_outcome(periodic_svc_t *, exec_outcome_t, bool);
static void exec_child(const char *, char **, struct method_context *, int,
    int) __NORETURN;
static void fd_log(int, bool, const char *, ...) __PRINTFLIKE(3);

static char *
xstrdup(const char *s)
{
	size_t	len = strlen(s) + 1;
	char	*p = umem_alloc(len, UMEM_NOFAIL);

	bcopy(s, p, len);
	return (p);
}

static void
xstrfree(char *s)
{
	if (s != NULL) {
		umem_free(s, strlen(s) + 1);
	}
}

static char *
xasprintf(const char *fmt, ...) __PRINTFLIKE(1);

static char *
xasprintf(const char *fmt, ...)
{
	va_list	ap;
	int	n;
	char	*p;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	VERIFY3S(n, >=, 0);

	p = umem_alloc(n + 1, UMEM_NOFAIL);

	va_start(ap, fmt);
	(void) vsnprintf(p, n + 1, fmt, ap);
	va_end(ap);

	return (p);
}

/*
 * Logging to an instance's log.
 */

/*
 * Write a message to fd in the format svc.startd uses for its own messages
 * in an instance's log, "[ month day time message ]" (the brackets
 * distinguish them from method output); see vlog_instance() in svc.startd.
 * In a method child, lock must be false: tz_lock may have been held by
 * another thread when we forked.
 */
static void
vfd_log(int fd, bool lock, const char *fmt, va_list ap)
{
	char		timebuf[LOG_DATE_SIZE] = "";
	char		msg[1024];
	char		line[sizeof (msg) + LOG_DATE_SIZE + 8];
	struct tm	tm;
	time_t		now;
	int		n;

	if (fd < 0) {
		return;
	}

	(void) vsnprintf(msg, sizeof (msg), fmt, ap);

	now = time(NULL);
	if (lock) {
		mutex_enter(&tz_lock);
	}
	if (localtime_r(&now, &tm) != NULL) {
		(void) strftime(timebuf, sizeof (timebuf), "%b %e %T", &tm);
	}
	if (lock) {
		mutex_exit(&tz_lock);
	}

	n = snprintf(line, sizeof (line), "[ %s %s ]\n", timebuf, msg);
	if (n < 0) {
		return;
	}
	if ((size_t)n >= sizeof (line)) {
		n = sizeof (line) - 1;
		line[n - 1] = '\n';
	}

	(void) write(fd, line, n);
}

static void
fd_log(int fd, bool lock, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfd_log(fd, lock, fmt, ap);
	va_end(ap);
}

/*
 * Log a message to svc's log, as svc.startd's log_instance() does. As there,
 * a log we can't open is silently skipped, and the message isn't localized.
 */
void
inst_log(const periodic_svc_t *svc, const char *fmt, ...)
{
	va_list	ap;
	int	fd;

	if (svc == NULL || svc->ps_logfile == NULL) {
		return;
	}

	fd = open(svc->ps_logfile, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		return;
	}

	va_start(ap, fmt);
	vfd_log(fd, true, fmt, ap);
	va_end(ap);

	(void) close(fd);
}

/*
 * The method environment, after svc.startd's env.c.
 */

/*
 * Read /etc/default/init into the environment every method starts with, as
 * svc.startd's init_env() does (itself a clone of what init(8) does).
 */
static void
env_init(void)
{
	void		*dstate;
	const char	*tokp;
	size_t		i;

	glob_env_n = 16;
	glob_envp = umem_zalloc(sizeof (char *) * glob_env_n, UMEM_NOFAIL);
	glob_envp[0] = xstrdup(DEF_PATH);
	i = 1;

	if (definit_open(DEFINIT_DEFAULT_FILE, &dstate) != 0) {
		logmsg(_("Cannot open %s. Environment not initialized."),
		    DEFINIT_DEFAULT_FILE);
	} else {
		while ((tokp = definit_token(dstate)) != NULL) {
			/*
			 * We run with the umask svc.startd gave us, so skip
			 * CMASK, and SMF_ variables are ours to set.
			 */
			if (strncmp(tokp, "CMASK=", 6) == 0 ||
			    strncmp(tokp, "SMF_", 4) == 0) {
				continue;
			}

			glob_envp[i] = xstrdup(tokp);

			/* Double the environment whenever it is full */
			if (++i == glob_env_n) {
				char **newp;

				newp = umem_zalloc(sizeof (char *) *
				    glob_env_n * 2, UMEM_NOFAIL);
				bcopy(glob_envp, newp,
				    sizeof (char *) * glob_env_n);
				umem_free(glob_envp,
				    sizeof (char *) * glob_env_n);
				glob_envp = newp;
				glob_env_n *= 2;
			}
		}
		definit_close(dstate);
	}

	glob_envp[i] = NULL;
	glob_env_cnt = i;

	/* Used to set SMF_ZONENAME */
	(void) getzonenamebyid(getzoneid(), zonename, sizeof (zonename));
}

static bool
valid_env_var(const char *var, const periodic_svc_t *svc)
{
	const char *cp = strchr(var, '=');

	if (cp == NULL || cp == var) {
		inst_log(svc, "Invalid environment variable \"%s\".", var);
		return (false);
	}
	if (strncmp(var, "SMF_", 4) == 0) {
		inst_log(svc, "Invalid environment variable \"%s\"; \"SMF_\" "
		    "prefix is reserved.", var);
		return (false);
	}

	return (true);
}

static char **
find_dup(const char *var, char **env, const periodic_svc_t *svc)
{
	char **p;

	for (p = env; *p != NULL; p++) {
		const char *eq = strchr(*p, '=');

		VERIFY3P(eq, !=, NULL);
		if (strncmp(*p, var, eq - *p + 1) == 0) {
			break;
		}
	}

	if (*p == NULL) {
		return (NULL);
	}

	/* Overriding the default path is expected */
	if (strncmp(*p, DEF_PATH, strlen(DEF_PATH)) != 0) {
		inst_log(svc, "Ignoring duplicate environment variable \"%s\".",
		    *p);
	}

	return (p);
}

/*
 * Build the environment for svc's method, as svc.startd's set_smf_env()
 * does: the SMF_ variables, then the global environment, then the method
 * context's environment, which overrides the global one. The result and
 * its strings are allocated with umem; *nslotsp is the size of the array,
 * for free_env().
 */
static char **
build_env(const periodic_svc_t *svc, const struct method_context *mc,
    size_t *nslotsp)
{
	char	**nenv, **np, **p;
	size_t	nslots;

	/* The four SMF_ variables, the global env, the method's, and NULL */
	nslots = 4 + glob_env_cnt + mc->env_sz + 1;
	nenv = umem_zalloc(sizeof (char *) * nslots, UMEM_NOFAIL);
	np = nenv;

	*np++ = xasprintf("SMF_FMRI=%s", svc->ps_fmri);
	*np++ = xasprintf("SMF_METHOD=%s", EXEC_METHOD);
	*np++ = xasprintf("SMF_RESTARTER=%s", my_fmri);
	*np++ = xasprintf("SMF_ZONENAME=%s", zonename);

	for (p = glob_envp; *p != NULL; p++) {
		if (valid_env_var(*p, NULL)) {
			*np++ = xstrdup(*p);
		}
	}

	if (mc->env != NULL) {
		for (p = mc->env; *p != NULL; p++) {
			char **dup_pos;

			if (!valid_env_var(*p, svc)) {
				continue;
			}

			if ((dup_pos = find_dup(*p, nenv, svc)) != NULL) {
				xstrfree(*dup_pos);
				*dup_pos = xstrdup(*p);
			} else {
				VERIFY3P(np, <, nenv + nslots - 1);
				*np++ = xstrdup(*p);
			}
		}
	}
	*np = NULL;

	*nslotsp = nslots;
	return (nenv);
}

static void
free_env(char **env, size_t nslots)
{
	for (size_t i = 0; i < nslots; i++) {
		xstrfree(env[i]);
	}
	umem_free(env, sizeof (char *) * nslots);
}

/*
 * The list of runs in progress.
 */

static exec_run_t *
run_find(const char *fmri)
{
	for (exec_run_t *r = runs; r != NULL; r = r->er_next) {
		if (strcmp(r->er_fmri, fmri) == 0) {
			return (r);
		}
	}
	return (NULL);
}

/*
 * The run in progress with the given ID (from an event, which may not be a
 * run's, or may be from a run that has finished), or NULL. There are only
 * as many runs as instances running at once, so a list is enough.
 */
static exec_run_t *
run_find_id(uint64_t id)
{
	for (exec_run_t *r = runs; r != NULL; r = r->er_next) {
		if (r->er_id == id) {
			return (r);
		}
	}
	return (NULL);
}

static exec_run_t *
run_create(const char *fmri, pid_t pid, ctid_t ctid, bool adopted)
{
	exec_run_t *r = umem_zalloc(sizeof (*r), UMEM_NOFAIL);

	r->er_id = event_id();
	r->er_fmri = xstrdup(fmri);
	r->er_pid = pid;
	r->er_ctid = ctid;
	r->er_evfd = -1;
	r->er_adopted = adopted;

	r->er_next = runs;
	runs = r;

	return (r);
}

/*
 * Forget r, abandoning its contract. By now the contract is empty (or we
 * are giving up on it), so abandoning it destroys it.
 */
static void
run_destroy(exec_run_t *r)
{
	exec_run_t	**pp;
	int		err;

	for (pp = &runs; *pp != r; pp = &(*pp)->er_next) {
		VERIFY3P(*pp, !=, NULL);
	}
	*pp = r->er_next;

	if (r->er_timer_armed) {
		(void) timer_delete(r->er_timer);
	}
	if (r->er_evfd >= 0) {
		(void) close(r->er_evfd);
	}
	if (r->er_ctid != -1 && (err = contract_abandon_id(r->er_ctid)) != 0) {
		logmsg(_("%s: failed to abandon contract %d: %s"), r->er_fmri,
		    (int)r->er_ctid, strerror(err));
	}

	xstrfree(r->er_fmri);
	umem_free(r, sizeof (*r));
}

/*
 * Signal every process in r's contract.
 */
static void
run_kill(exec_run_t *r, int sig)
{
	if (r->er_ctid != -1) {
		if (sigsend(P_CTID, r->er_ctid, sig) == -1 && errno != ESRCH) {
			logmsg(_("%s: could not signal all contract members: "
			    "%s"), r->er_fmri, strerror(errno));
		}
	} else if (r->er_pid > 0) {
		/* Without a contract, all we can do is the start method */
		(void) kill(r->er_pid, sig);
	}
}

/*
 * Start (or continue) watching r's contract events endpoint for its empty
 * event.
 */
static bool
run_associate(exec_run_t *r)
{
	if (port_associate(evport, PORT_SOURCE_FD, (uintptr_t)r->er_evfd,
	    POLLIN, (void *)(uintptr_t)r->er_id) != 0) {
		logmsg(_("%s: failed to watch contract %d: %s"), r->er_fmri,
		    (int)r->er_ctid, strerror(errno));
		return (false);
	}
	return (true);
}

/*
 * Kill r's contract when its method's timeout expires.
 */
static void
run_arm_timeout(exec_run_t *r, int64_t secs)
{
	struct sigevent		sev = { 0 };
	struct itimerspec	its = { 0 };

	r->er_pn.portnfy_port = evport;
	r->er_pn.portnfy_user = (void *)(uintptr_t)r->er_id;
	sev.sigev_notify = SIGEV_PORT;
	sev.sigev_value.sival_ptr = &r->er_pn;

	if (timer_create(CLOCK_REALTIME, &sev, &r->er_timer) != 0) {
		logmsg(_("%s: failed to create method timer, method will not "
		    "time out: %s"), r->er_fmri, strerror(errno));
		return;
	}

	its.it_value.tv_sec = (time_t)secs;
	if (timer_settime(r->er_timer, 0, &its, NULL) != 0) {
		logmsg(_("%s: failed to set method timer, method will not "
		    "time out: %s"), r->er_fmri, strerror(errno));
		(void) timer_delete(r->er_timer);
		return;
	}

	r->er_timer_armed = true;
}

/*
 * The start method of r has finished, and its contract is empty. Reap it
 * and work out how it went, logging to svc's log as svc.startd's
 * method_run() does. svc may be NULL if the instance has since been
 * deleted.
 */
static exec_outcome_t
run_reap(exec_run_t *r, const periodic_svc_t *svc)
{
	char	buf[SIG2STR_MAX];
	int	status;
	int	code;
	pid_t	pid;

	if (r->er_adopted) {
		inst_log(svc, "Method \"%s\" from before %s restarted has "
		    "finished; its exit status is unknown.", EXEC_METHOD,
		    my_fmri);
		return (EO_UNKNOWN);
	}

	/*
	 * The start method's process left the contract when it exited, so
	 * it has exited (or is in the middle of exiting) by now, and this
	 * won't block for long.
	 */
	do {
		pid = waitpid(r->er_pid, &status, 0);
	} while (pid == -1 && errno == EINTR);

	if (pid == -1) {
		logmsg(_("%s: couldn't waitpid() for %s method (pid %d): %s"),
		    r->er_fmri, EXEC_METHOD, (int)r->er_pid, strerror(errno));
		return (EO_UNKNOWN);
	}

	if (r->er_timedout) {
		inst_log(svc, "Method \"%s\" timed out.", EXEC_METHOD);
		return (EO_FAULT);
	}

	if (!WIFEXITED(status)) {
		if (WIFSIGNALED(status)) {
			(void) sig2str(WTERMSIG(status), buf);
			logmsg(_("%s: Method \"%s\" failed due to signal %s."),
			    r->er_fmri, EXEC_METHOD, buf);
			inst_log(svc, "Method \"%s\" failed due to signal %s.",
			    EXEC_METHOD, buf);
		} else {
			logmsg(_("%s: Method \"%s\" failed with wait status "
			    "%d."), r->er_fmri, EXEC_METHOD, status);
		}
		return (EO_FAULT);
	}

	code = WEXITSTATUS(status);
	inst_log(svc, "Method \"%s\" exited with status %d.", EXEC_METHOD,
	    code);

	switch (code) {
	case SMF_EXIT_OK:
	case SMF_EXIT_NODAEMON:
		return (EO_SUCCESS);
	case SMF_EXIT_MON_DEGRADE:
		return (EO_DEGRADE);
	case SMF_EXIT_TEMP_DISABLE:
		return (EO_TEMP_DISABLE);
	case SMF_EXIT_MON_OFFLINE:
		return (EO_DISABLE);
	case SMF_EXIT_ERR_CONFIG:
	case SMF_EXIT_ERR_NOSMF:
	case SMF_EXIT_ERR_PERM:
	case SMF_EXIT_ERR_FATAL:
		logmsg(_("%s: Method \"%s\" failed with exit status %d."),
		    r->er_fmri, EXEC_METHOD, code);
		return (EO_FATAL);
	default:
		logmsg(_("%s: Method \"%s\" failed with exit status %d."),
		    r->er_fmri, EXEC_METHOD, code);
		return (EO_FAULT);
	}
}

/*
 * r's contract is empty (or we can no longer watch it): finish the run.
 */
static void
run_finish(exec_run_t *r)
{
	periodic_svc_t	*svc;
	exec_outcome_t	outcome;

	/* The instance may have been deleted while it ran */
	svc = periodic_svc_get(r->er_fmri);

	outcome = run_reap(r, svc);

	if (svc != NULL) {
		(void) clear_run(svc);
	}
	run_destroy(r);

	if (svc != NULL) {
		method_done(svc, outcome);
	}
}

/*
 * We can't watch r's contract, so we'd never know when it finishes. Rather
 * than leave the instance running forever, kill the run and finish it.
 */
static void
run_lost(exec_run_t *r)
{
	logmsg(_("%s: killing contract %d, which we can't watch"),
	    r->er_fmri, (int)r->er_ctid);
	run_kill(r, SIGKILL);
	r->er_timedout = true;
	run_finish(r);
}

/*
 * r's events endpoint is readable. Read every pending event, and finish the
 * run if one says the contract is empty.
 */
static void
run_ct_event(exec_run_t *r)
{
	ct_evthdl_t	ev;
	bool		empty = false;
	int		err;

	for (;;) {
		if ((err = ct_event_read(r->er_evfd, &ev)) != 0) {
			break;
		}
		if (ct_event_get_type(ev) == CT_PR_EV_EMPTY) {
			empty = true;
		}
		ct_event_free(ev);
	}

	if (empty) {
		run_finish(r);
		return;
	}

	if (err != EAGAIN && err != EINTR) {
		logmsg(_("%s: failed to read events of contract %d: %s"),
		    r->er_fmri, (int)r->er_ctid, strerror(err));
		run_lost(r);
		return;
	}

	if (!run_associate(r)) {
		run_lost(r);
	}
}

/*
 * r's method timed out. Kill everything in its contract; we'll see the
 * contract empty as a result. The message is svc.startd's.
 */
static void
run_timeout(exec_run_t *r)
{
	logmsg(_("%s: Method or service exit timed out.  Killing contract "
	    "%d."), r->er_fmri, (int)r->er_ctid);
	inst_log(periodic_svc_get(r->er_fmri), "Method or service exit timed "
	    "out.  Killing contract %d.", (int)r->er_ctid);

	r->er_timedout = true;
	run_kill(r, SIGKILL);
}

/*
 * Count a non-fatal fault of svc. Returns whether it has reached the fault
 * threshold. Based on svc.startd's update_fault_count().
 */
static bool
fault_count_incr(periodic_svc_t *svc)
{
	svc->ps_fault_count++;
	logmsg(_("%s: Increasing fault count to %u"), svc->ps_fmri,
	    svc->ps_fault_count);

	return (svc->ps_fault_count >= FAULT_THRESHOLD);
}

/*
 * Disable svc, until reboot if temporary, as svc.startd's
 * method_temp_disable() does: set the enabled property (or its override),
 * and let svc.startd send us a disable event.
 */
static void
method_disable(periodic_svc_t *svc, bool temporary)
{
	if (smf_disable_instance(svc->ps_fmri,
	    temporary ? SMF_TEMPORARY : 0) != 0) {
		logmsg(_("%s: could not %sdisable the service: %s"),
		    svc->ps_fmri, temporary ? _("temporarily ") : "",
		    scf_strerror(scf_error()));
	}
}

/*
 * Act on how svc's run went (see "Outcomes" above). Called on the main
 * thread.
 */
static void
method_done(periodic_svc_t *svc, exec_outcome_t outcome)
{
	bool online = (svc->ps_state == RESTARTER_STATE_ONLINE ||
	    svc->ps_state == RESTARTER_STATE_DEGRADED);
	uint_t old_count = svc->ps_fault_count;
	bool old_degraded = svc->ps_fault_degraded;

	/* First, so that update_state() sets the right auxiliary state */
	svc_set_running(svc, false);

	method_outcome(svc, outcome, online);

	if (svc->ps_fault_count != old_count ||
	    svc->ps_fault_degraded != old_degraded) {
		(void) save_faults(svc);
	}
}

/*
 * The state changes of method_done().
 */
static void
method_outcome(periodic_svc_t *svc, exec_outcome_t outcome, bool online)
{

	switch (outcome) {
	case EO_UNKNOWN:
		break;

	case EO_SUCCESS:
		svc->ps_fault_count = 0;
		if (svc->ps_state == RESTARTER_STATE_DEGRADED &&
		    svc->ps_fault_degraded) {
			svc->ps_fault_degraded = false;
			inst_log(svc, "Method \"%s\" succeeded; leaving "
			    "degraded state.", EXEC_METHOD);
			update_state(svc, RESTARTER_STATE_ONLINE, RERR_NONE,
			    restarter_str_none);
		}
		break;

	case EO_DEGRADE:
		/* As svc.startd, SMF_EXIT_MON_DEGRADE resets the count */
		svc->ps_fault_count = 0;
		if (online) {
			svc->ps_fault_degraded = true;
		}
		if (svc->ps_state == RESTARTER_STATE_ONLINE) {
			update_state(svc, RESTARTER_STATE_DEGRADED, RERR_FAULT,
			    restarter_str_method_failed);
		}
		break;

	case EO_FAULT:
		if (!online) {
			break;
		}
		if (fault_count_incr(svc)) {
			inst_log(svc, "Method \"%s\" failed %u times in a "
			    "row; transitioning to maintenance.", EXEC_METHOD,
			    svc->ps_fault_count);
			svc->ps_fault_degraded = false;
			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_MAINT, RERR_FAULT,
			    restarter_str_fault_threshold_reached);
			break;
		}
		svc->ps_fault_degraded = true;
		if (svc->ps_state == RESTARTER_STATE_ONLINE) {
			inst_log(svc, "Method \"%s\" failed; transitioning "
			    "to degraded.", EXEC_METHOD);
			update_state(svc, RESTARTER_STATE_DEGRADED, RERR_FAULT,
			    restarter_str_method_failed);
		}
		break;

	case EO_FATAL:
		if (online) {
			inst_log(svc, "Method \"%s\" failed fatally; "
			    "transitioning to maintenance.", EXEC_METHOD);
			svc->ps_fault_degraded = false;
			svc_unschedule(svc);
			update_state(svc, RESTARTER_STATE_MAINT, RERR_FAULT,
			    restarter_str_method_failed);
		}
		break;

	case EO_TEMP_DISABLE:
		method_disable(svc, true);
		break;

	case EO_DISABLE:
		method_disable(svc, false);
		break;
	}
}

/*
 * Starting a run.
 */

/*
 * Open, set up and activate the process contract template for a run of
 * svc's method, so that the next fork() creates its contract. Returns the
 * template's fd, to be cleared and closed after forking, or -1. Based on
 * inetd's create_contract_template() and contract_prefork().
 */
static int
exec_tmpl_activate(const periodic_svc_t *svc)
{
	int fd, err;

	if ((fd = open(CTFS_ROOT "/process/template",
	    O_RDWR | O_CLOEXEC)) == -1) {
		logmsg(_("%s: failed to open contract template %s: %s"),
		    svc->ps_fmri, CTFS_ROOT "/process/template",
		    strerror(errno));
		return (-1);
	}

	/*
	 * Make the contract inheritable, so that a later svc.periodicd can
	 * adopt it, and make hardware errors fatal. As with inetd, limit
	 * the scope of fatal events to the process group.
	 */
	if (((err = ct_pr_tmpl_set_param(fd,
	    CT_PR_INHERIT | CT_PR_PGRPONLY)) != 0) ||
	    ((err = ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR)) != 0) ||
	    ((err = ct_tmpl_set_critical(fd, CT_PR_EV_EMPTY)) != 0) ||
	    ((err = ct_tmpl_set_informative(fd, 0)) != 0) ||
	    ((err = ct_tmpl_set_cookie(fd, EXEC_COOKIE)) != 0) ||
	    ((err = ct_pr_tmpl_set_svc_fmri(fd, svc->ps_fmri)) != 0) ||
	    ((err = ct_pr_tmpl_set_svc_aux(fd, EXEC_METHOD)) != 0)) {
		logmsg(_("%s: failed to set contract template terms: %s"),
		    svc->ps_fmri, strerror(err));
		(void) close(fd);
		return (-1);
	}

	if ((err = ct_tmpl_activate(fd)) != 0) {
		logmsg(_("%s: failed to activate contract template: %s"),
		    svc->ps_fmri, strerror(err));
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * Whether a failure to get a method context, of the given mc_error_t type
 * (an errno value or scf_error_t), might succeed if tried again: running out
 * of memory or other resources, or losing the repository. Anything else
 * (e.g. a user that doesn't exist) is a problem with the configuration.
 */
static bool
mc_error_transient(int type)
{
	switch (type) {
	case EAGAIN:
	case ENOMEM:
	case ENFILE:
	case SCF_ERROR_NO_MEMORY:
	case SCF_ERROR_NO_RESOURCES:
	case SCF_ERROR_NO_SERVER:
	case SCF_ERROR_NOT_BOUND:
	case SCF_ERROR_CONNECTION_BROKEN:
	case SCF_ERROR_BACKEND_ACCESS:
		return (true);
	default:
		return (false);
	}
}

/*
 * Run svc's start method now. Returns 0 if it was started (or was :true,
 * which finishes immediately), EBUSY if a run is already in progress (the
 * caller should skip this one), or another errno value if it couldn't be
 * started, which has been logged. Failing to fork or to set up the
 * contract counts as a non-fatal fault, as a failed run does, and failing
 * to get the method context is a fatal fault unless it may be transient
 * (see mc_error_transient()); either may change svc's state. Must be called
 * on the main thread.
 */
int
exec_start(periodic_svc_t *svc)
{
	periodic_exec_t		*pe = &svc->ps_exec;
	struct method_context	*mc = NULL;
	char			mc_msg[RESTARTER_ERRMSGSZ];
	int			mc_type;
	char			*cmd = NULL;
	char			**env = NULL;
	size_t			envslots = 0;
	int			logfd = -1;
	int			tmpl;
	int			err = 0;
	pid_t			pid;
	ctid_t			ctid;
	int64_t			now;
	exec_run_t		*r;

	if (run_find(svc->ps_fmri) != NULL) {
		return (EBUSY);
	}

	if (pe->pe_exec == NULL) {
		logmsg(_("%s: no %s method to run"), svc->ps_fmri,
		    EXEC_METHOD);
		return (EINVAL);
	}

	if (restarter_is_null_method(pe->pe_exec)) {
		inst_log(svc, "Executing %s method (null).", EXEC_METHOD);
		method_done(svc, EO_SUCCESS);
		return (0);
	}

	/*
	 * As svc.startd does for each method it runs, get the method context
	 * now rather than when the configuration was loaded, so that a run
	 * sees the current state of the users, groups, projects and pools it
	 * names (e.g. from a name service). The context itself still comes
	 * from the running snapshot, so only a refresh changes that.
	 */
	mc_type = get_method_context(svc, &mc, mc_msg, sizeof (mc_msg));
	if (mc_type != 0) {
		logmsg(_("%s: failed to get %s method context: %s"),
		    svc->ps_fmri, EXEC_METHOD, mc_msg);
		inst_log(svc, "%s", mc_msg);
		method_done(svc, mc_error_transient(mc_type) ? EO_FAULT :
		    EO_FATAL);
		return (EINVAL);
	}

	/*
	 * Open the log now, as root, for the method's output; the method
	 * context may change who we are in the child. If we can't, the
	 * output goes to /dev/null, as with svc.startd's setlog().
	 */
	if (svc->ps_logfile != NULL) {
		logfd = open(svc->ps_logfile,
		    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (logfd < 0) {
			logmsg(_("%s: couldn't open log %s: %s"),
			    svc->ps_fmri, svc->ps_logfile, strerror(errno));
		}
	}

	fd_log(logfd, true, "Executing %s method (\"%s\").", EXEC_METHOD,
	    pe->pe_exec);

	/* Do everything we can before forking, so the child does little */
	cmd = xasprintf("exec %s", pe->pe_exec);
	env = build_env(svc, mc, &envslots);

	if ((tmpl = exec_tmpl_activate(svc)) == -1) {
		err = EAGAIN;
		goto out;
	}

	now = (int64_t)time(NULL);
	pid = fork();
	if (pid == 0) {
		exec_child(cmd, env, mc, logfd, tmpl);
	}
	err = errno;

	/* As inetd's contract_postfork(), so other forks don't get one */
	(void) ct_tmpl_clear(tmpl);
	(void) close(tmpl);

	if (pid == -1) {
		logmsg(_("%s: Couldn't fork to execute method %s: %s"),
		    svc->ps_fmri, pe->pe_exec, strerror(err));
		goto out;
	}
	err = 0;

	if ((errno = contract_latest(&ctid)) != 0) {
		/* We can still wait for it, but not for its contract */
		logmsg(_("%s: couldn't get new contract's id: %s"),
		    svc->ps_fmri, strerror(errno));
		ctid = -1;
	}

	r = run_create(svc->ps_fmri, pid, ctid, false);
	svc_set_running(svc, true);
	(void) note_run(svc, pid, ctid, now);

	if (ctid == -1) {
		run_lost(r);
		goto out;
	}

	r->er_evfd = contract_open(ctid, "process", "events",
	    O_RDONLY | O_NONBLOCK);
	if (r->er_evfd < 0) {
		logmsg(_("%s: failed to open events of contract %d: %s"),
		    svc->ps_fmri, (int)ctid, strerror(errno));
		run_lost(r);
		goto out;
	}

	if (!run_associate(r)) {
		run_lost(r);
		goto out;
	}

	if (pe->pe_timeout_secs > 0) {
		run_arm_timeout(r, pe->pe_timeout_secs);
	}

out:
	if (err != 0) {
		fd_log(logfd, true, "Method \"%s\" could not be started: %s.",
		    EXEC_METHOD, strerror(err));
	}

	if (env != NULL) {
		free_env(env, envslots);
	}
	xstrfree(cmd);
	if (logfd >= 0) {
		(void) close(logfd);
	}
	if (mc != NULL) {
		restarter_free_method_context(mc);
	}

	if (err != 0) {
		method_done(svc, EO_FAULT);
	}

	return (err);
}

/*
 * The method child. As with svc.startd's exec_method(): set up standard
 * input, output and error, apply the method context, and exec the method
 * through the shell. Errors are reported on standard error, which is the
 * instance's log, and with the same exit statuses svc.startd uses. We
 * _exit() rather than exit(), so that stdio buffers inherited from
 * svc.periodicd (logmsg() writes to stdout) aren't flushed twice.
 */
static void
exec_child(const char *cmd, char **env, struct method_context *mc,
    int logfd, int tmpl)
{
	sigset_t	mask;
	const char	*errf;
	int		fd;
	int		err;

	/*
	 * Our active contract template was copied to us; don't let anything
	 * the method forks inherit it.
	 */
	(void) ct_tmpl_clear(tmpl);

	/*
	 * svc.periodicd blocks every signal (it handles the ones it cares
	 * about with a signalfd, and installs no handlers). As inetd does,
	 * unblock them for the method.
	 */
	(void) sigemptyset(&mask);
	(void) sigprocmask(SIG_SETMASK, &mask, NULL);

	/*
	 * Put each run in its own session and process group, so that it
	 * can't signal svc.periodicd or other runs by process group, and so
	 * that the PGRPONLY scope of the contract's fatal events is the run.
	 */
	(void) setsid();

	/* Standard input from /dev/null, output and error to the log */
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) >= 0) {
		(void) dup2(fd, STDIN_FILENO);
		if (logfd < 0) {
			logfd = fd;
		}
	}
	if (logfd >= 0) {
		(void) dup2(logfd, STDOUT_FILENO);
		(void) dup2(logfd, STDERR_FILENO);
	}
	closefrom(STDERR_FILENO + 1);

	/* Set credentials and the rest of the method context */
	if ((err = restarter_set_method_context(mc, &errf)) != 0) {
		fd_log(STDERR_FILENO, false,
		    "%s could not set context for method: ", my_fmri);

		if (err == -1) {
			if (strcmp(errf, "core_set_process_path") == 0) {
				fd_log(STDERR_FILENO, false,
				    "Could not set corefile path.");
			} else if (strcmp(errf, "setproject") == 0) {
				fd_log(STDERR_FILENO, false, "%s: a resource "
				    "control assignment failed", errf);
			} else if (strcmp(errf, "pool_set_binding") == 0) {
				fd_log(STDERR_FILENO, false, "%s: a system "
				    "error occurred", errf);
			}
			_exit(1);
		}

		if (errf != NULL && strcmp(errf, "pool_set_binding") == 0) {
			switch (err) {
			case ENOENT:
				fd_log(STDERR_FILENO, false, "%s: the pool "
				    "could not be found", errf);
				break;
			case EBADF:
				fd_log(STDERR_FILENO, false, "%s: the "
				    "configuration is invalid", errf);
				break;
			case EINVAL:
				fd_log(STDERR_FILENO, false, "%s: pool name "
				    "\"%s\" is invalid", errf,
				    mc->resource_pool);
				break;
			default:
				fd_log(STDERR_FILENO, false, "%s: %s", errf,
				    strerror(err));
				break;
			}
			_exit(SMF_EXIT_ERR_CONFIG);
		}

		if (errf != NULL && strcmp(errf, "chdir") == 0) {
			fd_log(STDERR_FILENO, false, "%s: %s (\"%s\")", errf,
			    strerror(err), mc->working_dir);
			_exit(SMF_EXIT_ERR_CONFIG);
		}

		if (errf != NULL) {
			fd_log(STDERR_FILENO, false, "%s: %s", errf,
			    strerror(err));

			switch (err) {
			case EINVAL:
			case EPERM:
			case ENOENT:
			case ENAMETOOLONG:
			case ERANGE:
			case ESRCH:
				_exit(SMF_EXIT_ERR_CONFIG);
			default:
				_exit(1);
			}
		}

		switch (err) {
		case ENOMEM:
			fd_log(STDERR_FILENO, false, "Out of memory.");
			_exit(1);
		case ENOENT:
			fd_log(STDERR_FILENO, false,
			    "Missing passwd entry for user.");
			_exit(SMF_EXIT_ERR_CONFIG);
		default:
			fd_log(STDERR_FILENO, false, "%s", strerror(err));
			_exit(1);
		}
	}

	(void) execle(EXEC_SHELL, EXEC_SHELL, "-c", cmd, NULL, env);

	fd_log(STDERR_FILENO, false, "Failed to exec %s -c '%s': %s",
	    EXEC_SHELL, cmd, strerror(errno));
	_exit(EXEC_EXIT_NOEXEC);
}

/*
 * Adopting runs from a previous svc.periodicd.
 */

/*
 * Adopt the contract ctid, which our contract inherited, if it is the
 * contract of a run, and watch it until it is empty. Based on the adoption
 * loop in svc.startd's contract_init().
 */
static void
recover_one(ctid_t ctid)
{
	ct_stathdl_t	st;
	char		*fmri = NULL;
	char		*sfmri;
	pid_t		*members;
	uint_t		nmembers;
	int		sfd, cfd, efd;
	int		err;
	exec_run_t	*r;

	if ((sfd = contract_open(ctid, "process", "status", O_RDONLY)) < 0) {
		logmsg(_("Can not open contract %d status: %s"), (int)ctid,
		    strerror(errno));
		return;
	}

	if ((err = ct_status_read(sfd, CTD_ALL, &st)) != 0) {
		logmsg(_("Can not read contract %d status: %s"), (int)ctid,
		    strerror(err));
		(void) close(sfd);
		return;
	}

	if (ct_status_get_cookie(st) != EXEC_COOKIE) {
		/* Not a run; leave it to be cleaned up with our contract */
		ct_status_free(st);
		(void) close(sfd);
		return;
	}

	if ((err = ct_pr_status_get_svc_fmri(st, &sfmri)) == 0) {
		fmri = xstrdup(sfmri);
	}
	ct_status_free(st);

	if (fmri == NULL) {
		logmsg(_("Can not get service of contract %d: %s"), (int)ctid,
		    strerror(err));
		(void) close(sfd);
		return;
	}

	if ((cfd = contract_open(ctid, "process", "ctl", O_WRONLY)) < 0) {
		logmsg(_("%s: Can not open contract %d ctl for adoption: %s"),
		    fmri, (int)ctid, strerror(errno));
		goto fail;
	}
	err = ct_ctl_adopt(cfd);
	(void) close(cfd);
	if (err != 0) {
		logmsg(_("%s: Can not adopt contract %d: %s"), fmri,
		    (int)ctid, strerror(err));
		goto fail;
	}

	if ((efd = contract_open(ctid, "process", "events",
	    O_RDONLY | O_NONBLOCK)) < 0) {
		logmsg(_("%s: failed to open events of contract %d: %s"),
		    fmri, (int)ctid, strerror(errno));
		(void) contract_abandon_id(ctid);
		goto fail;
	}

	/*
	 * Its empty event is critical, so it's still queued if the run
	 * finished while no svc.periodicd was around, and run_ct_event()
	 * will see it. Check now anyway, so we can log that the run
	 * finished without waiting for the main loop.
	 */
	if (ct_status_read(sfd, CTD_ALL, &st) == 0) {
		if (ct_pr_status_get_members(st, &members, &nmembers) == 0 &&
		    nmembers == 0) {
			ct_status_free(st);
			logmsg(_("%s: run interrupted when %s stopped has "
			    "finished"), fmri, my_fmri);
			(void) close(efd);
			(void) contract_abandon_id(ctid);
			goto fail;
		}
		ct_status_free(st);
	}
	(void) close(sfd);
	sfd = -1;

	r = run_create(fmri, -1, ctid, true);
	r->er_evfd = efd;
	logmsg(_("%s: adopted contract %d of a run still in progress"),
	    fmri, (int)ctid);

	if (!run_associate(r)) {
		run_lost(r);
	}

	xstrfree(fmri);
	return;

fail:
	if (sfd >= 0) {
		(void) close(sfd);
	}
	xstrfree(fmri);
}

/*
 * Adopt the runs that were in progress when the previous svc.periodicd
 * exited, as svc.startd's contract_init() adopts its inherited contracts.
 */
static void
exec_recover(void)
{
	ct_stathdl_t	st;
	ctid_t		self, *ctids;
	uint_t		nctids;
	int		fd, err;

	if ((self = getctid()) == -1) {
		logmsg(_("Can not get our contract; unable to adopt runs "
		    "in progress: %s"), strerror(errno));
		return;
	}

	if ((fd = contract_open(self, "process", "status", O_RDONLY)) < 0) {
		logmsg(_("Can not open our contract status; unable to adopt "
		    "runs in progress: %s"), strerror(errno));
		return;
	}

	err = ct_status_read(fd, CTD_ALL, &st);
	(void) close(fd);
	if (err != 0) {
		logmsg(_("Can not read our contract status; unable to adopt "
		    "runs in progress: %s"), strerror(err));
		return;
	}

	if ((err = ct_pr_status_get_contracts(st, &ctids, &nctids)) != 0) {
		logmsg(_("Can not get our inherited contracts; unable to "
		    "adopt runs in progress: %s"), strerror(err));
		ct_status_free(st);
		return;
	}

	for (uint_t i = 0; i < nctids; i++) {
		recover_one(ctids[i]);
	}

	ct_status_free(st);
}

/*
 * Interfaces for the rest of svc.periodicd.
 */

/*
 * Set up method execution: read the global method environment, and adopt
 * any runs left in progress by a previous svc.periodicd. Called once from
 * init(), after the event port is created and before we register for
 * restarter events (so that svc_create() can see the adopted runs).
 */
void
exec_init(void)
{
	env_init();
	exec_recover();
}

/*
 * Re-read the global method environment (/etc/default/init), e.g. after
 * svc.periodicd is refreshed. Runs already started keep theirs.
 */
void
exec_refresh(void)
{
	for (size_t i = 0; i < glob_env_cnt; i++) {
		xstrfree(glob_envp[i]);
	}
	umem_free(glob_envp, sizeof (char *) * glob_env_n);
	glob_envp = NULL;
	glob_env_n = glob_env_cnt = 0;

	env_init();
}

/*
 * Whether a run of the instance fmri is in progress.
 */
bool
exec_running(const char *fmri)
{
	return (run_find(fmri) != NULL);
}

/*
 * Called by the main loop for each event it gets. Returns true if the event
 * belonged to a run (and has been handled), false if it is someone else's.
 */
bool
exec_port_event(const port_event_t *pe)
{
	exec_run_t *r;

	switch (pe->portev_source) {
	case PORT_SOURCE_FD:
	case PORT_SOURCE_TIMER:
		break;
	default:
		return (false);
	}

	r = run_find_id((uint64_t)(uintptr_t)pe->portev_user);

	switch (pe->portev_source) {
	case PORT_SOURCE_FD:
		if (r == NULL || (int)pe->portev_object != r->er_evfd) {
			return (false);
		}
		run_ct_event(r);
		return (true);

	case PORT_SOURCE_TIMER:
		if (r == NULL || !r->er_timer_armed ||
		    (timer_t)pe->portev_object != r->er_timer) {
			return (false);
		}
		run_timeout(r);
		return (true);

	default:
		return (false);
	}
}
