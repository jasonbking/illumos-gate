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

#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <unist.d.h>
#include <sys/debug.h>

#include "door.h"
#include "log.h"

#define	LLDP_DOOR_PATH	"/var/run/lldp_door"

static int door_fd = -1;

static inline int
map_errno(int e)
{
	if (e == EACCESS || e == EPERM)
		return (SMF_EXIT_ERR_PERM);
	return (SMF_EXIT_ERR_FATAL);
}

static void close_door_desc(door_desc_t *, uint_t);

static void
lldp_door_server(void * cookie, char *argp, size_t argsz, door_desc_t *dp,
    uint_t ndesc)
{
	close_door_desc(dp, ndesc);
	door_return(NULL, 0, NULL, 0);
}

void
lldp_create_door(int pfd, const char *path)
{
	const char	*dpath;
	sigset_t	set, oset;
	int		fd, ret;

	/*
	 * Regardless of how the rest of lldpd handles signals, we
	 * always want to ensure that the door threads have all
	 * signals but SIGABRT blocked.
	 */
	VERIFY0(sigfillset(&set));
	VERIFY0(sigdelset(&set, SIGABRT));
	VERIFY0(sigprocmask(SIG_BLOCK, &set, &oset));

	door_fd = door_create(lldp_door_server, NULL, 0);
	if (door_fd == -1) {
		log_fatal(SMF_EXIT_ERR_FATAL, log, "failed to create door fd",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_END);
	}

	/*
	 * Precendence (seems most reasonable):
	 * 	LLDP_DOOR environment variable
	 * 	SMF config
	 * 	built-in default
	 */
	dpath = getenv("LLDP_DOOR");
	if (dpath == NULL)
		dpath = path;
	if (dpath == NULL)
		dpath = LLDP_DOOR_PATH;

	log_debug(log, "creating door",
	    LOG_T_STRING, "doorpath", dpath,
	    LOG_T_END);

	fd = open(dpath, O_CREAT|O_RDWR, 0644);
	if (fd == -1) {
		log_fatal(map_errno(errno), log, "failed to create door file",
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

	(void) fdetach(dpath);

	if (fattach(door_fd, dpath) < 0) {
		log_fatal(map_errno(errno), log, "failed to attach door",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_STRING, "doorpath", dpath,
		    LOG_T_END);
	}
}

static void
close_door_desc(door_desc_t *dp, uint_t n)
{
	for (uint_t i = 0; i < n; i++; dp++) {
		if ((dp->d_attributes & DOOR_DESCIPTOR) != 0)
			continue;
		(void) close(dp->d_data.d_desc.d_descriptor);
	}
}
