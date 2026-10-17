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

/*
 * Telling others that our neighbors have changed.
 *
 * There are two ways:
 *
 *   - Events (EC_LLDP/ESC_LLDP_REMOTE_CHANGE; see sys/sysevent/lldp.h),
 *     published on the LLDP_EVENT_CHAN event channel. Each agent rate
 *     limits its own (see agent_notify()). The channel is bound during
 *     startup, while we're still root: binding needs access to
 *     /dev/sysevent, but publishing through the binding needs no
 *     privileges. (Posting a sysevent through syseventd instead would need
 *     {PRIV_SYS_CONFIG}.)
 *
 *   - A generation number, bumped on every change to any agent's neighbors
 *     (and when agents come and go), which LLDP_DOOR_CMD_WAIT callers wait
 *     on (e.g. 'lldp show-neighbors -w').
 */

#include <errno.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <string.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/lldp.h>
#include <sys/time.h>
#include <lldp_door.h>

#include "log.h"
#include "notify.h"

static evchan_t	*notify_chan;
static mutex_t	notify_chan_lock = DEFAULTMUTEX;

/* Protects the rest; a leaf lock (agents call in holding their a_lock) */
static mutex_t	notify_lock = DEFAULTMUTEX;
static cond_t	notify_cv = DEFAULTCV;
static uint32_t	notify_gen = 1;		/* Never 0 */
static uint_t	notify_waiters;
static bool	notify_exiting;

void
notify_init(void)
{
	int ret;

	ret = sysevent_evc_bind(LLDP_EVENT_CHAN, &notify_chan, EVCH_CREAT);
	if (ret != 0) {
		notify_chan = NULL;
		log_warn(log, "failed to bind event channel; neighbor change "
		    "events won't be published",
		    LOG_T_STRING, "channel", LLDP_EVENT_CHAN,
		    LOG_T_STRING, "errmsg", strerror(ret),
		    LOG_T_END);
	}
}

/* Wake (and fail) any waiters, as we're exiting */
void
notify_fini(void)
{
	mutex_enter(&notify_lock);
	notify_exiting = true;
	VERIFY0(cond_broadcast(&notify_cv));
	mutex_exit(&notify_lock);

	mutex_enter(&notify_chan_lock);
	if (notify_chan != NULL) {
		(void) sysevent_evc_unbind(notify_chan);
		notify_chan = NULL;
	}
	mutex_exit(&notify_chan_lock);
}

/* Something changed: wake any waiters */
void
notify_change(void)
{
	mutex_enter(&notify_lock);
	if (++notify_gen == 0)
		notify_gen = 1;
	VERIFY0(cond_broadcast(&notify_cv));
	mutex_exit(&notify_lock);
}

/*
 * LLDP_DOOR_CMD_WAIT: wait (for up to timeout seconds) for the generation
 * to differ from gen (unless gen is 0), then return it in *genp.
 */
int
notify_wait(uint32_t gen, uint_t timeout, uint32_t *genp)
{
	hrtime_t	deadline;
	int		ret = 0;

	timeout = MIN(timeout, LLDP_WAIT_MAX);
	deadline = gethrtime() + (hrtime_t)timeout * NANOSEC;

	mutex_enter(&notify_lock);

	if (notify_exiting) {
		mutex_exit(&notify_lock);
		return (ESHUTDOWN);
	}

	if (gen != 0 && gen == notify_gen) {
		if (notify_waiters >= LLDP_DOOR_WAITERS) {
			mutex_exit(&notify_lock);
			return (EAGAIN);
		}
		notify_waiters++;

		while (notify_gen == gen && !notify_exiting) {
			hrtime_t	left = deadline - gethrtime();
			timestruc_t	rel;

			if (left <= 0)
				break;

			rel.tv_sec = left / NANOSEC;
			rel.tv_nsec = left % NANOSEC;
			(void) cond_reltimedwait(&notify_cv, &notify_lock,
			    &rel);
		}

		notify_waiters--;
		if (notify_exiting)
			ret = ESHUTDOWN;
	}

	*genp = notify_gen;
	mutex_exit(&notify_lock);
	return (ret);
}

/*
 * Publish an EC_LLDP/ESC_LLDP_REMOTE_CHANGE event for an agent's link. l
 * is the agent's log.
 */
void
notify_publish(log_t *l, const char *link, uint32_t linkid,
    uint32_t neighbors, const lldp_agent_stats_t *st)
{
	nvlist_t	*nvl = NULL;
	int		ret;

	mutex_enter(&notify_chan_lock);
	if (notify_chan == NULL) {
		mutex_exit(&notify_chan_lock);
		return;
	}

	if ((ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, LLDP_EVENT_VERSION,
	    LLDP_EVENT_CUR_VERSION)) != 0 ||
	    (ret = nvlist_add_string(nvl, LLDP_EVENT_LINK, link)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, LLDP_EVENT_LINKID, linkid)) != 0 ||
	    (ret = nvlist_add_uint32(nvl, LLDP_EVENT_NEIGHBORS,
	    neighbors)) != 0 ||
	    (ret = nvlist_add_uint64(nvl, LLDP_EVENT_INSERTS,
	    st->las_rem_inserts)) != 0 ||
	    (ret = nvlist_add_uint64(nvl, LLDP_EVENT_UPDATES,
	    st->las_rem_updates)) != 0 ||
	    (ret = nvlist_add_uint64(nvl, LLDP_EVENT_DELETES,
	    st->las_rem_deletes)) != 0 ||
	    (ret = nvlist_add_uint64(nvl, LLDP_EVENT_AGEOUTS,
	    st->las_ageouts)) != 0 ||
	    (ret = nvlist_add_uint64(nvl, LLDP_EVENT_DROPS,
	    st->las_rem_drops)) != 0) {
		mutex_exit(&notify_chan_lock);
		log_syserr(l, "failed to build neighbor change event", ret);
		nvlist_free(nvl);
		return;
	}

	ret = sysevent_evc_publish(notify_chan, EC_LLDP,
	    ESC_LLDP_REMOTE_CHANGE, LLDP_EVENT_VENDOR, LLDP_EVENT_PUBLISHER,
	    nvl, EVCH_NOSLEEP);
	mutex_exit(&notify_chan_lock);

	if (ret != 0) {
		log_warn(l, "failed to publish neighbor change event",
		    LOG_T_STRING, "errmsg", strerror(ret),
		    LOG_T_END);
	} else {
		log_debug(l, "published neighbor change event",
		    LOG_T_UINT32, "neighbors", neighbors,
		    LOG_T_END);
	}

	nvlist_free(nvl);
}
