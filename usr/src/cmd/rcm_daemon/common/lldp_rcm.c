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
 * This RCM module lets links that lldpd(8) is running an LLDP agent on be
 * offlined and removed (e.g. for DR). lldpd keeps a DLPI stream open on each
 * link it advertises on, which would otherwise prevent the link from being
 * detached.
 *
 * The module registers interest in the datalink resource
 * (SUNW_datalink/<linkid>) of each link lldpd has an agent for, which it
 * learns from lldpd's door (lldp_get_stats()). The registrations are
 * refreshed whenever rcm_daemon asks modules to register, which it does
 * before each offline, so links lldpd starts running an agent on later
 * are picked up.
 *
 * On offline, lldpd sends a shutdown LLDPDU on the link (if it was
 * advertising, so neighbors discard our information right away) and closes
 * it. On online (an offline being undone), lldpd reopens the link. On
 * remove, lldpd destroys the agent. lldpd itself creates an agent when a
 * link is attached (via the ESC_DATALINK_PHYS_ADD sysevent), so this module
 * doesn't need to handle new links.
 *
 * If lldpd isn't running (or has no agent for a link), there's nothing to
 * release, so every request succeeds.
 */

#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <sys/types.h>
#include <libdllink.h>
#include <liblldp.h>
#include "rcm_module.h"

#ifndef lint
#define	_(x)	gettext(x)
#else
#define	_(x)	x
#endif

#define	RCM_LINK_PREFIX		"SUNW_datalink"	/* RCM datalink name prefix */
#define	RCM_LINK_RESOURCE_MAX	(13 + LINKID_STR_WIDTH)

/* Cache state flags */
typedef enum {
	CACHE_NODE_STALE	= 0x1,		/* lldpd has no agent for it */
	CACHE_NODE_NEW		= 0x2,		/* not yet registered */
	CACHE_NODE_OFFLINED	= 0x4		/* lldpd released the link */
} cache_node_state_t;

/* Cache lookup options */
#define	CACHE_NO_REFRESH	0x1
#define	CACHE_REFRESH		0x2

typedef struct link_cache {
	struct link_cache	*lc_next;
	struct link_cache	*lc_prev;
	char			*lc_resource;	/* SUNW_datalink/<linkid> */
	datalink_id_t		lc_linkid;
	char			lc_agent[MAXLINKNAMELEN]; /* hardware name */
	cache_node_state_t	lc_state;
} link_cache_t;

static link_cache_t	cache_head;
static link_cache_t	cache_tail;
static mutex_t		cache_lock;

static dladm_handle_t	dld_handle = NULL;

static int	lldp_register(rcm_handle_t *);
static int	lldp_unregister(rcm_handle_t *);
static int	lldp_get_info(rcm_handle_t *, char *, id_t, uint_t, char **,
		    char **, nvlist_t *, rcm_info_t **);
static int	lldp_suspend(rcm_handle_t *, char *, id_t, timespec_t *,
		    uint_t, char **, rcm_info_t **);
static int	lldp_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
		    rcm_info_t **);
static int	lldp_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
		    rcm_info_t **);
static int	lldp_undo_offline(rcm_handle_t *, char *, id_t, uint_t,
		    char **, rcm_info_t **);
static int	lldp_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
		    rcm_info_t **);

static int		cache_update(rcm_handle_t *);
static void		cache_insert(link_cache_t *);
static void		cache_remove(link_cache_t *);
static link_cache_t	*cache_lookup(rcm_handle_t *, char *, char);
static void		node_free(link_cache_t *);
static void		cache_free(void);

static struct rcm_mod_ops lldp_ops = {
	RCM_MOD_OPS_VERSION,
	lldp_register,
	lldp_unregister,
	lldp_get_info,
	lldp_suspend,
	lldp_resume,
	lldp_offline,
	lldp_undo_offline,
	lldp_remove,
	NULL,
	NULL,
	NULL
};

struct rcm_mod_ops *
rcm_mod_init(void)
{
	char		errmsg[DLADM_STRSIZE];
	dladm_status_t	status;

	rcm_log_message(RCM_TRACE1, "LLDP: mod_init\n");

	cache_head.lc_next = &cache_tail;
	cache_head.lc_prev = NULL;
	cache_tail.lc_prev = &cache_head;
	cache_tail.lc_next = NULL;
	(void) mutex_init(&cache_lock, 0, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    _("LLDP: mod_init failed: cannot open datalink handle: "
		    "%s\n"), dladm_status2str(status, errmsg));
		return (NULL);
	}

	return (&lldp_ops);
}

const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "LLDP: mod_info\n");

	return ("LLDP module");
}

int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "LLDP: mod_fini\n");

	/*
	 * As with the other datalink modules, the framework doesn't give us
	 * a handle here to unregister with, so just free the cache.
	 */
	cache_free();
	(void) mutex_destroy(&cache_lock);

	dladm_close(dld_handle);
	return (RCM_SUCCESS);
}

/*
 * Set *errorp (which the framework frees) to describe a failure.
 */
static void
lldp_log_err(datalink_id_t linkid, char **errorp, const char *errmsg)
{
	char		link[MAXLINKNAMELEN];
	char		errstr[DLADM_STRSIZE];
	dladm_status_t	status;
	size_t		len;

	link[0] = '\0';
	if (linkid != DATALINK_INVALID_LINKID &&
	    (status = dladm_datalink_id2info(dld_handle, linkid, NULL, NULL,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    _("LLDP: cannot get link name for %u: %s\n"), linkid,
		    dladm_status2str(status, errstr));
	}

	rcm_log_message(RCM_ERROR, _("LLDP: %s(%s)\n"), errmsg, link);

	if (errorp == NULL)
		return;

	len = strlen(errmsg) + strlen(link) + 16;
	if ((*errorp = malloc(len)) != NULL) {
		if (link[0] == '\0') {
			(void) snprintf(*errorp, len, "LLDP: %s", errmsg);
		} else {
			(void) snprintf(*errorp, len, "LLDP: %s(%s)", errmsg,
			    link);
		}
	}
}

/*
 * Whether err (from lldp_link_notify()) means lldpd has nothing to do for
 * the link: it isn't running, or it has no agent for the link.
 */
static boolean_t
lldp_not_using(int err)
{
	return (err == 0 || err == ENOENT || err == ECONNREFUSED);
}

static int
lldp_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "LLDP: register\n");

	if (cache_update(hd) < 0)
		return (RCM_FAILURE);

	return (RCM_SUCCESS);
}

static int
lldp_unregister(rcm_handle_t *hd)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE1, "LLDP: unregister\n");

	(void) mutex_lock(&cache_lock);
	node = cache_head.lc_next;
	while (node != &cache_tail) {
		if (rcm_unregister_interest(hd, node->lc_resource, 0) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("LLDP: failed to unregister %s\n"),
			    node->lc_resource);
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		cache_remove(node);
		node_free(node);
		node = cache_head.lc_next;
	}
	(void) mutex_unlock(&cache_lock);

	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
lldp_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **info)
{
	link_cache_t	*node;
	char		link[MAXLINKNAMELEN];
	const char	*fmt = _("%s: LLDP agent");
	size_t		len;

	rcm_log_message(RCM_TRACE1, "LLDP: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("LLDP: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Prefer the (possibly renamed) datalink name */
	if (dladm_datalink_id2info(dld_handle, node->lc_linkid, NULL, NULL,
	    NULL, link, sizeof (link)) != DLADM_STATUS_OK) {
		(void) strlcpy(link, node->lc_agent, sizeof (link));
	}
	(void) mutex_unlock(&cache_lock);

	len = strlen(fmt) + strlen(link) + 1;
	if ((*usagep = malloc(len)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("LLDP: get_info(%s) malloc failure\n"), rsrc);
		errno = ENOMEM;
		return (RCM_FAILURE);
	}
	(void) snprintf(*usagep, len, fmt, link);

	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "LLDP");

	rcm_log_message(RCM_TRACE1, "LLDP: get_info(%s) info = %s\n", rsrc,
	    *usagep);
	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
lldp_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "LLDP: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
lldp_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	rcm_log_message(RCM_TRACE1, "LLDP: resume(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * lldp_offline() - Ask lldpd to release the link. lldpd can always do so,
 * so a query always succeeds.
 */
/*ARGSUSED*/
static int
lldp_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t	*node;
	int		err;

	rcm_log_message(RCM_TRACE1, "LLDP: offline(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		/* lldpd isn't using the link (any more) */
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1,
		    "LLDP: offline query succeeded(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	err = lldp_link_notify(LLDP_LINK_EV_OFFLINE, node->lc_linkid);
	if (!lldp_not_using(err)) {
		rcm_log_message(RCM_ERROR,
		    _("LLDP: lldpd failed to release link: %s\n"),
		    strerror(err));
		lldp_log_err(node->lc_linkid, errorp,
		    "lldpd failed to release link");
		(void) mutex_unlock(&cache_lock);
		errno = err;
		return (RCM_FAILURE);
	}

	node->lc_state |= CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "LLDP: offline succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * lldp_undo_offline() - The offline was undone (or the link is back):
 * ask lldpd to reopen the link.
 */
/*ARGSUSED*/
static int
lldp_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t	*node;
	int		err;

	rcm_log_message(RCM_TRACE1, "LLDP: online(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		lldp_log_err(DATALINK_INVALID_LINKID, errorp, "no such link");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	if (!(node->lc_state & CACHE_NODE_OFFLINED)) {
		rcm_log_message(RCM_TRACE1, "LLDP: link not offlined(%s)\n",
		    rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * If lldpd can't reopen the link, it logs why; the link itself is
	 * usable, so don't fail the online.
	 */
	err = lldp_link_notify(LLDP_LINK_EV_ONLINE, node->lc_linkid);
	if (!lldp_not_using(err)) {
		rcm_log_message(RCM_WARNING,
		    _("LLDP: lldpd failed to reopen link %u: %s\n"),
		    node->lc_linkid, strerror(err));
	}

	node->lc_state &= ~CACHE_NODE_OFFLINED;
	rcm_log_message(RCM_TRACE1, "LLDP: online succeeded(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * lldp_remove() - The link is gone: ask lldpd to destroy its agent, and
 * forget about it.
 */
/*ARGSUSED*/
static int
lldp_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **info)
{
	link_cache_t	*node;
	int		err;

	rcm_log_message(RCM_TRACE1, "LLDP: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (node == NULL) {
		rcm_log_message(RCM_INFO,
		    _("LLDP: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	cache_remove(node);
	(void) mutex_unlock(&cache_lock);

	err = lldp_link_notify(LLDP_LINK_EV_REMOVE, node->lc_linkid);
	if (!lldp_not_using(err)) {
		rcm_log_message(RCM_WARNING,
		    _("LLDP: lldpd failed to remove agent for link %u: %s\n"),
		    node->lc_linkid, strerror(err));
	}

	/*
	 * Once the remove completes, rcm_daemon drops our registration for
	 * the resource itself.
	 */
	node_free(node);
	return (RCM_SUCCESS);
}

static link_cache_t *
cache_lookup(rcm_handle_t *hd, char *rsrc, char options)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "LLDP: cache lookup(%s)\n", rsrc);

	assert(MUTEX_HELD(&cache_lock));
	if (options & CACHE_REFRESH) {
		/* drop lock since update locks cache again */
		(void) mutex_unlock(&cache_lock);
		(void) cache_update(hd);
		(void) mutex_lock(&cache_lock);
	}

	for (node = cache_head.lc_next; node != &cache_tail;
	    node = node->lc_next) {
		if (strcmp(rsrc, node->lc_resource) == 0) {
			rcm_log_message(RCM_TRACE2,
			    "LLDP: cache lookup succeeded(%s)\n", rsrc);
			return (node);
		}
	}
	return (NULL);
}

static void
node_free(link_cache_t *node)
{
	if (node != NULL) {
		free(node->lc_resource);
		free(node);
	}
}

static void
cache_insert(link_cache_t *node)
{
	assert(MUTEX_HELD(&cache_lock));

	/* insert at the head for best performance */
	node->lc_next = cache_head.lc_next;
	node->lc_prev = &cache_head;

	node->lc_next->lc_prev = node;
	node->lc_prev->lc_next = node;
}

static void
cache_remove(link_cache_t *node)
{
	assert(MUTEX_HELD(&cache_lock));
	node->lc_next->lc_prev = node->lc_prev;
	node->lc_prev->lc_next = node->lc_next;
	node->lc_next = NULL;
	node->lc_prev = NULL;
}

/*
 * Add (or refresh) the cache entry for one of lldpd's agents.
 */
static int
cache_add_agent(const lldp_stats_t *s)
{
	link_cache_t	*node;
	char		*rsrc;

	assert(MUTEX_HELD(&cache_lock));

	if ((rsrc = malloc(RCM_LINK_RESOURCE_MAX)) == NULL) {
		rcm_log_message(RCM_ERROR, _("LLDP: malloc error(%s): %u\n"),
		    strerror(errno), s->ls_linkid);
		return (-1);
	}
	(void) snprintf(rsrc, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, s->ls_linkid);

	for (node = cache_head.lc_next; node != &cache_tail;
	    node = node->lc_next) {
		if (strcmp(rsrc, node->lc_resource) == 0)
			break;
	}

	if (node != &cache_tail) {
		free(rsrc);
		node->lc_state &= ~CACHE_NODE_STALE;
		return (0);
	}

	if ((node = calloc(1, sizeof (link_cache_t))) == NULL) {
		free(rsrc);
		rcm_log_message(RCM_ERROR, _("LLDP: calloc: %s\n"),
		    strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_DEBUG, "LLDP: %s is a new resource (agent %s)\n",
	    rsrc, s->ls_link);

	node->lc_resource = rsrc;
	node->lc_linkid = s->ls_linkid;
	(void) strlcpy(node->lc_agent, s->ls_link, sizeof (node->lc_agent));
	node->lc_state = CACHE_NODE_NEW;
	cache_insert(node);
	return (0);
}

/*
 * cache_update() - Make the cache (and our registrations) match the links
 * lldpd currently has agents for.
 */
static int
cache_update(rcm_handle_t *hd)
{
	link_cache_t	*node, *nnode;
	lldp_stats_t	*stats = NULL;
	uint_t		n = 0;
	int		err;
	int		rv = 0;

	rcm_log_message(RCM_TRACE2, "LLDP: cache_update\n");

	(void) mutex_lock(&cache_lock);

	for (node = cache_head.lc_next; node != &cache_tail;
	    node = node->lc_next) {
		node->lc_state |= CACHE_NODE_STALE;
	}

	/*
	 * If lldpd isn't running, it has no agents, so everything is stale.
	 * If we can't tell, keep what we have.
	 */
	err = lldp_get_stats(NULL, &stats, &n);
	if (err == 0) {
		for (uint_t i = 0; i < n; i++) {
			if (cache_add_agent(&stats[i]) != 0)
				rv = -1;
		}
		lldp_stats_free(stats, n);
	} else if (err != ECONNREFUSED) {
		rcm_log_message(RCM_WARNING,
		    _("LLDP: cannot get lldpd's agents: %s\n"), strerror(err));
		for (node = cache_head.lc_next; node != &cache_tail;
		    node = node->lc_next) {
			node->lc_state &= ~CACHE_NODE_STALE;
		}
		rv = -1;
	}

	for (node = cache_head.lc_next; node != &cache_tail; node = nnode) {
		nnode = node->lc_next;

		/*
		 * Keep links we've offlined until they're onlined or removed
		 * (lldpd still has their agents, but may have restarted).
		 */
		if ((node->lc_state & CACHE_NODE_STALE) &&
		    !(node->lc_state & CACHE_NODE_OFFLINED)) {
			(void) rcm_unregister_interest(hd, node->lc_resource,
			    0);
			rcm_log_message(RCM_DEBUG, "LLDP: unregistered %s\n",
			    node->lc_resource);
			cache_remove(node);
			node_free(node);
			continue;
		}

		if (!(node->lc_state & CACHE_NODE_NEW))
			continue;

		if (rcm_register_interest(hd, node->lc_resource, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("LLDP: failed to register %s\n"),
			    node->lc_resource);
			rv = -1;
		} else {
			rcm_log_message(RCM_DEBUG, "LLDP: registered %s\n",
			    node->lc_resource);
			node->lc_state &= ~CACHE_NODE_NEW;
		}
	}

	(void) mutex_unlock(&cache_lock);
	return (rv);
}

static void
cache_free(void)
{
	link_cache_t *node;

	rcm_log_message(RCM_TRACE2, "LLDP: cache_free\n");

	(void) mutex_lock(&cache_lock);
	node = cache_head.lc_next;
	while (node != &cache_tail) {
		cache_remove(node);
		node_free(node);
		node = cache_head.lc_next;
	}
	(void) mutex_unlock(&cache_lock);
}
