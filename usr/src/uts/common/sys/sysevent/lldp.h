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

#ifndef _SYS_SYSEVENT_LLDP_H
#define	_SYS_SYSEVENT_LLDP_H

/*
 * LLDP event definitions. These are private, and subject to change.
 *
 * lldpd publishes these on the LLDP_EVENT_CHAN event channel (see
 * sysevent_evc_bind(3SYSEVENT)), rather than through syseventd, so it
 * needs no privileges to do so. Subscribing to the channel requires access
 * to /dev/sysevent.
 *
 * Event type EC_LLDP/ESC_LLDP_REMOTE_CHANGE
 *
 *	The information lldpd has about the neighbors of one of its agents
 *	(its remote systems data) has changed: a neighbor has been added,
 *	removed (it sent a shutdown LLDPDU, its information aged out, or the
 *	link went down), or has sent different information. This is the
 *	equivalent of the LLDP-V2-MIB's lldpV2RemTablesChange notification.
 *
 *	Events are rate limited: for each agent, at most one is published per
 *	notification_interval seconds (an lldpd agent property), each
 *	covering every change since the last. They can be disabled for an
 *	agent with its notify property. The counters are the agent's totals
 *	(as 'lldp stats' shows), so a subscriber can tell what kinds of
 *	change happened since the previous event; 'lldp show-neighbors'
 *	shows the neighbors themselves.
 *
 *	Event Class	- EC_LLDP
 *	Event Sub-Class	- ESC_LLDP_REMOTE_CHANGE
 *	Event Vendor	- LLDP_EVENT_VENDOR
 *	Event Publisher	- LLDP_EVENT_PUBLISHER
 *
 *	Attribute Name	- LLDP_EVENT_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- LLDP_EVENT_CUR_VERSION
 *
 *	Attribute Name	- LLDP_EVENT_LINK
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- <the agent's link, by its hardware name (e.g. igb0)>
 *
 *	Attribute Name	- LLDP_EVENT_LINKID
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- <its datalink id>
 *
 *	Attribute Name	- LLDP_EVENT_NEIGHBORS
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- <its current number of neighbors>
 *
 *	Attribute Name	- LLDP_EVENT_INSERTS, LLDP_EVENT_UPDATES,
 *			  LLDP_EVENT_DELETES, LLDP_EVENT_AGEOUTS,
 *			  LLDP_EVENT_DROPS
 *	Attribute Type	- SE_DATA_TYPE_UINT64
 *	Attribute Value	- <the agent's count of neighbors added, changed,
 *			  removed (for any reason), removed because their
 *			  information aged out, and not added because it
 *			  had too many>
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	LLDP_EVENT_CHAN		"org.illumos:lldp:events"
#define	LLDP_EVENT_VENDOR	"illumos"
#define	LLDP_EVENT_PUBLISHER	"lldpd"

#define	LLDP_EVENT_VERSION	"lldp_event_version"
#define	LLDP_EVENT_LINK		"lldp_link"
#define	LLDP_EVENT_LINKID	"lldp_linkid"
#define	LLDP_EVENT_NEIGHBORS	"lldp_neighbors"
#define	LLDP_EVENT_INSERTS	"lldp_inserts"
#define	LLDP_EVENT_UPDATES	"lldp_updates"
#define	LLDP_EVENT_DELETES	"lldp_deletes"
#define	LLDP_EVENT_AGEOUTS	"lldp_ageouts"
#define	LLDP_EVENT_DROPS	"lldp_drops"

#define	LLDP_EVENT_CUR_VERSION	1

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_LLDP_H */
