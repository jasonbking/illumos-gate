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

#ifndef _LLDP_DOOR_H
#define	_LLDP_DOOR_H

/*
 * Private door protocol between lldpd and liblldp. This header is not
 * installed; it is only used to build lldpd and liblldp, which must agree
 * on LLDP_DOOR_VERSION.
 *
 * Every request is a lldp_door_req_t. Every reply begins with a
 * lldp_door_reply_t. If ldrp_error is non-zero, the request failed (with
 * an errno value) and nothing follows the header. Otherwise, ldrp_count
 * records follow, starting at offset LLDP_DOOR_REC_OFF.
 *
 * All structures use only fixed-size types and are laid out identically
 * for ILP32 and LP64, so 32-bit consumers can talk to a 64-bit lldpd (and
 * vice versa).
 *
 * LLDP_DOOR_CMD_NEIGHBORS
 *
 *	Returns the neighbors of every agent (ldrq_link is empty), or of a
 *	single agent. Agents are identified by their link's hardware name
 *	(e.g. 'igb0'), which is what's returned in ldn_link and the cursor;
 *	ldrq_link may also be the link's datalink name if it has been
 *	renamed. Each record is a lldp_door_nbr_t followed by the neighbor's
 *	most recently received LLDPDU, exactly as received (up to and
 *	including the End TLV), padded so that the next record is 8-byte
 *	aligned.
 *
 *	A reply holds at most LLDP_DOOR_REPLY_MAX bytes. If there were more
 *	neighbors than fit, LLDP_DOOR_F_MORE is set in ldrp_flags, and the
 *	caller should repeat the request with ldrq_cursor set to ldrp_next to
 *	retrieve the next page. An all-zero cursor starts from the beginning.
 *
 *	Neighbors are returned ordered by agent name, then by MSAP (chassis
 *	id, port id). The cursor records the position of the last neighbor
 *	returned rather than an index, so neighbors that are added or removed
 *	between pages never cause a neighbor to be returned twice. A neighbor
 *	added behind the cursor during pagination won't be returned.
 *
 *	Errors: ENOENT (no agent for ldrq_link), EINVAL (malformed request).
 *
 * LLDP_DOOR_CMD_STATS
 *
 *	Returns the statistics of every agent (ldrq_link is empty), or of a
 *	single agent (named as for LLDP_DOOR_CMD_NEIGHBORS). Each record is
 *	a lldp_door_stats_t (which also gives the agent's datalink id),
 *	ordered by agent name. Pagination works the
 *	same way as for LLDP_DOOR_CMD_NEIGHBORS, except the cursor only
 *	holds the name of the last agent returned (ldc_chassis_len and
 *	ldc_port_len are zero).
 *
 *	Errors: ENOENT (no agent for ldrq_link), EINVAL (malformed request).
 *
 * LLDP_DOOR_CMD_LINK_OFFLINE, LLDP_DOOR_CMD_LINK_ONLINE,
 * LLDP_DOOR_CMD_LINK_REMOVE
 *
 *	Sent by the lldp RCM module when the link with datalink id
 *	ldrq_linkid is being offlined (e.g. for DR), when that's undone (or
 *	the link is back online), and when it's been removed. On offline,
 *	lldpd sends a shutdown LLDPDU (if it was advertising) and closes the
 *	link, so it can be detached; on online, it reopens it (unless the
 *	agent is disabled); on remove, it destroys the agent. No records are
 *	returned; the request is complete when the reply is sent.
 *
 *	The caller must be in lldpd's zone and have {PRIV_SYS_DL_CONFIG} in
 *	its effective set.
 *
 *	Errors: ENOENT (no agent for the link), EPERM (insufficient
 *	privileges), EIO (the link couldn't be reopened), ESHUTDOWN (lldpd
 *	is exiting).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <liblldp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	LLDP_DOOR_PATH		"/var/run/lldp_door"

/* If set, overrides LLDP_DOOR_PATH (for both lldpd and liblldp) */
#define	LLDP_DOOR_ENV		"LLDP_DOOR"

#define	LLDP_DOOR_VERSION	2

/*
 * Maximum size of a reply. This is large enough for a record with the
 * largest possible LLDPDU (a received PDU is limited to the link's maximum
 * SDU, and to 64K by lldpd), so every page holds at least one record.
 */
#define	LLDP_DOOR_REPLY_MAX	(128 * 1024)

typedef enum lldp_door_cmd {
	LLDP_DOOR_CMD_NEIGHBORS = 1,
	LLDP_DOOR_CMD_STATS = 2,
	LLDP_DOOR_CMD_LINK_OFFLINE = 3,
	LLDP_DOOR_CMD_LINK_ONLINE = 4,
	LLDP_DOOR_CMD_LINK_REMOVE = 5,
} lldp_door_cmd_t;

/*
 * Position within the neighbor list. ldc_link is the agent of the last
 * neighbor returned, and ldc_chassis / ldc_port are the values (subtype
 * + id) of its Chassis ID and Port ID TLVs. An empty ldc_link means
 * 'start at the beginning'. For LLDP_DOOR_CMD_STATS, only ldc_link is
 * used.
 */
typedef struct lldp_door_cursor {
	char		ldc_link[MAXLINKNAMELEN];
	uint16_t	ldc_chassis_len;
	uint16_t	ldc_port_len;
	uint8_t		ldc_chassis[LLDP_CHASSIS_MAX + 1];
	uint8_t		ldc_port[LLDP_PORT_MAX + 1];
} lldp_door_cursor_t;

typedef struct lldp_door_req {
	uint32_t		ldrq_version;	/* LLDP_DOOR_VERSION */
	uint32_t		ldrq_cmd;	/* lldp_door_cmd_t */
	char			ldrq_link[MAXLINKNAMELEN];
	uint32_t		ldrq_linkid;	/* LLDP_DOOR_CMD_LINK_* */
	uint32_t		ldrq_pad;
	lldp_door_cursor_t	ldrq_cursor;
} lldp_door_req_t;

/* ldrp_flags */
#define	LLDP_DOOR_F_MORE	0x1	/* More data; reissue with ldrp_next */

typedef struct lldp_door_reply {
	uint32_t		ldrp_version;	/* LLDP_DOOR_VERSION */
	int32_t			ldrp_error;	/* 0 or an errno value */
	uint32_t		ldrp_flags;
	uint32_t		ldrp_count;	/* Number of records */
	lldp_door_cursor_t	ldrp_next;
} lldp_door_reply_t;

/* Offset of the first record in a reply */
#define	LLDP_DOOR_REC_OFF	P2ROUNDUP(sizeof (lldp_door_reply_t), 8)

typedef struct lldp_door_nbr {
	uint32_t	ldn_reclen;	/* Length of record incl. padding */
	uint16_t	ldn_pdu_len;	/* Length of ldn_pdu */
	uint16_t	ldn_ttl;	/* Seconds until the info ages out */
	char		ldn_link[MAXLINKNAMELEN];
	uint8_t		ldn_pdu[];
} lldp_door_nbr_t;

#define	LLDP_DOOR_NBR_RECLEN(pdulen)	\
	P2ROUNDUP(sizeof (lldp_door_nbr_t) + (pdulen), 8)

typedef struct lldp_door_stats {
	char			lds_link[MAXLINKNAMELEN];
	uint32_t		lds_linkid;	/* datalink_id_t */
	uint32_t		lds_pad;
	lldp_agent_stats_t	lds_stats;
} lldp_door_stats_t;

/* Records are fixed size, so this keeps every one 8-byte aligned */
CTASSERT(sizeof (lldp_door_stats_t) % 8 == 0);

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_DOOR_H */
