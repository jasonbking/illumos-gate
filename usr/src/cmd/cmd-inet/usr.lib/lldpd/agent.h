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
 * Copyright 2024 Jason King
 */

#ifndef _AGENT_H
#define	_AGENT_H

#include <inttypes.h>
#include <libdlpi.h>
#include <liblldp.h>
#include <libuutil.h>
#include <synch.h>
#include <thread.h>

#include "lldpd.h"
#include "timer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct log;
struct neighbor;

typedef enum tx_state {
	TX_LLDP_INITIALIZE	= 0,
	TX_IDLE			= 1,
	TX_SHUTDOWN_FRAME	= 2,
	TX_INFO_FRAME		= 3,
} tx_state_t;
#define	TX_BEGIN		TX_LLDP_INITIALIZE

typedef struct tx {
	tx_state_t	tx_state;
	struct log	*tx_log;

	lldp_timer_t	tx_shutdown;
	uint16_t	tx_ttl;
	bool		tx_now;
} tx_t;

typedef enum ttr_state {
	TX_TIMER_INITIALIZE	= 0,
	TX_TIMER_IDLE		= 1,
	TX_TIMER_EXPIRES	= 2,
	SIGNAL_TX		= 3,
	TX_TICK			= 4,
	TX_FAST_START		= 5,
} ttr_state_t;
#define	TTR_BEGIN		TX_TIMER_INITIALIZE

typedef struct ttr {
	ttr_state_t	ttr_state;
	struct log	*ttr_log;

	lldp_timer_t	ttr_timer;
	uint16_t	ttr_tx_fast;
	uint16_t	ttr_tx_credit;
	bool		ttr_tick;
} ttr_t;

typedef enum rx_state {
	LLDP_WAIT_PORT_OPERATIONAL	= 0,
	DELETE_AGED_INFO		= 1,
	RX_LLDP_INITIALIZE		= 2,
	RX_WAIT_FOR_FRAME		= 3,
	RX_FRAME			= 4,
	DELETE_INFO			= 5,
	UPDATE_INFO			= 6,
} rx_state_t;
#define	RX_BEGIN		LLDP_WAIT_PORT_OPERATIONAL

/*
 * A received frame waiting to be processed by the rx state machine.
 */
typedef struct rx_pdu {
	uint8_t		*rp_data;	/* Exactly rp_len bytes */
	size_t		rp_len;
	uint8_t		rp_src[DLPI_PHYSADDR_MAX];
	size_t		rp_srclen;
} rx_pdu_t;

/*
 * Frames received but not yet processed. Since a link normally has a single
 * neighbor (e.g. a switch port), this only needs to absorb small bursts
 * (e.g. a neighbor's fast start or a shutdown PDU followed by a new one).
 * If it fills, newly received frames are discarded.
 */
#define	RX_QUEUE_LEN	4

typedef struct rx {
	rx_state_t		rx_state;
	struct log		*rx_log;

	/*
	 * Buffer frames are received into (by recv_frame(), on the main
	 * thread), sized to the agent's maximum PDU (see agent_max_pdu()).
	 * Only resized by recv_frame() before receiving into it.
	 */
	uint8_t			*rx_buf;
	size_t			rx_buf_size;

	/* Queue of received frames: a ring of rx_qcount from rx_qhead */
	rx_pdu_t		rx_queue[RX_QUEUE_LEN];
	uint_t			rx_qhead;
	uint_t			rx_qcount;

	struct neighbor		*rx_neighbor;
	struct neighbor		*rx_curr_neighbor;
	uint16_t		rx_ttl;

	lldp_timer_t		rx_too_many_neighbors_timer;
	bool			rx_info_age;
	bool			rx_bad_frame;
	bool			rx_changes;
	bool			rx_too_many_neighbors;
} rx_t;

/*
 * Link information sent in the IEEE 802.3 MAC/PHY Configuration/Status TLV.
 * Updated from the main thread (with a_lock held once the agent is
 * running) when the agent is created and on link state/speed changes.
 */
typedef struct agent_phy {
	bool		ap_autoneg_sup;	/* Auto-negotiation supported */
	bool		ap_autoneg_en;	/* Auto-negotiation enabled */
	uint16_t	ap_adv_caps;	/* ifMauAutoNegCapAdvertisedBits */
	uint16_t	ap_mau;		/* Operational dot3MauType */
} agent_phy_t;

/*
 * What the Port ID TLV is built from (the port_id_type SMF property), with
 * the Port ID subtype used for each in parentheses.
 */
typedef enum port_id_src {
	PORT_ID_IFNAME,		/* Datalink name (interface name) */
	PORT_ID_HWNAME,		/* Hardware name (interface name) */
	PORT_ID_MACADDR,	/* Factory MAC address (MAC address) */
	PORT_ID_LABEL,		/* topo label (locally assigned) */
	PORT_ID_LOCAL,		/* port_id property (locally assigned) */
} port_id_src_t;

typedef struct agent_cfg {
	lldp_admin_status_t	ac_status;
	port_id_src_t		ac_port_id_src;
	char			*ac_port_id;	/* For PORT_ID_LOCAL */
	lldp_tx_core_tlv_t	ac_tx_tlvs;
	lldp_tx_8021_tlv_t	ac_tx_8021_tlvs;
	lldp_tx_8023_tlv_t	ac_tx_8023_tlvs;
	char			*ac_desc;

	char			*ac_label;
	char			*ac_devname;
	uint32_t		ac_portnum;

	uint16_t		ac_mtu;

	uint16_t		ac_tx_hold;
	uint16_t		ac_tx_interval;
	uint16_t		ac_reinit_delay;
	uint16_t		ac_tx_credit_max;
	uint16_t		ac_tx_fast_msg;
	uint16_t		ac_tx_fast_init;

	uint16_t		ac_neighbor_max;
} agent_cfg_t;

typedef struct agent {
	uu_list_node_t		a_node;

	mutex_t			a_lock;
	cond_t			a_cv;

	/*
	 * The hardware name of the link (e.g. 'igb0') is the agent's
	 * canonical name: it's used for SMF property groups, logging, and
	 * door replies. If the datalink has been renamed, a_linkname is its
	 * current datalink name (otherwise it's the same as a_name); lookups
	 * by link (agent_find(), topo) accept either.
	 */
	char			*a_name;	/* RO */
	char			*a_linkname;	/* RO */
	datalink_id_t		a_linkid;	/* RO */
	struct log		*a_log;		/* RW */
	thread_t		a_tid;		/* RO */

	dlpi_handle_t		a_dlh;
	dlpi_notifyid_t		a_dl_nid;
	dlpi_info_t		a_dl_info;
	fd_cb_t			a_dl_cb;

	bool			a_exit;		/* RW */
	bool			a_send_shutdown; /* RW: on exit */
	bool			a_port_enabled;	/* RW */

	agent_cfg_t		a_cfg;
	agent_phy_t		a_phy;

	/*
	 * The link's factory MAC address, or if the driver can't report
	 * that, its current address (a_mac_factory is false).
	 */
	uint8_t			a_macaddr[DLPI_PHYSADDR_MAX];
	size_t			a_macaddrlen;
	bool			a_mac_factory;

	/*
	 * The Port ID we advertise, built from the configuration and the
	 * system by agent_port_update(). Neighbors identify our information
	 * by chassis id and port id, so when the port id of a running agent
	 * changes, the new id is staged in a_new_port; the agent's thread
	 * then sends a shutdown LLDPDU with the old id (so neighbors discard
	 * it immediately) before switching to the new one.
	 *
	 * a_port_desc is the Port Description used when none is configured
	 * (port_desc): the identifying information about the port that the
	 * port id doesn't already carry.
	 */
	lldp_port_t		a_port;
	lldp_port_t		a_new_port;
	bool			a_port_change;
	char			*a_port_desc;

	uu_list_t		*a_neighbors;

	lldp_clock_t		a_clk;
	rx_t			a_rx;
	tx_t			a_tx;
	ttr_t			a_ttr;

	bool			a_local_changes;
	bool			a_new_neighbor;

	lldp_agent_stats_t	a_stats;
} agent_t;

#define	IS_AGENT_THREAD(a)	((a)->a_tid == thr_self())

extern mutex_t		agent_list_lock;
extern uu_list_t	*agent_list;

void	agent_init(void);

agent_t	*agent_create(const char *, const char *, datalink_id_t);
agent_t	*agent_find(const char *);
void	agent_start(agent_t *);
void	agent_stop(agent_t *, bool);
void	agent_wait(agent_t *);
void	agent_destroy(agent_t *);
bool	agent_enable(agent_t *);
void	agent_disable(agent_t *);

void			agent_set_cfg(agent_t *, agent_cfg_t *);
void			agent_set_status(agent_t *, lldp_admin_status_t);
lldp_admin_status_t	agent_get_status(agent_t *);

void agent_local_change(agent_t *);
size_t agent_num_neighbors(agent_t *);

#ifdef __cplusplus
}
#endif

#endif /* _AGENT_H */
