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

#ifndef _AGENT_H
#define	_AGENT_H

#include <inttypes.h>
#include <libdlpi.h>
#include <liblldp.h>
#include <synch.h>
#include <thread.h>
#include <libuutil.h>

#include "buf.h"
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

/* XXX: There's probably a better place for this */
#define	LLDP_PDU_MAX	512

typedef struct tx {
	tx_state_t	tx_state;
	struct log	*tx_log;

	uint8_t		tx_frame[LLDP_PDU_MAX];
	buf_t		tx_buf;

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

typedef struct rx {
	rx_state_t		rx_state;
	struct log		*rx_log;

	uint8_t			rx_frame[LLDP_PDU_MAX];
	buf_t			rx_buf;
	struct neighbor		*rx_neighbor;
	struct neighbor		*rx_curr_neighbor;
	uu_list_index_t		rx_curr_idx;
	uint16_t		rx_ttl;

	lldp_timer_t		rx_too_many_neighbors_timer;
	bool			rx_info_age;
	bool			rx_recv_frame;
	bool			rx_bad_frame;
	bool			rx_changes;
	bool			rx_too_many_neighbors;
} rx_t;

typedef struct agent_cfg {
	lldp_port_t		ac_port;
	lldp_admin_status_t	ac_status;
	lldp_tx_core_tlv_t	ac_tx_tlvs;
	lldp_tx_8021_tlv_t	ac_tx_8021_tlvs;
	lldp_tx_8023_tlv_t	ac_tx_8023_tlvs;
	char			*ac_desc;
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

	char			*a_name;
	struct log		*a_log;
	thread_t		a_tid;

	dlpi_handle_t		a_dlh;
	dlpi_notifyid_t		a_dl_nid;
	dlpi_info_t		a_dl_info;
	fd_cb_t			a_dl_cb;

	bool			a_exit;
	bool			a_port_enabled;

	agent_cfg_t		a_cfg;

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

void	agent_init(int);

agent_t	*agent_create(const char *);
void	agent_destroy(agent_t *);
bool	agent_enable(agent_t *);
void	agent_disable(agent_t *);

void			agent_set_status(agent_t *, lldp_admin_status_t);
lldp_admin_status_t	agent_get_status(agent_t *);

void agent_local_change(agent_t *);
void agent_rx_frame(agent_t *);
size_t agent_num_neighbors(agent_t *);

#ifdef __cplusplus
}
#endif

#endif /* _AGENT_H */
