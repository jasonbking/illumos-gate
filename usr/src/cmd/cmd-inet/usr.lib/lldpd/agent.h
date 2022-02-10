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
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tx_state {
	TX_LLDP_INITIALIZE	= 0,
	TX_IDLE			= 1,
	TX_SHUTDOWN_FRAME	= 2,
	TX_INFO_FRAME		= 3,
} tx_state_t;
#define	TX_BEGIN		TX_LLDP_INITIALIZE

typedef enum timer_state {
	TX_TIMER_INITIALIZE	= 0,
	TX_TIMER_IDLE		= 1,
	TX_TIMER_EXPIRES	= 2,
	SIGNAL_TX		= 3,
	TX_TICK			= 4,
	TX_FAST_START		= 5,
} timer_state_t;
#define	TIMER_BEGIN		TX_TIMER_INITIALIZE

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

struct log;

typedef struct agent {
	mutex_t			lock;
	condvar_t		cv;

	char			*name;
	log_t			*log;
	thread_t		tid;

	dlpi_handle_t		dlh;
	dlpi_notifyid_t		dl_nid;
	dlpi_info_t		dl_info;

	bool			exit;
	bool			port_enabled;
	lldp_admin_status_t	status;

	uu_list_t		*neighbors;

	lldp_clock_t		clk;
	lldp_timer_t		ttx_timer;
	lldp_timer_t		ttx_shutdown;
	lldp_timer_t		t_toomany;

	tx_state_t		tx_state;
	log_t			tx_log;

	rx_state_t		rx_state;
	log_t			rx_log;

	timer_state_t		timer_state;
	log_t			timer_log;

	uint16_t		tx_ttl;
	uint16_t		rx_ttl;
	uint16_t		tx_interval;
	uint16_t		tx_fast_msg;
	uint8_t			tx_credit_max;
	uint8_t			tx_credit;
	uint8_t			tx_fast;
	uint8_t			tx_fast_init;
	uint8_t			tx_msg_hold;
	uint8_t			reinit_delay;

	bool			tx_ttr;
	bool			tx_shutdown;
	bool			tx_now;
	bool			rx_info_age;
	bool			recv_frame;
	bool			rx_changes;
	bool			bad_frame;
	bool			local_changes;
	bool			new_neighbor;
	bool			tx_tick;
	bool			too_many_neighbors;

	buf_t			rxbuf;
	buf_t			txbuf;

	lldp_agent_stats_t	stats;
} lldp_agent_t;

agent_t *agent_create(const char *, int, struct periodic_handle);
void agent_destroy(agent_t *);

bool agent_enable(agent_t *);
void agent_disable(agent_t *);
void agent_set_status(agent_t *, lldp_admin_status_t);
void agent_local_change(agent_t *);
void agent_rx_frame(agent_t *);
void agent_age_rxinfo(agent_t *);
size_t agent_num_neighbors(agent_t *);

#ifdef __cplusplus
}
#endif

#endif /* _AGENT_H */
