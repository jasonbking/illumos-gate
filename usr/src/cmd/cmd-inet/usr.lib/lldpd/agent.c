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

#include <atomic.h>
#include <errno.h>
#include <inttypes.h>
#include <libuutil.h>
#include <pthread.h>
#include <umem.h>

#include "agent.h"
#include "log.h"
#include "neighbor.h"


#define	DEFAULT_MSG_FAST_TX	1
#define	DEFAULT_MSG_TX_HOLD	4
#define	DEFAULT_MSG_TX_INTERVAL	30
#define	DEFAULT_REINIT_DELAY	2
#define	DEFAULT_TX_CREDIT_MAX	5
#define	DEFAULT_TX_FAST_INIT	4

static void *agent_thread(void *);

static void rx_init_lldp(agent_t *);
static void delete_objects(agent_t *);
static void tx_add_credit(agent_t *);

static bool tx_machine(agent_t *);
static bool tx_next_state(agent_t *);

static bool rx_machine(agent_t *);
static bool rx_next_state(agent_t *);

static bool timer_machine(agent_t *);
static bool timer_next_state(agent_t *);

static void ttx_timer_cb(agent_t *);
static void ttx_shutdown_cb(agent_t *);
static void too_many_cb(agent_t *);

static const char *tx_statestr(tx_state_t);
static const char *rx_statestr(rx_state_t);
static const char *timer_statestr(timer_state_t);

static uu_list_pool_t	*neighbor_pool;

static const uint_t	lldp_sap = 0x88cc;
static const uint8_t	lldp_addr[ETHERADDRL] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e
};

static inline bool
dec(uint16_t *vp)
{
	if (*vp == 0)
		return (false);
	*vp--;
	return (true);
}

agent_t *
agent_create(const char *name)
{
	agent_t *a;
	int ret;

	a = umem_zalloc(sizeof (*a), UMEM_DEFAULT);
	if (a == NULL)
		goto fail;

	mutex_init(&a->lock, ERRORCHECKMUTEX, NULL);
	cond_init(&a->cv, DEFAULTCV, NULL);

	a->name = uu_strdup(name);
	if (a->name)
		goto fail;

	if (log_child(log, &a->log,
	    LOG_T_STRING, "agent", a->name,
	    LOG_T_END) != 0)
		goto fail;

	if (log_child(a->log, &a->tx_log,
	    LOG_T_STRING, "state_machine", "tx",
	    LOG_T_END) != 0)
		goto fail;

	if (log_child(a->log, &a->rx_log,
	    LOG_T_STRING, "state_machine", "rx",
	    LOG_T_END) != 0)
		goto fail;

	if (log_child(a->log, &a->timer_log,
	    LOG_T_STRING, "state_machine", "timer",
	    LOG_T_END) != 0)
		goto fail;

	if (!lldp_timer_init(a->clk, LLDP_TIMER_TX, &a->ttx_timer, a,
	    ttx_timer_cb))
		goto fail;

	if (!lldp_timer_init(a->clk, LLDP_TIMER_SHUT, &a->ttx_shutdown, a,
	    ttx_shutdown_cb))
		goto fail;

	if (!lldp_timer_init(a->clk, LLDP_TIMER_TOO_MANY, &a->t_toomany, a,
	    too_many_cb))
		goto fail;

	a->neighbors = neighbor_list_new(a);
	a->ph = ph;
	a->evport = evport;

	a->tx_fast_msg = DEFAULT_MSG_FAST_TX;
	a->tx_msg_hold = DEFAULT_MSG_TX_HOLD;
	a->tx_interval = DEFAULT_MSG_TX_INTERVAL;
	a->reinit_delay = DEFAULT_REINIT_DELAY;
	a->tx_credit_max = DEFAULT_TX_CREDIT_MAX;
	a->tx_fast_init = DEFAULT_TX_FAST_INIT;

	/* XXX: Override defaults from config */

	a->tx_state = TX_BEGIN;
	a->rx_state = RX_BEGIN;
	a->timer_state = TIMER_BEGIN;
	a->port_enabled = false;

	ret = thr_create(NULL, 0, agent_thread, a, 0, &a->tid);
	if (ret != 0) {
		/*
		 * Use the agent's log instance to include the agent name
		 * in the output.
		 */
		log_syserr(a->log, "failed to create agent thread", ret);
		goto fail;
	}

	return (a);

fail:
	log_error(log, "out of memory while creating agent",
	    LOG_T_STRING, "agent", name,
	    LOG_T_END);
	agent_destroy(a);
	return (NULL);
}

void
agent_destroy(agent_t *a)
{
	if (a == NULL)
		return;

	if (a->tid != 0) {
		thread_t tid = a->tid;

		a->exit = true;
		membar_producer();
		VERIFY0(cond_signal(&a->cv));
		VERIFY0(thr_join(tid, NULL, NULL));
	}

	VERIFY(!a->port_enabled);
	VERIFY(a->dlh = NULL);

	lldp_timer_fini(&a->ttx_shutdown);
	lldp_timer_fini(&a->ttx_timer);
	log_fini(a->timer_log);
	log_fini(a->rx_log);
	log_fini(a->tx_log);
	log_fini(a->log);
	uu_free(a->name);
	uu_list_destroy(a->neighbors);
	VERIFY0(cond_destroy(&a->cv));
	VERIFY0(mutex_destroy(&a->lock));
	umem_free(a, sizeof (*a));
}

bool
agent_enable(agent_t *a)
{
	int ret;

	mutex_enter(&a->lock);
	a->port_enabled = true;
	VERIFY0(cond_signal(&a->cv));
	return (true);
}

void
agent_disable(agent_t *a)
{
	mutex_enter(&a->lock);
	a->port_enabled = false;
	VERIFY0(cond_signal(&a->cv));
	mutex_exit(&a->lock);
}

void
agent_set_status(agent_t *a, lldp_admin_status_t status)
{
	mutex_enter(&a->lock);
	a->status = status;
	VERIFY0(cond_signal(&a->cv));
	mutex_exit(&a->lock);
}

void
agent_age_rxinfo(agent_t *a)
{
	mutex_enter(&a->lock);
	a->rx_info_age = true;
	VERIFY0(cond_signal(&a->cv));
	mutex_exit(&a->lock);
}

static void *
agent_thread(void *arg)
{
	agent_t		*a = arg;
	int		ret;
	bool		run_tx, run_rx, run_timer;
	timestruc_t	tick;

	log = a->log;

	mutex_enter(&a->lock);

	ret = pthread_setname_np(pthread_self(), a->name);
	if (ret != 0) {
		log_syserr(log, "failed to set agent thread name", ret);
		mutex_exit(&a->lock);
		return (NULL);
	}

	run_tx = tx_machine(a);
	run_rx = rx_machine(a);
	run_timer = timer_machine(a);

	lldp_clock_tick(a->clk, &tick);
	while (!a->exit) {
		/*
		 * Run each state machine until no conditions are met in
		 * each respective machine to allow them to transition to
		 * a new state.
		 */
		do {
			if (run_tx)
				run_tx = tx_machine(a);
			if (run_rx)
				run_rx = rx_machine(a);
			if (run_timer)
				run_timer = timer_machine(a);
		} while (run_tx || run_rx || run_timer);

		/*
		 * Wait for an external trigger (via cv) or for the clock
		 * to tick, then recheck for any state transitions.
		 */
		while (!run_tx && !run_rx && !run_timer) {
			ret = cond_reltimedwait(&a->cv, &a->lock, &tick);

			if (a->exit)
				break;

			if (ret == ETIME) {
				mutex_enter(&a->lock);
				lldp_clock_tock(a->clk);
				lldp_clock_tick(a->clk, &tick);
			}

			run_tx = tx_next_state(a);
			run_rx = rx_next_state(a);
			run_timer = timer_next_state(a);
		}		
	}

	return (a);
}

static uint16_t
tx_ttl(const agent_t *a)
{
	uint32_t val = a->msg_tx_interval * a->msg_tx_hold + 1;
	return (MIN(UINT16_MAX, val));
}

static bool
tx_machine(agent_t *a)
{
	log_debug(a->tx_log, "state machine running",
	    LOG_T_STRING, "state", tx_statestr(a->tx_state),
	    LOG_T_END);

	switch (a->tx_state) {
	case TX_LLDP_INITIALIZE:
		tx_initialize(a);
		lldp_timer_set(&a->ttx_shutdown, 0);
		break;
	case TX_IDLE:
		log_trace(a->tx_log, "set tx_ttl",
		    LOG_T_UINT32, "tx_ttl", (uint32_t)a->tx_ttl,
		    LOG_T_END);
		a->tx_ttl = tx_ttl(a);
		break;
	case TX_SHUTDOWN_FRAME:
		make_shutdown_pdu(a);
		tx_frame(a);
		lldp_timer_set(&a->ttx_shutdown, a->reinit_delay);
		break;
	case TX_INFO_FRAME:
		make_pdu(a);
		tx_frame(a);
		if (dec(&a->tx_credit)) {
			log_trace(a->tx_log, "dec(tx_credit)",
			    LOG_T_UINT32, "tx_credit", (uint32_t)a->tx_credit,
			    LOG_T_END);
		}
		a->tx_now = false;
		break;
	}

	return (tx_next_state(a));
}

static bool
tx_next_state(agent_t *restrict a)
{
	tx_state_t next;

	if (!a->port_enabled) {
		next = TX_LLDP_INITIALIZE;
		goto done;
	}

	switch (a->tx_state) {
	case TX_LLDP_INITIALIZE:
		if (a->status == LLDP_LINK_TX || a->status == LLDP_LINK_TXRX) {
			next = TX_IDLE;
			break;
		}
		return (false);
	case TX_IDLE:
		if (a->status == LLDP_LINK_DISABLED ||
		    a->status == LLDP_LINK_RX) {
			next = TX_SHUTDOWN_FRAME;
			break;
		}

		if (a->tx_now && a->tx_credit > 0) {
			next = TX_INFO_FRAME;
			break;
		}
		return (false);
	case TX_SHUTDOWN_FRAME:
		if (a->tx_shutdown) {
			next = TX_LLDP_INITIALIZE;
			break;
		}
		return (false);
	case TX_INFO_FRAME:
		next = TX_IDLE;
		break;
	}

done:
	log_debug(a->tx_log, "state transition",
	    LOG_T_STRING, "oldstate", tx_statestr(a->tx_state),
	    LOG_T_STRING, "newstate", tx_statestr(next),
	    LOG_T_END);

	a->tx_state = next;
	return (true);
}

static bool
rx_machine(agent_t *a)
{
	log_debug(a->rx_log, "state machine running",
	    LOG_T_STRING, "state", rx_statestr(a->rx_state),
	    LOG_T_END);

	switch (a->rx_state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		break;
	case DELETE_AGED_INFO:
		delete_objects(a);
		a->rx_info_age = false;
		something_changed_remote(a);
		break;
	case RX_LLDP_INITIALIZE:
		rx_init_lldp(a);
		a->rcv_frame = false;
		break;
	case RX_WAIT_FOR_FRAME:
		a->bad_frame = false;
		a->rx_info_age = false;
		break;
	case RX_FRAME:
		a->rx_changes = false;
		a->rcv_frame = false;
		rx_process_frame(a);
		break;
	case DELETE_INFO:
		delete_objects(a);
		something_changed_remote(a);
		break;
	case UPDATE_INFO:
		update_objects(a);
		something_changed_remote(a);
		break;
	}

	return (rx_next(a));
}

static bool
rx_next(agent_t *a)
{
	rx_state_t next;

	if (!a->rx_info_age && !a->port_enabled) {
		next = LLDP_WAIT_PORT_OPERATIONAL;
		goto done;
	}

	switch (a->rx_state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		if (a->rx_info_age) {
			next = DELETE_AGED_INFO;
			break;
		}

		if (a->port_enabled)
			next = RX_LLDP_INITIALIZE;
			break;
		}
		return (false);
	case DELETE_AGED_INFO:
		next = LLDP_WAIT_PORT_OPERATIONAL;
		break;
	case RX_LLDP_INITIALIZE:
		if (a->status == LLDP_LINK_RX ||
		    a->status == LLDP_LINK_TXRX) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}
		return (false);
	case RX_WAIT_FOR_FRAME:
		if (a->rx_info_age) {
			next = DELETE_INFO;
			break;
		}

		if (a->rcv_frame) {
			next = RX_FRAME;
			break;
		}

		if (a->status == LLDP_LINK_DISABLED ||
		    a->status == LLDP_LINK_TX) {
			next = RX_LLDP_INITIALIZE;
			break;
		}
		return (false);
	case RX_FRAME:
		if (a->rx_ttl == 0) {
			next = DELETE_INFO;
			break;
		}

		if (a->rx_ttl != 0 && a->rx_changes) {
			next = UPDATE_INFO;
			break;
		}

		if (a->bad_frame || (a->rx_ttl != 0 && !a->rx_changes)) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}
		return (false);
	case DELETE_INFO:
		next = RX_WAIT_FOR_FRAME;
		break;
	case UPDATE_INFO:
		next = RX_WAIT_FOR_FRAME;
		break;
	}

done:
	log_debug(a->rx_log, "state transition",
	    LOG_T_STRING, "oldstate", rx_statestr(a->rx_state),
	    LOG_T_STRING, "newstate", rx_statestr(next),
	    LOG_T_END);

	a->rx_state = next;
	return (true);
}

static bool
timer_machine(agent_t *a)
{
	log_debug(a->timer_log, "state machine running",
	    LOG_T_STRING, "state", timer_statestr(a->timer_state),
	    LOG_T_END);

	switch (a->timer_state) {
	case TX_TIMER_INITIALIZE:
		lldp_timer_set(&a->ttx_tick, 0);
		lldp_timer_set(&a->ttx_timer, 0);
		a->tx_tick = false;
		a->tx_now = false;
		a->tx_ttr = false;
		a->tx_fast = 0;
		a->new_neighbor = false;
		a->tx_credit = a->tx_credit_max;
		break;
	case TX_TIMER_IDLE:
		lldp_timer_set(&a->ttx_tick, 1);
		break;
	case TX_TICK:
		a->tx_tick = false;
		tx_add_credit(a);
		break;
	case TX_TIMER_EXPIRES:
		if (dec(&a->tx_fast)) {
			log_trace(&a->tx_log, "decremented tx_fast",
			    LOG_T_UINT32, "tx_fast", (uint32_t)a->tx_fast,
			    LOG_T_END);
		}
		break;
	case SIGNAL_TX:
		a->tx_now = true;
		a->local_change = false;
		lldp_timer_set(&a->ttx_timer,
		    a->tx_fast > 0 ? a->msg_fast_tx : a->msg_tx_interval);
		break;
	case TX_FAST_START:
		a->new_neighbor = false;
		if (a->tx_fast == 0)
			a->tx_fast = a->tx_fast_init;
		break;
	}

	return (timer_next(a));
}

static bool
timer_next(agent_t *a)
{
	timer_state_t next;

	if (!a->port_enabled || a->admin_status == LLDP_LINK_DISABLED ||
	    a->admin_status == LLDP_LINK_RX) {
		next = TX_TIMER_INITIALIZE;
		goto done;
	}

	switch (a->timer_state) {
	case TX_TIMER_INITIALIZE:
		if (a->status == LLDP_LINK_TX ||
		    a->status == LLDP_LINK_TXRX) {
			next = TX_TIMER_IDLE;
			break;
		}
		return (false);
	case TX_TIMER_IDLE:
		if (a->local_change) {
			next = SIGNAL_TX;
			break;
		}

		if (a->tx_ttr) {
			next = TX_TIMER_EXPIRES;
			break;
		}

		if (a->new_neighbor) {
			next = TX_FAST_START;
			break;
		}

		if (a->tx_tick) {
			next = TX_TICK;
			break;
		}
		return (false);
	case TX_TIMER_EXPIRES:
		next = SIGNAL_TX;
		break;
	case TX_TICK:
		next = TX_TIMER_IDLE;
		break;
	case SIGNAL_TX:
		next = TX_TIMER_IDLE;
		break;
	case TX_FAST_START:
		next = TX_TIMER_EXPIRES;
		break;
	}

done:
	log_debug(a->timer_log, "state transition",
	    LOG_T_STRING, "oldstate", timer_statestr(a->timer_state),
	    LOG_T_STRING, "newstate", timer_statestr(next),
	    LOG_T_END);

	a->timer_state = next;

	return (true);
}

static void
rx_init_lldp(agent_t *a)
{
	void		*cookie = NULL;
	neighbors_t	*nb;
	int		ret;

	a->too_many_neighbors = false;

	while ((nb = uu_list_teardown(a->neighbors, &cookie)) != NULL)
		neighbor_free(nb);

	ret = dlpi_open(a->name, &a->dlh, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(a->rx_log, "failed to open link", ret);
		a->port_enabled = false;
		return;
	}

	ret = dlpi_info(a->dlh, &a->dl_info, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(a->rx_log, "failed to get link info", ret);
		goto fail;
	}

	ret = dlpi_enabmulti(a->dlh, lldp_addr, sizeof (lldp_addr));
	if (ret != DLPI_SUCCESS) {
		log_dlerr(a->rx_log, "failed to bind to LLDP multicast address",
		    LOG_T_END);
		goto fail;
	}

	ret = dlpi_bind(a->dlh, lldp_sap, NULL);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(a->rx_log, "failed to bind to LLDP SAP", LOG_T_END);
		goto fail;
	}

	/* TODO: schedule fd */
	return;

fail:
	dlpi_close(a->dlh);
	a->dlh = NULL:
	a->port_enabled = false;
}

static void
delete_objects(agent_t *a)
{
	char		chassis[256];
	char		port[256];
	neighbor_t	*nb;
	uu_list_walk_t	*wk;
	time_t		now;
	uint32_t	count;

	log_debug(a->rx_log, "ageing out neighbors", LOG_T_END);

	now = time(NULL);

	wk = uu_list_walk_start(a->neighbors, UU_WALK_ROBUST);
	if (wk == NULL) {
		log_fatal(a->rx_log, "cannot iterate through neighbors",
		    LOG_T_END);
		return;
	}

	count = 0;
	while ((nb = uu_list_walk_next(wk)) != NULL) {
		if (nb->nb_time + nb->nb_ttl > now)
			continue;

		(void) lldp_chassis_str(&nb.nb_chassis , chassis,
		    sizeof (chassis));
		(void) lldp_port_str(&nb.nb_port, port, sizeof (port));

		log_info(a->rx_log, "ageing out neighbor",
		    LOG_T_STRING, "chassis", chassis,
		    LOG_T_STRING, "port", port,
		    LOG_T_END);

		uu_list_remove(a->neighbors, nb);
		neighbor_free(nb);
		count++;
	}

	log_info(a->rx_log, "ageing out complete",
	    LOG_T_UINT32, "numaged", count,
	    LOG_T_END);

	uu_list_walk_end(wk);
}

static void
tx_add_credit(agent_t *a)
{
	if (a->tx_credit == a->tx_credit_max)
		return;
	a->tx_credit++;
}

static void
ttx_timer_cb(void *arg)
{
	agent_t *a = arg;
	a->tx_ttr = true;
}
	
static void
ttx_shutdown_cb(void *arg)
{
	agent_t *a = arg;
	a->tx_shutdown = true;
}

static void
too_many_cb(void *arg)
{
	agent_t *a = arg;
	a->too_many_neighbors = true;
#define	STR(x) case ##x: return (#x)
static const char *
tx_statestr(tx_state_t st)
{
	switch (st) {
	STR(TX_LLDP_INITIALIZE);
	STR(TX_IDLE);
	STR(TX_SHUTDOWN_FRAME);
	STR(TX_INFO_FRAME);
	}
}

static const char *
rx_statestr(rx_state_t st)
{
	switch (st) {
	STR(LLDP_WAIT_PORT_OPERATIONAL);
	STR(DELETE_AGED_INFO);
	STR(RX_LLDP_INITIALIZE);
	STR(RX_WAIT_FOR_FRAME);
	STR(RX_FRAME);
	STR(DELETE_INFO);
	STR(UPDATE_INFO);
	}
}

static const char *
timer_statestr(timer_state_t st)
{
	switch (st) {
	STR(TX_TIMER_INITIALIZE);
	STR(TX_TIMER_IDLE);
	STR(TX_TIMER_EXPIRES);
	STR(SIGNAL_TX);
	STR(TX_TICK);
	STR(TX_FAST_START);
	}
}
#undef STR
