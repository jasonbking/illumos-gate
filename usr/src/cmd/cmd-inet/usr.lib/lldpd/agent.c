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

#include <atomic.h>
#include <errno.h>
#include <inttypes.h>
#include <libdlpi.h>
#include <libuutil.h>
#include <pthread.h>
#include <string.h>
#include <synch.h>
#include <umem.h>
#include <unistd.h>
#include <sys/containerof.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/sysmacros.h>

#include "agent.h"
#include "config.h"
#include "log.h"
#include "neighbor.h"
#include "pdu.h"
#include "timer.h"
#include "util.h"

#define	DEFAULT_MSG_FAST_TX	1
#define	DEFAULT_MSG_TX_HOLD	4
#define	DEFAULT_MSG_TX_INTERVAL	30
#define	DEFAULT_REINIT_DELAY	2
#define	DEFAULT_TX_CREDIT_MAX	5
#define	DEFAULT_TX_FAST_INIT	4

static void *agent_thread(void *);
static bool open_port(agent_t *);
static void recv_frame(int, void *);

static void tx_initialize(agent_t *);
static void rx_init_lldp(agent_t *);
static void update_objects(agent_t *);
static void delete_objects(agent_t *);
static void tx_add_credit(agent_t *);
static void something_changed_remote(agent_t *);

static void tx_init(agent_t *);
static void tx_fini(tx_t *);
static bool tx_machine(agent_t *);
static bool tx_next_state(tx_t *);

static void rx_init(agent_t *);
static void rx_fini(rx_t *);
static bool rx_machine(agent_t *);
static bool rx_next_state(agent_t *);

static void ttr_init(agent_t *);
static void ttr_fini(ttr_t *);
static bool ttr_machine(agent_t *);
static bool ttr_next_state(ttr_t *);

static const char *tx_statestr(tx_state_t);
static const char *rx_statestr(rx_state_t);
static const char *ttr_statestr(ttr_state_t);

static void tx_frame(dlpi_handle_t, buf_t *, log_t *);
static void rx_process_frame(agent_t *);

static const uint_t	lldp_sap = 0x88cc;
static const uint8_t	lldp_addr[ETHERADDRL] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e
};

static uu_list_pool_t	*agent_list_pool;

mutex_t			agent_list_lock = ERRORCHECKMUTEX;
uu_list_t		*agent_list;

static inline bool
dec(uint16_t *vp)
{
	if (*vp == 0)
		return (false);
	(*vp)--;
	return (true);
}

static inline lldp_admin_status_t
admin_status(const agent_t *a)
{
	return (a->a_cfg.ac_status);
}

static inline bool
too_many_neighbors(const agent_t *a)
{
	if (uu_list_numnodes(a->a_neighbors) >= a->a_cfg.ac_neighbor_max)
		return (true);
	return (false);
}

agent_t *
agent_create(const char *name)
{
	agent_t *a;
	int ret;

	a = umem_zalloc(sizeof (*a), UMEM_NOFAIL);

	VERIFY0(mutex_init(&a->a_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));
	VERIFY0(cond_init(&a->a_cv, USYNC_THREAD, NULL));
	uu_list_node_init(a, &a->a_node, agent_list_pool);

	a->a_name = xstrdup(name);
	a->a_port_enabled = false;

	(void) log_child(log, &a->a_log,
	    LOG_T_STRING, "agent", a->a_name,
	    LOG_T_END);

	if (!lldp_clock_init(a, &a->a_clk))
		nomem();

	tx_init(a);
	rx_init(a);
	ttr_init(a);

	a->a_neighbors = neighbor_list_new(a);
	a->a_cfg.ac_tx_fast_msg = DEFAULT_MSG_FAST_TX;
	a->a_cfg.ac_tx_hold = DEFAULT_MSG_TX_HOLD;
	a->a_cfg.ac_tx_interval = DEFAULT_MSG_TX_INTERVAL;
	a->a_cfg.ac_reinit_delay = DEFAULT_REINIT_DELAY;
	a->a_cfg.ac_tx_credit_max = DEFAULT_TX_CREDIT_MAX;
	a->a_cfg.ac_tx_fast_init = DEFAULT_TX_FAST_INIT;

	a->a_cfg.ac_status = LLDP_LINK_TXRX;

	a->a_smf_inst = scf_instance_create(rep_handle);
	a->a_smf_snap = scf_snapshot_create(rep_handle);
	a->a_smf_val = scf_value_create(rep_handle);
	a->a_smf_prop = scf_property_create(rep_handle);
	a->ac_smf_pg = scf_pg_create(rep_handle);
	// XXX: change for failure

	
	config_agent_init(a);
	(void) config_agent_read(a);

	a->a_dl_cb.fc_fn = recv_frame;
	a->a_dl_cb.fc_arg = a;

	if (!open_port(a)) {
		agent_destroy(a);
		return (NULL);
	}

	ret = thr_create(NULL, 0, agent_thread, a, THR_SUSPENDED, &a->a_tid);
	if (ret != 0)
		panic("failed to create agent thread");

	return (a);
}

void
agent_start(agent_t *a)
{
	VERIFY0(thr_continue(a->a_tid));
}

void
agent_destroy(agent_t *a)
{
	if (a->a_tid != 0) {
		thread_t tid = a->a_tid;

		a->a_exit = true;
		membar_producer();
		VERIFY0(cond_signal(&a->a_cv));
		VERIFY0(thr_join(tid, NULL, NULL));
	}

	if (a->a_dlh != NULL)
		dlpi_close(a->a_dlh);

	ttr_fini(&a->a_ttr);
	tx_fini(&a->a_tx);
	rx_fini(&a->a_rx);
	free(a->a_name);
	uu_list_destroy(a->a_neighbors);
	VERIFY0(cond_destroy(&a->a_cv));
	VERIFY0(mutex_destroy(&a->a_lock));
	umem_free(a, sizeof (*a));
}

bool
agent_enable(agent_t *a)
{
	VERIFY(!IS_AGENT_THREAD(a));

	mutex_enter(&a->a_lock);
	a->a_port_enabled = true;
	VERIFY0(cond_signal(&a->a_cv));
	log_info(a->a_log, "port enabled", LOG_T_END);
	mutex_exit(&a->a_lock);
	return (true);
}

void
agent_disable(agent_t *a)
{
	VERIFY(!IS_AGENT_THREAD(a));

	mutex_enter(&a->a_lock);
	a->a_port_enabled = false;
	VERIFY0(cond_signal(&a->a_cv));
	log_info(a->a_log, "port disabled", LOG_T_END);
	mutex_exit(&a->a_lock);
}

void
agent_set_status(agent_t *a, lldp_admin_status_t status)
{
	VERIFY(!IS_AGENT_THREAD(a));

	lldp_admin_status_t old_status;

	switch (status) {
	case LLDP_LINK_DISABLED:
	case LLDP_LINK_RX:
	case LLDP_LINK_TX:
	case LLDP_LINK_TXRX:
		break;
	default:
		panic("invalid admin status");
	}

	mutex_enter(&a->a_lock);
	old_status = a->a_cfg.ac_status;
	a->a_cfg.ac_status = status;
	VERIFY0(cond_signal(&a->a_cv));
	log_info(a->a_log, "agent admin status change",
	    LOG_T_STRING, "old_status", lldp_admin_status_str(old_status),
	    LOG_T_STRING, "new_status", lldp_admin_status_str(status),
	    LOG_T_END);
	mutex_exit(&a->a_lock);
}

lldp_admin_status_t
agent_get_status(agent_t *a)
{
	VERIFY(!IS_AGENT_THREAD(a));

	lldp_admin_status_t status;

	mutex_enter(&a->a_lock);
	status = admin_status(a);
	mutex_exit(&a->a_lock);

	return (status);
}

void
agent_local_change(agent_t *a)
{
	VERIFY(!IS_AGENT_THREAD(a));

	mutex_enter(&a->a_lock);
	a->a_local_changes = true;
	VERIFY0(cond_signal(&a->a_cv));
	mutex_exit(&a->a_lock);
}

size_t
agent_num_neighbors(agent_t *a)
{
	size_t n;

	VERIFY(!IS_AGENT_THREAD(a));

	mutex_enter(&a->a_lock);
	n = uu_list_numnodes(a->a_neighbors);
	mutex_exit(&a->a_lock);
	return (n);
}

static void *
agent_thread(void *arg)
{
	agent_t		*a = arg;
	int		ret;
	bool		run_tx, run_rx, run_ttr;
	timestruc_t	tick;

	log = a->a_log;

	mutex_enter(&a->a_lock);

	VERIFY0(pthread_setname_np(pthread_self(), a->a_name));

	if (!schedule_fd(dlpi_fd(a->a_dlh), &a->a_dl_cb)) {
		log_fatal(SMF_EXIT_ERR_FATAL, log,
		    "failed to schedule port",
		    LOG_T_STRING, "errmsg", strerror(errno),
		    LOG_T_UINT32, "errno", errno,
		    LOG_T_END);
	}

	run_tx = tx_machine(a);
	run_rx = rx_machine(a);
	run_ttr = ttr_machine(a);

	lldp_clock_tick(&a->a_clk, &tick);
	while (!a->a_exit) {
		/*
		 * Run each state machine until they are 'idle' -- i.e.
		 * there are no conditions present to allow the state
		 * machines to transition to a new state.
		 */
		do {
			if (run_tx)
				run_tx = tx_machine(a);
			if (run_rx)
				run_rx = rx_machine(a);
			if (run_ttr)
				run_ttr = ttr_machine(a);
		} while (run_tx || run_rx || run_ttr);

		/*
		 * Wait for an external trigger (via cv) or for the clock
		 * to tick, then recheck for any state transitions.
		 */
		while (!run_tx && !run_rx && !run_ttr) {
			ret = cond_timedwait(&a->a_cv, &a->a_lock, &tick);

			if (a->a_exit)
				break;

			if (ret == ETIME) {
				lldp_clock_tock(&a->a_clk);
				lldp_clock_tick(&a->a_clk, &tick);
			}

			run_tx = tx_next_state(&a->a_tx);
			run_rx = rx_next_state(a);
			run_ttr = ttr_next_state(&a->a_ttr);
		}
	}

	return (a);
}

static uint16_t
tx_ttl(const agent_t *a)
{
	const agent_cfg_t *cfg = &a->a_cfg;
	uint32_t val = cfg->ac_tx_interval * cfg->ac_tx_hold + 1;
	return (MIN(UINT16_MAX, val));
}

static void
tx_init(agent_t *a)
{
	tx_t *tx = &a->a_tx;

	TRACE_ENTER(a->a_log);

	(void) log_child(a->a_log, &tx->tx_log,
	    LOG_T_STRING, "state_machine", "tx",
	    LOG_T_END);

	lldp_timer_init(&a->a_clk, &tx->tx_shutdown, "txShutdownWhile", tx,
	    tx->tx_log, NULL, NULL);
	tx->tx_state = TX_BEGIN;

	TRACE_RETURN(a->a_log);
}

static void
tx_fini(tx_t *tx)
{
	lldp_timer_fini(&tx->tx_shutdown);
	log_fini(tx->tx_log);
}

static bool
tx_machine(agent_t *a)
{
	tx_t	*tx = &a->a_tx;
	buf_t	tx_buf;

	TRACE_ENTER(tx->tx_log);

	log_debug(tx->tx_log, "state machine running",
	    LOG_T_STRING, "state", tx_statestr(tx->tx_state),
	    LOG_T_END);

	switch (tx->tx_state) {
	case TX_LLDP_INITIALIZE:
		tx_initialize(a);
		lldp_timer_set(&tx->tx_shutdown, 0);
		break;
	case TX_IDLE:
		log_trace(tx->tx_log, "set tx_ttl",
		    LOG_T_UINT32, "tx_ttl", (uint32_t)tx->tx_ttl,
		    LOG_T_END);
		tx->tx_ttl = tx_ttl(a);
		break;
	case TX_SHUTDOWN_FRAME:
		(void) memset(tx->tx_frame, '\0', sizeof (tx->tx_frame));
		buf_init(&tx_buf, tx->tx_frame, sizeof (tx->tx_frame));
		make_shutdown_pdu(a, &tx_buf);
		tx_frame(a->a_dlh, &tx_buf, tx->tx_log);

		lldp_timer_set(&tx->tx_shutdown, a->a_cfg.ac_reinit_delay);
		break;
	case TX_INFO_FRAME:
		(void) memset(tx->tx_frame, '\0', sizeof (tx->tx_frame));
		buf_init(&tx_buf, tx->tx_frame, sizeof (tx->tx_frame));
		make_pdu(a, &tx_buf);
		tx_frame(a->a_dlh, &tx_buf, tx->tx_log);
		if (dec(&a->a_ttr.ttr_tx_credit)) {
			uint32_t credit = a->a_ttr.ttr_tx_credit;

			log_trace(tx->tx_log, "dec(tx_credit)",
			    LOG_T_UINT32, "tx_credit", credit,
			    LOG_T_END);
		}
		tx->tx_now = false;
		break;
	}

	bool next = tx_next_state(tx);

	TRACE_RETURN(tx->tx_log);
	return (next);
}

static bool
tx_next_state(tx_t *tx)
{
	agent_t *a = __containerof(tx, agent_t, a_tx);
	tx_state_t next = tx->tx_state;

	TRACE_ENTER(tx->tx_log);

	if (!a->a_port_enabled) {
		next = TX_LLDP_INITIALIZE;
		goto done;
	}

	switch (tx->tx_state) {
	case TX_LLDP_INITIALIZE:
		if (admin_status(a) == LLDP_LINK_TX ||
		    admin_status(a) == LLDP_LINK_TXRX) {
			next = TX_IDLE;
			break;
		}
		break;
	case TX_IDLE:
		if (admin_status(a) == LLDP_LINK_DISABLED ||
		    admin_status(a) == LLDP_LINK_RX) {
			next = TX_SHUTDOWN_FRAME;
			break;
		}

		if (tx->tx_now && a->a_ttr.ttr_tx_credit > 0) {
			next = TX_INFO_FRAME;
			break;
		}
		break;
	case TX_SHUTDOWN_FRAME:
		if (lldp_timer_val(&tx->tx_shutdown) == 0) {
			next = TX_LLDP_INITIALIZE;
			break;
		}
		break;
	case TX_INFO_FRAME:
		next = TX_IDLE;
		break;
	default:
		panic("invalid state");
	}

done:
	if (tx->tx_state == next) {
		TRACE_RETURN(tx->tx_log);
		return (false);
	}

	log_debug(tx->tx_log, "state transition",
	    LOG_T_STRING, "oldstate", tx_statestr(tx->tx_state),
	    LOG_T_STRING, "newstate", tx_statestr(next),
	    LOG_T_END);

	tx->tx_state = next;

	TRACE_RETURN(tx->tx_log);
	return (true);
}

static void
rx_init(agent_t *a)
{
	rx_t *rx = &a->a_rx;

	(void) memset(rx, '\0', sizeof (*rx));

	(void) log_child(a->a_log, &rx->rx_log,
	    LOG_T_STRING, "state_machine", "rx",
	    LOG_T_END);

	lldp_timer_init(&a->a_clk, &rx->rx_too_many_neighbors_timer,
	    "tooManyNeighborsTimer", rx, rx->rx_log, "tooManyNeighbors",
	    &rx->rx_too_many_neighbors);
	(void) memset(rx->rx_frame, '\0', sizeof (rx->rx_frame));
	rx->rx_frame_len = 0;
	rx->rx_state = RX_BEGIN;
}

static void
rx_fini(rx_t *rx)
{
	lldp_timer_fini(&rx->rx_too_many_neighbors_timer);
	log_fini(rx->rx_log);
}

static bool
rx_next_state(agent_t *a)
{
	rx_t		*rx = &a->a_rx;
	rx_state_t	next = rx->rx_state;

	if (!rx->rx_info_age && !a->a_port_enabled) {
		next = LLDP_WAIT_PORT_OPERATIONAL;
		goto done;
	}

	switch (rx->rx_state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		if (rx->rx_info_age) {
			next = DELETE_AGED_INFO;
			break;
		}

		if (a->a_port_enabled) {
			next = RX_LLDP_INITIALIZE;
			break;
		}
		break;
	case DELETE_AGED_INFO:
		next = LLDP_WAIT_PORT_OPERATIONAL;
		break;
	case RX_LLDP_INITIALIZE:
		if (admin_status(a) == LLDP_LINK_RX ||
		    admin_status(a) == LLDP_LINK_TXRX) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}
		break;
	case RX_WAIT_FOR_FRAME:
		if (rx->rx_info_age) {
			next = DELETE_INFO;
			break;
		}

		if (rx->rx_recv_frame) {
			next = RX_FRAME;
			break;
		}

		if (admin_status(a) == LLDP_LINK_DISABLED ||
		    admin_status(a) == LLDP_LINK_TX) {
			next = RX_LLDP_INITIALIZE;
			break;
		}
		break;
	case RX_FRAME:
		if (rx->rx_ttl == 0) {
			next = DELETE_INFO;
			break;
		}

		if (rx->rx_ttl != 0 && rx->rx_changes) {
			next = UPDATE_INFO;
			break;
		}

		if (rx->rx_bad_frame ||
		    (rx->rx_ttl != 0 && !rx->rx_changes)) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}
		break;
	case DELETE_INFO:
		next = RX_WAIT_FOR_FRAME;
		break;
	case UPDATE_INFO:
		next = RX_WAIT_FOR_FRAME;
		break;
	default:
		panic("invalid state");
	}

done:
	if (rx->rx_state == next) {
		TRACE_RETURN(rx->rx_log);
		return (false);
	}

	log_debug(rx->rx_log, "state transition",
	    LOG_T_STRING, "oldstate", rx_statestr(rx->rx_state),
	    LOG_T_STRING, "newstate", rx_statestr(next),
	    LOG_T_END);

	rx->rx_state = next;
	return (true);
}

static bool
rx_machine(agent_t *a)
{
	rx_t *rx = &a->a_rx;

	TRACE_ENTER(rx->rx_log);

	log_debug(rx->rx_log, "state machine running",
	    LOG_T_STRING, "state", rx_statestr(rx->rx_state),
	    LOG_T_END);

	switch (rx->rx_state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		break;
	case DELETE_AGED_INFO:
		delete_objects(a);
		rx->rx_info_age = false;
		something_changed_remote(a);
		break;
	case RX_LLDP_INITIALIZE:
		rx_init_lldp(a);
		rx->rx_recv_frame = false;
		break;
	case RX_WAIT_FOR_FRAME:
		rx->rx_bad_frame = false;
		rx->rx_info_age = false;
		break;
	case RX_FRAME:
		rx->rx_changes = false;
		rx->rx_recv_frame = false;
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

	bool next = rx_next_state(a);

	TRACE_RETURN(rx->rx_log);
	return (next);
}

static void
ttr_init(agent_t *a)
{
	ttr_t *ttr = &a->a_ttr;

	(void) log_child(a->a_log, &ttr->ttr_log,
	    LOG_T_STRING, "state_machine", "ttr",
	    LOG_T_END);
	lldp_timer_init(&a->a_clk, &ttr->ttr_timer, "txTTR", ttr, ttr->ttr_log,
	    "tx_now", &a->a_tx.tx_now);
	ttr->ttr_state = TTR_BEGIN;
}

static void
ttr_fini(ttr_t *ttr)
{
	lldp_timer_fini(&ttr->ttr_timer);
	log_fini(ttr->ttr_log);
}

static bool
ttr_next_state(ttr_t *ttr)
{
	agent_t *a = __containerof(ttr, agent_t, a_ttr);
	ttr_state_t next = ttr->ttr_state;

	if (!a->a_port_enabled || admin_status(a) == LLDP_LINK_DISABLED ||
	    admin_status(a) == LLDP_LINK_RX) {
		next = TX_TIMER_INITIALIZE;
		goto done;
	}

	switch (ttr->ttr_state) {
	case TX_TIMER_INITIALIZE:
		if (admin_status(a) == LLDP_LINK_TX ||
		    admin_status(a) == LLDP_LINK_TXRX) {
			next = TX_TIMER_IDLE;
			break;
		}
		break;
	case TX_TIMER_IDLE:
		if (a->a_local_changes) {
			next = SIGNAL_TX;
			break;
		}

		if (lldp_timer_val(&ttr->ttr_timer) == 0) {
			next = TX_TIMER_EXPIRES;
			break;
		}

		if (a->a_new_neighbor) {
			next = TX_FAST_START;
			break;
		}

		if (ttr->ttr_tick) {
			next = TX_TICK;
			break;
		}
		break;
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
	default:
		panic("invalid state");
	}

done:
	if (ttr->ttr_state == next) {
		TRACE_RETURN(ttr->ttr_log);
		return (false);
	}

	log_debug(ttr->ttr_log, "state transition",
	    LOG_T_STRING, "oldstate", ttr_statestr(ttr->ttr_state),
	    LOG_T_STRING, "newstate", ttr_statestr(next),
	    LOG_T_END);

	ttr->ttr_state = next;

	return (true);
}

static bool
ttr_machine(agent_t *a)
{
	ttr_t *ttr = &a->a_ttr;

	log_debug(ttr->ttr_log, "state machine running",
	    LOG_T_STRING, "state", ttr_statestr(ttr->ttr_state),
	    LOG_T_END);

	switch (ttr->ttr_state) {
	case TX_TIMER_INITIALIZE:
		lldp_timer_set(&ttr->ttr_timer, 0);
		ttr->ttr_tick = false;
		ttr->ttr_tx_fast = 0;
		ttr->ttr_tx_credit = a->a_cfg.ac_tx_credit_max;
		a->a_tx.tx_now = false;
		a->a_new_neighbor = false;
		break;
	case TX_TIMER_IDLE:
		break;
	case TX_TICK:
		ttr->ttr_tick = false;
		tx_add_credit(a);
		break;
	case TX_TIMER_EXPIRES:
		if (dec(&ttr->ttr_tx_fast)) {
			log_trace(ttr->ttr_log, "decremented tx_fast",
			    LOG_T_UINT32, "tx_fast", (uint32_t)ttr->ttr_tx_fast,
			    LOG_T_END);
		}
		break;
	case SIGNAL_TX:
		a->a_tx.tx_now = true;
		a->a_local_changes = false;
		lldp_timer_set(&ttr->ttr_timer, ttr->ttr_tx_fast > 0 ?
		    ttr->ttr_tx_fast : a->a_cfg.ac_tx_interval);
		break;
	case TX_FAST_START:
		a->a_new_neighbor = false;
		if (ttr->ttr_tx_fast == 0)
			ttr->ttr_tx_fast = a->a_cfg.ac_tx_fast_init;
		break;
	}

	return (ttr_next_state(ttr));
}

static void
tx_initialize(agent_t *a)
{
	/* TODO */
}

static void
rx_init_lldp(agent_t *a)
{
	rx_t		*rx = &a->a_rx;
	void		*cookie = NULL;
	neighbor_t	*nb;

	rx->rx_too_many_neighbors = false;

	while ((nb = uu_list_teardown(a->a_neighbors, &cookie)) != NULL)
		neighbor_free(nb);
}

static void
update_objects(agent_t *a)
{
	rx_t *rx = &a->a_rx;
	neighbor_t *old_nb = rx->rx_curr_neighbor;
	neighbor_t *nb = rx->rx_neighbor;

	ASSERT3P(old_nb, !=, nb);
	ASSERT(neighbor_same(old_nb, nb));

	lldp_timer_init(&a->a_clk, &nb->nb_timer, "rxInfoAge", nb,
	    rx->rx_log, "rxInfoAge", &rx->rx_info_age);
	lldp_timer_set(&nb->nb_timer, rx->rx_ttl);
	uu_list_insert(a->a_neighbors, nb, rx->rx_curr_idx);

	uu_list_remove(a->a_neighbors, old_nb);
	neighbor_free(old_nb);
	rx->rx_curr_neighbor = NULL;
}

static void
delete_objects(agent_t *a)
{
	neighbor_t	*nb;
	uu_list_walk_t	*wk;
	log_t		*l = a->a_rx.rx_log;
	uint32_t	count;

	log_debug(l, "ageing out neighbors", LOG_T_END);

	wk = xuu_list_walk_start(a->a_neighbors, UU_WALK_ROBUST);
	if (wk == NULL) {
		/* This should be the only reason we fail */
		VERIFY3U(uu_error(), ==, UU_ERROR_NO_MEMORY);
		nomem();
	}

	count = 0;
	while ((nb = uu_list_walk_next(wk)) != NULL) {
		if (lldp_timer_val(&nb->nb_timer) > 0)
			continue;

		log_info(l, "ageing out neighbor",
		    LOG_T_CHASSIS, "chassis",
		    tlv_list_get(&nb->nb_core_tlvs, 0),
		    LOG_T_PORT, "port", tlv_list_get(&nb->nb_core_tlvs, 1),
		    LOG_T_END);

		uu_list_remove(a->a_neighbors, nb);
		neighbor_free(nb);
		count++;
	}

	log_info(l, "ageing out complete",
	    LOG_T_UINT32, "num_aged", count,
	    LOG_T_END);

	uu_list_walk_end(wk);
}

void
something_changed_local(agent_t *a, bool locked)
{
	VERIFY(!IS_AGENT_THREAD(a));

	if (!locked)
		mutex_enter(&a->a_lock);

	a->a_local_changes = true;
	VERIFY0(cond_signal(&a->a_cv));

	if (!locked)
		mutex_exit(&a->a_lock);
}

static void
something_changed_remote(agent_t *a)
{
	/* TODO */
}

static void
tx_frame(dlpi_handle_t dlh, buf_t *b, log_t *l)
{
	int ret;

	VERIFY3U(buf_len(b), >, 0);

	ret = dlpi_send(dlh, lldp_addr, sizeof (lldp_addr), buf_ptr(b),
	    buf_len(b), NULL);
	if (ret != DLPI_SUCCESS)
		log_dlerr(l, "failed to send PDU", ret);

	(void) memset(buf_ptr(b), '\0', buf_len(b));
}

static void
tx_add_credit(agent_t *a)
{
	if (a->a_ttr.ttr_tx_credit == a->a_cfg.ac_tx_credit_max)
		return;
	a->a_ttr.ttr_tx_credit++;
}

static void
recv_frame(int fd __unused, void *arg)
{
	agent_t		*a = arg;
	rx_t		*rx = &a->a_rx;
	uint8_t		src[DLPI_PHYSADDR_MAX] = { 0 };
	dlpi_recvinfo_t	di = { 0 };
	size_t		srclen = sizeof (src);
	int		ret;

	/* We should be running outside the agent's thread */
	VERIFY3U(thr_self(), !=, a->a_tid);

	mutex_enter(&a->a_lock);

	(void) memset(rx->rx_frame, '\0', sizeof (rx->rx_frame));
	rx->rx_frame_len = sizeof (rx->rx_frame);

	ret = dlpi_recv(a->a_dlh, &src, &srclen, rx->rx_frame,
	    &rx->rx_frame_len, 0, &di);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log, "receive error", ret);
		rx->rx_bad_frame = true;
		goto done;
	}

	if (di.dri_totmsglen > sizeof (rx->rx_frame)) {
		log_info(rx->rx_log, "oversize message",
		    LOG_T_MAC, "src", src,
		    LOG_T_UINT32, "len", (uint32_t)sizeof (rx->rx_frame),
		    LOG_T_END);
		rx->rx_bad_frame = true;
		/* XXX: do we need to drain dlh? */

		goto done;
	}

	/*
	 * Notifications (e.g. link up/down) will generate 0
	 * byte reads, so we just ignore.
	 */ 
	if (di.dri_totmsglen == 0)
		goto done;

	log_debug(rx->rx_log, "received frame",
	    LOG_T_MAC, "src", src,
	    LOG_T_UINT32, "len", (uint32_t)rx->rx_frame_len,
	    LOG_T_END);

	rx->rx_recv_frame = true;

done:
	if (!schedule_fd(dlpi_fd(a->a_dlh), &a->a_dl_cb)) {
		log_syserr(log, "failed to schedule port", errno);
		a->a_port_enabled = false;
	}
	mutex_exit(&a->a_lock);
	VERIFY0(cond_signal(&a->a_cv));
}

static void
rx_process_frame(agent_t *a)
{
	rx_t *rx = &a->a_rx;
	buf_t b;

	VERIFY3U(rx->rx_frame_len, <=, UINT16_MAX);
	buf_init(&b, rx->rx_frame, rx->rx_frame_len);

	if (!process_pdu(rx->rx_log, &b, &rx->rx_neighbor)) {
		rx->rx_bad_frame = true;
		return;
	}

	if (rx->rx_neighbor == NULL || too_many_neighbors(a)) {
		/* TODO: too many neighbors */
		return;
	}

	rx->rx_ttl = rx->rx_neighbor->nb_ttl;
	rx->rx_curr_neighbor = uu_list_find(a->a_neighbors, rx->rx_neighbor,
	    NULL, &rx->rx_curr_idx);
	rx->rx_changes = !neighbor_same(rx->rx_curr_neighbor, rx->rx_neighbor);

	if (!rx->rx_changes) {
		/* If no changes, just update the TTL and free the new pkt */
		rx->rx_curr_neighbor->nb_ttl = rx->rx_ttl;
		neighbor_free(rx->rx_neighbor);
		rx->rx_neighbor = NULL;
	}
}

static void
lldp_dlpi_cb(dlpi_handle_t dlh, dlpi_notifyinfo_t *ni, void *arg)
{
	agent_t *a = arg;

	ASSERT(MUTEX_HELD(&a->a_lock));

	switch (ni->dni_note) {
	case DL_NOTE_LINK_UP:
		log_info(a->a_log, "link up; port enabled",
		    LOG_T_END);
		a->a_port_enabled = true;
		break;

	case DL_NOTE_LINK_DOWN:
		log_info(a->a_log, "link down; port disabled",
		    LOG_T_END);

		a->a_port_enabled = false;
		break;

	case DL_NOTE_SDU_SIZE:
		log_info(log, "max SDU changed",
		    LOG_T_STRING, "port", a->a_name,
		    LOG_T_UINT32, "max_sdu", ni->dni_size,
		    LOG_T_END);

		a->a_dl_info.di_max_sdu = ni->dni_size;
		break;
	}

	something_changed_local(a, true);
}

static bool
open_port(agent_t *a)
{
	int ret;

	ret = dlpi_open(a->a_name, &a->a_dlh, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(log, "failed to open link", ret);
		goto fail;
	}

	ret = dlpi_info(a->a_dlh, &a->a_dl_info, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(log, "failed to get link info", ret);
		goto fail;
	}

	ret = dlpi_enabmulti(a->a_dlh, lldp_addr, sizeof (lldp_addr));
	if (ret != DLPI_SUCCESS) {
		log_dlerr(log, "failed to bind to LLDP multicast address", ret);
		goto fail;
	}

	ret = dlpi_bind(a->a_dlh, lldp_sap, NULL);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(log, "failed to bind to LLDP SAP", ret);
		goto fail;
	}

	ret = dlpi_enabnotify(a->a_dlh, DL_NOTE_LINK_DOWN | DL_NOTE_LINK_UP |
	    DL_NOTE_PHYS_ADDR | DL_NOTE_SDU_SIZE, lldp_dlpi_cb, a,
	    &a->a_dl_nid);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(log, "failed to enable DLPI notifications", ret);
		goto fail;
	}

	return (true);

fail:
	if (a->a_dlh != NULL) {
		dlpi_close(a->a_dlh);
		a->a_dlh = NULL;
	}

	return (false);
}

static int
agent_name_cmp(const void *a, const void *b, void *arg __unused)
{
	const agent_t *l = a;
	const agent_t *r = b;

	return (strcmp(l->a_name, r->a_name));
}

void
agent_init(void)
{
	TRACE_ENTER(log);

	mutex_enter(&agent_list_lock);

	agent_list_pool = uu_list_pool_create("agent-pool", sizeof (agent_t),
	    offsetof(agent_t, a_node), agent_name_cmp, UU_LIST_POOL_DEBUG);
	if (agent_list_pool == NULL) {
		int ev = uu_error();

		log_fatal(SMF_EXIT_ERR_FATAL, log,
		    "failed to create agent list pool",
		    LOG_T_STRING, "errmsg", uu_strerror(ev),
		    LOG_T_UINT32, "uu_error", ev,
		    LOG_T_END);
	}

	agent_list = uu_list_create(agent_list_pool, NULL, UU_LIST_DEBUG);
	if (agent_list == NULL) {
		int ev = uu_error();

		log_fatal(SMF_EXIT_ERR_FATAL, log,
		    "failed to create agent list",
		    LOG_T_STRING, "errmsg", uu_strerror(ev),
		    LOG_T_UINT32, "uu_error", ev,
		    LOG_T_END);
	}

	mutex_exit(&agent_list_lock);
	TRACE_RETURN(log);
}

#define	STR(x) case x: return (#x)
static const char *
tx_statestr(tx_state_t st)
{
	switch (st) {
	STR(TX_LLDP_INITIALIZE);
	STR(TX_IDLE);
	STR(TX_SHUTDOWN_FRAME);
	STR(TX_INFO_FRAME);
	}
	panic("invalid state");
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
	panic("invalid state");
}

static const char *
ttr_statestr(ttr_state_t st)
{
	switch (st) {
	STR(TX_TIMER_INITIALIZE);
	STR(TX_TIMER_IDLE);
	STR(TX_TIMER_EXPIRES);
	STR(SIGNAL_TX);
	STR(TX_TICK);
	STR(TX_FAST_START);
	}
	panic("invalid state");
}
#undef STR
