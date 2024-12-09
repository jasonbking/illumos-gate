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
#include <stropts.h>
#include <synch.h>
#include <umem.h>
#include <unistd.h>
#include <sys/containerof.h>
#include <sys/debug.h>
#include <sys/dld.h>
#include <sys/dld_ioc.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/ethernet.h>
#include <sys/sysmacros.h>

#include "agent.h"
#include "config.h"
#include "log.h"
#include "neighbor.h"
#include "pdu.h"
#include "timer.h"
#include "util.h"

static void *agent_thread(void *);
static void agent_update_phy(agent_t *);
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
agent_create(const char *name, datalink_id_t linkid)
{
	agent_t *a;
	int ret;

	a = umem_zalloc(sizeof (*a), UMEM_NOFAIL);

	VERIFY0(mutex_init(&a->a_lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL));
	VERIFY0(cond_init(&a->a_cv, USYNC_THREAD, NULL));
	uu_list_node_init(a, &a->a_node, agent_list_pool);

	a->a_name = xstrdup(name);
	a->a_linkid = linkid;
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

	/*
	 * Start with the default agent configuration, overridden by any
	 * agent-specific configuration in SMF.
	 */
	config_agent_init(a);

	a->a_dl_cb.fc_fn = recv_frame;
	a->a_dl_cb.fc_arg = a;

	if (!open_port(a)) {
		agent_destroy(a);
		return (NULL);
	}

	agent_update_phy(a);

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

	/*
	 * Free the neighbors (and any in-flight neighbor) first; their
	 * rxInfoAge timers are attached to the agent's clock.
	 */
	if (a->a_neighbors != NULL) {
		void		*cookie = NULL;
		neighbor_t	*nb;

		while ((nb = uu_list_teardown(a->a_neighbors,
		    &cookie)) != NULL) {
			neighbor_free(nb);
		}
	}
	neighbor_free(a->a_rx.rx_neighbor);
	a->a_rx.rx_neighbor = NULL;
	a->a_rx.rx_curr_neighbor = NULL;

	ttr_fini(&a->a_ttr);
	tx_fini(&a->a_tx);
	rx_fini(&a->a_rx);
	lldp_clock_fini(&a->a_clk);
	config_agent_cfg_free(&a->a_cfg);
	free(a->a_name);
	if (a->a_neighbors != NULL)
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

/*
 * Replace the SMF-configurable portion of an agent's configuration with
 * that of cfg. Values derived from the system rather than from SMF (port id,
 * topo information, MTU) are retained. The agent takes ownership of any
 * memory referenced by cfg, so the caller must not use or free it after
 * this returns.
 */
void
agent_set_cfg(agent_t *a, agent_cfg_t *cfg)
{
	VERIFY(!IS_AGENT_THREAD(a));

	agent_cfg_t	old;
	agent_cfg_t	*cur = &a->a_cfg;

	mutex_enter(&a->a_lock);

	old = *cur;

	/* Carry over the values that don't come from SMF */
	cfg->ac_port = old.ac_port;
	cfg->ac_label = old.ac_label;
	cfg->ac_devname = old.ac_devname;
	cfg->ac_portnum = old.ac_portnum;
	cfg->ac_mtu = old.ac_mtu;
	old.ac_label = old.ac_devname = NULL;

	*cur = *cfg;

	/*
	 * If txCreditMax was lowered, don't let the current credit exceed
	 * the new maximum (tx_add_credit() only stops at exactly the max).
	 */
	if (a->a_ttr.ttr_tx_credit > cur->ac_tx_credit_max)
		a->a_ttr.ttr_tx_credit = cur->ac_tx_credit_max;

	if (old.ac_status != cur->ac_status) {
		log_info(a->a_log, "agent admin status change",
		    LOG_T_STRING, "old_status",
		    lldp_admin_status_str(old.ac_status),
		    LOG_T_STRING, "new_status",
		    lldp_admin_status_str(cur->ac_status),
		    LOG_T_END);
	}

	/* What we advertise may have changed, so (re)send our info */
	a->a_local_changes = true;
	VERIFY0(cond_signal(&a->a_cv));

	mutex_exit(&a->a_lock);

	config_agent_cfg_free(&old);
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
	timestruc_t	rel;

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

	lldp_clock_start(&a->a_clk);
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
		 *
		 * We wait using a relative timeout computed from the clock's
		 * monotonic deadline, so changes to the system time don't
		 * affect us. Whatever woke us (timeout, signal, or a
		 * spurious wakeup), lldp_clock_advance() processes any
		 * ticks that are due.
		 */
		while (!run_tx && !run_rx && !run_ttr) {
			lldp_clock_reltime(&a->a_clk, &rel);
			ret = cond_reltimedwait(&a->a_cv, &a->a_lock, &rel);
			VERIFY(ret == 0 || ret == ETIME || ret == EINTR);

			if (a->a_exit)
				break;

			(void) lldp_clock_advance(&a->a_clk);

			run_tx = tx_next_state(&a->a_tx);
			run_rx = rx_next_state(a);
			run_ttr = ttr_next_state(&a->a_ttr);
		}
	}

	mutex_exit(&a->a_lock);
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
	    "tooManyNeighborsTimer", rx, rx->rx_log, NULL, NULL);
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
		/*
		 * A bad frame doesn't produce a valid rx_ttl, so check for it
		 * first rather than act on a stale TTL.
		 */
		if (rx->rx_bad_frame) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}

		if (rx->rx_ttl == 0) {
			next = DELETE_INFO;
			break;
		}

		if (rx->rx_changes) {
			next = UPDATE_INFO;
			break;
		}

		next = RX_WAIT_FOR_FRAME;
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
		/* Abandon any frame that was being processed */
		neighbor_free(rx->rx_neighbor);
		rx->rx_neighbor = NULL;
		rx->rx_curr_neighbor = NULL;
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

/*
 * The ttr machine goes TX_TIMER_IDLE -> TX_TICK -> TX_TIMER_IDLE on every
 * clock tick (once a second). Those transitions are routine, so they (and
 * running the machine in those states, which does nothing of note) aren't
 * logged.
 */
static inline bool
ttr_is_tick(ttr_state_t from, ttr_state_t to)
{
	return ((from == TX_TIMER_IDLE && to == TX_TICK) ||
	    (from == TX_TICK && to == TX_TIMER_IDLE));
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

	if (!ttr_is_tick(ttr->ttr_state, next)) {
		log_debug(ttr->ttr_log, "state transition",
		    LOG_T_STRING, "oldstate", ttr_statestr(ttr->ttr_state),
		    LOG_T_STRING, "newstate", ttr_statestr(next),
		    LOG_T_END);
	}

	ttr->ttr_state = next;

	return (true);
}

static bool
ttr_machine(agent_t *a)
{
	ttr_t *ttr = &a->a_ttr;

	if (ttr->ttr_state != TX_TICK && ttr->ttr_state != TX_TIMER_IDLE) {
		log_debug(ttr->ttr_log, "state machine running",
		    LOG_T_STRING, "state", ttr_statestr(ttr->ttr_state),
		    LOG_T_END);
	}

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
	lldp_timer_set(&rx->rx_too_many_neighbors_timer, 0);

	neighbor_free(rx->rx_neighbor);
	rx->rx_neighbor = NULL;
	rx->rx_curr_neighbor = NULL;

	while ((nb = uu_list_teardown(a->a_neighbors, &cookie)) != NULL)
		neighbor_free(nb);
}

/*
 * Add the newly received neighbor information (rx_neighbor) to the agent's
 * neighbor list, replacing any existing information from the same MSAP
 * (rx_curr_neighbor).
 */
static void
update_objects(agent_t *a)
{
	rx_t		*rx = &a->a_rx;
	neighbor_t	*old_nb = rx->rx_curr_neighbor;
	neighbor_t	*nb = rx->rx_neighbor;
	uu_list_index_t	idx;

	VERIFY3P(nb, !=, NULL);
	ASSERT3P(old_nb, !=, nb);
	ASSERT(old_nb == NULL || !neighbor_same(old_nb, nb));

	if (old_nb != NULL) {
		uu_list_remove(a->a_neighbors, old_nb);
		neighbor_free(old_nb);
	}

	lldp_timer_init(&a->a_clk, &nb->nb_timer, "rxInfoAge", nb,
	    rx->rx_log, "rxInfoAge", &rx->rx_info_age);
	lldp_timer_set(&nb->nb_timer, rx->rx_ttl);

	/*
	 * Look up the insertion point now rather than reuse the index from
	 * rx_process_frame(); removing old_nb above invalidates it.
	 */
	VERIFY3P(uu_list_find(a->a_neighbors, nb, NULL, &idx), ==, NULL);
	uu_list_insert(a->a_neighbors, nb, idx);

	if (old_nb == NULL) {
		log_info(rx->rx_log, "new neighbor",
		    LOG_T_CHASSIS, "chassis",
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_CHASSIS),
		    LOG_T_PORT, "port",
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_PORT),
		    LOG_T_UINT32, "ttl", (uint32_t)nb->nb_ttl,
		    LOG_T_END);

		/* 802.1AB 9.2.7.7.4: trigger fast transmission */
		a->a_new_neighbor = true;
	}

	rx->rx_neighbor = NULL;
	rx->rx_curr_neighbor = NULL;
}

static void
delete_objects(agent_t *a)
{
	neighbor_t	*nb;
	uu_list_walk_t	*wk;
	log_t		*l = a->a_rx.rx_log;
	uint32_t	count;

	/*
	 * A shutdown PDU (TTL 0) for a known MSAP: rx_process_frame() leaves
	 * the matching neighbor in rx_curr_neighbor.
	 */
	nb = a->a_rx.rx_curr_neighbor;
	if (nb != NULL) {
		log_info(l, "neighbor shut down",
		    LOG_T_CHASSIS, "chassis",
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_CHASSIS),
		    LOG_T_PORT, "port",
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_PORT),
		    LOG_T_END);

		uu_list_remove(a->a_neighbors, nb);
		neighbor_free(nb);
		a->a_rx.rx_curr_neighbor = NULL;
	}

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
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_CHASSIS),
		    LOG_T_PORT, "port",
		    tlv_list_get(&nb->nb_core_tlvs, NB_TLV_PORT),
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
	rx_t		*rx = &a->a_rx;
	neighbor_t	*nb, *curr;
	buf_t		b;

	VERIFY3U(rx->rx_frame_len, <=, UINT16_MAX);
	buf_init(&b, rx->rx_frame, rx->rx_frame_len);

	/* Any previous frame should have been fully consumed */
	ASSERT3P(rx->rx_neighbor, ==, NULL);
	neighbor_free(rx->rx_neighbor);
	rx->rx_neighbor = NULL;
	rx->rx_curr_neighbor = NULL;

	if (!process_pdu(rx->rx_log, &b, &nb)) {
		rx->rx_bad_frame = true;
		return;
	}
	VERIFY3P(nb, !=, NULL);

	rx->rx_ttl = nb->nb_ttl;
	curr = uu_list_find(a->a_neighbors, nb, NULL, NULL);

	/*
	 * A shutdown PDU. If we know the MSAP, delete_objects() (via
	 * DELETE_INFO) removes it. Either way the PDU itself isn't needed.
	 */
	if (rx->rx_ttl == 0) {
		rx->rx_curr_neighbor = curr;
		neighbor_free(nb);
		return;
	}

	if (curr == NULL) {
		/*
		 * A new MSAP. If we're at our limit, discard the new
		 * information (802.1AB 9.2.7.7.4); tooManyNeighborsTimer
		 * tracks how long the condition persists.
		 */
		if (rx->rx_too_many_neighbors &&
		    lldp_timer_val(&rx->rx_too_many_neighbors_timer) == 0) {
			rx->rx_too_many_neighbors = false;
		}

		if (too_many_neighbors(a)) {
			lldp_timer_t *t = &rx->rx_too_many_neighbors_timer;

			if (!rx->rx_too_many_neighbors) {
				log_warn(rx->rx_log, "too many neighbors; "
				    "discarding information from new neighbor",
				    LOG_T_UINT32, "neighbor_max",
				    (uint32_t)a->a_cfg.ac_neighbor_max,
				    LOG_T_CHASSIS, "chassis",
				    tlv_list_get(&nb->nb_core_tlvs,
				    NB_TLV_CHASSIS),
				    LOG_T_PORT, "port",
				    tlv_list_get(&nb->nb_core_tlvs,
				    NB_TLV_PORT),
				    LOG_T_END);
			}

			rx->rx_too_many_neighbors = true;
			lldp_timer_set(t, MAX(lldp_timer_val(t), rx->rx_ttl));

			neighbor_free(nb);
			rx->rx_changes = false;
			return;
		}

		rx->rx_neighbor = nb;
		rx->rx_changes = true;
		return;
	}

	if (neighbor_same(curr, nb)) {
		/*
		 * Nothing changed; just refresh the existing information's
		 * TTL and restart its rxInfoAge timer.
		 */
		curr->nb_ttl = rx->rx_ttl;
		lldp_timer_set(&curr->nb_timer, rx->rx_ttl);
		neighbor_free(nb);
		rx->rx_changes = false;
		return;
	}

	rx->rx_curr_neighbor = curr;
	rx->rx_neighbor = nb;
	rx->rx_changes = true;
}

/*
 * Read a (fixed size) MAC property of the agent's link. libdladm only
 * exposes the media property as a string, so we issue the same ioctl
 * libdladm uses to get the raw values. Must be called from the main thread
 * (it uses dl_handle).
 */
static bool
link_get_prop(agent_t *a, mac_prop_id_t id, const char *name, void *val,
    size_t len)
{
	dld_ioc_macprop_t	*dip;
	size_t			dsize = DLD_MACPROP_BUFSIZE(len);
	bool			ret = false;

	dip = umem_zalloc(dsize, UMEM_NOFAIL);
	dip->pr_linkid = a->a_linkid;
	dip->pr_num = id;
	dip->pr_flags = 0;
	dip->pr_valsize = len;
	(void) strlcpy(dip->pr_name, name, sizeof (dip->pr_name));

	if (ioctl(dladm_dld_fd(dl_handle), DLDIOC_GETMACPROP, dip) == 0) {
		(void) memcpy(val, dip->pr_val, len);
		ret = true;
	}

	umem_free(dip, dsize);
	return (ret);
}

static bool
link_get_flag(agent_t *a, mac_prop_id_t id, const char *name)
{
	uint8_t v = 0;

	return (link_get_prop(a, id, name, &v, sizeof (v)) && v != 0);
}

/*
 * IANAifMauAutoNegCapBits are SNMP BITS: bit 0 is the most significant bit
 * of the (16-bit, for this TLV) field.
 */
#define	MAU_CAP_BIT(n)		((uint16_t)(0x8000 >> (n)))
#define	MAU_CAP_OTHER		MAU_CAP_BIT(0)	/* bOther */
#define	MAU_CAP_10BASET		MAU_CAP_BIT(1)	/* b10baseT */
#define	MAU_CAP_10BASETFD	MAU_CAP_BIT(2)	/* b10baseTFD */
#define	MAU_CAP_100BASET4	MAU_CAP_BIT(3)	/* b100baseT4 */
#define	MAU_CAP_100BASETX	MAU_CAP_BIT(4)	/* b100baseTX */
#define	MAU_CAP_100BASETXFD	MAU_CAP_BIT(5)	/* b100baseTXFD */
#define	MAU_CAP_1000BASEX	MAU_CAP_BIT(12)	/* b1000baseX */
#define	MAU_CAP_1000BASEXFD	MAU_CAP_BIT(13)	/* b1000baseXFD */
#define	MAU_CAP_1000BASET	MAU_CAP_BIT(14)	/* b1000baseT */
#define	MAU_CAP_1000BASETFD	MAU_CAP_BIT(15)	/* b1000baseTFD */

static const struct {
	mac_prop_id_t	ac_id;
	const char	*ac_name;
	uint16_t	ac_bit;
} adv_caps[] = {
	{ MAC_PROP_ADV_10HDX_CAP, "adv_10hdx_cap", MAU_CAP_10BASET },
	{ MAC_PROP_ADV_10FDX_CAP, "adv_10fdx_cap", MAU_CAP_10BASETFD },
	/* libdladm has no name for this one; the kernel only uses the id */
	{ MAC_PROP_ADV_100T4_CAP, "adv_100t4_cap", MAU_CAP_100BASET4 },
	{ MAC_PROP_ADV_100HDX_CAP, "adv_100hdx_cap", MAU_CAP_100BASETX },
	{ MAC_PROP_ADV_100FDX_CAP, "adv_100fdx_cap", MAU_CAP_100BASETXFD },
	/*
	 * The 16-bit field only has room for speeds up to 1G; anything
	 * faster is reported as bOther.
	 */
	{ MAC_PROP_ADV_2500FDX_CAP, "adv_2500fdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_5000FDX_CAP, "adv_5000fdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_10GFDX_CAP, "adv_10gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_25GFDX_CAP, "adv_25gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_40GFDX_CAP, "adv_40gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_50GFDX_CAP, "adv_50gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_100GFDX_CAP, "adv_100gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_200GFDX_CAP, "adv_200gfdx_cap", MAU_CAP_OTHER },
	{ MAC_PROP_ADV_400GFDX_CAP, "adv_400gfdx_cap", MAU_CAP_OTHER },
};

static bool
media_is_1000base_x(mac_ether_media_t m)
{
	switch (m) {
	case ETHER_MEDIA_1000BASE_X:
	case ETHER_MEDIA_1000BASE_SX:
	case ETHER_MEDIA_1000BASE_LX:
	case ETHER_MEDIA_1000BASE_CX:
	case ETHER_MEDIA_1000BASE_BX:
		return (true);
	default:
		return (false);
	}
}

/*
 * Refresh the information we advertise in the 802.3 MAC/PHY
 * Configuration/Status TLV. Called from the main thread, with a_lock held
 * if the agent's thread is running.
 */
static void
agent_update_phy(agent_t *a)
{
	agent_phy_t		phy = { 0 };
	uint32_t		media = ETHER_MEDIA_UNKNOWN;
	uint8_t			v;

	/*
	 * There's no property for whether a link supports auto-negotiation
	 * (only the cap_autoneg kstat); a link whose driver implements the
	 * adv_autoneg_cap property is assumed to support it.
	 */
	if (link_get_prop(a, MAC_PROP_AUTONEG, "adv_autoneg_cap", &v,
	    sizeof (v))) {
		phy.ap_autoneg_sup = true;
		phy.ap_autoneg_en = (v != 0);
	}

	if (!link_get_prop(a, MAC_PROP_MEDIA, "media", &media,
	    sizeof (media))) {
		media = ETHER_MEDIA_UNKNOWN;
	}
	phy.ap_mau = lldp_ether_media_to_mau((mac_ether_media_t)media);

	if (phy.ap_autoneg_en) {
		for (size_t i = 0; i < ARRAY_SIZE(adv_caps); i++) {
			if (link_get_flag(a, adv_caps[i].ac_id,
			    adv_caps[i].ac_name)) {
				phy.ap_adv_caps |= adv_caps[i].ac_bit;
			}
		}

		/* 1000BASE-X and 1000BASE-T have separate bits */
		bool x = media_is_1000base_x((mac_ether_media_t)media);

		if (link_get_flag(a, MAC_PROP_ADV_1000HDX_CAP,
		    "adv_1000hdx_cap")) {
			phy.ap_adv_caps |= x ?
			    MAU_CAP_1000BASEX : MAU_CAP_1000BASET;
		}
		if (link_get_flag(a, MAC_PROP_ADV_1000FDX_CAP,
		    "adv_1000fdx_cap")) {
			phy.ap_adv_caps |= x ?
			    MAU_CAP_1000BASEXFD : MAU_CAP_1000BASETFD;
		}
	}

	if (memcmp(&phy, &a->a_phy, sizeof (phy)) != 0) {
		log_debug(a->a_log, "link PHY information",
		    LOG_T_UINT32, "media", media,
		    LOG_T_UINT32, "mau", (uint32_t)phy.ap_mau,
		    LOG_T_BOOLEAN, "autoneg_supported", phy.ap_autoneg_sup,
		    LOG_T_BOOLEAN, "autoneg_enabled", phy.ap_autoneg_en,
		    LOG_T_XINT32, "adv_caps", (uint32_t)phy.ap_adv_caps,
		    LOG_T_END);
		a->a_phy = phy;
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

		/* The media (e.g. transceiver) may have changed */
		agent_update_phy(a);
		break;

	case DL_NOTE_SPEED:
		agent_update_phy(a);
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
	    DL_NOTE_PHYS_ADDR | DL_NOTE_SDU_SIZE | DL_NOTE_SPEED, lldp_dlpi_cb,
	    a, &a->a_dl_nid);
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

	/* Sorted by name; door clients rely on this ordering */
	agent_list = uu_list_create(agent_list_pool, NULL,
	    UU_LIST_DEBUG | UU_LIST_SORTED);
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
