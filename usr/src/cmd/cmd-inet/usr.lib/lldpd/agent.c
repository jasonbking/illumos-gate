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
#include <libdlpi.h>
#include <libuutil.h>
#include <pthread.h>
#include <string.h>
#include <synch.h>
#include <umem.h>
#include <sys/containerof.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/sysmacros.h>

#include "agent.h"
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

#define	LLDP_PDU_MAX		512

static void *agent_thread(void *);

static void tx_initialize(agent_t *);
static void rx_init_lldp(agent_t *);
static void update_objects(agent_t *);
static void delete_objects(agent_t *);
static void tx_add_credit(agent_t *);
static void something_changed_remote(agent_t *);

static void tx_init(agent_t *, tx_t *);
static void tx_fini(tx_t *);
static bool tx_machine(tx_t *);
static bool tx_next_state(tx_t *);

static void rx_init(agent_t *, rx_t *);
static void rx_fini(rx_t *);
static bool rx_machine(rx_t *);
static bool rx_next_state(rx_t *);

static void ttr_init(agent_t *, ttr_t *);
static void ttr_fini(ttr_t *);
static bool ttr_machine(ttr_t *);
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

	a->a_name = xstrdup(name);
	a->a_port_enabled = false;

	log_child(log, &a->a_log,
	    LOG_T_STRING, "agent", a->a_name,
	    LOG_T_END);

	tx_init(a, &a->a_tx);
	rx_init(a, &a->a_rx);
	ttr_init(a, &a->a_ttr);

	a->a_neighbors = neighbor_list_new(a);
	a->a_cfg.ac_tx_fast_msg = DEFAULT_MSG_FAST_TX;
	a->a_cfg.ac_tx_hold = DEFAULT_MSG_TX_HOLD;
	a->a_cfg.ac_tx_interval = DEFAULT_MSG_TX_INTERVAL;
	a->a_cfg.ac_reinit_delay = DEFAULT_REINIT_DELAY;
	a->a_cfg.ac_tx_credit_max = DEFAULT_TX_CREDIT_MAX;
	a->a_cfg.ac_tx_fast_init = DEFAULT_TX_FAST_INIT;

	/* XXX: Override defaults from config */

	ret = thr_create(NULL, 0, agent_thread, a, 0, &a->a_tid);
	if (ret != 0)
		panic("failed to create agent thread");

	return (a);
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

	VERIFY(!a->a_port_enabled);
	VERIFY(a->a_dlh == NULL);

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
	VERIFY3U(a->a_tid, !=, thr_self());

	mutex_enter(&a->a_lock);
	a->a_port_enabled = true;
	VERIFY0(cond_signal(&a->a_cv));
	return (true);
}

void
agent_disable(agent_t *a)
{
	VERIFY3U(a->a_tid, !=, thr_self());

	mutex_enter(&a->a_lock);
	a->a_port_enabled = false;
	VERIFY0(cond_signal(&a->a_cv));
	mutex_exit(&a->a_lock);
}

void
agent_set_status(agent_t *a, lldp_admin_status_t status)
{
	VERIFY3U(a->a_tid, !=, thr_self());

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
	a->a_cfg.ac_status = status;
	VERIFY0(cond_signal(&a->a_cv));
	mutex_exit(&a->a_lock);
}

lldp_admin_status_t
agent_get_status(agent_t *a)
{
	VERIFY3U(a->a_tid, !=, thr_self());

	lldp_admin_status_t status;

	mutex_enter(&a->a_lock);
	status = admin_status(a);
	mutex_exit(&a->a_lock);

	return (status);
}

void
agent_local_change(agent_t *a)
{
	VERIFY3U(a->a_tid, !=, thr_self());

	mutex_enter(&a->a_lock);
	a->a_local_changes = true;
	VERIFY0(cond_signal(&a->a_cv));
	mutex_exit(&a->a_lock);
}

size_t
agent_num_neighbors(agent_t *a)
{
	size_t n;

	VERIFY3U(a->a_tid, !=, thr_self());

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

	run_tx = tx_machine(&a->a_tx);
	run_rx = rx_machine(&a->a_rx);
	run_ttr = ttr_machine(&a->a_ttr);

	lldp_clock_tick(&a->a_clk, &tick);
	while (!a->a_exit) {
		/*
		 * Run each state machine until they are 'idle' -- i.e.
		 * there are no conditions present to allow the state
		 * machines to transition to a new state.
		 */
		do {
			if (run_tx)
				run_tx = tx_machine(&a->a_tx);
			if (run_rx)
				run_rx = rx_machine(&a->a_rx);
			if (run_ttr)
				run_ttr = ttr_machine(&a->a_ttr);
		} while (run_tx || run_rx || run_ttr);

		/*
		 * Wait for an external trigger (via cv) or for the clock
		 * to tick, then recheck for any state transitions.
		 */
		while (!run_tx && !run_rx && !run_ttr) {
			ret = cond_reltimedwait(&a->a_cv, &a->a_lock, &tick);

			if (a->a_exit)
				break;

			if (ret == ETIME) {
				mutex_enter(&a->a_lock);
				lldp_clock_tock(&a->a_clk);
				lldp_clock_tick(&a->a_clk, &tick);
			}

			run_tx = tx_next_state(&a->a_tx);
			run_rx = rx_next_state(&a->a_rx);
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
tx_init(agent_t *a, tx_t *tx)
{
	log_child(a->a_log, &tx->tx_log,
	    LOG_T_STRING, "state_machine", "tx",
	    LOG_T_END);

	lldp_timer_init(&a->a_clk, &tx->tx_shutdown, "txShutdownWhile", tx,
	    tx->tx_log, NULL, NULL);
	buf_init(&tx->tx_buf, LLDP_PDU_MAX);
	tx->tx_state = TX_BEGIN;
}

static void
tx_fini(tx_t *tx)
{
	buf_fini(&tx->tx_buf);
	lldp_timer_fini(&tx->tx_shutdown);
	log_fini(tx->tx_log);
}

static bool
tx_machine(tx_t *tx)
{
	agent_t *a = __containerof(tx, agent_t, a_tx);

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
		make_shutdown_pdu(a, &tx->tx_buf);
		tx_frame(a->a_dlh, &tx->tx_buf, tx->tx_log);
		lldp_timer_set(&tx->tx_shutdown, a->a_cfg.ac_reinit_delay);
		break;
	case TX_INFO_FRAME:
		make_pdu(a, &tx->tx_buf);
		tx_frame(a->a_dlh, &tx->tx_buf, tx->tx_log);
		if (dec(&a->a_ttr.ttr_tx_credit)) {
			uint32_t credit = a->a_ttr.ttr_tx_credit;

			log_trace(tx->tx_log, "dec(tx_credit)",
			    LOG_T_UINT32, "tx_credit", credit,
			    LOG_T_END);
		}
		tx->tx_now = false;
		break;
	}

	return (tx_next_state(tx));
}

static bool
tx_next_state(tx_t *tx)
{
	agent_t *a = __containerof(tx, agent_t, a_tx);
	tx_state_t next;

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
		return (false);
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
		return (false);
	case TX_SHUTDOWN_FRAME:
		if (lldp_timer_val(&tx->tx_shutdown) == 0) {
			next = TX_LLDP_INITIALIZE;
			break;
		}
		return (false);
	case TX_INFO_FRAME:
		next = TX_IDLE;
		break;
	default:
		panic("invalid state");
	}

done:
	log_debug(tx->tx_log, "state transition",
	    LOG_T_STRING, "oldstate", tx_statestr(tx->tx_state),
	    LOG_T_STRING, "newstate", tx_statestr(next),
	    LOG_T_END);

	tx->tx_state = next;
	return (true);
}

static void
rx_init(agent_t *a, rx_t *rx)
{
	(void) memset(rx, '\0', sizeof (*rx));

	log_child(a->a_log, &rx->rx_log,
	    LOG_T_STRING, "state_machine", "rx",
	    LOG_T_END);

	lldp_timer_init(&a->a_clk, &rx->rx_too_many_neighbors_timer,
	    "tooManyNeighborsTimer", rx, rx->rx_log, "tooManyNeighbors",
	    &rx->rx_too_many_neighbors);
	buf_init(&rx->rx_buf, LLDP_PDU_MAX);
	rx->rx_state = RX_BEGIN;
}

static void
rx_fini(rx_t *rx)
{
	buf_fini(&rx->rx_buf);
	lldp_timer_fini(&rx->rx_too_many_neighbors_timer);
	log_fini(rx->rx_log);
}

static bool
rx_next_state(rx_t *rx)
{
	agent_t *a = __containerof(rx, agent_t, a_rx);
	rx_state_t next;

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
		return (false);
	case DELETE_AGED_INFO:
		next = LLDP_WAIT_PORT_OPERATIONAL;
		break;
	case RX_LLDP_INITIALIZE:
		if (admin_status(a) == LLDP_LINK_RX ||
		    admin_status(a) == LLDP_LINK_TXRX) {
			next = RX_WAIT_FOR_FRAME;
			break;
		}
		return (false);
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
		return (false);
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
		return (false);
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
	log_debug(rx->rx_log, "state transition",
	    LOG_T_STRING, "oldstate", rx_statestr(rx->rx_state),
	    LOG_T_STRING, "newstate", rx_statestr(next),
	    LOG_T_END);

	rx->rx_state = next;
	return (true);
}

static bool
rx_machine(rx_t *rx)
{
	agent_t *a = __containerof(rx, agent_t, a_rx);

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

	return (rx_next_state(rx));
}

static void
ttr_init(agent_t *a, ttr_t *ttr)
{
	log_child(a->a_log, &ttr->ttr_log,
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
	ttr_state_t next;

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
		return (false);
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
	default:
		panic("invalid state");
	}

done:
	log_debug(ttr->ttr_log, "state transition",
	    LOG_T_STRING, "oldstate", ttr_statestr(ttr->ttr_state),
	    LOG_T_STRING, "newstate", ttr_statestr(next),
	    LOG_T_END);

	ttr->ttr_state = next;

	return (true);
}

static bool
ttr_machine(ttr_t *ttr)
{
	agent_t *a = __containerof(ttr, agent_t, a_ttr);

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
	int		ret;

	rx->rx_too_many_neighbors = false;

	while ((nb = uu_list_teardown(a->a_neighbors, &cookie)) != NULL)
		neighbor_free(nb);

	ret = dlpi_open(a->a_name, &a->a_dlh, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log, "failed to open link", ret);
		a->a_port_enabled = false;
		return;
	}

	ret = dlpi_info(a->a_dlh, &a->a_dl_info, 0);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log, "failed to get link info", ret);
		goto fail;
	}

	ret = dlpi_enabmulti(a->a_dlh, lldp_addr, sizeof (lldp_addr));
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log,
		    "failed to bind to LLDP multicast address", ret);
		goto fail;
	}

	ret = dlpi_bind(a->a_dlh, lldp_sap, NULL);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log, "failed to bind to LLDP SAP", ret);
		goto fail;
	}

	/* TODO: schedule fd */
	return;

fail:
	dlpi_close(a->a_dlh);
	a->a_dlh = NULL;
	a->a_port_enabled = false;
}

static void
update_objects(agent_t *a)
{
	rx_t *rx = &a->a_rx;
	neighbor_t *old_nb = rx->rx_curr_neighbor;
	neighbor_t *nb = rx->rx_neighbor;

	ASSERT3P(old_nb, !=, nb);
	ASSERT(neighbor_cmp_msap(old_nb, nb));

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
	char		chassis[256];
	char		port[256];
	neighbor_t	*nb;
	uu_list_walk_t	*wk;
	log_t		*l = a->a_rx.rx_log;
	uint32_t	count;

	log_debug(l, "ageing out neighbors", LOG_T_END);

	wk = uu_list_walk_start(a->a_neighbors, UU_WALK_ROBUST);
	if (wk == NULL) {
		log_fatal(l, "cannot iterate through neighbors",
		    LOG_T_END);
		return;
	}

	count = 0;
	while ((nb = uu_list_walk_next(wk)) != NULL) {
		if (lldp_timer_val(&nb->nb_timer) > 0)
			continue;

		(void) lldp_chassis_str(&nb->nb_chassis , chassis,
		    sizeof (chassis));
		(void) lldp_port_str(&nb->nb_port, port, sizeof (port));

		log_info(l, "ageing out neighbor",
		    LOG_T_STRING, "chassis", chassis,
		    LOG_T_STRING, "port", port,
		    LOG_T_END);

		uu_list_remove(a->a_neighbors, nb);
		neighbor_free(nb);
		count++;
	}

	log_info(l, "ageing out complete",
	    LOG_T_UINT32, "numaged", count,
	    LOG_T_END);

	uu_list_walk_end(wk);
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

	VERIFY3U(b->b_idx, >, 0);

	ret = dlpi_send(dlh, lldp_addr, sizeof (lldp_addr), b->b_data,
	    b->b_idx, NULL);
	if (ret != DLPI_SUCCESS)
		log_dlerr(l, "failed to send PDU", ret);

	b->b_idx = 0;
	(void) memset(b->b_data, '\0', b->b_size);
}

static void
tx_add_credit(agent_t *a)
{
	if (a->a_ttr.ttr_tx_credit == a->a_cfg.ac_tx_credit_max)
		return;
	a->a_ttr.ttr_tx_credit++;
}

static bool
recv_frame(rx_t *rx, dlpi_handle_t dlh)
{
	buf_t		*b = &rx->rx_buf;
	uint8_t		src[DLPI_PHYSADDR_MAX] = { 0 };
	dlpi_recvinfo_t	di = { 0 };
	size_t		srclen = 0;
	size_t 		blen = b->b_size;
	int		ret;

	ret = dlpi_recv(dlh, &src, &srclen, b->b_data, &blen, 0, &di);
	if (ret != DLPI_SUCCESS) {
		log_dlerr(rx->rx_log, "receive error", ret);
		rx->rx_bad_frame = true;
		return (false);
	}

	if (di.dri_totmsglen > b->b_size) {
		log_info(rx->rx_log, "oversize message",
		    LOG_T_MAC, "src", src,
		    LOG_T_UINT32, "len", (uint32_t)blen,
		    LOG_T_END);
		rx->rx_bad_frame = true;
		/* XXX: do we need to drain dlh? */
		return (false);
	}

	log_debug(rx->rx_log, "received frame",
	    LOG_T_MAC, "src", src,
	    LOG_T_UINT32, "len", (uint32_t)blen,
	    LOG_T_END);

	b->b_idx = blen;
	return (true);
}

static void
rx_process_frame(agent_t *a)
{
	rx_t *rx = &a->a_rx;
	buf_t *b = &rx->rx_buf;

	if (!recv_frame(rx, a->a_dlh)) {
		return;
	}

	if (!process_pdu(rx->rx_log, b, &rx->rx_neighbor)) {
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
	rx->rx_changes = neighbor_cmp(rx->rx_curr_neighbor, rx->rx_neighbor);

	if (!rx->rx_changes) {
		/* If no changes, just update the TTL and free the new pkt */
		rx->rx_curr_neighbor->nb_ttl = rx->rx_ttl;
		neighbor_free(rx->rx_neighbor);
		rx->rx_neighbor = NULL;
	}
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
