/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
 * Copyright 2024-2026 RackTop Systems, Inc.
 */

/*
 * General Soft rings - Simulating Rx rings in S/W.
 *
 * Soft ring is a data abstraction containing a queue and a worker
 * thread and represents a hardware Rx ring in software. Each soft
 * ring set can have a collection of soft rings for separating
 * L3/L4 specific traffic (IPv4 from IPv6 or TCP from UDP) or for
 * allowing a higher degree of parallelism by sending traffic to
 * one of the soft rings for a SRS (using a hash on src IP or port).
 * Each soft ring worker thread can be bound to a different CPU
 * allowing the processing for each soft ring to happen in parallel
 * and independent from each other.
 *
 * Protocol soft rings:
 *
 * Each SRS has at an minimum 3 softrings. One each for IPv4 TCP,
 * IPv4 UDP and rest (OTH - for IPv6 and everything else). The
 * SRS does dynamic polling and enforces link level bandwidth but
 * it does so for all traffic (IPv4 and IPv6 and all protocols) on
 * that link. However, each protocol layer wants a different
 * behaviour. For instance IPv4 TCP has per CPU squeues which
 * enforce their own polling and flow control so IPv4 TCP traffic
 * needs to go to a separate soft ring which can be polled by the
 * TCP squeue. It also allows TCP squeue to push back flow control
 * all the way to NIC hardware (if it puts its corresponding soft
 * ring in the poll mode and soft ring queue builds up, the
 * shared srs_poll_pkt_cnt goes up and SRS automatically stops
 * more packets from entering the system).
 *
 * Similarly, the UDP benefits from a DLS bypass and packet chaining
 * so sending it to a separate soft ring is desired. All the rest of
 * the traffic (including IPv6 is sent to OTH softring). The IPv6
 * traffic current goes through OTH softring and via DLS because
 * it need more processing to be done. Irrespective of the sap
 * (IPv4 or IPv6) or the transport, the dynamic polling, B/W enforcement,
 * cpu assignment, fanout, etc apply to all traffic since they
 * are implement by the SRS which is agnostic to sap or transport.
 *
 * Fanout soft rings:
 *
 * On a multithreaded system, we can assign more CPU and multi thread
 * the stack by creating a soft ring per CPU and spreading traffic
 * based on a hash computed on src IP etc. Since we still need to
 * keep the protocol separation, we create a set of 3 soft ring per
 * CPU (specified by cpu list or degree of fanout).
 *
 * NOTE: See the block level comment on top of mac_sched.c
 */

#include <sys/types.h>
#include <sys/callb.h>
#include <sys/callo.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/taskq.h>
#include <sys/vlan.h>
#include <inet/ipsec_impl.h>
#include <inet/ip_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>

#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_flow_impl.h>
#include <sys/mac_stat.h>

static void mac_rx_soft_ring_drain(mac_soft_ring_t *);
static void mac_soft_ring_fire(void *);
static void mac_soft_ring_worker(mac_soft_ring_t *);
static void mac_tx_soft_ring_drain(mac_soft_ring_t *);

uint32_t mac_tx_soft_ring_max_q_cnt = 100000;
uint32_t mac_tx_soft_ring_hiwat = 1000;

/*
 * Allow one bandwidth-delay product plus a fixed burst, subject to hard
 * packet and byte limits.
 */
uint32_t mac_srs_delay_max_q_cnt = 100000;
size_t mac_srs_delay_burst_bytes = 1024 * 1024;
size_t mac_srs_delay_max_q_bytes = 256 * 1024 * 1024;

extern kmem_cache_t *mac_soft_ring_cache;

typedef enum {
	MAC_SRS_DELAY_RX,
	MAC_SRS_DELAY_TX
} mac_srs_delay_type_t;

typedef struct mac_srs_delay_s {
	taskq_ent_t		msd_tqent;
	list_node_t		msd_node;
	boolean_t		msd_ready;
	mac_srs_delay_type_t	msd_type;
	mac_soft_ring_set_t	*msd_srs;
	flow_entry_t		*msd_flent;
	mblk_t			*msd_chain;
	uint32_t		msd_count;
	size_t			msd_size;
	hrtime_t		msd_process_time;
	union {
		struct {
			void		*msd_arg;
			boolean_t	msd_loopback;
		} rx;
		struct {
			mac_client_handle_t msd_mch;
			uintptr_t	msd_hint;
			uint16_t	msd_flag;
		} tx;
	} msd_u;
} mac_srs_delay_t;

extern void mac_rx_srs_process_delayed(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);
extern void mac_tx_delayed(mac_client_handle_t, mblk_t *, uintptr_t, uint16_t);

void
mac_srs_delay_init(mac_soft_ring_set_t *srs)
{
	list_create(&srs->srs_delay_list, sizeof (mac_srs_delay_t),
	    offsetof(mac_srs_delay_t, msd_node));
}

void
mac_srs_delay_fini(mac_soft_ring_set_t *srs)
{
	VERIFY(list_is_empty(&srs->srs_delay_list));
	list_destroy(&srs->srs_delay_list);
}

static void
mac_srs_delay_run(void *arg)
{
	mac_soft_ring_set_t *srs = ((mac_srs_delay_t *)arg)->msd_srs;
	flow_entry_t *worker_flent = srs->srs_flent;

	FLOW_REFHOLD(worker_flent);

	for (;;) {
		mac_srs_delay_t *delay;
		flow_entry_t *flent;

		mutex_enter(&srs->srs_lock);
		delay = list_head(&srs->srs_delay_list);
		if (delay == NULL || !delay->msd_ready) {
			srs->srs_delay_running = B_FALSE;
			mutex_exit(&srs->srs_lock);
			FLOW_REFRELE(worker_flent);
			return;
		}

		list_remove(&srs->srs_delay_list, delay);
		ASSERT3U(srs->srs_delay_count, >=, delay->msd_count);
		ASSERT3U(srs->srs_delay_size, >=, delay->msd_size);
		srs->srs_delay_count -= delay->msd_count;
		srs->srs_delay_size -= delay->msd_size;
		mutex_exit(&srs->srs_lock);

		flent = delay->msd_flent;
		switch (delay->msd_type) {
		case MAC_SRS_DELAY_RX:
			mac_rx_srs_process_delayed(delay->msd_u.rx.msd_arg,
			    (mac_resource_handle_t)srs, delay->msd_chain,
			    delay->msd_u.rx.msd_loopback);
			break;
		case MAC_SRS_DELAY_TX:
			mac_tx_delayed(delay->msd_u.tx.msd_mch,
			    delay->msd_chain, delay->msd_u.tx.msd_hint,
			    delay->msd_u.tx.msd_flag);
			break;
		default:
			panic("invalid MAC SRS delay type %d",
			    delay->msd_type);
		}

		kmem_free(delay, sizeof (*delay));
		FLOW_REFRELE(flent);
	}
}

static void
mac_srs_delay_fire(void *arg)
{
	mac_srs_delay_t *delay = arg;
	mac_soft_ring_set_t *srs = delay->msd_srs;
	boolean_t dispatch = B_FALSE;

	mutex_enter(&srs->srs_lock);
	delay->msd_ready = B_TRUE;
	if (list_head(&srs->srs_delay_list) == delay &&
	    !srs->srs_delay_running) {
		srs->srs_delay_running = B_TRUE;
		dispatch = B_TRUE;
	}
	mutex_exit(&srs->srs_lock);

	if (dispatch) {
		taskq_dispatch_ent(system_taskq, mac_srs_delay_run, delay,
		    TQ_NOSLEEP, &delay->msd_tqent);
	}
}

static void
mac_srs_delay_start(mac_srs_delay_t *delay)
{
	DTRACE_PROBE1(disturb__delay, mac_soft_ring_set_t *, delay->msd_srs);

	(void) timeout_generic(CALLOUT_NORMAL, mac_srs_delay_fire, delay,
	    delay->msd_process_time, NANOSEC / MICROSEC,
	    CALLOUT_FLAG_ABSOLUTE | CALLOUT_FLAG_ROUNDUP);
}

static void
mac_srs_delay_count(mblk_t *mp_chain, uint32_t *countp, size_t *sizep)
{
	uint32_t count = 0;
	size_t size = 0;

	for (mblk_t *mp = mp_chain; mp != NULL; mp = mp->b_next) {
		count++;
		size += msgdsize(mp);
	}

	*countp = count;
	*sizep = size;
}

static size_t
mac_srs_delay_byte_limit(mac_soft_ring_set_t *srs, uint32_t delay_usec)
{
	const uint64_t divisor = 8 * MICROSEC;
	const size_t burst_bytes = mac_srs_delay_burst_bytes;
	const size_t max_bytes = mac_srs_delay_max_q_bytes;
	uint64_t link_speed = srs->srs_mcip->mci_flent->fe_nic_speed;
	uint64_t delay_bytes, whole, remainder, remainder_bytes;

	if (delay_usec == 0 || link_speed == 0) {
		delay_bytes = 0;
	} else {
		whole = link_speed / divisor;
		remainder = link_speed % divisor;
		remainder_bytes = (remainder * delay_usec + divisor - 1) /
		    divisor;

		if (whole > max_bytes / delay_usec ||
		    whole * delay_usec >
		    max_bytes - MIN(remainder_bytes, max_bytes)) {
			delay_bytes = max_bytes;
		} else {
			delay_bytes = whole * delay_usec + remainder_bytes;
		}
	}

	if (delay_bytes >= max_bytes ||
	    burst_bytes >= max_bytes - delay_bytes) {
		return (max_bytes);
	}

	return (delay_bytes + burst_bytes);
}

static boolean_t
mac_srs_delay_over_limit(mac_soft_ring_set_t *srs, uint32_t count,
    size_t size, uint32_t delay_usec)
{
	const size_t byte_limit = mac_srs_delay_byte_limit(srs, delay_usec);
	const uint32_t packet_limit = mac_srs_delay_max_q_cnt;

	if ((uint64_t)srs->srs_delay_count + count > packet_limit) {
		return (B_TRUE);
	}

	return (size > byte_limit || srs->srs_delay_size > byte_limit - size);
}

boolean_t
mac_srs_delay_rx(mac_soft_ring_set_t *srs, void *arg, mblk_t *mp_chain,
    boolean_t loopback)
{
	mac_srs_delay_t *delay;
	uint32_t count, delay_usec;
	size_t size;
	boolean_t drop = B_FALSE;

	mac_srs_delay_count(mp_chain, &count, &size);
	delay = kmem_zalloc(sizeof (*delay), KM_NOSLEEP);
	if (delay == NULL) {
		mutex_enter(&srs->srs_lock);
		if (srs->srs_delay == 0) {
			mutex_exit(&srs->srs_lock);
			return (B_FALSE);
		}
		srs->srs_rx.sr_stat.mrs_sdrops += count;
		srs->srs_rx.sr_stat.mrs_delaydrops += count;
		mutex_exit(&srs->srs_lock);
		freemsgchain(mp_chain);
		return (B_TRUE);
	}

	delay->msd_type = MAC_SRS_DELAY_RX;
	delay->msd_srs = srs;
	delay->msd_flent = srs->srs_flent;
	delay->msd_chain = mp_chain;
	delay->msd_count = count;
	delay->msd_size = size;
	delay->msd_u.rx.msd_arg = arg;
	delay->msd_u.rx.msd_loopback = loopback;

	FLOW_REFHOLD(srs->srs_flent);
	mutex_enter(&srs->srs_lock);
	delay_usec = srs->srs_delay;
	if (delay_usec == 0) {
		mutex_exit(&srs->srs_lock);
		FLOW_REFRELE(srs->srs_flent);
		kmem_free(delay, sizeof (*delay));
		return (B_FALSE);
	}

	if (mac_srs_delay_over_limit(srs, count, size, delay_usec)) {
		srs->srs_rx.sr_stat.mrs_sdrops += count;
		srs->srs_rx.sr_stat.mrs_delaydrops += count;
		drop = B_TRUE;
	} else {
		delay->msd_process_time = gethrtime() +
		    (hrtime_t)delay_usec * (NANOSEC / MICROSEC);
		srs->srs_delay_count += count;
		srs->srs_delay_size += size;
		srs->srs_rx.sr_stat.mrs_admdelays += count;
		list_insert_tail(&srs->srs_delay_list, delay);
	}
	mutex_exit(&srs->srs_lock);

	if (drop) {
		FLOW_REFRELE(srs->srs_flent);
		kmem_free(delay, sizeof (*delay));
		freemsgchain(mp_chain);
		return (B_TRUE);
	}

	mac_srs_delay_start(delay);
	return (B_TRUE);
}

boolean_t
mac_srs_delay_tx(mac_soft_ring_set_t *srs, mac_client_handle_t mch,
    mblk_t *mp_chain, uintptr_t hint, uint16_t flag, mblk_t **ret_mp,
    mac_tx_cookie_t *cookiep)
{
	mac_srs_delay_t *delay;
	uint32_t count, delay_usec;
	size_t size;
	boolean_t reject = B_FALSE;

	mac_srs_delay_count(mp_chain, &count, &size);
	delay = kmem_zalloc(sizeof (*delay), KM_NOSLEEP);
	if (delay != NULL) {
		delay->msd_type = MAC_SRS_DELAY_TX;
		delay->msd_srs = srs;
		delay->msd_flent = srs->srs_flent;
		delay->msd_chain = mp_chain;
		delay->msd_count = count;
		delay->msd_size = size;
		delay->msd_u.tx.msd_mch = mch;
		delay->msd_u.tx.msd_hint = hint;
		delay->msd_u.tx.msd_flag = flag;
	}

	FLOW_REFHOLD(srs->srs_flent);
	mutex_enter(&srs->srs_lock);
	delay_usec = srs->srs_delay;
	if (delay_usec == 0) {
		mutex_exit(&srs->srs_lock);
		FLOW_REFRELE(srs->srs_flent);
		if (delay != NULL)
			kmem_free(delay, sizeof (*delay));
		return (B_FALSE);
	}

	if (delay == NULL ||
	    mac_srs_delay_over_limit(srs, count, size, delay_usec)) {
		reject = B_TRUE;
	} else {
		delay->msd_process_time = gethrtime() +
		    (hrtime_t)delay_usec * (NANOSEC / MICROSEC);
		srs->srs_delay_count += count;
		srs->srs_delay_size += size;
		srs->srs_tx.st_stat.mts_admdelays += count;
		list_insert_tail(&srs->srs_delay_list, delay);
	}
	mutex_exit(&srs->srs_lock);

	if (reject) {
		FLOW_REFRELE(srs->srs_flent);
		if (delay != NULL)
			kmem_free(delay, sizeof (*delay));
		*cookiep = (mac_tx_cookie_t)srs;
		if (flag & MAC_TX_NO_ENQUEUE) {
			*ret_mp = mp_chain;
		} else {
			mutex_enter(&srs->srs_lock);
			srs->srs_tx.st_stat.mts_sdrops += count;
			srs->srs_tx.st_stat.mts_delaydrops += count;
			mutex_exit(&srs->srs_lock);
			freemsgchain(mp_chain);
		}
		return (B_TRUE);
	}

	mac_srs_delay_start(delay);
	return (B_TRUE);
}

#define	ADD_SOFTRING_TO_SET(mac_srs, softring) {			\
	if (mac_srs->srs_soft_ring_head == NULL) {			\
		mac_srs->srs_soft_ring_head = softring;			\
		mac_srs->srs_soft_ring_tail = softring;			\
	} else {							\
		/* ADD to the list */					\
		softring->s_ring_prev =					\
			mac_srs->srs_soft_ring_tail;			\
		mac_srs->srs_soft_ring_tail->s_ring_next = softring;	\
		mac_srs->srs_soft_ring_tail = softring;			\
	}								\
	mac_srs->srs_soft_ring_count++;					\
}

/*
 * mac_soft_ring_worker_wakeup
 *
 * Wake up the soft ring worker thread to process the queue as long
 * as no one else is processing it and upper layer (client) is still
 * ready to receive packets.
 */
void
mac_soft_ring_worker_wakeup(mac_soft_ring_t *ringp)
{
	ASSERT(MUTEX_HELD(&ringp->s_ring_lock));
	if (!(ringp->s_ring_state & S_RING_PROC) &&
	    !(ringp->s_ring_state & S_RING_BLANK) &&
	    (ringp->s_ring_tid == NULL)) {
		if (ringp->s_ring_wait != 0) {
			ringp->s_ring_tid =
			    timeout(mac_soft_ring_fire, ringp,
			    ringp->s_ring_wait);
		} else {
			/* Schedule the worker thread. */
			cv_signal(&ringp->s_ring_async);
		}
	}
}

/*
 * Create a soft ring, do the necessary setup and bind the worker
 * thread to the assigned CPU.
 */
static mac_soft_ring_t *
mac_soft_ring_create_i(int id, clock_t wait, const mac_soft_ring_state_t type,
    pri_t pri, mac_client_impl_t *mcip, mac_soft_ring_set_t *mac_srs,
    processorid_t cpuid)
{
	mac_soft_ring_t		*ringp;
	char			name[S_RING_NAMELEN];

	VERIFY3U(type & SR_STATE, ==, 0);

	bzero(name, 64);
	ringp = kmem_cache_alloc(mac_soft_ring_cache, KM_SLEEP);

	if (type & ST_RING_TCP) {
		(void) snprintf(name, sizeof (name),
		    "mac_tcp_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_TCP6) {
		(void) snprintf(name, sizeof (name),
		    "mac_tcp6_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_UDP) {
		(void) snprintf(name, sizeof (name),
		    "mac_udp_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_UDP6) {
		(void) snprintf(name, sizeof (name),
		    "mac_udp6_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_OTH) {
		(void) snprintf(name, sizeof (name),
		    "mac_oth_soft_ring_%d_%p", id, (void *)mac_srs);
	} else {
		ASSERT(type & ST_RING_TX);
		(void) snprintf(name, sizeof (name),
		    "mac_tx_soft_ring_%d_%p", id, (void *)mac_srs);
	}

	bzero(ringp, sizeof (mac_soft_ring_t));
	(void) strncpy(ringp->s_ring_name, name, S_RING_NAMELEN + 1);
	ringp->s_ring_name[S_RING_NAMELEN] = '\0';
	mutex_init(&ringp->s_ring_lock, NULL, MUTEX_DEFAULT, NULL);
	ringp->s_ring_notify_cb_info.mcbi_lockp = &ringp->s_ring_lock;

	ringp->s_ring_state = type;
	ringp->s_ring_wait = MSEC_TO_TICK(wait);
	ringp->s_ring_mcip = mcip;
	ringp->s_ring_set = mac_srs;

	/*
	 * Protect against access from DR callbacks (mac_walk_srs_bind/unbind)
	 * which can't grab the mac perimeter
	 */
	mutex_enter(&mac_srs->srs_lock);
	ADD_SOFTRING_TO_SET(mac_srs, ringp);
	mutex_exit(&mac_srs->srs_lock);

	/*
	 * set the bind CPU to -1 to indicate
	 * no thread affinity set
	 */
	ringp->s_ring_cpuid = ringp->s_ring_cpuid_save = -1;
	ringp->s_ring_worker = thread_create(NULL, 0,
	    mac_soft_ring_worker, ringp, 0, &p0, TS_RUN, pri);
	if (cpuid != -1)
		(void) mac_soft_ring_bind(ringp, cpuid);

	return (ringp);
}

mac_soft_ring_t *
mac_soft_ring_create_rx(int id, clock_t wait, const mac_soft_ring_state_t type,
    pri_t pri, mac_client_impl_t *mcip, mac_soft_ring_set_t *mac_srs,
    processorid_t cpuid, mac_direct_rx_t rx_func, void *x_arg1)
{
	VERIFY3U((type & ST_RING_TX), ==, 0);

	mac_soft_ring_t *ringp = mac_soft_ring_create_i(id, wait, type, pri,
	    mcip, mac_srs, cpuid);

	ringp->s_ring_drain_func = mac_rx_soft_ring_drain;
	ringp->s_ring_rx_func = rx_func;
	ringp->s_ring_rx_arg1 = x_arg1;
	ringp->s_ring_rx_arg2 = NULL;
	if (mac_srs->srs_type & SRST_ENQUEUE) {
		ringp->s_ring_state |= ST_RING_WORKER_ONLY;
	}

	mac_soft_ring_stat_create(ringp);

	return (ringp);
}

mac_soft_ring_t *
mac_soft_ring_create_tx(int id, clock_t wait, const mac_soft_ring_state_t type,
    pri_t pri, mac_client_impl_t *mcip, mac_soft_ring_set_t *mac_srs,
    processorid_t cpuid, mac_ring_t *ring)
{
	VERIFY3U((type & ST_RING_TX), ==, 0);
	VERIFY(ring != NULL);

	mac_soft_ring_t *ringp = mac_soft_ring_create_i(id, wait,
	    type | ST_RING_TX, pri, mcip, mac_srs, cpuid);

	ringp->s_ring_drain_func = mac_tx_soft_ring_drain;
	ringp->s_ring_tx_arg1 = mcip;
	ringp->s_ring_tx_arg2 = ring;
	ringp->s_ring_tx_max_q_cnt = mac_tx_soft_ring_max_q_cnt;
	ringp->s_ring_tx_hiwat =
	    (mac_tx_soft_ring_hiwat > mac_tx_soft_ring_max_q_cnt) ?
	    mac_tx_soft_ring_max_q_cnt : mac_tx_soft_ring_hiwat;
	if (mcip->mci_state_flags & MCIS_IS_AGGR_CLIENT) {
		mac_srs_tx_t *tx = &mac_srs->srs_tx;
		VERIFY3P(tx->st_soft_rings[ring->mr_index], ==, NULL);
		tx->st_soft_rings[ring->mr_index] = ringp;
	}

	mac_soft_ring_stat_create(ringp);

	return (ringp);
}

/*
 * mac_soft_ring_free
 *
 * Free the soft ring once we are done with it.
 */
void
mac_soft_ring_free(mac_soft_ring_t *softring)
{
	ASSERT((softring->s_ring_state &
	    (S_RING_CONDEMNED | S_RING_CONDEMNED_DONE | S_RING_PROC)) ==
	    (S_RING_CONDEMNED | S_RING_CONDEMNED_DONE));
	mac_drop_chain(softring->s_ring_first, "softring free");
	softring->s_ring_tx_arg2 = NULL;
	mac_soft_ring_stat_delete(softring);
	mac_callback_free(softring->s_ring_notify_cb_list);
	kmem_cache_free(mac_soft_ring_cache, softring);
}

int mac_soft_ring_thread_bind = 1;

/*
 * mac_soft_ring_bind
 *
 * Bind a soft ring worker thread to supplied CPU.
 */
cpu_t *
mac_soft_ring_bind(mac_soft_ring_t *ringp, processorid_t cpuid)
{
	cpu_t *cp;
	boolean_t clear = B_FALSE;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (mac_soft_ring_thread_bind == 0) {
		DTRACE_PROBE1(mac__soft__ring__no__cpu__bound,
		    mac_soft_ring_t *, ringp);
		return (NULL);
	}

	cp = cpu_get(cpuid);
	if (cp == NULL || !cpu_is_online(cp))
		return (NULL);

	mutex_enter(&ringp->s_ring_lock);
	ringp->s_ring_state |= S_RING_BOUND;
	if (ringp->s_ring_cpuid != -1)
		clear = B_TRUE;
	ringp->s_ring_cpuid = cpuid;
	mutex_exit(&ringp->s_ring_lock);

	if (clear)
		thread_affinity_clear(ringp->s_ring_worker);

	DTRACE_PROBE2(mac__soft__ring__cpu__bound, mac_soft_ring_t *,
	    ringp, processorid_t, cpuid);

	thread_affinity_set(ringp->s_ring_worker, cpuid);

	return (cp);
}

/*
 * mac_soft_ring_unbind
 *
 * Un Bind a soft ring worker thread.
 */
void
mac_soft_ring_unbind(mac_soft_ring_t *ringp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	mutex_enter(&ringp->s_ring_lock);
	if (!(ringp->s_ring_state & S_RING_BOUND)) {
		ASSERT(ringp->s_ring_cpuid == -1);
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_cpuid = -1;
	ringp->s_ring_state &= ~S_RING_BOUND;
	thread_affinity_clear(ringp->s_ring_worker);
	mutex_exit(&ringp->s_ring_lock);
}

/*
 * PRIVATE FUNCTIONS
 */

static void
mac_soft_ring_fire(void *arg)
{
	mac_soft_ring_t	*ringp = arg;

	mutex_enter(&ringp->s_ring_lock);
	if (ringp->s_ring_tid == NULL) {
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_tid = NULL;

	if (!(ringp->s_ring_state & S_RING_PROC)) {
		cv_signal(&ringp->s_ring_async);
	}
	mutex_exit(&ringp->s_ring_lock);
}

/*
 * Drain the soft ring pointed to by ringp.
 *
 *    o s_ring_first: pointer to the queued packet chain.
 *
 *    o s_ring_rx_func: pointer to to the client's Rx routine.
 *
 *    o s_ring_rx_{arg1,arg2}: opaque values specific to the client.
 */
static void
mac_rx_soft_ring_drain(mac_soft_ring_t *ringp)
{
	mblk_t		*mp;
	void		*arg1;
	mac_resource_handle_t arg2;
	timeout_id_t	tid;
	mac_direct_rx_t	proc;
	int		cnt;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	ringp->s_ring_run = curthread;
	ASSERT(mutex_owned(&ringp->s_ring_lock));
	ASSERT(!(ringp->s_ring_state & S_RING_PROC));

	if ((tid = ringp->s_ring_tid) != NULL)
		ringp->s_ring_tid = NULL;

	ringp->s_ring_state |= S_RING_PROC;

	proc = ringp->s_ring_rx_func;
	arg1 = ringp->s_ring_rx_arg1;
	arg2 = ringp->s_ring_rx_arg2;

	while ((ringp->s_ring_first != NULL) &&
	    !(ringp->s_ring_state & S_RING_PAUSE)) {
		mp = ringp->s_ring_first;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		cnt = ringp->s_ring_count;
		ringp->s_ring_count = 0;
		ringp->s_ring_size = 0;
		mutex_exit(&ringp->s_ring_lock);

		if (tid != NULL) {
			(void) untimeout(tid);
			tid = NULL;
		}

		(*proc)(arg1, arg2, mp, NULL);

		/*
		 * If we have an SRS performing bandwidth control, then
		 * we need to decrement the size and count so the SRS
		 * has an accurate measure of the data queued between
		 * the SRS and its soft rings. We decrement the
		 * counters only when the packet is processed by both
		 * the SRS and the soft ring.
		 */
		mutex_enter(&mac_srs->srs_lock);
		MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
		mutex_exit(&mac_srs->srs_lock);

		mutex_enter(&ringp->s_ring_lock);
	}
	ringp->s_ring_state &= ~S_RING_PROC;
	if (ringp->s_ring_state & S_RING_CLIENT_WAIT)
		cv_signal(&ringp->s_ring_client_cv);
	ringp->s_ring_run = NULL;
}

/*
 * The soft ring worker routine to process any queued packets. In
 * normal case, the worker thread is bound to a CPU. If the soft ring
 * handles TCP packets then the worker thread is bound to the same CPU
 * as the TCP squeue.
 */
static void
mac_soft_ring_worker(mac_soft_ring_t *ringp)
{
	kmutex_t *lock = &ringp->s_ring_lock;
	kcondvar_t *async = &ringp->s_ring_async;
	mac_soft_ring_set_t *srs = ringp->s_ring_set;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "mac_soft_ring");
	mutex_enter(lock);
start:
	for (;;) {
		while (((ringp->s_ring_first == NULL ||
		    (ringp->s_ring_state & (S_RING_BLOCK|S_RING_BLANK))) &&
		    !(ringp->s_ring_state & S_RING_PAUSE)) ||
		    (ringp->s_ring_state & S_RING_PROC)) {

			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}

		/*
		 * Either we have work to do, or we have been asked to
		 * shutdown temporarily or permanently
		 */
		if (ringp->s_ring_state & S_RING_PAUSE)
			goto done;

		ringp->s_ring_drain_func(ringp);
	}
done:
	mutex_exit(lock);
	mutex_enter(&srs->srs_lock);
	mutex_enter(lock);

	ringp->s_ring_state |= S_RING_QUIESCE_DONE;
	if (!(ringp->s_ring_state & S_RING_CONDEMNED)) {
		srs->srs_soft_ring_quiesced_count++;
		cv_broadcast(&srs->srs_async);
		mutex_exit(&srs->srs_lock);
		while (!(ringp->s_ring_state &
		    (S_RING_RESTART | S_RING_CONDEMNED)))
			cv_wait(&ringp->s_ring_async, &ringp->s_ring_lock);
		mutex_exit(lock);
		mutex_enter(&srs->srs_lock);
		mutex_enter(lock);
		srs->srs_soft_ring_quiesced_count--;
		if (ringp->s_ring_state & S_RING_RESTART) {
			ASSERT(!(ringp->s_ring_state & S_RING_CONDEMNED));
			ringp->s_ring_state &= ~(S_RING_RESTART |
			    S_RING_QUIESCE | S_RING_QUIESCE_DONE);
			cv_broadcast(&srs->srs_async);
			mutex_exit(&srs->srs_lock);
			goto start;
		}
	}
	ASSERT(ringp->s_ring_state & S_RING_CONDEMNED);
	ringp->s_ring_state |= S_RING_CONDEMNED_DONE;
	CALLB_CPR_EXIT(&cprinfo);
	srs->srs_soft_ring_condemned_count++;
	cv_broadcast(&srs->srs_async);
	mutex_exit(&srs->srs_lock);
	thread_exit();
}

/*
 * mac_soft_ring_intr_enable and mac_soft_ring_intr_disable
 *
 * these functions are called to toggle the sending of packets to the
 * client. They are called by the client. the client gets the name
 * of these routine and corresponding cookie (pointing to softring)
 * during capability negotiation at setup time.
 *
 * Enabling is allow the processing thread to send packets to the
 * client while disabling does the opposite.
 */
int
mac_soft_ring_intr_enable(void *arg)
{
	mac_soft_ring_t *ringp = (mac_soft_ring_t *)arg;
	mutex_enter(&ringp->s_ring_lock);
	ringp->s_ring_state &= ~S_RING_BLANK;
	if (ringp->s_ring_first != NULL)
		mac_soft_ring_worker_wakeup(ringp);
	mutex_exit(&ringp->s_ring_lock);
	return (0);
}

boolean_t
mac_soft_ring_intr_disable(void *arg)
{
	mac_soft_ring_t *ringp = (mac_soft_ring_t *)arg;
	boolean_t sring_blanked = B_FALSE;
	/*
	 * Stop worker thread from sending packets above.
	 * Squeue will poll soft ring when it needs packets.
	 */
	mutex_enter(&ringp->s_ring_lock);
	if (!(ringp->s_ring_state & S_RING_PROC)) {
		ringp->s_ring_state |= S_RING_BLANK;
		sring_blanked = B_TRUE;
	}
	mutex_exit(&ringp->s_ring_lock);
	return (sring_blanked);
}

/*
 * mac_soft_ring_poll
 *
 * This routine is called by the client to poll for packets from
 * the soft ring. The function name and cookie corresponding to
 * the soft ring is exchanged during capability negotiation during
 * setup.
 */
mblk_t *
mac_soft_ring_poll(mac_soft_ring_t *ringp, size_t bytes_to_pickup)
{
	mblk_t	*head, *tail;
	mblk_t	*mp;
	size_t	sz = 0;
	int	cnt = 0;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	ASSERT(mac_srs != NULL);

	mutex_enter(&ringp->s_ring_lock);
	head = tail = mp = ringp->s_ring_first;
	if (head == NULL) {
		mutex_exit(&ringp->s_ring_lock);
		return (NULL);
	}

	if (ringp->s_ring_size <= bytes_to_pickup) {
		head = ringp->s_ring_first;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		cnt = ringp->s_ring_count;
		ringp->s_ring_count = 0;
		sz = ringp->s_ring_size;
		ringp->s_ring_size = 0;
	} else {
		while (mp && sz <= bytes_to_pickup) {
			sz += msgdsize(mp);
			cnt++;
			tail = mp;
			mp = mp->b_next;
		}
		ringp->s_ring_count -= cnt;
		ringp->s_ring_size -= sz;
		tail->b_next = NULL;
		if (mp == NULL) {
			ringp->s_ring_first = NULL;
			ringp->s_ring_last = NULL;
			ASSERT(ringp->s_ring_count == 0);
		} else {
			ringp->s_ring_first = mp;
		}
	}

	mutex_exit(&ringp->s_ring_lock);
	/*
	 * Update the shared count and size counters so
	 * that SRS has a accurate idea of queued packets.
	 */
	mutex_enter(&mac_srs->srs_lock);
	MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
	mutex_exit(&mac_srs->srs_lock);
	return (head);
}

/*
 * Enable direct client (IP) callback function from the softrings.
 * Callers need to make sure they don't need any DLS layer processing
 */
void
mac_soft_ring_dls_bypass_enable(mac_soft_ring_t *softring,
    mac_direct_rx_t rx_func, void *rx_arg1)
{
	VERIFY3P(rx_func, !=, NULL);
	mutex_enter(&softring->s_ring_lock);
	softring->s_ring_rx_func = rx_func;
	softring->s_ring_rx_arg1 = rx_arg1;
	mutex_exit(&softring->s_ring_lock);
}

/* Disable DLS bypass. */
void
mac_soft_ring_dls_bypass_disable(mac_soft_ring_t *softring,
    mac_client_impl_t *mcip)
{
	mutex_enter(&softring->s_ring_lock);
	/*
	 * Before modifying the ring state we first wait for any in-progress
	 * processing to stop.
	 */
	while (softring->s_ring_state & S_RING_PROC) {
		softring->s_ring_state |= S_RING_CLIENT_WAIT;
		cv_wait(&softring->s_ring_client_cv,
		    &softring->s_ring_lock);
	}

	softring->s_ring_state &= ~S_RING_CLIENT_WAIT;
	softring->s_ring_rx_func = mac_rx_deliver;
	softring->s_ring_rx_arg1 = mcip;
	mutex_exit(&softring->s_ring_lock);
}

void
mac_soft_ring_poll_enable(mac_soft_ring_t *sr, mac_direct_rx_t drx,
    void *drx_arg, mac_resource_cb_t *rcb, uint32_t pri)
{
	mac_rx_fifo_t mrf;

	/* Only TCP/IP clients are poll capable at the moment. */
	VERIFY((sr->s_ring_state & (ST_RING_TCP | ST_RING_TCP6)) != 0);
	/* The client resourse callback structure better be set. */
	VERIFY3P(rcb->mrc_arg, !=, NULL);
	/* Polling should be configured only once on a given softring. */
	VERIFY3P(sr->s_ring_rx_arg2, ==, NULL);

	/*
	 * As polling elides DLS processing we must make sure that
	 * softring processing (i.e. non-polling) also bypasses DLS
	 * processing.
	 */
	mac_soft_ring_dls_bypass_enable(sr, drx, drx_arg);

	bzero(&mrf, sizeof (mrf));
	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_receive = (mac_receive_t)mac_soft_ring_poll;
	mrf.mrf_intr_enable =
	    (mac_intr_enable_t)mac_soft_ring_intr_enable;
	mrf.mrf_intr_disable =
	    (mac_intr_disable_t)mac_soft_ring_intr_disable;
	mrf.mrf_rx_arg = sr;
	mrf.mrf_intr_handle = (mac_intr_handle_t)sr;
	mrf.mrf_cpu_id = sr->s_ring_cpuid;
	mrf.mrf_flow_priority = pri;

	sr->s_ring_rx_arg2 = rcb->mrc_add(rcb->mrc_arg,
	    (mac_resource_t *)&mrf);
}

void
mac_soft_ring_poll_disable(mac_soft_ring_t *sr, mac_resource_cb_t *rcb,
    mac_client_impl_t *mcip)
{
	/* Only TCP/IP clients are poll capable at the moment. */
	VERIFY((sr->s_ring_state & (ST_RING_TCP | ST_RING_TCP6)) != 0);

	/*
	 * Remove the IP ring if there is one associated with this
	 * softring. Note that IP rings are a limited resource; and
	 * SRST_CLIENT_POLL_V4/V6 being set on the SRS is no guarantee
	 * that all TCP softrings have an associated IP ring. This is by
	 * design. See ip_squeue_add_ring().
	 */
	if (sr->s_ring_rx_arg2 != NULL) {
		VERIFY3P(rcb->mrc_arg, !=, NULL);
		rcb->mrc_remove(rcb->mrc_arg, sr->s_ring_rx_arg2);
		sr->s_ring_rx_arg2 = NULL;
	}

	mac_soft_ring_dls_bypass_disable(sr, mcip);
}

/*
 * mac_soft_ring_signal
 *
 * Typically used to set the soft ring state to QUIESCE, CONDEMNED, or
 * RESTART.
 *
 * In the Rx side, the quiescing is done bottom up. After the Rx upcalls
 * from the driver are done, then the Rx SRS is quiesced and only then can
 * we signal the soft rings. Thus this function can't be called arbitrarily
 * without satisfying the prerequisites. On the Tx side, the threads from
 * top need to quiesced, then the Tx SRS and only then can we signal the
 * Tx soft rings.
 */
void
mac_soft_ring_signal(mac_soft_ring_t *softring,
    const mac_soft_ring_state_t sr_flag)
{
	mutex_enter(&softring->s_ring_lock);
	softring->s_ring_state |= sr_flag;
	cv_signal(&softring->s_ring_async);
	mutex_exit(&softring->s_ring_lock);
}

/*
 * mac_tx_soft_ring_drain
 *
 * The transmit side drain routine in case the soft ring was being
 * used to transmit packets.
 */
static void
mac_tx_soft_ring_drain(mac_soft_ring_t *ringp)
{
	mblk_t			*mp;
	void			*arg1;
	void			*arg2;
	mblk_t			*tail;
	uint_t			saved_pkt_count, saved_size;
	mac_tx_stats_t		stats;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	saved_pkt_count = saved_size = 0;
	ringp->s_ring_run = curthread;
	ASSERT(mutex_owned(&ringp->s_ring_lock));
	ASSERT(!(ringp->s_ring_state & S_RING_PROC));

	ringp->s_ring_state |= S_RING_PROC;
	arg1 = ringp->s_ring_tx_arg1;
	arg2 = ringp->s_ring_tx_arg2;

	while (ringp->s_ring_first != NULL) {
		mp = ringp->s_ring_first;
		tail = ringp->s_ring_last;
		saved_pkt_count = ringp->s_ring_count;
		saved_size = ringp->s_ring_size;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		ringp->s_ring_count = 0;
		ringp->s_ring_size = 0;
		mutex_exit(&ringp->s_ring_lock);

		mp = mac_tx_send(arg1, arg2, mp, &stats);

		mutex_enter(&ringp->s_ring_lock);
		if (mp != NULL) {
			/* Device out of tx desc, set block */
			tail->b_next = ringp->s_ring_first;
			ringp->s_ring_first = mp;
			ringp->s_ring_count +=
			    (saved_pkt_count - stats.mts_opackets);
			ringp->s_ring_size += (saved_size - stats.mts_obytes);
			if (ringp->s_ring_last == NULL)
				ringp->s_ring_last = tail;

			if (ringp->s_ring_tx_woken_up) {
				ringp->s_ring_tx_woken_up = B_FALSE;
			} else {
				ringp->s_ring_state |= S_RING_BLOCK;
				ringp->s_st_stat.mts_blockcnt++;
			}

			ringp->s_ring_state &= ~S_RING_PROC;
			ringp->s_ring_run = NULL;
			return;
		} else {
			ringp->s_ring_tx_woken_up = B_FALSE;
			SRS_TX_STATS_UPDATE(mac_srs, &stats);
			SOFTRING_TX_STATS_UPDATE(ringp, &stats);
		}
	}

	if (ringp->s_ring_count == 0 && ringp->s_ring_state &
	    (S_RING_TX_HIWAT | S_RING_WAKEUP_CLIENT | S_RING_ENQUEUED)) {
		mac_client_impl_t *mcip =  ringp->s_ring_mcip;
		boolean_t wakeup_required = B_FALSE;

		if (ringp->s_ring_state &
		    (S_RING_TX_HIWAT|S_RING_WAKEUP_CLIENT)) {
			wakeup_required = B_TRUE;
		}
		ringp->s_ring_state &=
		    ~(S_RING_TX_HIWAT | S_RING_WAKEUP_CLIENT | S_RING_ENQUEUED);
		mutex_exit(&ringp->s_ring_lock);
		if (wakeup_required) {
			mac_tx_invoke_callbacks(mcip, (mac_tx_cookie_t)ringp);
			/*
			 * If the client is not the primary MAC client, then we
			 * need to send the notification to the clients upper
			 * MAC, i.e. mci_upper_mip.
			 */
			mac_tx_notify(mcip->mci_upper_mip != NULL ?
			    mcip->mci_upper_mip : mcip->mci_mip);
		}
		mutex_enter(&ringp->s_ring_lock);
	}
	ringp->s_ring_state &= ~S_RING_PROC;
	ringp->s_ring_run = NULL;
}

/*
 * This is the same RNG used by ipd, which based on the old BSD 4.1 rand.
 * It's currently good enough for flow disturbance.
 */
static inline int
mac_srs_nextrand(mac_soft_ring_set_t *srs)
{
	ASSERT(MUTEX_HELD(&srs->srs_lock));

	srs->srs_rand = srs->srs_rand * 1103515245L + 12345;
	return (srs->srs_rand & 0x7fffffff);
}

/*
 * Disturb a SRS associated with a flow. Returns B_TRUE if packet
 * should be retained, B_FALSE if it should be dropped.
 */
static boolean_t
mac_srs_disturb_pkt(mac_soft_ring_set_t *srs, mblk_t **mpp,
    boolean_t *corruptedp)
{
	mblk_t *mp = *mpp;
	mblk_t *bp;
	int rand;

	ASSERT(MUTEX_HELD(&srs->srs_lock));
	*corruptedp = B_FALSE;

	if (srs->srs_drop != 0 &&
	    mac_srs_nextrand(srs) % 100 < srs->srs_drop)
		return (B_FALSE);

	if (srs->srs_corrupt == 0)
		return (B_TRUE);

	rand = mac_srs_nextrand(srs);
	if (rand % 100 >= srs->srs_corrupt)
		return (B_TRUE);

	/*
	 * If an mblk_t is shared, we need to clone it so we can
	 * modify our local copy without impacting shared owners.
	 */
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		if (DB_TYPE(bp) == M_DATA && MBLKL(bp) != 0 &&
		    DB_REF(bp) > 1)
			break;
	}

	if (bp != NULL) {
		mblk_t *newmp = copymsg(mp);

		if (newmp == NULL)
			return (B_TRUE);

		newmp->b_next = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
		mp = *mpp = newmp;
	}

	unsigned char *dp;
	uint_t off, len;

	/*
	 * Changing one byte in each segment of a packet should be
	 * good enough.
	 */
	for (; mp != NULL; mp = mp->b_cont) {
		len = MBLKL(mp);

		if (len == 0)
			continue;

		/*
		 * Avoid touching any control messages out of an abundance
		 * of caution.
		 */
		if (DB_TYPE(mp) != M_DATA)
			continue;

		off = rand % len;
		dp = mp->b_rptr + off;
		off = rand % 8;
		*dp = *dp ^ (1 << off);
		*corruptedp = B_TRUE;
	}

	return (B_TRUE);
}

/*
 * This largely mirrors the logic in ipd (see ipd_hook()), just done
 * per flow.
 */
void
mac_srs_disturb(mac_soft_ring_set_t *srs, mblk_t **mp_chainp, int *drop_cntp,
    size_t *drop_bytesp, int *corrupt_cntp)
{
	mblk_t *drop_chain;
	mblk_t *mp, *mp_prev, *mp_next;

	ASSERT(MUTEX_HELD(&srs->srs_lock));

	drop_chain = NULL;
	if (drop_cntp != NULL)
		*drop_cntp = 0;
	if (drop_bytesp != NULL)
		*drop_bytesp = 0;
	if (corrupt_cntp != NULL)
		*corrupt_cntp = 0;

	/*
	 * We should only be invoked when one of the disturb parameters
	 * has been set.
	 */
	ASSERT(srs->srs_corrupt > 0 || srs->srs_drop > 0);

	if (srs->srs_drop == 0 && srs->srs_corrupt == 0) {
		return;
	}

	mp_prev = NULL;
	mp = *mp_chainp;
	while (mp != NULL) {
		boolean_t corrupted;
		mblk_t *old_mp = mp;

		mp_next = mp->b_next;

		if (mac_srs_disturb_pkt(srs, &mp, &corrupted)) {
			if (mp != old_mp) {
				if (mp_prev != NULL)
					mp_prev->b_next = mp;
				else
					*mp_chainp = mp;
			}
			if (corrupted && corrupt_cntp != NULL)
				(*corrupt_cntp)++;

			/* keep packet and move on */
			mp_prev = mp;
			mp = mp_next;
			continue;
		}

		/*
		 * need to drop this packet, remove from chain and add
		 * to drop_chain
		 */
		if (mp_prev != NULL) {
			mp_prev->b_next = mp_next;
		} else {
			/* mblk to drop is at the head of the chain */
			*mp_chainp = mp_next;
		}

		if (drop_cntp != NULL)
			(*drop_cntp)++;
		if (drop_bytesp != NULL)
			*drop_bytesp += msgdsize(mp);

		/*
		 * we don't care about preserving the order of mblk_ts
		 * we are going to drop, so just head insert into drop_chain
		 */
		mp->b_next = drop_chain;
		drop_chain = mp;
		mp = mp_next;
	}

	if (drop_chain != NULL)
		freemsgchain(drop_chain);
}
