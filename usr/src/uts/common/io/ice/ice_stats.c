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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * This is heavily based on i40e_stats.c since the interfaces (and many of
 * the stats) are identical in terms of which stats exist and their
 * meaning.
 */

#include "ice.h"

static void
ice_stat_get_uint48(ice_t *ice, uintptr_t reg, kstat_named_t *ks,
    uint64_t *basep, bool init)
{
	uint64_t raw, delta;

	raw = ice_reg_read64(ice, reg);

	if (init) {
		*basep = raw;
		return;
	}

	/*
	 * Check for wraparound. Note that the register is actually
	 * 48 bits wide
	 */
	if (raw >= *basep) {
		delta = raw - *basep;
	} else {
		delta = 0x1000000000000ULL - *basep + raw;
	}

	ks->value.ui64 += delta;
	*basep = raw;
}

static void
ice_stat_get_uint32(ice_t *ice, uintptr_t reg, kstat_named_t *ks,
    uint64_t *basep, bool init)
{
	uint64_t raw, delta;

	raw = ice_reg_read(ice, reg);

	if (init) {
		*basep = raw;
		return;
	}

	/*
	 * Check for wraparound. Note that these registers are only
	 * 32-bits wide.
	 */
	if (raw >= *basep) {
		delta = raw - *basep;
	} else {
		delta = 0x100000000ULL - *basep + raw;
	}

	ks->value.ui64 += delta;
	*basep = raw;
}

static void
ice_stat_vsi_update(ice_vsi_t *vsi, bool init)
{
	ice_t			*ice = vsi->ivsi_ice;
	ice_vsi_stats_t		*st;
	ice_vsi_kstats_t	*kst;
	uint_t			id = vsi->ivsi_id;

	st = &vsi->ivsi_stats;
	kst = vsi->ivsi_kstats->ks_data;

	mutex_enter(&vsi->ivsi_lock);

	ice_stat_get_uint48(ice, ICE_GLV_GORCL(id), &kst->ivk_rx_bytes,
	    &st->ivs_rx_bytes, init);
	ice_stat_get_uint48(ice, ICE_GLV_UPRCL(id), &kst->ivk_rx_unicast,
	    &st->ivs_rx_unicast, init);
	ice_stat_get_uint48(ice, ICE_GLV_MPRCL(id), &kst->ivk_rx_multicast,
	    &st->ivs_rx_multicast, init);
	ice_stat_get_uint48(ice, ICE_GLV_BPRCL(id), &kst->ivk_rx_broadcast,
	    &st->ivs_rx_broadcast, init);

	ice_stat_get_uint32(ice, ICE_GLV_RDPC(id), &kst->ivk_rx_discards,
	    &st->ivs_rx_discards, init);

	ice_stat_get_uint48(ice, ICE_GLV_GOTCL(id), &kst->ivk_tx_bytes,
	    &st->ivs_tx_bytes, init);
	ice_stat_get_uint48(ice, ICE_GLV_UPTCL(id), &kst->ivk_tx_unicast,
	    &st->ivs_tx_unicast, init);
	ice_stat_get_uint48(ice, ICE_GLV_MPTCL(id), &kst->ivk_tx_multicast,
	    &st->ivs_tx_multicast, init);
	ice_stat_get_uint48(ice, ICE_GLV_BPTCL(id), &kst->ivk_tx_broadcast,
	    &st->ivs_tx_broadcast, init);

	ice_stat_get_uint32(ice, ICE_GLV_TEPC(id), &kst->ivk_tx_errors,
	    &st->ivs_tx_errors, init);

	mutex_exit(&vsi->ivsi_lock);

	/*
	 * Like i40e and ixgbe, we don't consider a failed kstat update
	 * to be service effecting (as opposed to other failures).
	 */
	if (ice_regs_check(ice) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_UNAFFECTED);
	}
}

static int
ice_stat_vsi_kstat_update(kstat_t *ksp, int rw)
{
	ice_vsi_t	*vsi;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	vsi = ksp->ks_private;

	ice_stat_vsi_update(vsi, false);

	return (0);
}

void
ice_stat_vsi_fini(ice_vsi_t *vsi)
{
	if (vsi->ivsi_kstats != NULL) {
		kstat_delete(vsi->ivsi_kstats);
		vsi->ivsi_kstats = NULL;
	}
}

bool
ice_stat_vsi_init(ice_vsi_t *vsi)
{
	ice_t			*ice = vsi->ivsi_ice;
	kstat_t			*ksp;
	ice_vsi_kstats_t	*ivk;
	char			buf[64];

	(void) snprintf(buf, sizeof (buf), "vsi_%u", vsi->ivsi_id);

	ksp = kstat_create(ICE_MODULE_NAME, ice->ice_inst, buf, "net",
	    KSTAT_TYPE_NAMED,
	    sizeof (ice_vsi_kstats_t) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		ice_error(ice, "Failed to create kstats for VSI %u",
		    vsi->ivsi_id);
		return (false);
	}

	vsi->ivsi_kstats = ksp;
	ivk = ksp->ks_data;
	ksp->ks_update = ice_stat_vsi_kstat_update;
	ksp->ks_private = vsi;

	kstat_named_init(&ivk->ivk_rx_bytes, "rx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_unicast, "rx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_rx_discards, "rx_discards",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_bytes, "tx_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_unicast, "tx_unicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ivk->ivk_tx_errors, "tx_errors",
	    KSTAT_DATA_UINT64);

	bzero(&vsi->ivsi_stats, sizeof (vsi->ivsi_stats));
	ice_stat_vsi_update(vsi, true);
	kstat_install(vsi->ivsi_kstats);

	return (true);
}

static void
ice_stat_pf_update(ice_t *ice, bool init)
{
	ice_pf_stats_t *ps = &ice->ice_pf_stats;
	ice_pf_kstats_t *ks = ice->ice_pf_ks->ks_data;
	uint_t		port = ice->ice_port_id;

	ASSERT(MUTEX_HELD(&ice->ice_stats_lock));

	ice_stat_get_uint48(ice, ICE_GLPRT_GORCL(port), &ks->ipk_rx_bytes,
	    &ps->ips_rx_bytes, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_UPRCL(port), &ks->ipk_rx_unicast,
	    &ps->ips_rx_unicast, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_MPRCL(port), &ks->ipk_rx_multicast,
	    &ps->ips_rx_multicast, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_BPRCL(port), &ks->ipk_rx_broadcast,
	    &ps->ips_rx_broadcast, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_GOTCL(port), &ks->ipk_tx_bytes,
	    &ps->ips_tx_bytes, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_UPTCL(port), &ks->ipk_tx_unicast,
	    &ps->ips_tx_unicast, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_MPTCL(port), &ks->ipk_tx_multicast,
	    &ps->ips_tx_multicast, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_BPTCL(port), &ks->ipk_tx_broadcast,
	    &ps->ips_tx_broadcast, init);

	ice_stat_get_uint48(ice, ICE_GLPRT_PRC64L(port), &ks->ipk_rx_size_64,
	    &ps->ips_rx_size_64, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC127L(port), &ks->ipk_rx_size_127,
	    &ps->ips_rx_size_127, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC255L(port), &ks->ipk_rx_size_255,
	    &ps->ips_rx_size_255, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC511L(port), &ks->ipk_rx_size_511,
	    &ps->ips_rx_size_511, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC1023L(port),
	    &ks->ipk_rx_size_1023, &ps->ips_rx_size_1023, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC1522L(port),
	    &ks->ipk_rx_size_1522, &ps->ips_rx_size_1522, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PRC9522L(port),
	    &ks->ipk_rx_size_9522, &ps->ips_rx_size_9522, init);

	ice_stat_get_uint48(ice, ICE_GLPRT_PTC64L(port), &ks->ipk_tx_size_64,
	    &ps->ips_tx_size_64, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC127L(port), &ks->ipk_tx_size_127,
	    &ps->ips_tx_size_127, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC255L(port), &ks->ipk_tx_size_255,
	    &ps->ips_tx_size_255, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC511L(port), &ks->ipk_tx_size_511,
	    &ps->ips_tx_size_511, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC1023L(port),
	    &ks->ipk_tx_size_1023, &ps->ips_tx_size_1023, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC1522L(port),
	    &ks->ipk_tx_size_1522, &ps->ips_tx_size_1522, init);
	ice_stat_get_uint48(ice, ICE_GLPRT_PTC9522L(port),
	    &ks->ipk_tx_size_9522, &ps->ips_tx_size_9522, init);

	ice_stat_get_uint32(ice, ICE_GLPRT_LXONRXC(port), &ks->ipk_link_xon_rx,
	    &ps->ips_link_xon_rx, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_LXOFFRXC(port),
	    &ks->ipk_link_xoff_rx, &ps->ips_link_xoff_rx, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_LXONTXC(port), &ks->ipk_link_xon_tx,
	    &ps->ips_link_xon_tx, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_LXOFFTXC(port),
	    &ks->ipk_link_xoff_tx, &ps->ips_link_xoff_tx, init);

	for (uint_t i = 0; i < 8; i++) {
		ice_stat_get_uint32(ice, ICE_GLPRT_PXONRXC(port, i),
		    &ks->ipk_priority_xon_rx[i], &ps->ips_priority_xon_rx[i],
		    init);
		ice_stat_get_uint32(ice, ICE_GLPRT_PXOFFRXC(port, i),
		    &ks->ipk_priority_xoff_rx[i], &ps->ips_priority_xoff_rx[i],
		    init);
		ice_stat_get_uint32(ice, ICE_GLPRT_PXONTXC(port, i),
		    &ks->ipk_priority_xon_tx[i], &ps->ips_priority_xon_tx[i],
		    init);
		ice_stat_get_uint32(ice, ICE_GLPRT_PXOFFTXC(port, i),
		    &ks->ipk_priority_xoff_tx[i], &ps->ips_priority_xoff_tx[i],
		    init);
		ice_stat_get_uint32(ice, ICE_GLPRT_RXON2OFFCNT(port, i),
		    &ks->ipk_priority_xon_2_xoff[i],
		    &ps->ips_priority_xon_2_xoff[i], init);
	}

	ice_stat_get_uint32(ice, ICE_GLPRT_CRCERRS(port),
	    &ks->ipk_crc_errors, &ps->ips_crc_errors, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_ILLERR(port),
	    &ks->ipk_illegal_bytes, &ps->ips_illegal_bytes, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_MLFC(port),
	    &ks->ipk_mac_local_faults, &ps->ips_mac_local_faults, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_MRFC(port),
	    &ks->ipk_mac_remote_faults, &ps->ips_mac_remote_faults, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_RLEC(port),
	    &ks->ipk_rx_length_errors, &ps->ips_rx_length_errors, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_RUC(port),
	    &ks->ipk_rx_undersize, &ps->ips_rx_undersize, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_RFC(port),
	    &ks->ipk_rx_fragments, &ps->ips_rx_fragments, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_ROC(port),
	    &ks->ipk_rx_oversize, &ps->ips_rx_oversize, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_RJC(port),
	    &ks->ipk_rx_jabber, &ps->ips_rx_jabber, init);
	ice_stat_get_uint32(ice, ICE_GLPRT_TDOLD(port),
	    &ks->ipk_tx_dropped_link_down, &ps->ips_tx_dropped_link_down, init);

	/*
	 * Similarly here, failure to retrieve these stats isn't
	 * considered service effecting.
	 */
	if (ice_regs_check(ice) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_UNAFFECTED);
	}
}

static int
ice_stat_pf_kstat_update(kstat_t *ksp, int rw)
{
	ice_t *ice = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	mutex_enter(&ice->ice_stats_lock);

	ice_stat_pf_update(ice, false);

	mutex_exit(&ice->ice_stats_lock);

	return (0);
}

bool
ice_stats_init(ice_t *ice)
{
	ice_pf_stats_t	*pf = &ice->ice_pf_stats;
	ice_pf_kstats_t	*ks;
	kstat_t		*ksp;

	ksp = kstat_create(ICE_MODULE_NAME, ice->ice_inst, "pfstats", "net",
	    KSTAT_TYPE_NAMED, sizeof (*ks) / sizeof (kstat_named_t), 0);
	if (ksp == NULL) {
		ice_error(ice, "Could not create kernel pf statistics");
		return (false);
	}

	ice->ice_pf_ks = ksp;
	ks = ksp->ks_data;
	ksp->ks_update = ice_stat_pf_kstat_update;
	ksp->ks_private = ice;

	kstat_named_init(&ks->ipk_rx_bytes, "rx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_unicast, "rx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_multicast, "rx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_broadcast, "rx_broadcast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_bytes, "tx_bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_unicast, "tx_unicast", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_multicast, "tx_multicast",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_broadcast, "tx_broadcast",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ks->ipk_rx_size_64, "rx_size_64", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_127, "rx_size_127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_255, "rx_size_255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_511, "rx_size_511",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_1023, "rx_size_1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_1522, "rx_size_1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_size_9522, "rx_size_9522",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ks->ipk_tx_size_64, "tx_size_64", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_127, "tx_size_127",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_255, "tx_size_255",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_511, "tx_size_511",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_1023, "tx_size_1023",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_1522, "tx_size_1522",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_size_9522, "tx_size_9522",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ks->ipk_link_xon_rx, "link_xon_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_link_xoff_rx, "link_xoff_rx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_link_xon_tx, "link_xon_tx",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_link_xoff_tx, "link_xoff_tx",
	    KSTAT_DATA_UINT64);

	for (uint_t i = 0; i < 8; i++) {
		char buf[64];

		(void) snprintf(buf, sizeof (buf), "priority_xon_rx%u", i);
		kstat_named_init(&ks->ipk_priority_xon_rx[i], buf,
		    KSTAT_DATA_UINT64);

		(void) snprintf(buf, sizeof (buf), "priority_xoff_rx%u", i);
		kstat_named_init(&ks->ipk_priority_xoff_rx[i], buf,
		    KSTAT_DATA_UINT64);

		(void) snprintf(buf, sizeof (buf), "priority_xon_tx%u", i);
		kstat_named_init(&ks->ipk_priority_xon_tx[i], buf,
		    KSTAT_DATA_UINT64);

		(void) snprintf(buf, sizeof (buf), "priority_xoff_tx%u", i);
		kstat_named_init(&ks->ipk_priority_xoff_tx[i], buf,
		    KSTAT_DATA_UINT64);

		(void) snprintf(buf, sizeof (buf), "priority_xon_2_xoff_%u", i);
		kstat_named_init(&ks->ipk_priority_xon_2_xoff[i], buf,
		    KSTAT_DATA_UINT64);
	}

	kstat_named_init(&ks->ipk_crc_errors, "crc_errors", KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_illegal_bytes, "illegal_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_mac_local_faults, "mac_local_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_mac_remote_faults, "mac_remote_faults",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_length_errors, "rx_length_errors",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_undersize, "rx_undersize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_fragments, "rx_fragments",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_oversize, "rx_oversize",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_rx_jabber, "rx_jabber",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&ks->ipk_tx_dropped_link_down, "tx_dropped_link_down",
	    KSTAT_DATA_UINT64);

	mutex_init(&ice->ice_stats_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	bzero(pf, sizeof (*pf));

	mutex_enter(&ice->ice_stats_lock);
	ice_stat_pf_update(ice, true);
	mutex_exit(&ice->ice_stats_lock);

	kstat_install(ice->ice_pf_ks);

	return (true);
}

void
ice_stats_fini(ice_t *ice)
{
	if (ice->ice_pf_ks != NULL) {
		kstat_delete(ice->ice_pf_ks);
		ice->ice_pf_ks = NULL;
	}

	mutex_destroy(&ice->ice_stats_lock);
}

int
ice_m_stat(void *arg, uint_t stat, uint64_t *valp)
{
	ice_t		*ice = arg;
	ice_pf_stats_t	*ips = &ice->ice_pf_stats;
	ice_pf_kstats_t	*ipk = ice->ice_pf_ks->ks_data;
	uint_t		port = ice->ice_port_id;
	int		ret = 0;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		mutex_enter(&ice->ice_lse_lock);
		*valp = ice->ice_link_cur_speed * 1000000ULL;
		mutex_exit(&ice->ice_lse_lock);
		return (0);

	case ETHER_STAT_LINK_DUPLEX:
		mutex_enter(&ice->ice_lse_lock);
		*valp = ice->ice_link_cur_duplex;
		mutex_exit(&ice->ice_lse_lock);
		return (0);

	default:
		break;
	}

	mutex_enter(&ice->ice_stats_lock);

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		ice_stat_get_uint48(ice, ICE_GLPRT_MPRCL(port),
		    &ipk->ipk_rx_multicast, &ips->ips_rx_multicast, false);
		*valp = ipk->ipk_rx_broadcast.value.ui64;
		break;

	case MAC_STAT_BRDCSTRCV:
		ice_stat_get_uint48(ice, ICE_GLPRT_BPRCL(port),
		    &ipk->ipk_rx_broadcast, &ips->ips_rx_broadcast, false);
		*valp = ipk->ipk_rx_broadcast.value.ui64;
		break;

	case MAC_STAT_MULTIXMT:
		ice_stat_get_uint48(ice, ICE_GLPRT_MPTCL(port),
		    &ipk->ipk_tx_multicast, &ips->ips_tx_multicast, false);
		*valp = ipk->ipk_tx_multicast.value.ui64;
		break;

	case MAC_STAT_BRDCSTXMT:
		ice_stat_get_uint48(ice, ICE_GLPRT_BPTCL(port),
		    &ipk->ipk_tx_broadcast, &ips->ips_tx_broadcast, false);
		*valp = ipk->ipk_tx_broadcast.value.ui64;
		break;

	case MAC_STAT_RBYTES:
		ice_stat_get_uint48(ice, ICE_GLPRT_GORCL(port),
		    &ipk->ipk_rx_bytes, &ips->ips_rx_bytes, false);
		*valp = ipk->ipk_rx_bytes.value.ui64;
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&ice->ice_stats_lock);

	if (ice_regs_check(ice) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_UNAFFECTED);
	}

	return (ret);
}

