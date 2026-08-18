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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * Describe the purpose of this file.
 */

#include <sys/dlpi.h>
#include "ice.h"

#define	ICE_TX_DMA_THRESH	"_tx_dma_threshold"
#define	ICE_RX_DMA_THRESH	"_rx_dma_threshold"
#define	ICE_RX_DMA_MAX_LOAN	"_rx_dma_maxloan"
#define	ICE_RX_INTR_MAX_PKT	"_rx_intr_maxpkt"

static char *ice_priv_props[] = {
	ICE_TX_DMA_THRESH,
	ICE_RX_DMA_THRESH,
	ICE_RX_DMA_MAX_LOAN,
	ICE_RX_INTR_MAX_PKT,
	NULL
};

/*
 * This table maps the Intel PHY bits to and from the corresponding MAC values
 * as well as tracks the various link speeds that we care about. The Intel PHY
 * table orders them based on speed, therefore we have our table based on the
 * minimum and maximum bits that are used.
 */
typedef struct ice_phy_map {
	uint_t	ipm_bit_min;
	uint_t	ipm_bit_max;
	uint_t	ipm_adv_prop;
	uint_t	ipm_en_prop;
} ice_phy_map_t;

/*
 * This maps a subset of hardware PHY IDs to properties and things that we know
 * about in the GLDv3.
 *
 * XXX: The latest revisison (2.8) seems to omit the 400GB entries --
 * should we do that as well?
 */
ice_phy_map_t ice_phy_map[] = {
	{ ICE_PHY_100BASE_TX, ICE_PHY_100M_SGMII,
	    MAC_PROP_ADV_100FDX_CAP, MAC_PROP_EN_100FDX_CAP },
	{ ICE_PHY_1000BASE_T, ICE_PHY_1G_SGMII,
	    MAC_PROP_ADV_1000FDX_CAP, MAC_PROP_EN_1000FDX_CAP },
	{ ICE_PHY_2500BASE_T, ICE_PHY_2500BASE_KX,
	    MAC_PROP_ADV_2500FDX_CAP, MAC_PROP_EN_2500FDX_CAP },
	{ ICE_PHY_5GBASE_T, ICE_PHY_5GBASE_KR,
	    MAC_PROP_ADV_5000FDX_CAP, MAC_PROP_EN_5000FDX_CAP },
	{ ICE_PHY_10GBASE_T, ICE_PHY_10G_SFI_C2C,
	    MAC_PROP_ADV_10GFDX_CAP, MAC_PROP_EN_10GFDX_CAP },
	{ ICE_PHY_25GBASE_T, ICE_PHY_25G_AUI_C2C,
	    MAC_PROP_ADV_25GFDX_CAP, MAC_PROP_EN_25GFDX_CAP },
	{ ICE_PHY_40GBASE_CR4, ICE_PHY_40G_XLAUI,
	    MAC_PROP_ADV_40GFDX_CAP, MAC_PROP_EN_40GFDX_CAP },
	{ ICE_PHY_50GBASE_CR2, ICE_PHY_50G_AUI1,
	    MAC_PROP_ADV_50GFDX_CAP, MAC_PROP_EN_50GFDX_CAP },
	{ ICE_PHY_100GBASE_CR4, ICE_PHY_100G_AUI2,
	    MAC_PROP_ADV_100GFDX_CAP, MAC_PROP_EN_100GFDX_CAP },
	{ ICE_PHY_200GBASE_CR4_PAM4, ICE_PHY_200G_AUI8,
	    MAC_PROP_ADV_200GFDX_CAP, MAC_PROP_EN_200GFDX_CAP },
	{ ICE_PHY_400G_BASE_FR8, ICE_PHY_400G_AUI8,
	    MAC_PROP_ADV_400GFDX_CAP, MAC_PROP_EN_400GFDX_CAP },
};

static ice_vsi_mac_t *
ice_find_mac(list_t *l, const uint8_t *addr)
{
	ice_vsi_mac_t *mac = NULL;

	for (mac = list_head(l); mac != NULL; mac = list_next(l, mac)) {
		if (bcmp(mac->ivm_mac, addr, ETHERADDRL) == 0) {
			return (mac);
		}
	}

	return (NULL);
}

static ice_vsi_mac_t *
ice_vsi_find_mac(ice_vsi_t *vsi, const uint8_t *addr)
{
	ASSERT(MUTEX_HELD(&vsi->ivsi_lock));
	return (ice_find_mac(&vsi->ivsi_macs, addr));
}

static int
ice_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi;
	ice_vsi_mac_t	*mac;

	/*
	 * For now, we assume we're always using the first VSI. If
	 * we start supporting multiple VSIs (e.g. VFs for virtualization)
	 * we probably need to have mac(9E) use the ice_vsi_t as it's
	 * handle instead of the ice_t.
	 */
	vsi = list_head(&ice->ice_vsi);

	mac = kmem_zalloc(sizeof (*mac), KM_SLEEP);
	bcopy(mac_addr, mac->ivm_mac, ETHERADDRL);

	mutex_enter(&vsi->ivsi_lock);
	if (ice_vsi_find_mac(vsi, mac_addr) != NULL) {
		/*
		 * mac_filter(9e) is a bit ambiguous here -- the mac is
		 * already there, so returning EEXIST seems reasonable,
		 * but it also has been added (just not by this call),
		 * so we return 0 to indicate that it has been added.
		 *
		 * XXX: might a dtrace probe or kstat be of use?
		 */
#ifdef DEBUG
		ice_error(ice, "tried to add existing mac "
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5]);
#endif

		goto fail;
	}

	if (!ice_add_mac(ice, vsi->ivsi_id, mac_addr, &mac->ivm_idx)) {
		goto fail;
	}

	list_insert_tail(&vsi->ivsi_macs, mac);
	mutex_exit(&vsi->ivsi_lock);

#ifdef DEBUG
	ice_error(ice, "added mac %02x:%02x:%02x:%02x:%02x:%02x",
	    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
	    mac_addr[5]);
#endif

	return (0);

fail:
	mutex_exit(&vsi->ivsi_lock);

	ice_error(ice, "failed to add mac %02x:%02x:%02x:%02x:%02x:%02x",
	    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
	    mac_addr[5]);

	kmem_free(mac, sizeof (*mac));
	return (EIO);
}

static int
ice_group_remove_mac(void *arg, const uint8_t *mac_addr)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi;
	ice_vsi_mac_t	*mac = NULL;
	int		ret = 0;

	vsi = list_head(&ice->ice_vsi);

	mutex_enter(&vsi->ivsi_lock);
	mac = ice_vsi_find_mac(vsi, mac_addr);
	if (mac == NULL) {
		mutex_exit(&vsi->ivsi_lock);

#ifdef DEBUG
		ice_error(ice, "tried to remove non-existent mac "
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5]);
#endif

		return (ENOENT);
	}

	if (!ice_remove_rule(ice, 1, &mac->ivm_idx)) {
		ice_error(ice, "failed to remove mac "
		    "%02x:%02x:%02x:%02x:%02x:%02x",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5]);
		ret = EIO;
		goto done;
	}

	list_remove(&vsi->ivsi_macs, mac);
	kmem_free(mac, sizeof (*mac));

#ifdef DEBUG
	ice_error(ice, "removed mac "
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
	    mac_addr[4], mac_addr[5]);
#endif

done:
	mutex_exit(&vsi->ivsi_lock);
	return (ret);
}

static void
ice_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ice_t		*ice = arg;
	ice_rx_ring_t	*rxr;

	/* We currently only have one group */
	ASSERT3S(group_index, ==, 0);
	ASSERT3S(ring_index, <, ice->ice_num_rxq_per_vsi);

	rxr = &ice->ice_rxr[ring_index];
	rxr->irxr_macrxring = rh;

	infop->mri_driver = (mac_ring_driver_t)rxr;
	infop->mri_start = ice_ring_rx_start;
	infop->mri_stop = ice_ring_rx_stop;
	infop->mri_poll = ice_ring_rx_poll;
	infop->mri_stat = ice_ring_rx_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)rxr;
	infop->mri_intr.mi_enable = ice_ring_rx_intr_enable;
	infop->mri_intr.mi_disable = ice_ring_rx_intr_disable;

	if ((ice->ice_intr_type & DDI_INTR_TYPE_MSIX) != 0) {
		ASSERT3U(rxr->irxr_vec, <, ice->ice_nintrs);

		infop->mri_intr.mi_ddi_handle =
		    ice->ice_intr_handles[rxr->irxr_vec];
	}
}

static void
ice_fill_tx_ring(void *arg, mac_ring_type_t rtype,
    const int group_index, const int ring_index,
    mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	ice_t		*ice = arg;
	ice_tx_ring_t	*txr;

	/* We currently don't use TX ring groups */
	ASSERT3S(group_index, ==, -1);

	ASSERT3S(ring_index, <, ice->ice_num_txq);

	txr = &ice->ice_txr[ring_index];
	txr->itxr_mactxring = rh;

	infop->mri_driver = (mac_ring_driver_t)txr;
	infop->mri_start = ice_ring_tx_start;
	infop->mri_stop = ice_ring_tx_stop;
	infop->mri_tx = ice_ring_tx;
	infop->mri_stat = ice_ring_tx_stat;
	infop->mri_intr.mi_handle = (mac_intr_handle_t)txr;
	infop->mri_intr.mi_enable = ice_ring_tx_intr_enable;
	infop->mri_intr.mi_disable = ice_ring_tx_intr_disable;

	if ((ice->ice_intr_type & DDI_INTR_TYPE_MSIX) != 0) {
		ASSERT3U(txr->itxr_vec, <, ice->ice_nintrs);

		infop->mri_intr.mi_ddi_handle =
		    ice->ice_intr_handles[txr->itxr_vec];
	}
}

static void
ice_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	ice_t *ice = arg;

	if (rtype != MAC_RING_TYPE_RX) {
		return;
	}

	infop->mgi_driver = (mac_group_driver_t)ice;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = ice_group_add_mac;
	infop->mgi_remmac = ice_group_remove_mac;
	infop->mgi_count = ice->ice_num_rxq_per_vsi;
}

static void
ice_m_stop(void *arg)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi = list_head(&ice->ice_vsi);

	ASSERT3P(vsi, !=, NULL);

	ice->ice_shutdown = true;
	membar_producer();

	if (!ice_remove_rule(ice, 1, &vsi->ivsi_bcast_rule_idx)) {
		ice_error(ice, "failed to remove brodcast address");
	}

	if (!ice_cmd_setup_link(ice, B_FALSE)) {
		ice_error(ice, "failed to stop link");
	}

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_link_status_update(ice)) {
		ice_error(ice, "failed to disable link status event updates");
	}

	ice_intr_hw_fini(ice);

	ice_tx_stop(ice);
	ice_rx_stop(ice);

	atomic_and_uint(&ice->ice_state, ~ICE_STARTED);
}

static int
ice_m_start(void *arg)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi = list_head(&ice->ice_vsi);
	uint16_t	mask;

	ASSERT3P(vsi, !=, NULL);

	/*
	 * The mac framework serializes calls to m_start and m_stop, so
	 * we're ok to set this without a lock.
	 */
	ice->ice_shutdown = false;
	membar_producer();

	if (!ice_rx_start(ice)) {
		ice->ice_shutdown = true;
		membar_producer();
		return (EIO);
	}

	ice_tx_start(ice);

	if (!ice_intr_hw_init(ice)) {
		return (EIO);
	}

	/*
	 * Mask off link status events. While we don't want to mask the
	 * following events per se, currently firmware will generate an infinite
	 * loop of link status events when an SFP is plugged into the adapter,
	 * but not at the other end.
	 */
	mask = ICE_CQ_SET_EVENT_MASK_LINK_FAULT |
	    ICE_CQ_SET_EVENT_MASK_SIGNAL_DETECT;

	if (!ice_cmd_set_event_mask(ice, mask)) {
		ice_error(ice, "failed to set LSE event mask");
		goto err;
	}

	mutex_enter(&ice->ice_lse_lock);
	ice->ice_lse_state |= ICE_LSE_STATE_ENABLE;
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_link_status_update(ice)) {
		ice_error(ice, "failed to enable link status updates");

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);
		goto err;
	}

	if (!ice_cmd_setup_link(ice, B_TRUE)) {
		ice_error(ice, "failed to start link");

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);

		(void) ice_link_status_update(ice);
	}

	/*
	 * It appears mac will call the mgi_addmac(9E) method with the
	 * default MAC address for us, so we only need to add the
	 * broadcast address to the switch filter.
	 */
	if (!ice_add_mac(ice, vsi->ivsi_id, ice_bcast_mac,
	    &vsi->ivsi_bcast_rule_idx)) {
		ice_error(ice, "failed to add brodcast address");
		goto err;
	}

	atomic_or_uint(&ice->ice_state, ICE_STARTED);

	return (0);
err:
	ice_intr_hw_fini(ice);
	return (EIO);
}

static int
ice_m_setpromisc(void *arg, boolean_t enable)
{
	ice_t	*ice = arg;
	bool	ret;

	if (enable) {
		ret = ice_promisc_on(ice);
	} else {
		ret = ice_promisc_off(ice);
	}

	return (ret ? 0 : EIO);
}

static int
ice_m_multicast(void *arg, boolean_t add, const uint8_t *addr)
{
	ice_t		*ice = arg;
	ice_vsi_t	*vsi;
	ice_vsi_mac_t	*mac = NULL;
	int		ret = 0;

	/*
	 * As noted elsewhere, multicast (as well as promiscuous) mode
	 * stuff always happens on the first ring group (i.e. the first
	 * VSI).
	 *
	 * This also means we use the first VSI's lock for controlling
	 * access to the list of multicast addresses, despite the list being
	 * held on the ice_t (mostly since we use the VSI lock for the MACs
	 * on that VSI).
	 *
	 * XXX: An alternative might be to just have one list of all
	 * MAC addresses (unicast and multicast) per VSI and just assert
	 * that we only have multicast addresses on the first VSI.
	 */
	vsi = list_head(&ice->ice_vsi);

	mutex_enter(&vsi->ivsi_lock);

	mac = ice_find_mac(&ice->ice_mc_macs, addr);
	if (!add) {
		if (mac == NULL) {
			ret = ENOENT;
			goto done;
		}

		if (!ice_remove_rule(ice, 1, &mac->ivm_idx)) {
			ret = EIO;
			goto done;
		}

		list_remove(&ice->ice_mc_macs, mac);
		kmem_free(mac, sizeof (*mac));
	} else {
		if (mac != NULL) {
			mutex_exit(&vsi->ivsi_lock);
			/*
			 * Similarly to adding a unicast MAC to a ring group,
			 * it's unclear since the MAC is already there if we
			 * should return something like EEXIST, or just
			 * return success, since both seem like they could
			 * be reasonable. For now at least, we'll just
			 * return success.
			 */
			return (0);
		}

		mac = kmem_zalloc(sizeof (*mac), KM_SLEEP);
		bcopy(addr, mac->ivm_mac, ETHERADDRL);

		if (!ice_add_mac(ice, vsi->ivsi_id, addr, &mac->ivm_idx)) {
			ret = EIO;
			goto done;
		}

		list_insert_tail(&ice->ice_mc_macs, mac);
	}

done:
	mutex_exit(&vsi->ivsi_lock);
	return (ret);
}

static boolean_t
ice_m_getcapab(void *arg, mac_capab_t capab, void *cap_data)
{
	ice_t *ice = arg;
	mac_capab_rings_t *cap_rings;

	switch (capab) {
	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = ice->ice_num_txq;
			cap_rings->mr_rget = ice_fill_tx_ring;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_rnum = ice->ice_num_rxq_per_vsi;
			cap_rings->mr_rget = ice_fill_rx_ring;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_gget = ice_fill_rx_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		default:
			return (B_FALSE);
		}

		break;
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		*txflags = 0;
		if (ice->ice_tx_hcksum_enable)
			*txflags = HCKSUM_INET_PARTIAL | HCKSUM_IPHDRCKSUM;

		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (!ice->ice_tx_lso_enable)
			return (B_FALSE);

		cap_lso->lso_flags =
		    LSO_TX_BASIC_TCP_IPV4 | LSO_TX_BASIC_TCP_IPV6;
		cap_lso->lso_basic_tcp_ipv4.lso_max = ICE_TX_LSO_MAXLEN;
		cap_lso->lso_basic_tcp_ipv6.lso_max = ICE_TX_LSO_MAXLEN;
		break;
	}
	case MAC_CAPAB_LED:
	case MAC_CAPAB_TRANSCEIVER:
		return (B_FALSE);
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
ice_m_setprop_private(ice_t *ice, const char *pr_name, uint_t pr_valsize,
    const void *pr_val)
{
	long	val;
	char	*eptr;
	int	ret;

	ret = ddi_strtol(pr_val, &eptr, 10, &val);
	if (ret != 0 || *eptr != '\0') {
		return (ret);
	}

	if (strcmp(pr_name, ICE_TX_DMA_THRESH) == 0) {
		if (val < ICE_TX_DMA_THRESH_MIN ||
		    val > ICE_TX_DMA_THRESH_MAX) {
			return (EINVAL);
		}

		ice->ice_tx_dma_min = val;
		membar_producer();
		return (0);
	}

	if (strcmp(pr_name, ICE_RX_DMA_THRESH) == 0) {
		if (val < ICE_RX_DMA_THRESH_MIN ||
		    val > ICE_RX_DMA_THRESH_MAX) {
			return (EINVAL);
		}

		ice->ice_rx_dma_min = val;
		membar_producer();
		return (0);
	}

	if (strcmp(pr_name, ICE_RX_DMA_MAX_LOAN) == 0) {
		if (val < ICE_RX_LOAN_MIN ||
		    val > ICE_RX_LOAN_MAX) {
			return (EINVAL);
		}

		ice->ice_rx_maxloan = val;
		membar_producer();
		return (0);
	}

	if (strcmp(pr_name, ICE_RX_INTR_MAX_PKT) == 0) {
		if (val < ICE_RX_INTR_MAX_PKT_MIN ||
		    val > ICE_RX_INTR_MAX_PKT_MAX) {
			return (EINVAL);
		}

		ice->ice_rx_limit_per_intr = val;
		membar_producer();
		return (0);
	}

	return (ENOTSUP);
}

static int
ice_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	ice_t		*ice = arg;
	uint32_t	new_mtu;
	int		ret = 0;

	/*
	 * The mac framework guarantees this call is single threaded
	 * (see block comments at the top of usr/src/uts/common/io/mac/mac.c)
	 *
	 * For the currently supported properties, the TX and RX code
	 * can handle inline changes to these (they might just take
	 * effect on the 'next' packet depending on timing), so we're
	 * ok to modify these without any additional locking.
	 */

	switch (pr_num) {
	/* These are always read only */
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
	case MAC_PROP_MEDIA:
		ret = ENOTSUP;
		break;

	case MAC_PROP_MTU:
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		if (new_mtu == ice->ice_mtu) {
			break;
		}

		if (new_mtu > ice->ice_max_mtu) {
			ret = EINVAL;
			break;
		}

		if (new_mtu < ETHERMIN) {
			ret = EINVAL;
			break;
		}

		if (ice_is_running(ice)) {
			ret = EBUSY;
			break;
		}

		ret = mac_maxsdu_update(ice->ice_mac_hdl, new_mtu);
		if (ret == 0) {
			ice_update_mtu(ice, new_mtu);
		}
		break;

	case MAC_PROP_PRIVATE:
		ret = ice_m_setprop_private(ice, pr_name, pr_valsize, pr_val);
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	return (ret);
}

static int
ice_m_getprop_private(ice_t *ice, const char *pr_name, uint_t pr_valsize,
    void *pr_val)
{
	uint32_t val = 0;

	if (strcmp(pr_name, ICE_TX_DMA_THRESH) == 0) {
		val = ice->ice_tx_dma_min;
	} else if (strcmp(pr_name, ICE_RX_DMA_THRESH) == 0) {
		val = ice->ice_rx_dma_min;
	} else if (strcmp(pr_name, ICE_RX_DMA_MAX_LOAN) == 0) {
		val = ice->ice_rx_maxloan;
	} else if (strcmp(pr_name, ICE_RX_INTR_MAX_PKT) == 0) {
		val = ice->ice_rx_limit_per_intr;
	} else {
		return (ENOTSUP);
	}

	if (snprintf(pr_val, pr_valsize, "%u", val) >= pr_valsize) {
		return (ERANGE);
	}

	return (0);
}

static int
ice_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	ice_t *ice = arg;
	int ret = 0;
	uint64_t speed;
	uint8_t *u8;

	mutex_enter(&ice->ice_lse_lock);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}
		bcopy(&ice->ice_link_cur_duplex, pr_val,
		    sizeof (link_duplex_t));
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}
		speed = ice->ice_link_cur_speed * 1000000ULL;
		bcopy(&speed, pr_val, sizeof (speed));
		break;
	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ice->ice_link_cur_state, pr_val,
		    sizeof (link_state_t));
		break;
	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}

		/* XXX Confirm that there is no control for autoneg */
		u8 = pr_val;
		*u8 = 1;
		break;
	case MAC_PROP_FLOWCTRL:
		if (pr_valsize < sizeof (link_flowctrl_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ice->ice_link_cur_fctl, pr_val,
		    sizeof (link_flowctrl_t));
		break;
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t)) {
			ret = EOVERFLOW;
			break;
		}

		bcopy(&ice->ice_mtu, pr_val, sizeof (uint32_t));
		break;

	/* TODO MAC_PROP_{ADV,EN}_FEC_CAP */

	/*
	 * There doesn't appear to be a way to manage or manipulate
	 * autoneg for individual speeds, so for now at least we report
	 * not supported
	 */
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:

	case MAC_PROP_ADV_2500FDX_CAP:
	case MAC_PROP_EN_2500FDX_CAP:

	case MAC_PROP_ADV_5000FDX_CAP:
	case MAC_PROP_EN_5000FDX_CAP:

	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:

	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:

	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:

	case MAC_PROP_ADV_50GFDX_CAP:
	case MAC_PROP_EN_50GFDX_CAP:

	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:

	case MAC_PROP_PRIVATE:
		ret = ice_m_getprop_private(ice, pr_name, pr_valsize, pr_val);
		break;

	default:
		ret = ENOTSUP;
	}

	mutex_exit(&ice->ice_lse_lock);

	return (ret);
}

static void
ice_m_propinfo_private(ice_t *ice, const char *pr_name,
    mac_prop_info_handle_t hdl)
{
	char		buf[64];
	uint32_t	def = 0;

	if (strcmp(pr_name, ICE_TX_DMA_THRESH) == 0) {
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_RW);
		def = ICE_TX_DMA_THRESH_DEF;
		mac_prop_info_set_range_uint32(hdl,
		    ICE_TX_DMA_THRESH_MIN,
		    ICE_TX_DMA_THRESH_MAX);
	} else if (strcmp(pr_name, ICE_RX_DMA_THRESH) == 0) {
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_RW);
		def = ICE_RX_DMA_THRESH_DEF;
		mac_prop_info_set_range_uint32(hdl,
		    ICE_RX_DMA_THRESH_MIN,
		    ICE_RX_DMA_THRESH_MAX);
	} else if (strcmp(pr_name, ICE_RX_DMA_MAX_LOAN) == 0) {
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_RW);
		def = ICE_RX_LOAN_DEF;
		mac_prop_info_set_range_uint32(hdl,
		    ICE_RX_LOAN_MIN,
		    ICE_RX_LOAN_MAX);
	} else if (strcmp(pr_name, ICE_RX_INTR_MAX_PKT) == 0) {
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_RW);
		def = ICE_RX_INTR_MAX_PKT_DEF;
		mac_prop_info_set_range_uint32(hdl,
		    ICE_RX_INTR_MAX_PKT_MIN,
		    ICE_RX_INTR_MAX_PKT_MAX);
	}

	(void) snprintf(buf, sizeof (buf), "%u", def);
	mac_prop_info_set_default_str(hdl, buf);
}

static void
ice_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t hdl)
{
	ice_t *ice = arg;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_perm(hdl, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_link_flowctrl(hdl,
		    LINK_FLOWCTRL_NONE);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(hdl, 0, ice->ice_max_mtu);
		break;

	case MAC_PROP_PRIVATE:
		ice_m_propinfo_private(ice, pr_name, hdl);
		break;

	default:
		break;
	}
}

static mac_callbacks_t ice_m_callbacks = {
	.mc_callbacks = MC_GETCAPAB | MC_GETPROP | MC_SETPROP | MC_PROPINFO,
	.mc_getstat = ice_m_stat,
	.mc_start = ice_m_start,
	.mc_stop = ice_m_stop,
	.mc_setpromisc = ice_m_setpromisc,
	.mc_multicst = ice_m_multicast,
	.mc_getcapab = ice_m_getcapab,
	.mc_setprop = ice_m_setprop,
	.mc_getprop = ice_m_getprop,
	.mc_propinfo = ice_m_propinfo
};

void
ice_mac_unregister(ice_t *ice)
{
	int ret;

	/*
	 * We're going away, there's not much else we can do at this point if
	 * this fails.
	 */
	ret = mac_unregister(ice->ice_mac_hdl);
	if (ret != 0) {
		ice_error(ice, "failed to unregister from MAC: %d", ret);
	}
}

boolean_t
ice_mac_register(ice_t *ice)
{
	int ret;
	mac_register_t *regp;

	if ((regp = mac_alloc(MAC_VERSION)) == NULL) {
		ice_error(ice, "failed to allocate MAC handle");
		return (B_FALSE);
	}

	regp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	regp->m_driver = ice;
	regp->m_dip = ice->ice_dip;
	regp->m_instance = 0;
	regp->m_src_addr = ice->ice_mac;
	regp->m_dst_addr = NULL;
	regp->m_callbacks = &ice_m_callbacks;
	regp->m_min_sdu = 0;
	regp->m_max_sdu = ice->ice_max_mtu;
	regp->m_pdata = NULL;
	regp->m_pdata_size = 0;
	regp->m_priv_props = ice_priv_props;
	regp->m_margin = VLAN_TAGSZ;
	regp->m_v12n = MAC_VIRT_LEVEL1;

	if ((ret = mac_register(regp, &ice->ice_mac_hdl)) != 0) {
		ice_error(ice, "failed to register ICE with MAC: %d", ret);
	}

	mac_free(regp);
	return (ret == 0);
}
