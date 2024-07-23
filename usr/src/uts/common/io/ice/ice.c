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
 * Intel 100 GbE Ethernet Driver
 */

#include "ice.h"

/*
 * The datasheet isn't clear how these are used by the driver other than
 * it appears to be required to inform the NIC of the driver version.
 * Since we're using both the datasheet and the FreeBSD ice driver as a
 * guide (without porting the FreeBSD code), we match what it uses since
 * they are known 'good' values.
 */
static uint8_t ice_ver_major = 1;
static uint8_t ice_ver_minor = 43;
static uint8_t ice_ver_patch = 3;
static uint8_t ice_ver_rc = 0;
static char ice_ver_str[] = "1.43.3-k";

const uint8_t ice_bcast_mac[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void ice_prepare_for_reset(ice_t *);
static bool ice_rebuild(ice_t *, bool);

/*
 * ice_glock protects ice_dlist which is a list of (global) ice_device_ts.
 * See the comment with ice_device_t in ice.h for more information.
 */
static kmutex_t ice_glock;
static list_t ice_dlist;

void
ice_error(ice_t *ice, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ice != NULL && ice->ice_dip != NULL) {
		vdev_err(ice->ice_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

int
ice_regs_check(ice_t *ice)
{
	ddi_fm_error_t de;

	if (!DDI_FM_ACC_ERR_CAP(ice->ice_fm_caps)) {
		return (DDI_FM_OK);
	}

	ddi_fm_acc_err_get(ice->ice_reg_hdl, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(ice->ice_reg_hdl, DDI_FME_VERSION);
	return (de.fme_status);
}

uint32_t
ice_reg_read(ice_t *ice, uintptr_t reg)
{
	return (ddi_get32(ice->ice_reg_hdl, (uint32_t *)(ice->ice_reg_base +
	    reg)));
}

void
ice_reg_write(ice_t *ice, uintptr_t reg, uint32_t val)
{
	ddi_put32(ice->ice_reg_hdl, (uint32_t *)(ice->ice_reg_base +
	    reg), val);
}

uint64_t
ice_reg_read64(ice_t *ice, uintptr_t reg)
{
	return (ddi_get64(ice->ice_reg_hdl, (uint64_t *)(ice->ice_reg_base +
	    reg)));
}

static ice_capability_t *
ice_capability_find(ice_t *ice, boolean_t device, ice_cap_id_t capid,
    uint_t major)
{
	uint_t i, max;
	ice_capability_t *cap;

	if (device) {
		cap = ice->ice_dev_caps;
		max = ice->ice_ndev_caps;
	} else {
		cap = ice->ice_func_caps;
		max = ice->ice_nfunc_caps;
	}

	for (i = 0; i < max; i++) {
		if (cap[i].icap_cap == capid) {
			if (cap[i].icap_major != major) {
				ice_error(ice, "found capability 0x%x, but it "
				    "has an unsupported major version 0x%x, "
				    "expected 0x%x", capid, cap[i].icap_cap,
				    major);
				continue;
			}
			return (&cap[i]);
		}
	}

	return (NULL);
}


static int
ice_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data __unused)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
ice_fm_init(ice_t *ice)
{
	ddi_iblock_cookie_t iblk;

	ice->ice_fm_caps = ddi_prop_get_int(DDI_DEV_T_ANY, ice->ice_dip,
	    DDI_PROP_DONTPASS, "fm_capable", DDI_FM_EREPORT_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
	    DDI_FM_ERRCB_CAPABLE);

	if (ice->ice_fm_caps < 0) {
		ice->ice_fm_caps = 0;
	} else if (ice->ice_fm_caps > 0xf) {
		ice->ice_fm_caps = DDI_FM_EREPORT_CAPABLE |
		    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
		    DDI_FM_ERRCB_CAPABLE;
	}

	/*
	 * Only register with fma if we have some capability.
	 */
	if (ice->ice_fm_caps != DDI_FM_NOT_CAPABLE) {
		ddi_fm_init(ice->ice_dip, &ice->ice_fm_caps, &iblk);

		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps) ||
		    DDI_FM_ERRCB_CAP(ice->ice_fm_caps)) {
			pci_ereport_setup(ice->ice_dip);
		}

		if (DDI_FM_ERRCB_CAP(ice->ice_fm_caps)) {
			ddi_fm_handler_register(ice->ice_dip, ice_fm_error_cb,
			    (void *)ice);
		}
	}
}

static void
ice_fm_fini(ice_t *ice)
{
	if (ice->ice_fm_caps != DDI_FM_NOT_CAPABLE) {
		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps) ||
		    DDI_FM_ERRCB_CAP(ice->ice_fm_caps)) {
			pci_ereport_teardown(ice->ice_dip);
		}

		if (DDI_FM_ERRCB_CAP(ice->ice_fm_caps)) {
			ddi_fm_handler_unregister(ice->ice_dip);
		}

		ddi_fm_fini(ice->ice_dip);
	}
}

static boolean_t
ice_regs_map(ice_t *ice)
{
	int ret;

	if (ddi_dev_regsize(ice->ice_dip, ICE_REG_NUMBER, &ice->ice_reg_size) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get register set %d size",
		    ICE_REG_NUMBER);
		return (B_FALSE);
	}

	bzero(&ice->ice_reg_attr, sizeof (ddi_device_acc_attr_t));
	ice->ice_reg_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	ice->ice_reg_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	ice->ice_reg_attr.devacc_attr_version = DDI_STRICTORDER_ACC;
	if (DDI_FM_ACC_ERR_CAP(ice->ice_fm_caps)) {
		ice->ice_reg_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		ice->ice_reg_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if ((ret = ddi_regs_map_setup(ice->ice_dip, ICE_REG_NUMBER,
	    &ice->ice_reg_base, 0, ice->ice_reg_size, &ice->ice_reg_attr,
	    &ice->ice_reg_hdl)) != DDI_SUCCESS) {
		ice_error(ice, "failed to map register set %d: %d",
		    ICE_REG_NUMBER, ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Identify the hardware in question. This looks at PCI configuration
 * information, saves that information, and potentially identifies information
 * about the device as a result.
 *
 * Right now there is only one primary MAC that this driver supports. We save
 * PCI information for debugging. If we support additional MACs in the future,
 * they should be added here.
 */
static void
ice_identify(ice_t *ice)
{
	uint32_t reg;

	ice->ice_pci_vid = pci_config_get16(ice->ice_pci_hdl, PCI_CONF_VENID);
	ice->ice_pci_did = pci_config_get16(ice->ice_pci_hdl, PCI_CONF_DEVID);
	ice->ice_pci_rev = pci_config_get8(ice->ice_pci_hdl, PCI_CONF_REVID);
	ice->ice_pci_svid = pci_config_get16(ice->ice_pci_hdl,
	    PCI_CONF_SUBVENID);
	ice->ice_pci_sdid = pci_config_get16(ice->ice_pci_hdl,
	    PCI_CONF_SUBSYSID);

	/*
	 * Determine the maximum speed of the device and determine anything that
	 * we need to derive from that.
	 */
	reg = ice_reg_read(ice, ICE_REG_GL_UFUSE_SOC);
	ice->ice_soc = reg;
	switch (ICE_REG_GL_UFUSE_SOC_BANDWIDTH(reg)) {
	case ICE_REG_GL_UFUSE_SOC_25_GBE:
		ice->ice_itr_gran = ICE_ITR_GRAN_25GBE;
		break;
	case ICE_REG_GL_UFUSE_SOC_50_GBE:
	case ICE_REG_GL_UFUSE_SOC_100_GBE:
	case ICE_REG_GL_UFUSE_SOC_200_GBE:
		ice->ice_itr_gran = ICE_ITR_GRAN;
		break;
	}

	reg = ice_reg_read(ice, ICE_REG_PF_FUNC_RID);
	ice->ice_pci_bus = ICE_REG_PF_FUNC_RID_BUS(reg);
	ice->ice_pci_dev = ICE_REG_PF_FUNC_RID_DEV(reg);
	ice->ice_pci_func = ICE_REG_PF_FUNC_RID_FUNC(reg);
	ice->ice_pf_id = ice->ice_pci_func;

	ice_set_mac(ice);
}

static void
ice_fm_ereport_fwmode(ice_t *ice, const char *mode, uint32_t fwsm)
{
	char buf[FM_MAX_CLASS];
	uint64_t ena;

	if (!DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
		return;
	}

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE,
	    DDI_FM_DEVICE_FW_CORRUPT);
	ena = fm_ena_generate(0, FM_ENA_FMT1);

	ddi_fm_ereport_post(ice->ice_dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
	    "fw_mode", DATA_TYPE_STRING, mode,
	    "mng_fwsm", DATA_TYPE_UINT32, fwsm,
	    NULL);

	ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_DEGRADED);
}

static bool
ice_check_mode(ice_t *ice)
{
	uint32_t reg;

	reg = ice_reg_read(ice, ICE_REG_MNG_FWSM);

	switch (ICE_REG_MNG_FWSM_FW_MODES(reg)) {
	case ICE_REG_MNG_FWSM_NORMAL:
		return (true);
	case ICE_REG_MNG_FWSM_DEBUG:
		/* This seems unusual enough to probably notify the operator */
		dev_err(ice->ice_dip, CE_NOTE, "NIC is in debug mode");
		return (true);
	case ICE_REG_MNG_FWSM_RECOVERY:
		ice_error(ice, "NIC is in recovery mode; cannot use");
		ice_fm_ereport_fwmode(ice, "recovery", reg);
		return (false);
	case ICE_REG_MNG_FWSM_DEBUG_RECOVERY:
		ice_error(ice, "NIC is in debug + recovery mode; cannot use");
		ice_fm_ereport_fwmode(ice, "debug_recovery", reg);
		return (false);
	}

	/*NOTREACHED*/
	return (false);
}

void
ice_update_mtu(ice_t *ice, uint_t mtu)
{
	ice->ice_mtu = mtu;

	/* XXX: This should be updated once we support vlan tagging */
	ice->ice_frame_size = mtu + sizeof (struct ether_header) + ETHERFCSL;
}

static int
ice_get_prop(ice_t *ice, char *prop, int min, int max, int def)
{
	int val;

	val = ddi_prop_get_int(DDI_DEV_T_ANY, ice->ice_dip, DDI_PROP_DONTPASS,
	    prop, def);
	if (val > max) {
		val = max;
	}
	if (val < min) {
		val = min;
	}
	return (val);
}

static bool
ice_get_bool_prop(ice_t *ice, char *prop, bool def)
{
	int val;
	int defval = def ? 1 : 0;

	val = ddi_prop_get_int(DDI_DEV_T_ANY, ice->ice_dip, DDI_PROP_DONTPASS,
	    prop, defval);

	return ((val != 0) ? true : false);
}

/*
 * Initialize any properties that we want to support via a driver.conf option.
 */
static void
ice_properties_init(ice_t *ice)
{
	/* XXX Come here and handle things like mtu, etc. */
	ice->ice_itr_rx = ICE_ITR_RX_DEFAULT;
	ice->ice_itr_tx = ICE_ITR_TX_DEFAULT;
	ice->ice_itr_other = ICE_ITR_OTHER_DEFAULT;

	ice->ice_tx_dma_min = ICE_TX_DMA_THRESH_DEF;

	ice->ice_tx_lso_enable = ice_get_bool_prop(ice, "tx_lso_enable", true);

	ice->ice_tx_hcksum_enable = ice_get_bool_prop(ice, "tx_hcksum_enable",
	    true);

	ice->ice_rx_hcksum_enable = ice_get_bool_prop(ice, "rx_hcksum_enable",
	    true);

	ice->ice_rx_dma_min = ICE_RX_DMA_THRESH_DEF;
	ice->ice_rx_maxloan = ICE_RX_LOAN_DEF;
	ice->ice_rx_limit_per_intr = ICE_RX_INTR_MAX_PKT_DEF;

	ice_update_mtu(ice, ICE_MTU_DEFAULT);
}

static boolean_t
ice_firmware_check(ice_t *ice, bool owner)
{
	/*
	 * The firmware version is a property of the device as a whole, so
	 * if we're not the PF responsible for populating ice_device's
	 * shared copy of it (see ice_device_fw_enter()), there's nothing
	 * for us to do here.
	 */
	if (!owner) {
		return (B_TRUE);
	}

	mutex_enter(&ice->ice_device->id_lock);
	if (!ice_cmd_get_version(ice, &ice->ice_device->id_fwinfo)) {
		mutex_exit(&ice->ice_device->id_lock);
		ice_error(ice, "failed to get firmware version "
		    "information");

		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
			char buf[FM_MAX_CLASS];
			uint64_t ena;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_DEVICE, DDI_FM_DEVICE_INVAL_STATE);
			ena = fm_ena_generate(0, FM_ENA_FMT1);

			ddi_fm_ereport_post(ice->ice_dip, buf, ena, DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    NULL);

			/* Try to carry on since this is just informational */
			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_UNAFFECTED);
		}

		return (B_FALSE);
	}
	mutex_exit(&ice->ice_device->id_lock);

	dev_err(ice->ice_dip, CE_CONT, "?firmware: %u.%u.%u",
	    ice->ice_device->id_fwinfo.ifi_fw_major,
	    ice->ice_device->id_fwinfo.ifi_fw_minor,
	    ice->ice_device->id_fwinfo.ifi_fw_patch);

	/* XXX Check if both are version 1? */

	return (B_TRUE);
}

/*
 * Sends the driver version to the NIC. 9.5.3 of the datasheet suggests this
 * must be done after querying the NIC for its version.
 */
static bool
ice_driver_version(ice_t *ice)
{
	if (!ice_cmd_driver_version(ice, ice_ver_major, ice_ver_minor,
	    ice_ver_patch, ice_ver_rc, ice_ver_str)) {
		ice_error(ice, "failed to inform NIC of driver version");
		return (false);
	}

	return (true);
}

static boolean_t
ice_caps_fetch(ice_t *ice)
{
	ice_capability_t *cap;

	/*
	 * This may be called more than once over the life of the driver (see
	 * ice_rebuild()), so free any previous capability arrays before
	 * fetching new ones instead of leaking them.
	 */
	if (ice->ice_dev_caps != NULL) {
		kmem_free(ice->ice_dev_caps, ice->ice_ndev_caps *
		    sizeof (ice_capability_t));
		ice->ice_ndev_caps = 0;
		ice->ice_dev_caps = NULL;
	}

	if (ice->ice_func_caps != NULL) {
		kmem_free(ice->ice_func_caps, ice->ice_nfunc_caps *
		    sizeof (ice_capability_t));
		ice->ice_nfunc_caps = 0;
		ice->ice_func_caps = NULL;
	}

	if (!ice_cmd_get_caps(ice, B_TRUE, &ice->ice_ndev_caps,
	    &ice->ice_dev_caps)) {
		ice_error(ice, "failed to get device capabilities");
		return (B_FALSE);
	}

	if (!ice_cmd_get_caps(ice, B_FALSE, &ice->ice_nfunc_caps,
	    &ice->ice_func_caps)) {
		ice_error(ice, "failed to get function capabilities");
		goto err;
	}

	/*
	 * Go through and find the capabilities that we expect and need to
	 * progress.
	 */
	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_VSI,
	    ICE_CAP_MAJOR_VSI)) == NULL) {
		ice_error(ice, "failed to find function VSI capability");
		goto err;
	}
	ice->ice_max_vsis = cap->icap_number;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_MAX_MTU,
	    ICE_CAP_MAJOR_MTU)) == NULL) {
		ice_error(ice, "failed to find function MTU capability");
		goto err;
	}
	ice->ice_max_mtu = cap->icap_number;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_RX_QUEUES,
	    ICE_CAP_MAJOR_RXQ)) == NULL) {
		ice_error(ice, "failed to find RX Queues capability");
		goto err;
	}
	ice->ice_max_rxq = cap->icap_number;
	ice->ice_first_rxq = cap->icap_physid;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_TX_QUEUES,
	    ICE_CAP_MAJOR_TXQ)) == NULL) {
		ice_error(ice, "failed to find TX Queues capability");
		goto err;
	}
	ice->ice_max_txq = cap->icap_number;
	ice->ice_first_txq = cap->icap_physid;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_MSI_X,
	    ICE_CAP_MAJOR_MSI_X)) == NULL) {
		ice_error(ice, "failed to find MSI-X capability");
		goto err;
	}
	ice->ice_max_msix = cap->icap_number;
	ice->ice_first_msix = cap->icap_physid;

	if ((cap = ice_capability_find(ice, B_FALSE, ICE_CAP_RSS,
	    ICE_CAP_MAJOR_RSS)) == NULL) {
		ice_error(ice, "failed to find RSS capability");
		goto err;
	}
	ice->ice_rss_table_size = cap->icap_number;

	return (B_TRUE);

err:
	if (ice->ice_dev_caps != NULL) {
		kmem_free(ice->ice_dev_caps, ice->ice_ndev_caps *
		    sizeof (ice_capability_t));
		ice->ice_ndev_caps = 0;
		ice->ice_dev_caps = NULL;
	}

	if (ice->ice_func_caps != NULL) {
		kmem_free(ice->ice_func_caps, ice->ice_nfunc_caps *
		    sizeof (ice_capability_t));
		ice->ice_nfunc_caps = 0;
		ice->ice_func_caps = NULL;
	}

	return (B_FALSE);
}

static void
ice_intr_ddi_free(ice_t *ice)
{
	int i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret = ddi_intr_free(ice->ice_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			ice_error(ice, "failed to free interrupt %d: %d",
			    i, ret);
		}

		list_destroy(&ice->ice_intr_handlers[i]);
	}

	kmem_free(ice->ice_intr_handlers, ice->ice_nintrs * sizeof (list_t));
	ice->ice_intr_handlers = NULL;

	if (ice->ice_intr_handles != NULL) {
		kmem_free(ice->ice_intr_handles, ice->ice_intr_handle_size);
		ice->ice_intr_handle_size = 0;
		ice->ice_intr_handles = NULL;
	}
}

static boolean_t
ice_intr_alloc_type(ice_t *ice, int type)
{
	int ret, req, min, count, act;

	switch (type) {
	case DDI_INTR_TYPE_FIXED:
	case DDI_INTR_TYPE_MSI:
		req = 1;
		min = 1;
		break;
	case DDI_INTR_TYPE_MSIX:
		min = 2;
		req = ice->ice_max_msix;
		break;
	default:
		ice_error(ice, "invalid interrupt type specified: %d", type);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_nintrs(ice->ice_dip, type, &count)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get number of interrupts of type %d: "
		    "%d", type, ret);
		return (B_FALSE);
	} else if (count < min) {
		ice_error(ice, "number of interrupts of type %d is %d, but "
		    "minimum number for the driver is %d", type, count, min);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_navail(ice->ice_dip, type, &count)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get available interrupts of type %d: "
		    "%d", type, ret);
		return (B_FALSE);
	} else if (count < min) {
		ice_error(ice, "available interrupts of type %d is %d, but "
		    "minimum number for the driver is %d", type, count, min);
		return (B_FALSE);
	}

	/*
	 * Limit the number of interrupts we request based on what's available.
	 */
	req = MIN(req, count);
	ice->ice_intr_handle_size = req * sizeof (ddi_intr_handle_t);
	ice->ice_intr_handles = kmem_alloc(ice->ice_intr_handle_size, KM_SLEEP);
	if ((ret = ddi_intr_alloc(ice->ice_dip, ice->ice_intr_handles, type, 0,
	    req, &act, DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
		ice_error(ice, "failed to allocate %d interrupts of type %d: "
		    "%d", req, type, ret);
		goto err;
	}

	ice->ice_intr_type = type;
	ice->ice_nintrs = act;

	if (act < min) {
		ice_error(ice, "allocated %d interrupts of type %d, but "
		    "required %d at a minimum", act, type, min);
		goto err;
	}

	if ((ret = ddi_intr_get_cap(ice->ice_intr_handles[0],
	    &ice->ice_intr_cap)) != DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt capability, type %d, "
		    "error: %d", type, ret);
		goto err;
	}

	if ((ret = ddi_intr_get_pri(ice->ice_intr_handles[0],
	    &ice->ice_intr_pri)) != DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt priority, type %d, "
		    "error: %d", type, ret);
		goto err;
	}

	ice->ice_intr_handlers = kmem_zalloc(ice->ice_nintrs * sizeof (list_t),
	    KM_SLEEP);
	for (uint_t i = 0; i < ice->ice_nintrs; i++) {
		list_create(&ice->ice_intr_handlers[i],
		    sizeof (ice_intr_handler_t),
		    offsetof(ice_intr_handler_t, iih_node));
	}

	return (B_TRUE);

err:
	ice_intr_ddi_free(ice);
	return (B_FALSE);
}

static boolean_t
ice_intr_ddi_alloc(ice_t *ice)
{
	int ret, types;

	if ((ret = ddi_intr_get_supported_types(ice->ice_dip, &types)) !=
	    DDI_SUCCESS) {
		ice_error(ice, "failed to get interrupt types: %d", ret);
		return (B_FALSE);
	}

	if ((types & DDI_INTR_TYPE_MSIX) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_MSIX)) {
			return (B_TRUE);
		}
	}

	if ((types & DDI_INTR_TYPE_MSI) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_MSI)) {
			return (B_TRUE);
		}
	}

	if ((types & DDI_INTR_TYPE_FIXED) != 0) {
		if (ice_intr_alloc_type(ice, DDI_INTR_TYPE_FIXED)) {
			return (B_TRUE);
		}
	}

	ice_error(ice, "failed to allocate interrupts for device");
	return (B_FALSE);
}

/*
 * Eventually we'll use this to distribute TX and RX queues to groups once
 * mac group support is added. For now, our default behavior is to use
 * all of the queues (capped by the number of CPUs online) unless the
 * user has requested fewer queues.
 */
static boolean_t
ice_calculate_groups(ice_t *ice)
{
	if (ice->ice_intr_type == DDI_INTR_TYPE_MSIX) {
		uint_t tx_want, rx_want;

		/* A value of 0 means use as many TX rings as we can */
		tx_want = ice_get_prop(ice, "tx_nrings", 0, ice->ice_max_txq,
		    0);
		if (tx_want == 0) {
			tx_want = ncpus_online;
		}
		VERIFY3U(tx_want, >, 0);

		rx_want = ice_get_prop(ice, "rx_nrings", 0, ice->ice_max_rxq,
		    0);
		if (rx_want == 0) {
			rx_want = ncpus_online;
		}

		ice->ice_num_txq = MIN(tx_want, ice->ice_max_txq);

		ice->ice_num_vsis = 1;
		ice->ice_num_rxq_per_vsi =
		    MAX(1, MIN(rx_want, ice->ice_max_rxq));

	} else {
		ice->ice_num_vsis = 1;
		ice->ice_num_rxq_per_vsi = 1;
		ice->ice_num_txq = 1;
	}

	return (B_TRUE);
}

static void
ice_intr_rem_ddi_handles(ice_t *ice)
{
	int i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret;

		if ((ret = ddi_intr_remove_handler(ice->ice_intr_handles[i])) !=
		    DDI_SUCCESS) {
			ice_error(ice, "failed to remove interrupt type %u "
			    "vector %d: %u", ice->ice_intr_type, i, ret);
		}
	}
}

static boolean_t
ice_intr_add_ddi_handles(ice_t *ice)
{
	int i;
	ddi_intr_handler_t *func;

	switch (ice->ice_intr_type) {
	case DDI_INTR_TYPE_MSIX:
		func = ice_intr_msix;
		break;
	case DDI_INTR_TYPE_MSI:
		func = ice_intr_msi;
		break;
	case DDI_INTR_TYPE_FIXED:
		func = ice_intr_intx;
		break;
	default:
		ice_error(ice, "encountered malformed ice interrupt type: %u",
		    ice->ice_intr_type);
		return (B_FALSE);
	}

	for (i = 0; i < ice->ice_nintrs; i++) {
		int ret;
		caddr_t vector = (void *)(uintptr_t)i;
		if ((ret = ddi_intr_add_handler(ice->ice_intr_handles[i],
		    func, ice, vector)) != DDI_SUCCESS) {
			ice_error(ice, "failed to add interrupt handler "
			    "type %u, vector %u", ret, vector);

			while (i > 0) {
				i--;
				(void) ddi_intr_remove_handler(
				    ice->ice_intr_handles[i]);
			}
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
ice_intr_ddi_disable(ice_t *ice)
{
	int ret;
	boolean_t rval = B_TRUE;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_disable(ice->ice_intr_handles,
		    ice->ice_nintrs)) != DDI_SUCCESS) {
			ice_error(ice, "failed to block disable interrupts: %d",
			    ret);
			rval = B_FALSE;
		}
	} else {
		int i;
		for (i = 0; i < ice->ice_nintrs; i++) {
			ret = ddi_intr_disable(ice->ice_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				ice_error(ice, "failed to disable interrupt "
				    "%d: %d", i, ret);
				rval = B_FALSE;
			}
		}
	}

	return (rval);
}

static boolean_t
ice_intr_ddi_enable(ice_t *ice)
{
	int ret;

	if (ice->ice_intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ice->ice_intr_handles,
		    ice->ice_nintrs)) != DDI_SUCCESS) {
			ice_error(ice, "failed to block enable interrupts: %d",
			    ret);
			return (B_FALSE);
		}
	} else {
		int i;
		for (i = 0; i < ice->ice_nintrs; i++) {
			if ((ret = ddi_intr_enable(ice->ice_intr_handles[i])) !=
			    DDI_SUCCESS) {
				ice_error(ice, "failed to enable interrupt "
				    "%d: %d", i, ret);
				while (--i >= 0) {
					(void) ddi_intr_disable(
					    ice->ice_intr_handles[i]);
				}
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

static void
ice_task_fini(ice_t *ice)
{
	ice_task_t *task = &ice->ice_task;

	taskq_wait(task->itk_tq);

	mutex_destroy(&task->itk_lock);
	taskq_destroy(task->itk_tq);
	mutex_destroy(&ice->ice_reset_lock);
}

static boolean_t
ice_task_init(ice_t *ice)
{
	ice_task_t *task = &ice->ice_task;

	mutex_init(&ice->ice_reset_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	task->itk_tq = taskq_create_instance("ice_task", ice->ice_inst, 1,
	    minclsyspri, 0, 0, 0);
	if (task->itk_tq == NULL) {
		ice_error(ice, "failed to create ice taskq");
		mutex_destroy(&ice->ice_reset_lock);
		return (B_FALSE);
	}

	mutex_init(&task->itk_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	return (B_TRUE);
}

static void
ice_link_state_set(ice_t *ice, link_state_t state)
{
	if (ice->ice_link_cur_state == state)
		return;

	ice->ice_link_cur_state = state;
	/*
	 * XXX This can fire while coming up in attach before we've actually
	 * registered with MAC.
	 */
	if (ice->ice_mac_hdl != NULL) {
		mac_link_update(ice->ice_mac_hdl, ice->ice_link_cur_state);
	}
}

/*
 * Go over the PHY and Link data to synthesize data that is useful to have
 * cached on the driver both for MAC and for inspection via mdb.
 */
static void
ice_link_prop_update(ice_t *ice)
{
	ice_link_status_t *link = &ice->ice_link;

	ASSERT(MUTEX_HELD(&ice->ice_lse_lock));

	if ((link->ils_status & ICE_LINK_STATUS_LINK_UP) == 0) {
		ice_link_state_set(ice, LINK_STATE_DOWN);
		ice->ice_link_cur_duplex = LINK_DUPLEX_UNKNOWN;
		ice->ice_link_cur_speed = 0;
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_NONE;
		return;
	}

	ice_link_state_set(ice, LINK_STATE_UP);
	ice->ice_link_cur_duplex = LINK_DUPLEX_FULL;

	switch (link->ils_curspeed) {
	case ICE_LINK_SPEED_200GB:
		ice->ice_link_cur_speed = 200000;
		break;
	case ICE_LINK_SPEED_100GB:
		ice->ice_link_cur_speed = 100000;
		break;
	case ICE_LINK_SPEED_50GB:
		ice->ice_link_cur_speed = 50000;
		break;
	case ICE_LINK_SPEED_40GB:
		ice->ice_link_cur_speed = 40000;
		break;
	case ICE_LINK_SPEED_25GB:
		ice->ice_link_cur_speed = 25000;
		break;
	case ICE_LINK_SPEED_20GB:
		ice->ice_link_cur_speed = 20000;
		break;
	case ICE_LINK_SPEED_10GB:
		ice->ice_link_cur_speed = 10000;
		break;
	case ICE_LINK_SPEED_5GB:
		ice->ice_link_cur_speed = 5000;
		break;
	case ICE_LINK_SPEED_2500MB:
		ice->ice_link_cur_speed = 2500;
		break;
	case ICE_LINK_SPEED_1GB:
		ice->ice_link_cur_speed = 1000;
		break;
	case ICE_LINK_SPEED_100MB:
		ice->ice_link_cur_speed = 100;
		break;
	case ICE_LINK_SPEED_10MB:
		ice->ice_link_cur_speed = 10;
		break;
	default:
		ice->ice_link_cur_speed = 0;
		break;
	}

	if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_TX) != 0 &&
	    (link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_RX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_BI;
	} else if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_TX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_TX;
	} else if ((link->ils_autoneg & ICE_LINK_AUTONEG_PAUSE_RX) != 0) {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_RX;
	} else {
		ice->ice_link_cur_fctl = LINK_FLOWCTRL_NONE;
	}
}

boolean_t
ice_link_status_update(ice_t *ice)
{
	ice_link_status_t link;
	ice_phy_abilities_t phy;
	ice_lse_t lse;
	boolean_t valid = B_FALSE;

	bzero(&link, sizeof (link));
	bzero(&phy, sizeof (phy));

	mutex_enter(&ice->ice_lse_lock);
	while ((ice->ice_lse_state & ICE_LSE_STATE_UPDATING) != 0) {
		cv_wait(&ice->ice_lse_cv, &ice->ice_lse_lock);
	}

	ice->ice_lse_state |= ICE_LSE_STATE_UPDATING;

	if ((ice->ice_lse_state & ICE_LSE_STATE_ENABLE) != 0) {
		lse = ICE_LSE_ENABLE;
	} else {
		lse = ICE_LSE_DISABLE;
	}
	mutex_exit(&ice->ice_lse_lock);

	if (!ice_cmd_get_phy_abilities(ice, &phy, B_TRUE)) {
		goto out;
	}

	if (!ice_cmd_get_link_status(ice, &link, lse)) {
		goto out;
	}
	valid = B_TRUE;

out:
	mutex_enter(&ice->ice_lse_lock);
	if (valid) {
		bcopy(&link, &ice->ice_link, sizeof (link));
		bcopy(&phy, &ice->ice_phy, sizeof (phy));

		ice_link_prop_update(ice);
	}

	ice->ice_lse_state &= ~ICE_LSE_STATE_UPDATING;
	cv_broadcast(&ice->ice_lse_cv);
	mutex_exit(&ice->ice_lse_lock);

	return (valid);
}

static const char *ice_mal_tx_str[] = {
	"wrong descriptor format/order",
	"descriptor fetch failed",
	"tail descriptor is not DDESC with EOP/NOP",
	"false scheduling",
	"tail value is bigger than ring length",
	"more than 8 data commands in packet",
	"zero packets sent in quanta and no head update in this quanta",
	"packet too small or packet too big",
	"TSO: TLEN is not coherent with sum",
	"TSO: tail reached before TLEN ended",
	"TSO: headers are spread > 3 descriptors",
	"TSO: sum of TSO buffers < sum of headers",
	"TSO: sum of TSH headers is 0/MSS is 0/TLEN is 0",
	"SSO: quanta does not include a whole number of SSO packets",
	"SSO+TSO: quanta bytes before additions exceed pkt_len*64",
	"SSO+TSO: quanta commands exceed max_cmds_in_sq",
	"TSO: total_descs_in_lso is not coherent with last_lso_quanta",
	"TSO: total_descs_in_lso is not coherent with TLEN",
	"TSO: quanta bytes is spread on more than max descriptors in quanta",
	"number of packets in quanta mismatch",
};

/* From 13.2.2.30.15 */
static const char *ice_mal_tx_pqm_str[] = {
	"PCI Dummy Completion",
	"PCI Unsupported Request Completion",
	"Unknown/Reserved",
	"Empty queue fetch -- should have been LSO",
	"Queue empty",
	"Queue full",
	"LSO Number of Descriptors is Zero",
	"LSO Length is Zero",
	"LSO MSS Below Minimum",
	"LSO MSS Above Maximum",
	"LSO Header Size Zero",
	"LSO on non-LSO TX Queue",
	"Skip One Quanta Only",
	"LSO Packet Count Zero",
	"SSO Length Zero",
	"SSO Length Exceeded",
	"SSO Packet Count Zero",
	"SSO Packet Count Exceeded",
	"SSO Number of Descriptors Zero",
	"SSO Number of Descriptors Exceeded",
	"Tail Greater than Ring Length",
	"Reserved Doorbell Type",
	"Illegal Head Drop Doorbell",
	"LSO Over Comms Queue",
	"Illegal VF Queue Number",
	"Queue Tail Greater Than Ring Length",
};

/*
 * Handle a malicious packet event. The name can be a bit misleaning since
 * it really just means the driver sent something to the NIC that it
 * considered invalid. This could be malicious (or more likely) indicative
 * of a driver bug, so reporting these can be useful regardless of the
 * intent.
 */
static void
ice_handle_mal(ice_t *ice)
{
	const char *eventstr = "";
	uint32_t v;
	uint32_t event;

	v = ice_reg_read(ice, ICE_GL_MDET_TX_TCLAN);

	if (ICE_GL_MDET_VALID(v)) {
		eventstr = "unknown";

		event = ICE_GL_MDET_EVENT(v);
		if (event < ARRAY_SIZE(ice_mal_tx_str)) {
			eventstr = ice_mal_tx_str[event];
		}

		ice_error(ice, "malicious driver event '%s' (%u) on "
		    "PF 0x%x VF 0x%x TX queue %u", eventstr, event,
		    ICE_GL_MDET_PF_NUM(v),
		    ICE_GL_MDET_VF_NUM(v),
		    ICE_GL_MDET_QNUM(v));

		/* Clear the error if it matches our PF */
		if (ice->ice_pci_func == ICE_GL_MDET_PF_NUM(v)) {
			ice_reg_write(ice, ICE_GL_MDET_TX_TCLAN, UINT32_MAX);
		}

		v = ice_reg_read(ice, ICE_PF_MDET_TX_TCLAN);
		if (ICE_PF_MDET_VALID(v)) {
			ice_reg_write(ice, ICE_PF_MDET_TX_TCLAN, 0xffff);
			ice_error(ice, "need reinit");
			/* XXX need reinit */
		}
	}

	v = ice_reg_read(ice, ICE_GL_MDET_TX_PQM);
	if (ICE_GL_MDET_TX_PQM_VALID(v)) {
		eventstr = "Unknown";

		event = ICE_GL_MDET_TX_PQM_EVENT(v);
		if (event < ARRAY_SIZE(ice_mal_tx_pqm_str)) {
			eventstr = ice_mal_tx_pqm_str[event];
		}

		ice_error(ice, "malicious TX PQM event '%s' (%u) on "
		    "PF 0x%x VF 0x%x TX queue %u", eventstr, event,
		    ICE_GL_MDET_TX_PQM_PF_NUM(v),
		    ICE_GL_MDET_TX_PQM_VF_NUM(v),
		    ICE_GL_MDET_TX_PQM_QNUM(v));

		/* Clear the rror if it matches our PF */
		if (ice->ice_pci_func == ICE_GL_MDET_TX_PQM_PF_NUM(v)) {
			ice_reg_write(ice, ICE_GL_MDET_TX_PQM, UINT32_MAX);
		}

		v = ice_reg_read(ice, ICE_PF_MDET_TX_PQM);
		if (ICE_PF_MDET_TX_PQM_VALID(v)) {
			ice_reg_write(ice, ICE_PF_MDET_TX_PQM, 0xffff);
			ice_error(ice, "need reinit");
			/* XXX need reinit */
		}
	}

	v = ice_reg_read(ice, ICE_GL_MDET_RX);
	if (ICE_GL_MDET_VALID(v)) {
		eventstr = "unknown";
		event = ICE_GL_MDET_EVENT(v);

		/*
		 * There's only 1 defined malicious RX event, so we
		 * don't need a lookup table for it.
		 */
		if (event == 1) {
			eventstr = "descriptor fetch failed";
		}

		ice_error(ice, "malicious driver event '%s' (%u) on "
		    "PF 0x%x VF 0x%x RX queue %u", eventstr, event,
		    ICE_GL_MDET_PF_NUM(v),
		    ICE_GL_MDET_VF_NUM(v),
		    ICE_GL_MDET_QNUM(v));

		/* Clear the error if it matches our PF */
		if (ice->ice_pci_func == ICE_GL_MDET_PF_NUM(v)) {
			ice_reg_write(ice, ICE_PF_MDET_RX, UINT32_MAX);
		}

		v = ice_reg_read(ice, ICE_PF_MDET_RX);
		if (ICE_PF_MDET_VALID(v)) {
			ice_reg_write(ice, ICE_PF_MDET_RX, 0xffff);
			ice_error(ice, "need reinit");
			/* XXX need reinit */
		}
	}
}

static void
ice_schedule_taskq(void *arg)
{
	ice_t *ice = arg;
	ice_task_t *task = &ice->ice_task;
	ice_work_task_t work;
	boolean_t again;

	/*
	 * Indicate that we've started running and snapshot the events that we
	 * need to operate on. It's important that we do this here as once we
	 * do, new events may be added in here. Once we grab this, we drop our
	 * hold on the lock to minimize time spent here.
	 */
start:
	mutex_enter(&task->itk_lock);
	work = task->itk_work;
	task->itk_work = 0;
	task->itk_state |= ICE_TASK_S_RUNNING;
	task->itk_state &= ~ICE_TASK_S_DISPATCHED;
	mutex_exit(&task->itk_lock);

	/*
	 * Process the control queue first as it may need to add additional work
	 * tasks that we should do in this iteration of the loop such as a link
	 * status event.
	 */
	if ((work & ICE_WORK_CONTROLQ) != 0) {
		work |= ice_controlq_rq_process(ice);
		work &= ~ICE_WORK_CONTROLQ;
	}

	if ((work & ICE_WORK_LINK_STATUS_EVENT) != 0) {
		if (!ice_link_status_update(ice)) {
			ice_error(ice, "failed to update ice link status due "
			    "to controlq event");
		}
		work &= ~ICE_WORK_LINK_STATUS_EVENT;
	}

	if ((work & ICE_WORK_MAL_DETECTED) != 0) {
		ice_handle_mal(ice);
		work &= ~ICE_WORK_MAL_DETECTED;
	}

	if ((work & ICE_WORK_NEED_RESET) != 0) {
		/*
		 * Something (e.g. an ECC error, or a user-requested PF reset
		 * via ICE_IOC_RESET) has told us that we should request our
		 * own PF reset. Quiesce first, since triggering the reset
		 * will immediately start tearing down the hardware state we
		 * depend on.
		 */
		ice_prepare_for_reset(ice);

		if (!ice_reset(ice, ICE_RESET_PFR)) {
			ice_error(ice, "failed to perform requested PF "
			    "reset");
			atomic_or_32(&ice->ice_state, ICE_ERROR);
		} else if (!ice_rebuild(ice, false)) {
			ice_error(ice, "failed to rebuild driver state "
			    "after PF reset");
			/* ice_rebuild() sets ICE_ERROR on failure */
		}

		work &= ~ICE_WORK_NEED_RESET;
	}

	if ((work & ICE_WORK_RESET_DETECTED) != 0) {
		/*
		 * The OICR GRST bit indicates that a CORE, GLOBAL, or EMP
		 * reset is either about to happen or is already underway,
		 * triggered by us, another PF, or firmware itself. Quiesce
		 * and then just wait for the hardware to finish resetting on
		 * its own; unlike ICE_WORK_NEED_RESET, we don't trigger
		 * anything here.
		 */
		ice_prepare_for_reset(ice);

		if (!ice_check_reset(ice)) {
			ice_error(ice, "device never came out of reset");
			atomic_or_32(&ice->ice_state, ICE_ERROR);
		} else if (!ice_rebuild(ice, true)) {
			ice_error(ice, "failed to rebuild driver state "
			    "after reset");
			/* ice_rebuild() sets ICE_ERROR on failure */
		}

		work &= ~ICE_WORK_RESET_DETECTED;
	}

	ASSERT0(work);

	/*
	 * At this point we believe that we have completed all of our work.
	 * Indicate that we're no longer running and
	 */
	mutex_enter(&task->itk_lock);
	task->itk_state &= ~ICE_TASK_S_RUNNING;
	again = (task->itk_state & ICE_TASK_S_DISPATCHED) != 0;
	mutex_exit(&task->itk_lock);

	if (again) {
		goto start;
	}
}

void
ice_schedule(ice_t *ice, ice_work_task_t work)
{
	ice_task_t *task = &ice->ice_task;

	mutex_enter(&task->itk_lock);
	task->itk_work |= work;

	/*
	 * If we already have dispatched the event, then there's no need for us
	 * to do anything else. It will be picked up as our scheduled work comes
	 * back around.
	 */
	if ((task->itk_state & ICE_TASK_S_DISPATCHED) != 0) {
		mutex_exit(&task->itk_lock);
		return;
	}

	task->itk_state |= ICE_TASK_S_DISPATCHED;
	if ((task->itk_state & ICE_TASK_S_RUNNING) == 0) {
		taskq_dispatch_ent(task->itk_tq, ice_schedule_taskq, ice, 0,
		    &task->itk_ent);
	}
	mutex_exit(&task->itk_lock);
}

/*
 * Walk the switch configuration to find information about our physical port. We
 * only expect there to be one such entry on a given device.
 */
static boolean_t
ice_switch_init(ice_t *ice)
{
	ice_hw_switch_config_t *swconf;
	uint16_t cur, nents, next;
	bool port_seen = false;

	swconf = kmem_alloc(ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX, KM_SLEEP);
	cur = 0;
	do {
		uint16_t i;

		bzero(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
		if (!ice_cmd_get_switch_config(ice, swconf,
		    ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX, cur, &nents, &next)) {
			ice_error(ice, "failed to get initial switch config");
			goto err;
		}

		for (i = 0; i < nents; i++) {
			uint16_t info = swconf[i].isc_vsi_info;

			if (ICE_SWITCH_ELT_TYPE(info) !=
			    ICE_SWITCH_TYPE_PHYSICAL_PORT) {
				continue;
			}

			if (port_seen) {
				ice_error(ice, "encounterd two different "
				    "physical port entries! First has ID "
				    "0x%x/0x%x, second has ID 0x%x/0x%x",
				    ice->ice_port_id, ice->ice_port_swid,
				    ICE_SWITCH_ELT_NUMBER(info),
				    swconf[i].isc_swid);
				goto err;
			}

			ice->ice_port_id = ICE_SWITCH_ELT_NUMBER(info);
			ice->ice_port_swid = swconf[i].isc_swid;
			port_seen = true;
		}

		cur = next;
	} while (cur != 0);

	kmem_free(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	return (B_TRUE);

err:
	kmem_free(swconf, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	return (B_FALSE);
}

static bool
ice_tx_scheduler_query(ice_t *ice)
{
	uint8_t			*buf = NULL;
	ice_hw_tx_sched_gen_t	*gen;
	size_t			buflen;
	uint16_t		nbranch;

	buf = kmem_zalloc(ICE_TX_SCHED_DEFAULT_TOPO_SIZE, KM_SLEEP);

	/*
	 * Take advantage of the required buffer size for the Query Scheduler
	 * Resource command (2048) being less than for querying the default
	 * topology size so we can reuse the buffer.
	 */
	CTASSERT(ICE_TX_SCHED_RES_ALLOC_SIZE <= ICE_TX_SCHED_DEFAULT_TOPO_SIZE);

	buflen = ICE_TX_SCHED_RES_ALLOC_SIZE;
	if (!ice_cmd_get_sched_resource_alloc(ice, buf, &buflen)) {
		goto fail;
	}

	if (buflen > ICE_TX_SCHED_RES_ALLOC_SIZE) {
		ice_error(ice, "resource allocation size (%zu bytes) is larger "
		    "than allowed", buflen);
		goto fail;
	}
	gen = (ice_hw_tx_sched_gen_t *)buf;

	ice->ice_tx_max_layers = LE_16(gen->ihtsg_nphys_layers);

	ice->ice_tx_max_sw_layers = LE_16(gen->ihtsg_nlayers);
	if (ice->ice_tx_max_sw_layers > ICE_SCHED_NODE_MAX_DEPTH) {
		ice_error(ice, "hardware reported invalid number of scheduling "
		    "layers (%u)", ice->ice_tx_max_sw_layers);
		goto fail;
	}

	if (buflen < sizeof (*gen)) {
		ice_error(ice, "hardware truncated scheduling data: "
		    "returned %zu bytes with %u layers ", buflen,
		    ice->ice_tx_max_sw_layers);
		goto fail;
	}

	for (uint_t i = 0; i < ice->ice_tx_max_sw_layers; i++) {
		ice->ice_tx_sched_max_sibs[i] =
		    gen->ihtsg_layer_prop[i].ihtsl_max_sibling;
	}

	buflen = ICE_TX_SCHED_DEFAULT_TOPO_SIZE;
	bzero(buf, buflen);
	if (!ice_cmd_get_default_scheduler(ice, buf, buflen, &nbranch)) {
		goto fail;
	}

	if (!ice_parse_tx_sched(ice, buf, buflen, nbranch)) {
		goto fail;
	}

	kmem_free(buf, ICE_TX_SCHED_DEFAULT_TOPO_SIZE);
	return (true);

fail:
	if (buf != NULL) {
		kmem_free(buf, ICE_TX_SCHED_DEFAULT_TOPO_SIZE);
	}

	return (false);
}

static bool
ice_tx_scheduler_init(ice_t *ice)
{
	mutex_init(&ice->ice_tx_sched_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	if (!ice_tx_scheduler_query(ice)) {
		mutex_destroy(&ice->ice_tx_sched_lock);
		return (false);
	}

	return (true);
}

/*
 * Rebuild the tx scheduler topology after a reset has cleared it out of
 * hardware. Unlike ice_tx_scheduler_init(), the lock has already been
 * initialized (and may still be referenced by things like queued up tx
 * scheduler node additions/removals), so we only discard and re-fetch the
 * topology itself. Note ice_parse_tx_sched() (called via
 * ice_tx_scheduler_query()) and ice_tx_sched_free_nodes() manage
 * ice_tx_sched_lock internally/expect the caller not to be holding it, so
 * we don't hold it across this call either.
 */
static bool
ice_tx_scheduler_rebuild(ice_t *ice)
{
	mutex_enter(&ice->ice_tx_sched_lock);
	if (ice->ice_tx_sched_root != NULL) {
		ice_tx_sched_free_nodes(ice, ice->ice_tx_sched_root);
		ice->ice_tx_sched_root = NULL;
	}
	mutex_exit(&ice->ice_tx_sched_lock);

	return (ice_tx_scheduler_query(ice));
}

static void
ice_vsi_context_fill(ice_t *ice, ice_vsi_t *vsi)
{
	ice_hw_vsi_context_t *ctx = &vsi->ivsi_ctxt;
	uint32_t table;
	uint16_t tc;

	/*
	 * Make sure everything in the context starts off zeroed.
	 */
	bzero(ctx, sizeof (*ctx));

	/*
	 * Set up general switch parameters. The default settings here are such
	 * that we don't allow traffic to loop back from the VSI, we explicitly
	 * allow it to reach the LAN, and we follow the programming manual's
	 * advice to turn on source pruning.
	 *
	 * XXX Come back for statistics
	 */
	ctx->ihvc_switch_id = ice->ice_port_swid;
	ctx->ihvc_switch_flags = ICE_HW_VSI_SWITCH_APPLY_SOURCE_PRUNE;
	ctx->ihvc_switch_flags2 = ICE_HW_VSI_SWITCH_LAN_ENABLE;

	/*
	 * By default we do not enable anything in the security section.
	 */

	/*
	 * For VLAN handling, by default we allow all tagged and untaggd packets
	 * on a given VSI. We do not enable VLAN insertion and we set it up such
	 * that hardware leaves the VLAN ID in the packet.
	 */
	ctx->ihvc_vlan_flags = ICE_HW_VSI_VLAN_SET_TAG(ctx->ihvc_vlan_flags,
	    ICE_HW_VSI_VLAN_ALL);
	ctx->ihvc_vlan_flags = ICE_HW_VSI_VLAN_SET_UP_MODE(ctx->ihvc_vlan_flags,
	    ICE_HW_VSI_VLAN_UP_DO_NONE);

	/*
	 * The next values are used to allow us to remap priority values that
	 * are found in VLAN tags. We make this a direct mapping. Both the
	 * ingress and egress tables are defined the same way, so we build one
	 * table.
	 */
	table = 0;
	for (uint_t i = 0; i < 8; i++) {
		table = ICE_HW_VSI_UP_TABLE_SET(table, i, i);
	}
	ctx->ihvc_ingress_table = LE_32(table);
	ctx->ihvc_egress_table = LE_32(table);
	ctx->ihvc_outer_table = LE_32(table);

	/*
	 * We do not set up any outer tag handling. The default setting of
	 * everyting to zero indicates that nothing should happen.
	 */

	/*
	 * Assign a contiguous set of queues to the VSI. They all go into the
	 * default traffic class as well. The traffic class is written as a
	 * number of queues that is 2^n. Therefore to correctly calculate the
	 * traffic class we need to subtract one from the total number of queues
	 * before passing that into ddi_fls.
	 */
	ctx->ihvc_queue_method = ICE_HW_VSI_QMAP_CONTIG;
	ctx->ihvc_queue_mapping[0] = LE_16(vsi->ivsi_frxq);
	ctx->ihvc_queue_mapping[1] = LE_16(vsi->ivsi_nrxq);
	tc = 0;
	tc = ICE_HW_VSI_TC_SET_QUEUE_OFF(tc, 0);
	tc = ICE_HW_VSI_TC_SET_NQUEUES(tc, ddi_fls(vsi->ivsi_nrxq - 1));
	ctx->ihvc_queue_tc[0] = LE_16(tc);

	/*
	 * Select the RSS LUT type based on the VSI type. This follows the
	 * approach taken by the FreeBSD driver (since it's known to work).
	 */
	switch (vsi->ivsi_type) {
	case ICE_VSI_TYPE_PF:
		ctx->ihvc_qopt_rss = ICE_HW_VSI_RSS_SET_LUT(0,
		    ICE_HW_VSI_RSS_PF_LUT);
		break;
	default:
		ctx->ihvc_qopt_rss = ICE_HW_VSI_RSS_SET_LUT(0,
		    ICE_HW_VSI_RSS_LUT_VSI);
		break;
	}
	ctx->ihvc_qopt_rss = ICE_HW_VSI_RSS_SET_HASH_SCHEME(ctx->ihvc_qopt_rss,
	    ICE_HW_VSI_RSS_SCHEME_TOEPLITZ);

	/*
	 * We don't define anything for ACLs, Flow director, or PASID. As the
	 * default zeroing of the structure leaves them disabled, this should be
	 * sufficient for now.
	 */
}

static void
ice_vsi_free(ice_t *ice, ice_vsi_t *vsi)
{
	ice_sched_node_t *node;

	if (vsi == NULL)
		return;

	if ((vsi->ivsi_flags & ICE_VSI_F_RSS_SET) != 0) {
		(void) ice_rss_config_fini(ice, vsi);
	}

	/*
	 * If we successfully created a TX scheduler subtree for this VSI
	 * (ice_tx_sched_add_vsi_node() itself backs out any partial work on
	 * its own failure), it belongs exclusively to this VSI and needs to
	 * be torn down here, otherwise it will leak.
	 */
	node = ice_tx_sched_vsi_node(vsi);
	if (node != NULL) {
		mutex_enter(&ice->ice_tx_sched_lock);
		if (!ice_tx_sched_del_subtree(ice, node)) {
			ice_error(ice, "failed to clean up VSI TX scheduler "
			    "nodes; leaking scheduler resources");
		}
		mutex_exit(&ice->ice_tx_sched_lock);
	}

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) != 0) {
		(void) ice_cmd_free_vsi(ice, vsi, B_FALSE);
	}

	ice_stat_vsi_fini(vsi);

	kmem_free(vsi, sizeof (ice_vsi_t));
}

static bool
ice_vsi_rss_init(ice_t *ice, ice_vsi_t *vsi)
{
	uint8_t	rss_key[ICE_RSS_KEY_LENGTH];
	uint8_t	*rss_lut;
	size_t	rss_lut_len;
	uint_t	i;
	bool	ret;

	/*
	 * Initialize the RSS key to random data. We're supposed to zero the
	 * extended bytes. So only fill the basic bytes with random data.
	 */
	bzero(rss_key, sizeof (rss_key));
	(void) random_get_pseudo_bytes(rss_key, ICE_RSS_KEY_STANDARD_LENGTH);

	/*
	 * The size of the LUT depends on which RSS LUT type this VSI uses
	 * (see ice_vsi_context_fill()): the main per-PF VSI uses the much
	 * larger PF-wide LUT (sized per the RSS capability reported by
	 * firmware), while VF/VMDQ VSIs use the small, fixed-size per-VSI
	 * LUT.
	 */
	if (vsi->ivsi_type == ICE_VSI_TYPE_PF) {
		rss_lut_len = ice->ice_rss_table_size;
	} else {
		rss_lut_len = ICE_RSS_LUT_SIZE_VSI;
	}
	rss_lut = kmem_alloc(rss_lut_len, KM_SLEEP);

	/*
	 * The LUT needs to be filled with target queues indexes. We do this
	 * naively by just filling up the LUT in order based on the number of
	 * queues present.
	 */
	for (i = 0; i < rss_lut_len; i++) {
		rss_lut[i] = i % vsi->ivsi_nrxq;
	}

	if (!ice_cmd_set_rss_key(ice, vsi, rss_key, sizeof (rss_key))) {
		kmem_free(rss_lut, rss_lut_len);
		return (false);
	}

	ret = ice_cmd_set_rss_lut(ice, vsi, rss_lut, rss_lut_len);

	kmem_free(rss_lut, rss_lut_len);

	return (ret);
}

static ice_vsi_t *
ice_vsi_alloc(ice_t *ice, uint_t vsi_id, ice_vsi_type_t type)
{
	ice_vsi_t *vsi;

	vsi = kmem_zalloc(sizeof (ice_vsi_t), KM_SLEEP);
	vsi->ivsi_ice = ice;
	vsi->ivsi_id = vsi_id;
	vsi->ivsi_type = type;

	/*
	 * All of the VSIs that we create need to be allocated from the general
	 * pool.
	 */
	vsi->ivsi_flags |= ICE_VSI_F_POOL_ALLOC;

	/*
	 * XXX This only makes sense for the PF and even then not very much.
	 * Figure out how to do queue assignments better. Also, keep in mind
	 * whether these queue allocations are in the function space or in the
	 * global space.
	 */
	vsi->ivsi_nrxq = ice->ice_num_rxq_per_vsi;
	vsi->ivsi_frxq = 0;
	vsi->ivsi_ntxq = ice->ice_num_txq;

	ice_vsi_context_fill(ice, vsi);

	if (!ice_cmd_add_vsi(ice, vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}
	vsi->ivsi_flags |= ICE_VSI_F_ACTIVE;

	if (!ice_vsi_rss_init(ice, vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}
	vsi->ivsi_flags |= ICE_VSI_F_RSS_SET;

	list_create(&vsi->ivsi_macs, sizeof (ice_vsi_mac_t),
	    offsetof(ice_vsi_mac_t, ivm_node));

	/*
	 * Since we currently do not offload traffic shaping (i.e. flows
	 * in MAC parlance) to the NIC, we also do not support multiple
	 * traffic classes. I.e. everything currently uses tc0. As such
	 * we only create a VSI tx scheduler node for tc0. If we ever
	 * add support for offloading flows to NICs, this likely will
	 * need to change.
	 */
	if (!ice_tx_sched_add_vsi_node(ice, vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}

	/*
	 * XXX What queue initialization should we be doing here?
	 */

	if (!ice_stat_vsi_init(vsi)) {
		ice_vsi_free(ice, vsi);
		return (NULL);
	}

	list_insert_tail(&ice->ice_vsi, vsi);

	return (vsi);
}

static bool
ice_pf_vsi_init(ice_t *ice)
{
	ice_vsi_t *vsi;

	list_create(&ice->ice_vsi, sizeof (ice_vsi_t),
	    offsetof(ice_vsi_t, ivsi_node));

	vsi = ice_vsi_alloc(ice, 0, ICE_VSI_TYPE_PF);
	if (vsi == NULL) {
		list_destroy(&ice->ice_vsi);
		return (false);
	}

	/*
	 * XXX We need to set up basic switch rules so that this gets the
	 * primary MAC, etc.
	 */

	return (true);
}

static bool
ice_rx_ring_init(ice_t *ice, ice_rx_ring_t *rxr, uint_t index)
{
	ice_rxq_stat_t	*rqs = &rxr->irxr_stats;
	char		buf[64];

	mutex_init(&rxr->irxr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));
	rxr->irxr_ice = ice;
	rxr->irxr_index = index;
	rxr->irxr_size = ice->ice_rx_rsize;

	(void) snprintf(buf, sizeof (buf), "rx_%u", index);

	rxr->irxr_kstat = kstat_create(ICE_MODULE_NAME,
	    ddi_get_instance(ice->ice_dip), buf, "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_rxq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (rxr->irxr_kstat == NULL) {
		ice_error(ice, "Failed to create kstats for RX ring %u", index);
		mutex_destroy(&rxr->irxr_lock);
		return (false);
	}

	rxr->irxr_kstat->ks_data = rqs;

	kstat_named_init(&rqs->icrxs_bytes, "bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_packets, "packets", KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_bind_bytes, "bind_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_bind_segs, "bind_segments",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_copy_bytes, "copy_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_copy_segs, "copy_segments",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_desc_error, "desc_error",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_copy_nomem, "copy_nomem",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_intr_limit, "intr_limit",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_bind_no_rcb, "bind_no_rcb",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_bind_no_mp, "bind_no_mp",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_hck_unknown, "hck_unknown",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_nol3l4p, "hck_nol3l4p",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_v6skip, "hck_v6skip",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_iperr, "hck_iperr",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_eiperr, "hck_eiperr",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_v4hdrok, "hck_v4hdrok",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_l4err, "hck_l4err",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_l4hdrok, "hck_l4hdrok",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_hck_udperr, "hck_udperr",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_tcperr, "hck_tcperr",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_sctperr, "hck_sctperr",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&rqs->icrxs_hck_set, "hck_set",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&rqs->icrxs_hck_miss, "hck_miss",
	    KSTAT_DATA_UINT64);

	kstat_install(rxr->irxr_kstat);
	return (true);
}

static void
ice_rx_ring_fini(ice_rx_ring_t *rxr)
{
	kstat_delete(rxr->irxr_kstat);
	rxr->irxr_kstat = NULL;
	mutex_destroy(&rxr->irxr_lock);
}

static bool
ice_tx_ring_init(ice_t *ice, ice_tx_ring_t *txr, uint_t index)
{
	ice_txq_stat_t	*tqs = &txr->itxr_stats;
	void		*pri = DDI_INTR_PRI(ice->ice_intr_pri);
	char		buf[64];


	txr->itxr_ice = ice;
	txr->itxr_index = index;
	txr->itxr_size = ICE_TX_RING_DEFAULT_SIZE;
	txr->itxr_teid = ICE_TX_SCHED_TEID_INVALID;
	txr->itxr_quiesce = true;

	mutex_init(&txr->itxr_lock, NULL, MUTEX_DRIVER, pri);
	mutex_init(&txr->itxr_tcb_lock, NULL, MUTEX_DRIVER, pri);
	cv_init(&txr->itxr_cv, NULL, CV_DRIVER, NULL);

	(void) snprintf(buf, sizeof (buf), "tx_%u", index);

	txr->itxr_kstat = kstat_create(ICE_MODULE_NAME,
	    ddi_get_instance(ice->ice_dip), buf, "net", KSTAT_TYPE_NAMED,
	    sizeof (ice_txq_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (txr->itxr_kstat == NULL) {
		ice_error(ice, "Failed to create kstats for TX ring %u", index);
		cv_destroy(&txr->itxr_cv);
		mutex_destroy(&txr->itxr_tcb_lock);
		mutex_destroy(&txr->itxr_lock);
		return (false);
	}

	txr->itxr_kstat->ks_data = tqs;

	kstat_named_init(&tqs->ictxs_bytes, "bytes", KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_packets, "packets", KSTAT_DATA_UINT64);

	kstat_named_init(&tqs->ictxs_bind_bytes, "bind_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_bind_frags, "bind_frags",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_copy_bytes, "copy_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_copy_frags, "copy_frags",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&tqs->ictxs_lso_bytes, "lso_bytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_lso_packets, "lso_packets",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&tqs->ictxs_bind_fails, "bind_fails",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_mss_retries, "mss_retries",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_full_copies, "full_copies",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&tqs->ictxs_hck_meoifail, "hck_meoifail",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_hck_nol2info, "hck_nol2info",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_hck_nol3info, "hck_nol3info",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_hck_nol4info, "hck_nol4info",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_hck_badl3, "hck_badl3",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_hck_badl4, "hck_badl4",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_lso_nohck, "lso_nohck",
	    KSTAT_DATA_UINT64);

	kstat_named_init(&tqs->ictxs_no_pkt_cache, "no_pkt_cache",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_drops, "drops", KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_blocked, "blocked", KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_badmss, "bad_mss", KSTAT_DATA_UINT64);
	kstat_named_init(&tqs->ictxs_toobig, "too_big", KSTAT_DATA_UINT64);

	kstat_install(txr->itxr_kstat);
	return (true);
}

void
ice_tx_ring_fini(ice_tx_ring_t *txr)
{
	kstat_delete(txr->itxr_kstat);
	txr->itxr_kstat = NULL;
	mutex_destroy(&txr->itxr_lock);
	mutex_destroy(&txr->itxr_tcb_lock);
	cv_destroy(&txr->itxr_cv);
}

static void
ice_ring_fini(ice_t *ice)
{
	uint_t i;

	for (i = ice->ice_num_txq; i > 0; i--) {
		ice_tx_ring_t *txr = &ice->ice_txr[i - 1];

		ice_intr_remove_handler(ice, txr->itxr_vec, &txr->itxr_intr);
		ice_tx_ring_fini(txr);
	}

	ASSERT3U(ice->ice_num_vsis, ==, 1);
	for (i = ice->ice_num_rxq_per_vsi; i > 0; i--) {
		ice_rx_ring_t *rxr = &ice->ice_rxr[i - 1];

		ice_intr_remove_handler(ice, rxr->irxr_vec, &rxr->irxr_intr);
		ice_rx_ring_fini(rxr);
	}

	cv_destroy(&ice->ice_rxbuf_cv);
	mutex_destroy(&ice->ice_small_bufs.ibp_lock);
	mutex_destroy(&ice->ice_bufs.ibp_lock);
	mutex_destroy(&ice->ice_rxbuf_lock);
}

static bool
ice_ring_init(ice_t *ice)
{
	size_t nrxq;
	size_t len;
	uint_t i;
	uint32_t vector = 1;	/* Vec 0 is for the controlq */

	nrxq = ice->ice_num_rxq_per_vsi * ice->ice_num_vsis;
	len = nrxq * sizeof (ice_rx_ring_t);
	ice->ice_rxr = kmem_zalloc(len, KM_SLEEP);

	for (i = 0; i < ice->ice_num_rxq_per_vsi; i++) {
		if (!ice_rx_ring_init(ice, &ice->ice_rxr[i], i))
			goto fail_rx;
	}

	len = ice->ice_num_txq * sizeof (ice_tx_ring_t);
	ice->ice_txr = kmem_zalloc(len, KM_SLEEP);

	for (i = 0; i < ice->ice_num_txq; i++) {
		if (!ice_tx_ring_init(ice, &ice->ice_txr[i], i))
			goto fail_tx;
	}

	/*
	 * Assign the available interrupt vectors to the RX and TX rings.
	 * Since the controlq always gets its own vector, we use > and not
	 * >= when comparing the # of vectors we want for a given 'scheme'
	 * (vector per queue, vector per tx/rx queue pair, etc).
	 */
	if (ice->ice_nintrs > nrxq + ice->ice_num_txq) {
		/* Every ring gets its own vector */
		for (i = 0; i < ice->ice_num_rxq_per_vsi; i++) {
			ASSERT3U(vector, <, ice->ice_nintrs);
			ice->ice_rxr[i].irxr_vec = vector++;
		}

		for (i = 0; i < ice->ice_num_txq; i++) {
			ASSERT3U(vector, <, ice->ice_nintrs);
			ice->ice_txr[i].itxr_vec = vector++;
		}
	} else if (ice->ice_nintrs > MAX(nrxq, ice->ice_num_txq)) {
		/*
		 * Try to pair up (as much as possible) a TX and RX queue
		 * to an interrupt vector.
		 */
		uint_t nvec = MAX(nrxq, ice->ice_num_txq);

		for (i = 0; i < nvec; i++) {
			ASSERT3U(vector, <, ice->ice_nintrs);
			if (i < nrxq)
				ice->ice_rxr[i].irxr_vec = vector;
			if (i < ice->ice_num_txq)
				ice->ice_txr[i].itxr_vec = vector;

			vector++;
		}
	} else {
		/* Just distribute the rings over the interrupts we have */

		for (i = 0; i < nrxq; i++) {
			ice->ice_rxr[i].irxr_vec = vector++;
			vector %= ice->ice_nintrs;

			/* Reserve vector 0 for the controlq if MSI-X */
			if (vector == 0 && ice->ice_nintrs > 1)
				vector++;
		}

		for (i = 0; i < ice->ice_num_txq; i++) {
			ice->ice_txr[i].itxr_vec = vector++;
			vector %= ice->ice_nintrs;

			/* Reserve vector 0 for the controlq */
			if (vector == 0 && ice->ice_nintrs > 1)
				vector++;
		}
	}

	/*
	 * Now that the vectors have been assigned, we can add the handlers
	 * to the appropriate vector.
	 */
	for (i = 0; i < nrxq; i++) {
		ice_rx_ring_t *rxr = &ice->ice_rxr[i];

		rxr->irxr_intr.iih_handler = ice_rx_interrupt;
		ice_intr_add_handler(ice, rxr->irxr_vec, &rxr->irxr_intr);
	}

	for (i = 0; i < ice->ice_num_txq; i++) {
		ice_tx_ring_t *txr = &ice->ice_txr[i];

		txr->itxr_intr.iih_handler = ice_tx_interrupt;
		ice_intr_add_handler(ice, txr->itxr_vec, &txr->itxr_intr);
	}

	mutex_init(&ice->ice_rxbuf_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));
	cv_init(&ice->ice_rxbuf_cv, NULL, CV_DRIVER, NULL);

	mutex_init(&ice->ice_bufs.ibp_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));
	mutex_init(&ice->ice_small_bufs.ibp_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ice->ice_intr_pri));

	return (true);

fail_tx:
	while (i-- > 0)
		ice_tx_ring_fini(&ice->ice_txr[i - 1]);

	i = ice->ice_num_rxq_per_vsi;

fail_rx:
	while (i-- > 0)
		ice_rx_ring_fini(&ice->ice_rxr[i - 1]);

	return (false);
}

/*
 * Quiesce the device in preparation for a PF/CORE/GLOBAL reset. This must be
 * called before triggering (ICE_WORK_NEED_RESET) or waiting out
 * (ICE_WORK_RESET_DETECTED) any of those resets, since the reset otherwise
 * pulls the rug out from under any outstanding I/O as well as all
 * hardware-owned state we depend on (the control queue, VSI and queue
 * contexts, switch rules, scheduler topology, etc). ice_rebuild() undoes
 * this once the reset has completed.
 *
 * It is safe to call this more than once in a row (e.g. if we're notified of
 * the same reset via both ICE_WORK_NEED_RESET and ICE_WORK_RESET_DETECTED);
 * only the first call does anything.
 *
 * This is serialized against mc_start(9E)/mc_stop(9E) (see ice_m_start() and
 * ice_m_stop()) via ice_reset_lock, since both of those also depend on (and
 * modify) the same hardware and software state.
 */
static void
ice_prepare_for_reset(ice_t *ice)
{
	ice_vsi_t *vsi;
	bool started;
	uint_t i;

	mutex_enter(&ice->ice_reset_lock);

	if (ice->ice_reset_prepared) {
		mutex_exit(&ice->ice_reset_lock);
		return;
	}

	vsi = list_head(&ice->ice_vsi);
	ASSERT3P(vsi, !=, NULL);

	started = (ice->ice_state & ICE_STARTED) != 0;

	if (started) {
		if (!ice_remove_rule(ice, 1, &vsi->ivsi_bcast_rule_idx)) {
			ice_error(ice, "failed to remove broadcast address "
			    "while preparing for reset");
		}

		if (!ice_cmd_setup_link(ice, B_FALSE)) {
			ice_error(ice, "failed to stop link while preparing "
			    "for reset");
		}

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state &= ~ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);

		if (!ice_link_status_update(ice)) {
			ice_error(ice, "failed to disable link status event "
			    "updates while preparing for reset");
		}

		ice_intr_hw_fini(ice);
	}

	/*
	 * Tear down any queues that are currently active in hardware. This
	 * would normally happen via mac(9E) calling mri_stop(9E) on each ring
	 * as part of bringing the whole device down, but since (from mac's
	 * point of view) the device stays up across a reset, we have to do
	 * it ourselves here and then undo it in ice_rebuild().
	 */
	for (i = 0; i < ice->ice_num_txq; i++) {
		ice_tx_ring_t *txr = &ice->ice_txr[i];

		if (!txr->itxr_quiesce) {
			ice_ring_tx_stop((mac_ring_driver_t)txr);
		}
	}

	for (i = 0; i < ice->ice_num_rxq_per_vsi; i++) {
		ice_rx_ring_t *rxr = &ice->ice_rxr[i];

		if (!rxr->irxr_shutdown) {
			ice_ring_rx_stop((mac_ring_driver_t)rxr);
		}
	}

	if (started) {
		ice_tx_stop(ice);
		ice_rx_stop(ice);
	}

	ice_controlq_fini(ice);

	ice->ice_reset_prepared = true;
	mutex_exit(&ice->ice_reset_lock);
}

/*
 * Restore driver and hardware state after a PF/CORE/GLOBAL reset has
 * completed, undoing ice_prepare_for_reset() and replaying whatever
 * hardware-owned state the reset discarded: the control queue, switch
 * config, TX scheduler topology, the VSI (including RSS and its TX scheduler
 * node), MAC filters (including promiscuous mode), and any queues and
 * interrupts that were previously active.
 *
 * "global" indicates whether the reset that occurred was a CORE, GLOBAL, or
 * EMP reset (true) as opposed to a PF reset (false). Unlike a PF reset,
 * which is scoped to just this PF, those reset types also clear
 * device-wide state that a PF reset leaves alone: the DDP package
 * configuration and, potentially, the device/function capabilities
 * themselves. So only in that case do we also redo ice_caps_fetch() and
 * reload the DDP package (ice_init_hw_tbls()/ice_load_ddp()), freeing the
 * previous software copies of that state first via ice_fini_hw_tbls() (and,
 * for capabilities, freeing ice_dev_caps/ice_func_caps directly).
 */
static bool
ice_rebuild(ice_t *ice, bool global)
{
	ice_vsi_t *vsi;
	ice_vsi_mac_t *mac;
	bool ok = true;
	bool started;
	uint_t i;

	mutex_enter(&ice->ice_reset_lock);

	if (!ice->ice_reset_prepared) {
		mutex_exit(&ice->ice_reset_lock);
		return (true);
	}

	vsi = list_head(&ice->ice_vsi);
	ASSERT3P(vsi, !=, NULL);
	started = (ice->ice_state & ICE_STARTED) != 0;

	if (!ice_controlq_init(ice)) {
		ice_error(ice, "failed to reinitialize control queue after "
		    "reset");
		mutex_exit(&ice->ice_reset_lock);
		return (false);
	}

	if (!ice_firmware_check(ice, true)) {
		ice_error(ice, "failed to query firmware version after "
		    "reset");
		ok = false;
	}

	if (!ice_cmd_clear_pf_config(ice)) {
		ice_error(ice, "failed to clear PF configuration after "
		    "reset");
		ok = false;
	}

	if (!ice_cmd_clear_pxe(ice)) {
		ice_error(ice, "failed to clear PXE mode after reset");
		ok = false;
	}

	/*
	 * A PF reset wipes all of the RSS flow profile and VSIG associations
	 * as well as any switch rules, so those need to be cleaned up as
	 * well
	 */
	if ((vsi->ivsi_flags & ICE_VSI_F_RSS_SET) != 0) {
		if (!ice_rss_config_fini(ice, vsi)) {
			ice_error(ice, "failed to tear down previous RSS "
			    "flow profile associations before reset rebuild");
			ok = false;
		}
		vsi->ivsi_flags &= ~ICE_VSI_F_RSS_SET;
	}

	if (global) {
		if (!ice_caps_fetch(ice)) {
			ice_error(ice, "failed to refetch device/function "
			    "capabilities after reset");
			ok = false;
		}

		/*
		 * Free the previous software tables and metadata built from
		 * the DDP package before reloading it, mirroring the
		 * ice_rss_config_fini()/ice_fini_hw_tbls() ordering used
		 * during a normal detach.
		 */
		ice_fini_hw_tbls(ice);
		ice_init_hw_tbls(ice);

		if (!ice_load_ddp(ice)) {
			ice_error(ice, "failed to reload DDP package after "
			    "reset");
			ok = false;
		}
	}

	if (!ice_switch_init(ice)) {
		ice_error(ice, "failed to reinitialize switch config after "
		    "reset");
		ok = false;
	}

	if (!ice_tx_scheduler_rebuild(ice)) {
		ice_error(ice, "failed to rebuild TX scheduler topology "
		    "after reset");
		ok = false;
	}

	ice_vsi_context_fill(ice, vsi);
	if (!ice_cmd_add_vsi(ice, vsi)) {
		ice_error(ice, "failed to recreate VSI after reset");
		ok = false;
		goto done;
	}

	if (!ice_vsi_rss_init(ice, vsi)) {
		ice_error(ice, "failed to reinitialize RSS after reset");
		ok = false;
	} else if (!ice_rss_config(ice)) {
		ice_error(ice, "failed to reconfigure RSS flow profiles "
		    "after reset");
		ok = false;
	} else {
		vsi->ivsi_flags |= ICE_VSI_F_RSS_SET;
	}

	if (!ice_tx_sched_add_vsi_node(ice, vsi)) {
		ice_error(ice, "failed to reinitialize TX scheduler VSI "
		    "node after reset");
		ok = false;
	}

	/*
	 * The reset wiped out all of our switch rules, so we need to replay
	 * every MAC filter (unicast and multicast) and, if it was previously
	 * enabled, promiscuous mode.
	 */
	mutex_enter(&vsi->ivsi_lock);
	for (mac = list_head(&vsi->ivsi_macs); mac != NULL;
	    mac = list_next(&vsi->ivsi_macs, mac)) {
		if (!ice_add_mac(ice, vsi->ivsi_id, mac->ivm_mac,
		    &mac->ivm_idx)) {
			ice_error(ice, "failed to replay unicast MAC filter "
			    "after reset");
			ok = false;
		}
	}

	for (mac = list_head(&ice->ice_mc_macs); mac != NULL;
	    mac = list_next(&ice->ice_mc_macs, mac)) {
		if (!ice_add_mac(ice, vsi->ivsi_id, mac->ivm_mac,
		    &mac->ivm_idx)) {
			ice_error(ice, "failed to replay multicast MAC "
			    "filter after reset");
			ok = false;
		}
	}
	mutex_exit(&vsi->ivsi_lock);

	if (ice->ice_promisc_enabled && !ice_promisc_on(ice)) {
		ice_error(ice, "failed to re-enable promiscuous mode after "
		    "reset");
		ok = false;
	}

	if (started) {
		if (!ice_add_mac(ice, vsi->ivsi_id, ice_bcast_mac,
		    &vsi->ivsi_bcast_rule_idx)) {
			ice_error(ice, "failed to re-add broadcast address "
			    "after reset");
			ok = false;
		}

		for (i = 0; i < ice->ice_num_rxq_per_vsi; i++) {
			ice_rx_ring_t *rxr = &ice->ice_rxr[i];

			if (ice_ring_rx_start((mac_ring_driver_t)rxr,
			    rxr->irxr_rxgen) != 0) {
				ice_error(ice, "failed to restart RX ring %u "
				    "after reset", i);
				ok = false;
			}
		}

		for (i = 0; i < ice->ice_num_txq; i++) {
			ice_tx_ring_t *txr = &ice->ice_txr[i];

			if (ice_ring_tx_start((mac_ring_driver_t)txr, 0) !=
			    0) {
				ice_error(ice, "failed to restart TX ring %u "
				    "after reset", i);
				ok = false;
			}
		}

		if (!ice_intr_hw_init(ice)) {
			ice_error(ice, "failed to reinitialize interrupts "
			    "after reset");
			ok = false;
		}

		mutex_enter(&ice->ice_lse_lock);
		ice->ice_lse_state |= ICE_LSE_STATE_ENABLE;
		mutex_exit(&ice->ice_lse_lock);

		if (!ice_link_status_update(ice)) {
			ice_error(ice, "failed to re-enable link status "
			    "event updates after reset");
			ok = false;
		}

		if (!ice_cmd_setup_link(ice, B_TRUE)) {
			ice_error(ice, "failed to restart link after reset");
			ok = false;
		}
	}

done:
	if (ok) {
		ice->ice_reset_prepared = false;
	} else {
		atomic_or_32(&ice->ice_state, ICE_ERROR);
	}

	mutex_exit(&ice->ice_reset_lock);

	return (ok);
}

/*
 * The OROM and Netlist images are conditionally present, so we number
 * images dynamically via ice_ufm_image_kind() rather than with fixed
 * indices.
 */
typedef enum {
	ICE_UFM_KIND_NVM = 0,
	ICE_UFM_KIND_DDP,
	ICE_UFM_KIND_OROM,
	ICE_UFM_KIND_NETLIST
} ice_ufm_kind_t;

static int
ice_ufm_image_kind(ice_t *ice, uint_t imgno, ice_ufm_kind_t *kindp)
{
	uint_t idx = 0;

	if (imgno == idx++) {
		*kindp = ICE_UFM_KIND_NVM;
		return (0);
	}
	if (imgno == idx++) {
		*kindp = ICE_UFM_KIND_DDP;
		return (0);
	}
	if (ice->ice_device->id_orom_valid && imgno == idx++) {
		*kindp = ICE_UFM_KIND_OROM;
		return (0);
	}
	if (ice->ice_device->id_netlist_valid && imgno == idx++) {
		*kindp = ICE_UFM_KIND_NETLIST;
		return (0);
	}

	return (EINVAL);
}

static int
ice_ufm_nimages(ddi_ufm_handle_t *ufmh, void *arg, uint_t *nimgs)
{
	ice_t *ice = arg;
	uint_t n = 2;

	if (ice->ice_device->id_orom_valid) {
		n++;
	}
	if (ice->ice_device->id_netlist_valid) {
		n++;
	}
	*nimgs = n;

	return (0);
}

static int
ice_ufm_fill_image(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    ddi_ufm_image_t *img)
{
	ice_t *ice = arg;
	ice_ufm_kind_t kind;
	uint_t nslots = 1;

	if (ice_ufm_image_kind(ice, imgno, &kind) != 0) {
		return (EINVAL);
	}

	switch (kind) {
	case ICE_UFM_KIND_NVM:
		ddi_ufm_image_set_desc(img, "NVM");
		if (ice->ice_device->id_nvm_pending_valid) {
			nslots = 2;
		}
		break;
	case ICE_UFM_KIND_DDP:
		ddi_ufm_image_set_desc(img, "DDP");
		break;
	case ICE_UFM_KIND_OROM:
		ddi_ufm_image_set_desc(img, "OROM");
		if (ice->ice_device->id_orom_pending_valid) {
			nslots = 2;
		}
		break;
	case ICE_UFM_KIND_NETLIST:
		ddi_ufm_image_set_desc(img, "Netlist");
		if (ice->ice_device->id_netlist_pending_valid) {
			nslots = 2;
		}
		break;
	default:
		return (EINVAL);
	}
	ddi_ufm_image_set_nslots(img, nslots);

	return (0);
}

static int
ice_ufm_fill_slot_nvm(ice_t *ice, uint_t slotno, ddi_ufm_slot_t *slot)
{
	const ice_fw_info_t *ifi = &ice->ice_device->id_fwinfo;
	char nvm_vers[16];
	nvlist_t *misc = NULL;
	int err;
	uint16_t dev_start;
	uint32_t eetrack;

	if (slotno == 0) {
		dev_start = ifi->ifi_nvm_dev_start;
		eetrack = ifi->ifi_nvm_eetrack;
	} else {
		dev_start = ice->ice_device->id_nvm_pending.invi_dev_start;
		eetrack = ice->ice_device->id_nvm_pending.invi_eetrack;
	}

	(void) snprintf(nvm_vers, sizeof (nvm_vers), "%x.%02x",
	    ICE_NVM_VER_HI(dev_start), ICE_NVM_VER_LO(dev_start));

	ddi_ufm_slot_set_attrs(slot, slotno == 0 ?
	    (DDI_UFM_ATTR_ACTIVE | DDI_UFM_ATTR_READABLE) :
	    DDI_UFM_ATTR_READABLE);
	ddi_ufm_slot_set_version(slot, nvm_vers);

	(void) nvlist_alloc(&misc, NV_UNIQUE_NAME, KM_SLEEP);
	if ((err = nvlist_add_uint32(misc, "eetrack", eetrack)) != 0) {
		nvlist_free(misc);
		return (err);
	}

	/*
	 * The running firmware/API version and the original (as-shipped)
	 * EETRACK ID only make sense for the currently active NVM image.
	 */
	if (slotno == 0) {
		char fw_vers[16], api_vers[16];

		(void) snprintf(fw_vers, sizeof (fw_vers), "%u.%u.%u",
		    ifi->ifi_fw_major, ifi->ifi_fw_minor, ifi->ifi_fw_patch);
		(void) snprintf(api_vers, sizeof (api_vers), "%u.%u.%u",
		    ifi->ifi_aq_major, ifi->ifi_aq_minor, ifi->ifi_aq_patch);

		if ((err = nvlist_add_string(misc, "firmware-version",
		    fw_vers)) != 0 ||
		    (err = nvlist_add_string(misc, "api-version",
		    api_vers)) != 0 ||
		    (err = nvlist_add_uint32(misc, "eetrack-orig",
		    ifi->ifi_nvm_eetrack_orig)) != 0) {
			nvlist_free(misc);
			return (err);
		}
	}
	ddi_ufm_slot_set_misc(slot, misc);

	return (0);
}

static int
ice_ufm_fill_slot_ddp(ice_t *ice, ddi_ufm_slot_t *slot)
{
	const ice_pkg_ver_t *pkg;
	const char *name;
	char ddp_vers[16];
	nvlist_t *misc = NULL;
	int err;

	/*
	 * Prefer the DDP package the device actually reports as active --
	 * this can differ from what we attempted to load from ice.pkg
	 * (ice_pkg_version/ice_pkg_name) if that load failed, or a
	 * different package was already active and the load was skipped.
	 * We fall back to what we attempted to load if we were unable to
	 * query the device for its active package.
	 */
	if (ice->ice_device->id_active_pkg_valid) {
		pkg = &ice->ice_device->id_active_pkg_version;
		name = ice->ice_device->id_active_pkg_name;
	} else {
		pkg = &ice->ice_device->id_pkg_version;
		name = ice->ice_device->id_pkg_name;
	}

	(void) snprintf(ddp_vers, sizeof (ddp_vers), "%u.%u.%u.%u",
	    pkg->ipv_major, pkg->ipv_minor, pkg->ipv_update, pkg->ipv_draft);

	ddi_ufm_slot_set_attrs(slot, DDI_UFM_ATTR_ACTIVE |
	    DDI_UFM_ATTR_READABLE);
	ddi_ufm_slot_set_version(slot, ddp_vers);

	if (name[0] != '\0') {
		(void) nvlist_alloc(&misc, NV_UNIQUE_NAME, KM_SLEEP);
		if ((err = nvlist_add_string(misc, "package-name",
		    name)) != 0) {
			nvlist_free(misc);
			return (err);
		}
		ddi_ufm_slot_set_misc(slot, misc);
	}

	return (0);
}

static int
ice_ufm_fill_slot_orom(ice_t *ice, uint_t slotno, ddi_ufm_slot_t *slot)
{
	const ice_orom_info_t *orom = (slotno == 0) ?
	    &ice->ice_device->id_orom : &ice->ice_device->id_orom_pending;
	char orom_vers[16];

	(void) snprintf(orom_vers, sizeof (orom_vers), "%u.%u.%u",
	    orom->ioi_major, orom->ioi_build, orom->ioi_patch);

	ddi_ufm_slot_set_attrs(slot, slotno == 0 ?
	    (DDI_UFM_ATTR_ACTIVE | DDI_UFM_ATTR_READABLE) :
	    DDI_UFM_ATTR_READABLE);
	ddi_ufm_slot_set_version(slot, orom_vers);

	return (0);
}

static int
ice_ufm_fill_slot_netlist(ice_t *ice, uint_t slotno, ddi_ufm_slot_t *slot)
{
	const ice_netlist_info_t *netlist = (slotno == 0) ?
	    &ice->ice_device->id_netlist : &ice->ice_device->id_netlist_pending;
	char netlist_vers[16], type_vers[16], rev_vers[16], hash_vers[16];
	nvlist_t *misc = NULL;
	int err;

	/*
	 * The major/minor/type/revision fields are stored in packed Binary
	 * Coded Decimal, so using '%x' correctly displays them as decimal
	 * numbers.
	 */
	(void) snprintf(netlist_vers, sizeof (netlist_vers), "%x.%x",
	    netlist->ini_major, netlist->ini_minor);
	(void) snprintf(type_vers, sizeof (type_vers), "%x.%x",
	    netlist->ini_type >> 16, netlist->ini_type & 0xffff);
	(void) snprintf(rev_vers, sizeof (rev_vers), "%x.%x",
	    netlist->ini_rev >> 16, netlist->ini_rev & 0xffff);
	(void) snprintf(hash_vers, sizeof (hash_vers), "%08x",
	    netlist->ini_hash);

	ddi_ufm_slot_set_attrs(slot, slotno == 0 ?
	    (DDI_UFM_ATTR_ACTIVE | DDI_UFM_ATTR_READABLE) :
	    DDI_UFM_ATTR_READABLE);
	ddi_ufm_slot_set_version(slot, netlist_vers);

	(void) nvlist_alloc(&misc, NV_UNIQUE_NAME, KM_SLEEP);
	if ((err = nvlist_add_string(misc, "type", type_vers)) != 0 ||
	    (err = nvlist_add_string(misc, "revision", rev_vers)) != 0 ||
	    (err = nvlist_add_string(misc, "hash", hash_vers)) != 0 ||
	    (err = nvlist_add_uint16(misc, "customer-version",
	    netlist->ini_cust_ver)) != 0) {
		nvlist_free(misc);
		return (err);
	}
	ddi_ufm_slot_set_misc(slot, misc);

	return (0);
}

static int
ice_ufm_fill_slot(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    uint_t slotno, ddi_ufm_slot_t *slot)
{
	ice_t *ice = arg;
	ice_ufm_kind_t kind;

	if (slotno > 1) {
		return (EINVAL);
	}

	if (ice_ufm_image_kind(ice, imgno, &kind) != 0) {
		return (EINVAL);
	}

	switch (kind) {
	case ICE_UFM_KIND_NVM:
		if (slotno == 1 && !ice->ice_device->id_nvm_pending_valid) {
			return (EINVAL);
		}
		return (ice_ufm_fill_slot_nvm(ice, slotno, slot));
	case ICE_UFM_KIND_DDP:
		if (slotno != 0) {
			return (EINVAL);
		}
		return (ice_ufm_fill_slot_ddp(ice, slot));
	case ICE_UFM_KIND_OROM:
		if (slotno == 1 && !ice->ice_device->id_orom_pending_valid) {
			return (EINVAL);
		}
		return (ice_ufm_fill_slot_orom(ice, slotno, slot));
	case ICE_UFM_KIND_NETLIST:
		if (slotno == 1 && !ice->ice_device->id_netlist_pending_valid) {
			return (EINVAL);
		}
		return (ice_ufm_fill_slot_netlist(ice, slotno, slot));
	default:
		return (EINVAL);
	}
}

static int
ice_ufm_getcaps(ddi_ufm_handle_t *ufmh, void *arg, ddi_ufm_cap_t *caps)
{
	*caps = DDI_UFM_CAP_REPORT;

	return (0);
}

static ddi_ufm_ops_t ice_ufm_ops = {
	ice_ufm_nimages,
	ice_ufm_fill_image,
	ice_ufm_fill_slot,
	ice_ufm_getcaps
};

/*
 * Release our reference to ice's ice_device_t, if any. Free the ice_device_t
 * if we are the last PF referencing it.
 */
static void
ice_device_rele(ice_t *ice)
{
	ice_device_t *idp = ice->ice_device;

	if (idp == NULL) {
		return;
	}

	/*
	 * If we were the ones fetching the various firmware versions
	 * but never finished (e.g. some later attach step failed),
	 * note it failed so other PFs don't attempt to fetch the
	 * firmware (thinking they're first).
	 */
	if (ice->ice_fw_owner) {
		mutex_enter(&idp->id_lock);
		if (idp->id_fw_state == ICE_DEVICE_FW_BUSY) {
			idp->id_fw_state = ICE_DEVICE_FW_FAILED;
			cv_broadcast(&idp->id_cv);
		}
		mutex_exit(&idp->id_lock);
	}

	mutex_enter(&ice_glock);
	list_remove(&idp->id_ice_list, ice);
	VERIFY3U(idp->id_nreg, >, 0);
	idp->id_nreg--;
	if (idp->id_nreg == 0) {
		list_remove(&ice_dlist, idp);
	} else {
		idp = NULL;
	}
	mutex_exit(&ice_glock);

	ice->ice_device = NULL;

	if (idp != NULL) {
		list_destroy(&idp->id_ice_list);
		cv_destroy(&idp->id_cv);
		mutex_destroy(&idp->id_lock);
		if (idp->id_pba != NULL) {
			kmem_free(idp->id_pba, idp->id_pba_len);
		}
		kmem_free(idp, sizeof (ice_device_t));
	}
}

/*
 * Fine the ice_device_t for our instance, or create a new one if it
 * doesn't exist. There is one ice_device_t for each PCI device that is
 * shared by all functions (e.g. a two port NIC will have an ice_device_t
 * that is shared by the ice_t instances corresponding to the ports on
 * that NIC).
 */
static ice_device_t *
ice_device_find(ice_t *ice)
{
	dev_info_t *parent = ddi_get_parent(ice->ice_dip);
	ice_device_t *idp;

	mutex_enter(&ice_glock);
	for (idp = list_head(&ice_dlist); idp != NULL;
	    idp = list_next(&ice_dlist, idp)) {
		if (idp->id_parent == parent &&
		    idp->id_pci_bus == ice->ice_pci_bus &&
		    idp->id_pci_dev == ice->ice_pci_dev) {
			break;
		}
	}

	if (idp == NULL) {
		idp = kmem_zalloc(sizeof (ice_device_t), KM_SLEEP);

		idp->id_parent = parent;
		idp->id_pci_bus = ice->ice_pci_bus;
		idp->id_pci_dev = ice->ice_pci_dev;

		mutex_init(&idp->id_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&idp->id_cv, NULL, CV_DRIVER, NULL);
		list_create(&idp->id_ice_list, sizeof (ice_t),
		    offsetof(ice_t, ice_dlink));

		list_insert_tail(&ice_dlist, idp);
	}

	idp->id_nreg++;
	list_insert_tail(&idp->id_ice_list, ice);
	mutex_exit(&ice_glock);

	return (idp);
}

/*
 * Reading the various firmware versions from the hardware can be
 * slow for certina things (e.g. the Option ROM). Instead of having the
 * instances step on top of each other (to ultimately get the same
 * information), the first instance through the gate 'owns' reading
 * the version information. While the read in process, other instances
 * on the same card will block here until reading is complete.
 *
 * Since we don't support updating any of the firmware from the
 * running OS (sadly, this still seems to be a very propritary and
 * undocumented process), once complete, these don't change and any
 * subsequent access can proceed without blocking.
 *
 * Returns true if caller is the first through the gate and should own
 * the task of updating the firmware versions. It should call
 * ice_device_fw_exit() when done. Other callers do not.
 */
static bool
ice_device_fw_enter(ice_device_t *idp)
{
	mutex_enter(&idp->id_lock);

	while (idp->id_fw_state == ICE_DEVICE_FW_BUSY) {
		cv_wait(&idp->id_cv, &idp->id_lock);
	}

	if (idp->id_fw_state == ICE_DEVICE_FW_DONE ||
	    idp->id_fw_state == ICE_DEVICE_FW_FAILED) {
		mutex_exit(&idp->id_lock);
		return (false);
	}

	ASSERT3S(idp->id_fw_state, ==, ICE_DEVICE_FW_NONE);
	idp->id_fw_state = ICE_DEVICE_FW_BUSY;

	mutex_exit(&idp->id_lock);
	return (true);
}

static void
ice_device_fw_exit(ice_device_t *idp, bool success)
{
	mutex_enter(&idp->id_lock);

	ASSERT3S(idp->id_fw_state, ==, ICE_DEVICE_FW_BUSY);

	idp->id_fw_state = success ? ICE_DEVICE_FW_DONE : ICE_DEVICE_FW_FAILED;
	cv_broadcast(&idp->id_cv);

	mutex_exit(&idp->id_lock);
}

static void
ice_cleanup(ice_t *ice)
{
	if (ice == NULL) {
		return;
	}

	if (ice->ice_seq & ICE_ATTACH_UFM) {
		ddi_ufm_fini(ice->ice_ufmh);
		ice->ice_seq &= ~ICE_ATTACH_UFM;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_ENABLE) {
		(void) ice_intr_ddi_disable(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_ENABLE;
	}

	if (ice->ice_seq & ICE_ATTACH_MAC) {
		ice_mac_unregister(ice);
		ice->ice_seq &= ~ICE_ATTACH_MAC;
	}

	if (ice->ice_seq & ICE_ATTACH_STATS) {
		ice_stats_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_STATS;
	}

	if (ice->ice_seq & ICE_ATTACH_RING) {
		ice_ring_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_RING;
	}

	if (ice->ice_seq & ICE_ATTACH_VSI) {
		ice_vsi_t *vsi;

		while ((vsi = list_remove_tail(&ice->ice_vsi)) != NULL) {
			ice_vsi_free(ice, vsi);
		}
		list_destroy(&ice->ice_vsi);

		ice_tx_sched_free_nodes(ice, ice->ice_tx_sched_root);
		mutex_destroy(&ice->ice_tx_sched_lock);

		ice->ice_seq &= ~ICE_ATTACH_VSI;
	}

	if (ice->ice_seq & ICE_ATTACH_TASK) {
		ice_task_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_TASK;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_HANDLER) {
		ice_intr_rem_ddi_handles(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_HANDLER;
	}

	if (ice->ice_seq & ICE_ATTACH_INTR_ALLOC) {
		ice_intr_ddi_free(ice);
		ice->ice_seq &= ~ICE_ATTACH_INTR_ALLOC;
	}

	if (ice->ice_seq & ICE_ATTACH_PBA) {
		ice->ice_seq &= ~ICE_ATTACH_PBA;
	}

	if (ice->ice_seq & ICE_ATTACH_LSE) {
		mutex_destroy(&ice->ice_lse_lock);
		cv_destroy(&ice->ice_lse_cv);
		ice->ice_seq &= ~ICE_ATTACH_LSE;
	}

	if (ice->ice_seq & ICE_ATTACH_CAPS) {
		if (ice->ice_dev_caps != NULL) {
			kmem_free(ice->ice_dev_caps, ice->ice_ndev_caps *
			    sizeof (ice_capability_t));
		}
		if (ice->ice_func_caps != NULL) {
			kmem_free(ice->ice_func_caps, ice->ice_nfunc_caps *
			    sizeof (ice_capability_t));
		}
		ice->ice_seq &= ~ICE_ATTACH_CAPS;
	}

	if (ice->ice_seq & ICE_ATTACH_NVM) {
		ice_nvm_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_NVM;
	}

	if (ice->ice_seq & ICE_ATTACH_CONTROLQ) {
		ice_controlq_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_CONTROLQ;
	}

	if (ice->ice_seq & ICE_ATTACH_REGS) {
		ddi_regs_map_free(&ice->ice_reg_hdl);
		ice->ice_seq &= ~ICE_ATTACH_REGS;
	}

	if (ice->ice_seq & ICE_ATTACH_PCI) {
		pci_config_teardown(&ice->ice_pci_hdl);
		ice->ice_seq &= ~ICE_ATTACH_PCI;
	}

	if (ice->ice_seq & ICE_ATTACH_FM) {
		ice_fm_fini(ice);
		ice->ice_seq &= ~ICE_ATTACH_FM;
	}

	ice_device_rele(ice);

	ASSERT0(ice->ice_seq);

	list_destroy(&ice->ice_mc_macs);
	ice_fini_hw_tbls(ice);

	kmem_free(ice, sizeof (ice_t));
}

static int
ice_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ice_t *ice;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	ice = kmem_zalloc(sizeof (ice_t), KM_SLEEP);
	ice->ice_dip = dip;
	ice->ice_inst = ddi_get_instance(dip);

	ice->ice_rx_rsize = ICE_TX_RING_DEFAULT_SIZE;

	list_create(&ice->ice_mc_macs, sizeof (ice_vsi_mac_t),
	    offsetof(ice_vsi_mac_t, ivm_node));

	ice_init_hw_tbls(ice);

	ice_fm_init(ice);
	ice->ice_seq |= ICE_ATTACH_FM;

	if (pci_config_setup(dip, &ice->ice_pci_hdl) != 0) {
		ice_error(ice, "failed to initialize PCI config space");
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_PCI;

	if (!ice_regs_map(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_REGS;

	ice_identify(ice);

	/*
	 * Now that we know our PCI bus/device/function, find (or create)
	 * the ice_device_t shared by every PF on this physical device.
	 */
	ice->ice_device = ice_device_find(ice);

	/* For now at least we can't handle recovery mode */
	if (!ice_check_mode(ice)) {
		goto err;
	}

	ice_properties_init(ice);

	if (!ice_pf_reset(ice)) {
		goto err;
	}

	if (!ice_controlq_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_CONTROLQ;

	/*
	 * Either start grabbing the firmware versions, or block
	 * until another PF finishes.
	 */
	ice->ice_fw_owner = ice_device_fw_enter(ice->ice_device);

	if (!ice_firmware_check(ice, ice->ice_fw_owner)) {
		goto err;
	}

	if (!ice_driver_version(ice)) {
		goto err;
	}

	if (!ice_cmd_clear_pf_config(ice)) {
		goto err;
	}

	if (!ice_cmd_clear_pxe(ice)) {
		goto err;
	}

	if (!ice_nvm_init(ice, ice->ice_fw_owner)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_NVM;

	/*
	 * If we were responsible for obtaining the versions,
	 * signal our completion
	 */
	if (ice->ice_fw_owner) {
		ice_device_fw_exit(ice->ice_device, true);
	}

	if (!ice_caps_fetch(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_CAPS;

	/*
	 * Ask firmware to report health status events over the ARQ. This is
	 * purely diagnostic, so failure here shouldn't cause attach to fail.
	 */
	if (!ice_cmd_set_health_status_config(ice,
	    ICE_CQ_HEALTH_STATUS_SET_PF_SPECIFIC |
	    ICE_CQ_HEALTH_STATUS_SET_GLOBAL)) {
		ice_error(ice, "!failed to enable firmware health status "
		    "events");
	}

	if (!ice_cmd_mac_read(ice, ice->ice_mac)) {
		goto err;
	}

	if (!ice_cmd_set_max_mtu(ice, ice->ice_max_mtu)) {
		goto err;
	}

	/*
	 * Note that this has to happen before we create any VSIs so that
	 * we have everything loaded so we can update the bits for RSS.
	 */
	if (!ice_load_ddp(ice)) {
		goto err;
	}

	mutex_init(&ice->ice_lse_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ice->ice_lse_cv, NULL, CV_DRIVER, NULL);
	ice->ice_seq |= ICE_ATTACH_LSE;

	if (!ice_link_status_update(ice)) {
		goto err;
	}

	/*
	 * XXX Firmware always returns EPERM if we try to read this, though the
	 * datasheet suggests that we should be able to do otherwise.
	 */
#if 0
	if (!ice_nvm_read_pba(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_PBA;
#endif

	if (!ice_intr_ddi_alloc(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_ALLOC;

	if (!ice_calculate_groups(ice)) {
		goto err;
	}

	if (!ice_intr_add_ddi_handles(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_HANDLER;


	if (!ice_task_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_TASK;

	if (!ice_switch_init(ice)) {
		goto err;
	}

	if (!ice_tx_scheduler_init(ice)) {
		goto err;
	}

	if (!ice_pf_vsi_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_VSI;
	if (!ice_rss_config(ice)) {
		goto err;
	}

	/*
	 * XXX We're punting on getting the switch and port configuration so we
	 * can deal with the tx scheduler. Wait to deal with the phy and link
	 * capabilities until we've done other stuff.
	 */

	if (!ice_ring_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_RING;

	if (ice_regs_check(ice) != DDI_FM_OK) {
		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_LOST);
		goto err;
	}

	if (!ice_stats_init(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_STATS;

	if (!ice_mac_register(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_MAC;

	if (!ice_intr_ddi_enable(ice)) {
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_INTR_ENABLE;

	if (ddi_ufm_init(ice->ice_dip, DDI_UFM_CURRENT_VERSION,
	    &ice_ufm_ops, &ice->ice_ufmh, ice) != 0) {
		ice_error(ice, "failed to initialize UFM subsystem");
		goto err;
	}
	ice->ice_seq |= ICE_ATTACH_UFM;

	ddi_ufm_update(ice->ice_ufmh);

	ddi_set_driver_private(dip, ice);

	return (DDI_SUCCESS);

err:
	ice_cleanup(ice);
	return (DDI_FAILURE);
}

static int
ice_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ice_t *ice;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if ((ice = ddi_get_driver_private(dip)) == NULL) {
		dev_err(dip, CE_WARN, "asked to detach instance %d, but "
		    "no ice_t state", ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(dip, NULL);
	ice_cleanup(ice);

	return (DDI_SUCCESS);
}

static struct cb_ops ice_cb_ops = {
	.cb_open = nodev,
	.cb_close = nodev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops ice_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ice_attach,
	.devo_detach = ice_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ice_cb_ops
};

static struct modldrv ice_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel 100 Gb Ethernet",
	.drv_dev_ops = &ice_dev_ops
};

static struct modlinkage ice_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ice_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	ice_tx_init();

	list_create(&ice_dlist, sizeof (ice_device_t), offsetof(ice_device_t,
	    id_link));
	mutex_init(&ice_glock, NULL, MUTEX_DRIVER, NULL);

	mac_init_ops(&ice_dev_ops, ICE_MODULE_NAME);

	if ((ret = mod_install(&ice_modlinkage)) != 0) {
		mac_fini_ops(&ice_dev_ops);
		mutex_destroy(&ice_glock);
		list_destroy(&ice_dlist);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ice_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ice_modlinkage)) != 0) {
		return (ret);
	}

	mac_fini_ops(&ice_dev_ops);

	mutex_destroy(&ice_glock);
	list_destroy(&ice_dlist);

	ice_tx_fini();

	return (ret);
}
