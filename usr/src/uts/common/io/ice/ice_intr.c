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
 * ice(7D) interrupt management
 */

#include "ice.h"

static uintptr_t
ice_intr_itr_reg(ice_t *ice, ice_itr_index_t type, uint_t intr)
{
	uintptr_t out = ICE_REG_GLINT_ITR_BASE;

	ASSERT3S(type, <, ICE_ITR_INDEX_NONE);
	ASSERT3U(intr, <, ice->ice_nintrs);

	return (out + 0x2000 * type + 4 * intr);
}

static uintptr_t
ice_glint_vect2func(ice_t *ice, uint_t n)
{
	uintptr_t reg = ICE_REG_GLINT_VECT2FUNC_BASE;

	ASSERT3U(n, <, ice->ice_max_msix);
	ASSERT3U(ice->ice_first_msix + n, <=, 2047);

	return (reg + (ice->ice_first_msix + n) * 4);
}

static uintptr_t
ice_glint_dyn_ctl(ice_t *ice, int vector)
{
	uintptr_t reg = ICE_REG_GLINT_DYN_CTL_BASE;

	ASSERT3S(vector, >=, 0);
	ASSERT3S(vector, <, ice->ice_nintrs);

	return (reg + vector * 4);
}

static void
ice_intr_itr_set(ice_t *ice, ice_itr_index_t type, uint_t val)
{
	uint_t i;

	for (i = 0; i < ice->ice_nintrs; i++) {
		ice_reg_write(ice, ice_intr_itr_reg(ice, type, i), val);
	}
}

static void
ice_intr_program(ice_t *ice, uintptr_t reg, uint_t msix, ice_itr_index_t itr)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_MSIX_INDX_SET(val, msix);
	val = ICE_REG_PFINT_ITR_INDX_SET(val, itr);

	ice_reg_write(ice, reg, val);
}

static void
ice_intr_cause_disable(ice_t *ice, uintptr_t reg)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 0);
	ice_reg_write(ice, reg, val);
}

static void
ice_intr_cause_enable(ice_t *ice, uintptr_t reg)
{
	uint32_t val = ice_reg_read(ice, reg);

	val = ICE_REG_PFINT_CAUSE_ENA_SET(val, 1);
	ice_reg_write(ice, reg, val);
}

static void
ice_intr_msix_enable(ice_t *ice, int vector)
{
	uintptr_t reg = ice_glint_dyn_ctl(ice, vector);
	uint32_t val = 0;

	val = ICE_REG_GLINT_DYN_CTL_INTENA_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_CLEARPBA_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);

	ice_reg_write(ice, reg, val);
}

static void
ice_intr_msix_disable(ice_t *ice, int vector)
{
	uintptr_t reg = ice_glint_dyn_ctl(ice, vector);
	uint32_t val = 0;

	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);
	ice_reg_write(ice, reg, val);
}

void
ice_intr_hw_fini(ice_t *ice)
{
	for (uint_t i = 1; i < ice->ice_nintrs; i++)
		ice_intr_msix_disable(ice, i);

	ice_intr_msix_disable(ice, 0);

	/*
	 * Clear all other cause values. Note, there is no explicit
	 * ice_intr_cause_disable required for this because the control for
	 * this is all based in the OICR enable.
	 */
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, 0);
	ice_intr_cause_disable(ice, ICE_REG_PFINT_FW_CTL);
}

/*
 * Program hardware to enable interrupts for the things that we care about.
 */
boolean_t
ice_intr_hw_init(ice_t *ice)
{
	uint_t i;
	uint32_t oicr = 0;

	/*
	 * In theory firmware should program this correctly. However, let's just
	 * make sure it's in a reasonable state.
	 */
	for (i = 0; i < ice->ice_nintrs; i++) {
		uintptr_t reg = ice_glint_vect2func(ice, i);
		uint32_t val = 0;

		val = ICE_REG_GLINT_VECT2FUNC_PF_NUM_SET(val, ice->ice_pf_id);
		val = ICE_REG_GLINT_VECT2FUNC_IS_PF_SET(val, 1);
		ice_reg_write(ice, reg, val);
	}

	ice_intr_itr_set(ice, ICE_ITR_INDEX_RX, ice->ice_itr_rx);
	ice_intr_itr_set(ice, ICE_ITR_INDEX_TX, ice->ice_itr_tx);
	ice_intr_itr_set(ice, ICE_ITR_INDEX_OTHER, ice->ice_itr_other);

	ice_intr_program(ice, ICE_REG_PFINT_FW_CTL, 0, ICE_ITR_INDEX_OTHER);
	ice_intr_cause_enable(ice, ICE_REG_PFINT_FW_CTL);

	for (i = 0; i < ice->ice_num_txq; i++) {
		const ice_tx_ring_t *txr = &ice->ice_txr[i];
		const uint32_t index = ice->ice_first_txq + txr->itxr_index;

		ice_intr_program(ice, ICE_REG_QINT_TQCTL(index),
		    txr->itxr_vec, ICE_ITR_INDEX_TX);
		ice_intr_cause_enable(ice, ICE_REG_QINT_TQCTL(index));
	}

	for (i = 0; i < ice->ice_num_vsis * ice->ice_num_rxq_per_vsi; i++) {
		const ice_rx_ring_t *rxr = &ice->ice_rxr[i];
		const uint32_t index = ice->ice_first_rxq + rxr->irxr_index;

		ice_intr_program(ice, ICE_REG_QINT_RQCTL(index),
		    rxr->irxr_vec, ICE_ITR_INDEX_RX);
		ice_intr_cause_enable(ice, ICE_REG_QINT_RQCTL(index));
	}

	/*
	 * Set up the OICR register. First we want to make sure nothing that was
	 * previously there is present. To do that we have to make sure that we
	 * set the current register to zero and then do a read of the OICR. As
	 * it's an auto-clearing register, that should work fine.
	 */
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, 0);
	(void) ice_reg_read(ice, ICE_REG_PFINT_OICR);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_ECC_ERR, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_MAL_DETECT, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_GRST, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_PCI_EXCEPTION, 1);
	oicr = ICE_REG_PFINT_OICR_SET(oicr, ICE_REG_OICR_HMC_ERR, 1);
	ice_reg_write(ice, ICE_REG_PFINT_OICR_ENA, oicr);
	ice_intr_program(ice, ICE_REG_PFINT_OICR_CTL, 0, ICE_ITR_INDEX_OTHER);
	ice_intr_cause_enable(ice, ICE_REG_PFINT_OICR_CTL);

	ice_intr_msix_enable(ice, 0);

	for (i = 1; i < ice->ice_nintrs; i++)
		ice_intr_msix_enable(ice, i);

	return (B_TRUE);
}

void
ice_intr_trigger_softint(ice_t *ice)
{
	uintptr_t reg = ICE_REG_GLINT_DYN_CTL_BASE;
	uint32_t val = 0;

	val = ICE_REG_GLINT_DYN_CTL_SWINT_TRIG_SET(val);
	val = ICE_REG_GLINT_DYN_CTL_ITR_INDX_SET(val, ICE_ITR_INDEX_NONE);
	val = ICE_REG_GLINT_DYN_CTL_INTENA_MSK_SET(val);
	ice_reg_write(ice, reg, val);
}

/*
 * Decode and log an HMC (Host Memory Cache) error indicated by
 * ICE_REG_OICR_HMC_ERR in the OICR. Unlike other OICR conditions, an HMC
 * error is purely informational/diagnostic; the hardware does not require a
 * reset to recover from it. We log the specifics and clear the error
 * indication in PFHMC_ERRORINFO as required by the hardware.
 */
static void
ice_log_hmc_error(ice_t *ice)
{
	uint32_t info, data;
	uint32_t index, errtype, objtype;
	boolean_t isvf;
	const char *errstr;

	info = ice_reg_read(ice, ICE_REG_PFHMC_ERRORINFO);
	data = ice_reg_read(ice, ICE_REG_PFHMC_ERRORDATA);

	index = ICE_REG_PFHMC_ERRORINFO_PMF_INDEX_GET(info);
	isvf = ICE_REG_PFHMC_ERRORINFO_PMF_ISVF_GET(info) != 0;
	errtype = ICE_REG_PFHMC_ERRORINFO_HMC_ERROR_TYPE_GET(info);
	objtype = ICE_REG_PFHMC_ERRORINFO_HMC_OBJECT_TYPE_GET(info);

	switch (errtype) {
	case ICE_HMC_ERR_PMF_INVALID:
		errstr = "Private Memory Function is not valid";
		break;
	case ICE_HMC_ERR_VF_IDX_INVALID:
		errstr = "invalid Private Memory Function index for PE "
		    "enabled VF";
		break;
	case ICE_HMC_ERR_VF_PARENT_PF_INVALID:
		errstr = "invalid parent PF for PE enabled VF";
		break;
	case ICE_HMC_ERR_INDEX_TOO_BIG:
		errstr = "object index too big";
		break;
	case ICE_HMC_ERR_ADDRESS_TOO_LARGE:
		errstr = "address extends beyond segment descriptor limit";
		break;
	case ICE_HMC_ERR_SEGMENT_DESC_INVALID:
		errstr = "segment descriptor is invalid";
		break;
	case ICE_HMC_ERR_SEGMENT_DESC_TOO_SMALL:
		errstr = "segment descriptor is too small";
		break;
	case ICE_HMC_ERR_PAGE_DESC_INVALID:
		errstr = "page descriptor is invalid";
		break;
	case ICE_HMC_ERR_UNSUPPORTED_REQUEST_COMPLETION:
		errstr = "unsupported request completion received from PCIe";
		break;
	case ICE_HMC_ERR_INVALID_OBJECT_TYPE:
		errstr = "invalid object type";
		break;
	default:
		errstr = "unknown HMC error";
		break;
	}

	ice_error(ice, "!%s HMC error detected on PMF index %u: %s "
	    "(errtype 0x%x, objtype 0x%x, data 0x%x)",
	    isvf ? "VF" : "PF", index, errstr, errtype, objtype, data);

	if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
		char buf[FM_MAX_CLASS];
		uint64_t ena;

		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", ICE_FM_SERVICE_ICE,
		    "hmc_err");
		ena = fm_ena_generate(0, FM_ENA_FMT1);

		ddi_fm_ereport_post(ice->ice_dip, buf, ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
		    FM_EREPORT_VERS0,
		    "pmf_index", DATA_TYPE_UINT32, index,
		    "pmf_is_vf", DATA_TYPE_BOOLEAN_VALUE, isvf,
		    "error_type", DATA_TYPE_UINT32, errtype,
		    "error", DATA_TYPE_STRING, errstr,
		    "object_type", DATA_TYPE_UINT32, objtype,
		    "error_data", DATA_TYPE_UINT32, data,
		    NULL);

		ddi_fm_service_impact(ice->ice_dip, DDI_SERVICE_UNAFFECTED);
	}

	/*
	 * Clear the error indication.
	 */
	ice_reg_write(ice, ICE_REG_PFHMC_ERRORINFO, 0);
}

/*
 * We've had our miscellaneous interrupt fire. This means that we need to go
 * through and see what actions we need to take. Almost all of the actions that
 * this indicates are handled asynchronously. This includes processing the
 * following data sources:
 *
 *  o OICR
 *  o Admin queue
 *
 * As a side effect of this, the interrupt will be enabled again and by reading
 * the OICR, it will be cleared.
 */
static void
ice_intr_misc_work(ice_t *ice)
{
	ice_work_task_t work = ICE_WORK_NONE;
	uint32_t oicr;

	/*
	 * Hardware doesn't provide a way of knowing whether or not the receive
	 * side of the admin queue has fired or not. We must always assume it
	 * has and ask it to be read by users.
	 */
	work |= ICE_WORK_CONTROLQ;

	/*
	 * Read the OICR and see if it indicates we need to do anything. Note
	 * this has a side effect of clearing the OICR.
	 */
	oicr = ice_reg_read(ice, ICE_REG_PFINT_OICR);

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_ECC_ERR) != 0) {
		ice_error(ice, "!observed an ECC error via OICR: "
		    "oicr 0x%x", oicr);

		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
			char buf[FM_MAX_CLASS];
			uint64_t ena;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_DEVICE, DDI_FM_DEVICE_INTERN_UNCORR);
			ena = fm_ena_generate(0, FM_ENA_FMT1);

			ddi_fm_ereport_post(ice->ice_dip, buf, ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
			    FM_EREPORT_VERS0,
			    "oicr", DATA_TYPE_UINT32, oicr,
			    "oicr_type", DATA_TYPE_STRING, "ECC error",
			    NULL);

			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_DEGRADED);
		}
		work |= ICE_WORK_NEED_RESET;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_PCI_EXCEPTION) != 0) {
		ice_error(ice, "!observed a PCI exception via OICR: "
		    "oicr 0x%x", oicr);

		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
			char buf[FM_MAX_CLASS];
			uint64_t ena;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_DEVICE, DDI_FM_DEVICE_INTERN_UNCORR);
			ena = fm_ena_generate(0, FM_ENA_FMT1);

			ddi_fm_ereport_post(ice->ice_dip, buf, ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
			    FM_EREPORT_VERS0,
			    "oicr", DATA_TYPE_UINT32, oicr,
			    "oicr_type", DATA_TYPE_STRING, "PCI exception",
			    NULL);

			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_DEGRADED);
		}
		work |= ICE_WORK_NEED_RESET;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_MAL_DETECT) != 0) {
		/*
		 * We are not currently enabling any VFs, so if this fires,
		 * that's a very suspicious thing and indicates that we need to
		 * question what's going on with hardware and probably deserves
		 * a reset (or we've programmed the NIC wrong).
		 */
		work |= ICE_WORK_MAL_DETECTED;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_GRST) != 0) {
		static const char *type_str[] = {
			"POR", "CORER", "GLOBR", "EMPR"
		};
		ice_reset_req_t type = ice_reset_type(ice);

		ice_error(ice, "!observed a %s reset via OICR",
		    type < ARRAY_SIZE(type_str) ? type_str[type] : "unknown");

		work |= ICE_WORK_RESET_DETECTED;
	}

	if (ICE_REG_PFINT_OICR_GET(oicr, ICE_REG_OICR_HMC_ERR) != 0) {
		ice_log_hmc_error(ice);
	}

	ice_schedule(ice, work);

	/*
	 * Come back and re-enable this interrupt.
	 */
	ice_intr_msix_enable(ice, 0);
}

uint_t
ice_intr_msix(caddr_t arg, caddr_t arg2)
{
	ice_t			*ice = (ice_t *)arg;
	list_t			*handlers;
	ice_intr_handler_t	*h;
	uint_t			vector = (uintptr_t)(void *)arg2;

	if (vector == 0) {
		ice_intr_misc_work(ice);
		return (DDI_INTR_CLAIMED);
	}

	handlers = &ice->ice_intr_handlers[vector];
	for (h = list_head(handlers); h != NULL; h = list_next(handlers, h)) {
		h->iih_handler(ice, h);
	}

	ice_intr_msix_enable(ice, vector);

	return (DDI_INTR_CLAIMED);
}

uint_t
ice_intr_msi(caddr_t arg, caddr_t arg2)
{
	ice_t			*ice = (ice_t *)arg;
	list_t			*handlers;
	ice_intr_handler_t	*h;

	handlers = &ice->ice_intr_handlers[0];
	for (h = list_head(handlers); h != NULL; h = list_next(handlers, h)) {
		h->iih_handler(ice, h);
	}

	return (DDI_INTR_CLAIMED);
}

uint_t
ice_intr_intx(caddr_t arg, caddr_t arg2)
{
	ice_t			*ice = (ice_t *)arg;
	list_t			*handlers;
	ice_intr_handler_t	*h;

	handlers = &ice->ice_intr_handlers[0];
	for (h = list_head(handlers); h != NULL; h = list_next(handlers, h)) {
		ASSERT3P(h->iih_handler, !=,  NULL);
		h->iih_handler(ice, h);
	}
	return (DDI_INTR_CLAIMED);
}

void
ice_intr_add_handler(ice_t *ice, uint_t vector, ice_intr_handler_t *h)
{
	list_t *handlers;

	ASSERT3U(vector, <, ice->ice_nintrs);
	ASSERT(!list_link_active(&h->iih_node));
	ASSERT3P(h->iih_handler, !=,  NULL);

	handlers = &ice->ice_intr_handlers[vector];
	list_insert_tail(handlers, h);
}

void
ice_intr_remove_handler(ice_t *ice, uint_t vector, ice_intr_handler_t *h)
{
	list_t *handlers;

	ASSERT3U(vector, <, ice->ice_nintrs);
	ASSERT(list_link_active(&h->iih_node));

	handlers = &ice->ice_intr_handlers[vector];
	list_remove(handlers, h);
}
