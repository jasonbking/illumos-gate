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
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <mdb/mdb_ctf.h>
#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include "ice.h"

/*
 * Ideally, we could replace this with something that could invoke
 * the equivalent of `::prtconf -d ice | ::devinfo -d` but as a walker.
 * There's probably a way, but not sure right now how...
 */
static int
ice_ice_walk_init(mdb_walk_state_t *wsp)
{
	return (mdb_layered_walk("devinfo", wsp));
}

typedef struct mdb_dev_info {
	ddi_node_state_t	devi_node_state;
	uintptr_t		devi_driver_data;
} mdb_dev_info_t;

static int
ice_ice_walk_step(mdb_walk_state_t *wsp)
{
	char		dname[MODMAXNAMELEN] = { 0 };
	mdb_dev_info_t	di = { 0 };

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_ctf_vread(&di, "struct dev_info", "mdb_dev_info_t",
	    wsp->walk_addr, 0) != 0) {
		return (WALK_ERR);
	}

	if (di.devi_node_state < DS_ATTACHED)
		return (WALK_NEXT);

	if (mdb_devinfo2driver(wsp->walk_addr, dname, sizeof (dname)) != 0)
		return (WALK_NEXT);

	if (strcmp(ICE_MODULE_NAME, dname) != 0)
		return (WALK_NEXT);

	wsp->walk_addr = di.devi_driver_data;

	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

typedef struct mdb_ice {
	int			ice_inst;
	ice_state_t		ice_state;
	uint_t			ice_num_vsis;
	uint_t			ice_num_txq;
	uint_t			ice_num_rxq_per_vsi;
	uintptr_t		ice_txr;
	uintptr_t		ice_rxr;
} mdb_ice_t;

static mdb_bitmask_t ice_state_bits[] = {
	{ "ICE_UNKNOWN", UINT32_MAX, 0 },
	{ "ICE_INITIALIZED", ICE_INITIALIZED, ICE_INITIALIZED },
	{ "ICE_STARTED", ICE_STARTED, ICE_STARTED },
	{ "ICE_ERROR", ICE_ERROR, ICE_ERROR },
	{ NULL, 0, 0 }
};

static int
ice_ice(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_ice_t	ice;

	if (addr == 0) {
		return (mdb_walk_dcmd("ice", "ice", 0, NULL));
	}

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %4s %-58s%</u>\n",
		    "ADDR", "INST", "STATE");
	}

	if (mdb_ctf_vread(&ice, "ice_t", "mdb_ice_t", addr, 0) != 0) {
		return (-1);
	}

	mdb_printf("%?p %4u 0x%x<%b>\n", addr, ice.ice_inst,
	    ice.ice_state, ice.ice_state, ice_state_bits);

	return (DCMD_OK);
}

typedef struct ice_walk_q_data {
	uintptr_t	iwqd_end;
	size_t		iwqd_len;
} ice_walk_q_data_t;

static int
ice_walk_txrxq_init(mdb_walk_state_t *wsp, bool tx)
{
	const char		*type = tx ? "ice_tx_ring_t" : "ice_rx_ring_t";
	mdb_ice_t		ice;
	ice_walk_q_data_t	*data;
	uintptr_t		start;
	uint_t			n;
	ssize_t			len;

	/* XXX: should we instead just walk all ice instances? */
	if (wsp->walk_addr == 0) {
		mdb_warn("ice_txq walker requires address of ice_t to walk");
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&ice, "ice_t", "mdb_ice_t", wsp->walk_addr, 0)) {
		return (WALK_ERR);
	}

	len = mdb_ctf_sizeof_by_name(type);
	if (len == -1) {
		mdb_warn("failed to get size of %s", type);
		return (WALK_ERR);
	}

	if (tx) {
		start = ice.ice_txr;
		n = ice.ice_num_txq;
	} else {
		start = ice.ice_rxr;
		n = ice.ice_num_rxq_per_vsi;
	}

	data = mdb_zalloc(sizeof (*data), UM_SLEEP);
	data->iwqd_end = start + (n * len);
	data->iwqd_len = len;

	wsp->walk_addr = start;
	wsp->walk_data = data;

	return (WALK_NEXT);
}

static int
ice_walk_txq_init(mdb_walk_state_t *wsp)
{
	return (ice_walk_txrxq_init(wsp, true));
}

static int
ice_walk_rxq_init(mdb_walk_state_t *wsp)
{
	return (ice_walk_txrxq_init(wsp, false));
}

static int
ice_walk_txrxq_step(mdb_walk_state_t *wsp)
{
	ice_walk_q_data_t	*data = wsp->walk_data;
	int			ret;

	if (wsp->walk_addr == data->iwqd_end)
		return (WALK_DONE);

	ret = wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata);
	if (ret != WALK_NEXT)
		return (ret);

	wsp->walk_addr += data->iwqd_len;
	return (WALK_NEXT);
}

static void
ice_walk_txrxq_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ice_walk_q_data_t));
}

typedef struct mdb_ice_tx_ring_t {
	uint32_t	itxr_index;
	uint16_t	itxr_size;
	uint16_t	itxr_avail;
	uint16_t	itxr_head;
	uint16_t	itxr_tail;
	bool		itxr_blocked;
	uintptr_t	itxr_tcbs;
	uintptr_t	itxr_descs;
} mdb_ice_tx_ring_t;

static int
ice_txq_cb(uintptr_t addr, const void *ignored __unused, void *arg)
{
	mdb_ice_tx_ring_t	txr = { 0 };
	uint_t			*flagsp = arg;

	if (mdb_ctf_vread(&txr, "ice_tx_ring_t", "mdb_ice_tx_ring_t",
	    addr, 0) != 0) {
		return (-1);
	}

	if (*flagsp & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%p %4u %5u %5u", addr, txr.itxr_index,
	    txr.itxr_size - txr.itxr_avail, txr.itxr_size);
	if (txr.itxr_blocked)
		mdb_printf(" BLOCKED");
	mdb_printf("\n");

	return (DCMD_OK);
}

static int
ice_txqs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %4s %5s %5s%</u>\n",
		    "ADDR", "IDX", "INUSE", "SIZE");
	}

	return (mdb_pwalk("ice_txq", ice_txq_cb, &flags, addr));
}

static void
ice_txq_dtype_str(ice_tx_desc_t *desc, char *buf, size_t buflen)
{
	switch (ICE_TX_DESC_DTYPE(LE_64(desc->itxd_qw1))) {
	case ICE_TX_DESC_DTYPE_DATA:
		(void) strlcpy(buf, "DATA", buflen);
		break;
	case ICE_TX_DESC_DTYPE_TCTX:
		(void) strlcpy(buf, "TCTX", buflen);
		break;
	case ICE_TX_DESC_DTYPE_FILTER:
		(void) strlcpy(buf, "FLTR", buflen);
		break;
	case ICE_TX_DESC_DTYPE_DONE:
		(void) strlcpy(buf, "DONE", buflen);
		break;
	default:
		(void) mdb_snprintf(buf, buflen, "%s",
		    ICE_TX_DESC_DTYPE(LE_64(desc->itxd_qw1)));
		break;
	}
}

static int
ice_txq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_ice_tx_ring_t	txr = { 0 };
	uintptr_t		tcb_base;
	ssize_t			desc_len;

	if (mdb_ctf_vread(&txr, "ice_tx_ring_t", "mdb_ice_tx_ring_t",
	    addr, 0) != 0) {
		return (-1);
	}

	/*
	 * Since the hardware supports both 16 and 32 byte descriptors
	 * we see which one the driver used in case we ever switch between
	 * them for some reason.
	 */
	desc_len = mdb_ctf_sizeof_by_name("ice_tx_desc_t");
	if (desc_len == -1) {
		mdb_warn("failed to read size of ice_tx_desc_t");
		return (-1);
	}

	tcb_base = txr.itxr_tcbs;

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-5s %16s %16s %4s%</u>\n",
		    "INDEX", "TCB", "DESC", "TYPE");
	}

	for (uint_t i = 0; i < txr.itxr_size; i++) {
		uintptr_t	tcb_addr;
		uintptr_t	desc_addr;
		ice_tx_desc_t	desc;
		char		tbuf[5];

		if (mdb_vread(&tcb_addr, sizeof (tcb_addr),
		    tcb_base + (i * sizeof (ice_tx_ctrl_block_t *))) < 0) {
			mdb_warn("failed to read TCB address for index %u", i);
			return (DCMD_ERR);
		}

		/*
		 * There is only one TX descriptor format supported by
		 * the NIC, so this should never change.
		 */
		desc_addr = txr.itxr_descs + (i * desc_len);
		if (mdb_vread(&desc, sizeof (desc), desc_addr) < 0) {
			mdb_warn("failed to read TX descriptor at index %u", i);
			return (DCMD_ERR);
		}

		ice_txq_dtype_str(&desc, tbuf, sizeof (tbuf));

		mdb_printf("%5u %16lx %16lx %4s", i, tcb_addr, desc_addr, tbuf);

		if (i == txr.itxr_head)
			mdb_printf(" HEAD");
		if (i == txr.itxr_tail)
			mdb_printf(" TAIL");

		mdb_printf("\n");
	}

	return (DCMD_OK);
}

#define	MASK(h, l)	((1UL << (((h) - (l) + 1UL) - 1UL)) >> (l))

static mdb_bitmask_t ice_tctx_cmd_bits[] = {
	{ "TSO", ICE_TX_CTXD_CMD_TSO, ICE_TX_CTXD_CMD_TSO },
	{ "TSYN", ICE_TX_CTXD_CMD_TSYN, ICE_TX_CTXD_CMD_TSYN },
	{ "IL2TAG2", ICE_TX_CTXD_CMD_IL2TAG2, ICE_TX_CTXD_CMD_IL2TAG2 },
	{ "IL2TAG2_IL2H", ICE_TX_CTXD_CMD_IL2TAG2_IL2H,
	    ICE_TX_CTXD_CMD_IL2TAG2_IL2H },
	{ "SWITCH_NONE", MASK(5, 4), 0 },
	{ "SWITCH_UPLINK", MASK(5, 4), 1 },
	{ "SWITCH_LOCAL", MASK(5, 4), 2 },
	{ "SWITCH_VSI", MASK(5, 4), 3 },
	{ NULL, 0, 0 },
};

static int
ice_tx_desc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char		tbuf[5];
	ice_tx_desc_t	desc;

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s  %4s%</u>\n", "VADDR", "TYPE");
	}

	mdb_printf("%#lr", addr);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("\n", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&desc, sizeof (desc), addr) < 0) {
		mdb_warn("failed to read TX descriptor at 0x%p", addr);
		return (DCMD_ERR);
	}

	desc.itxd_qw0 = LE_64(desc.itxd_qw0);
	desc.itxd_qw1 = LE_64(desc.itxd_qw1);

	ice_txq_dtype_str(&desc, tbuf, sizeof (tbuf));
	mdb_printf(" %s", tbuf);

	switch (ICE_TX_DESC_DTYPE(desc.itxd_qw1)) {
	case ICE_TX_DESC_DTYPE_DATA: {
		mdb_printf(" PADDR=%#lr\n", desc.itxd_qw0);

		mdb_printf("  %?s %4s", "", "");
		mdb_printf(" qw1=0x%lx\n", desc.itxd_qw1);

		mdb_printf("  %?s %4s", "", "");
		mdb_printf(" BSIZE=%u", ICE_TX_DESC_BSIZE(desc.itxd_qw1));

		uint64_t offset = ICE_TX_DESC_OFFSET(desc.itxd_qw1);

		mdb_printf(" MACLEN=%u", ICE_TX_DESC_OFFSET_MACLEN(offset));
		mdb_printf(" IPLEN=%u", ICE_TX_DESC_OFFSET_IPLEN(offset));
		mdb_printf(" L4LEN=%u", ICE_TX_DESC_OFFSET_L4LEN(offset));

		break;
	}

	case ICE_TX_DESC_DTYPE_TCTX:
		mdb_printf(" CMD=%#x <%b>", ICE_TX_CTXD_CMD(desc.itxd_qw1),
		    ICE_TX_CTXD_CMD(desc.itxd_qw1), ice_tctx_cmd_bits);

		mdb_printf(" %s=%#lr",
		    (ICE_TX_CTXD_CMD(desc.itxd_qw1) == ICE_TX_CTXD_CMD_TSO) ?
		    "TLEN" : "TSYN_REG");

		if (ICE_TX_CTXD_CMD(desc.itxd_qw1) & ICE_TX_CTXD_CMD_TSO) {
			mdb_printf(" MSS");
		} else if (ICE_TX_CTXD_SWTCH(ICE_TX_CTXD_CMD(desc.itxd_qw1)) ==
		    3) {
			mdb_printf(" VSI");
		} else {
			mdb_printf(" <ZERO>");
		}
		mdb_printf("=%#lr", ICE_TX_CTXD_MSS(desc.itxd_qw1));
		mdb_printf("\n");
		break;

	case ICE_TX_DESC_DTYPE_DONE:
		break;
	}

	return (DCMD_OK);
}

static mdb_dcmd_t ice_dcmds[] = {
	// { name, usage, descr, funcp, help, tab_comp }
	{ "ice", NULL, "print out the attached ice driver instances",
	    ice_ice, NULL, NULL },
	{ "ice_txqs", NULL, "print the TX ring state of the given ice_t",
	    ice_txqs, NULL, NULL },
	{ "ice_txq", NULL, "print the contents of the given TX ring", ice_txq,
	    NULL, NULL },
	{ "ice_tx_desc", NULL, "print out a TX descriptor", ice_tx_desc,
	    NULL, NULL },
	{ NULL }
};

static mdb_walker_t ice_walkers[] = {
	// { name, desc, init, step, fini, arg }
	{ "ice", "walk ice instances",
	    ice_ice_walk_init, ice_ice_walk_step, NULL, NULL },
	{ "ice_txq", "walk transmit queues of given ice_t",
	    ice_walk_txq_init, ice_walk_txrxq_step, ice_walk_txrxq_fini, NULL },
	{ "ice_rxq", "walk receive queues of given ice_t",
	    ice_walk_rxq_init, ice_walk_txrxq_step, ice_walk_txrxq_fini, NULL },
	{ NULL }
};

static const mdb_modinfo_t ice_modinfo = {
	MDB_API_VERSION, ice_dcmds, ice_walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&ice_modinfo);
}
