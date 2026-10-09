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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * PCIe related dcmds
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddipropdefs.h>
#include <sys/pci.h>
#include <sys/pcie_impl.h>
#include <sys/stdbool.h>
#include <string.h>

boolean_t
pcie_bus_match(const struct dev_info *devi, uintptr_t *bus_p)
{
	if (devi->devi_bus.port_up.info.port.type == DEVI_PORT_TYPE_PCI) {
		*bus_p = (uintptr_t)devi->devi_bus.port_up.priv_p;
	} else if (devi->devi_bus.port_down.info.port.type ==
	    DEVI_PORT_TYPE_PCI) {
		*bus_p = (uintptr_t)devi->devi_bus.port_down.priv_p;
	} else {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Read a property as ddi_prop_lookup_*() would: driver, system, global, then
 * hardware properties.  MDB cannot use the DDI property interfaces directly.
 */
static int
pciinfo_get_prop(const struct dev_info *devi, const char *name, void *value,
    size_t len)
{
	ddi_prop_t *props[4];
	ddi_prop_list_t global_props;
	uint_t i;

	props[0] = devi->devi_drv_prop_ptr;
	props[1] = devi->devi_sys_prop_ptr;
	props[2] = NULL;
	props[3] = devi->devi_hw_prop_ptr;

	if (devi->devi_global_prop_list != NULL) {
		if (mdb_vread(&global_props, sizeof (global_props),
		    (uintptr_t)devi->devi_global_prop_list) == -1) {
			mdb_warn("failed to read global property list at %p",
			    devi->devi_global_prop_list);
			return (-1);
		}
		props[2] = global_props.prop_list;
	}

	for (i = 0; i < sizeof (props) / sizeof (props[0]); i++) {
		ddi_prop_t prop;
		uintptr_t prop_addr = (uintptr_t)props[i];

		while (prop_addr != 0) {
			char prop_name[128];

			if (mdb_vread(&prop, sizeof (prop), prop_addr) == -1) {
				mdb_warn("failed to read property at %p",
				    prop_addr);
				return (-1);
			}

			if (mdb_readstr(prop_name, sizeof (prop_name),
			    (uintptr_t)prop.prop_name) == -1) {
				mdb_warn("failed to read property name at %p",
				    prop.prop_name);
				return (-1);
			}

			if (strcmp(prop_name, name) == 0) {
				if (prop.prop_flags & DDI_PROP_UNDEF_IT) {
					mdb_warn("property '%s' at %p is undefined",
					    name, prop_addr);
					return (-1);
				}

				if (prop.prop_len < (int)len) {
					mdb_warn("property '%s' at %p is too short",
					    name, prop_addr);
					return (-1);
				}

				if (mdb_vread(value, len,
				    (uintptr_t)prop.prop_val) == -1) {
					mdb_warn("failed to read property '%s' "
					    "value at %p", name, prop.prop_val);
					return (-1);
				}

				return (1);
			}

			prop_addr = (uintptr_t)prop.prop_next;
		}
	}

	return (0);
}

static int
pciinfo_get_segment(uintptr_t addr, struct dev_info *devi, uint16_t *segment)
{
	struct dev_info parent;
	struct dev_info *cur = devi;
	int value;
	int ret;

	for (;;) {
		ret = pciinfo_get_prop(cur, "pci-segment", &value,
		    sizeof (value));
		if (ret < 0)
			return (-1);

		if (ret != 0) {
			if (value < 0 || value > UINT16_MAX) {
				mdb_warn("invalid pci-segment value %d at %p",
				    value, addr);
				return (-1);
			}
			*segment = (uint16_t)value;
			return (0);
		}

		if (cur->devi_parent == NULL)
			break;

		addr = (uintptr_t)cur->devi_parent;
		if (mdb_vread(&parent, sizeof (parent), addr) == -1) {
			mdb_warn("failed to read parent devinfo at %p", addr);
			return (-1);
		}
		cur = &parent;
	}

	*segment = 0;
	return (0);
}

static int
pciinfo_devinfo_cb(uintptr_t addr, struct dev_info *devi, void *arg)
{
	char binding_name[128];
	uintptr_t bus_addr;
	uint32_t reg;
	uint16_t segment;
	int ret;

	if (!pcie_bus_match(devi, &bus_addr))
		return (WALK_NEXT);

	if (*(uint_t *)arg & DCMD_PIPE_OUT) {
		mdb_printf("%-0?p\n", addr);
		return (WALK_NEXT);
	}

	if (mdb_readstr(binding_name, sizeof (binding_name),
	    (uintptr_t)devi->devi_binding_name) == -1) {
		mdb_warn("failed to read binding name at %p",
		    devi->devi_binding_name);
		return (WALK_ERR);
	}

	ret = pciinfo_get_prop(devi, "reg", &reg, sizeof (reg));
	if (ret < 0 || pciinfo_get_segment(addr, devi, &segment) != 0)
		return (WALK_ERR);

	if (ret == 0) {
		mdb_warn("PCI device at %p has no reg property", addr);
		return (WALK_NEXT);
	}

	mdb_printf("%-0?p %-24s#%-4d %-7u %-3u %-6u %-8u\n", addr,
	    binding_name, devi->devi_instance, segment,
	    PCI_REG_BUS_G(reg), PCI_REG_DEV_G(reg), PCI_REG_FUNC_G(reg));

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
pciinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;

	if (argc != 0 || (flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_PIPE_OUT) == 0) {
		mdb_printf("%<u>%-?s %-29s %-7s %-3s %-6s %-8s%</u>\n",
		    "DEVINFO", "NAME", "SEGMENT", "BUS", "DEVICE", "FUNCTION");
	}

	status = mdb_walk("devinfo", pciinfo_devinfo_cb, &flags);
	if (status == -1) {
		mdb_warn("couldn't walk devinfo tree");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
pcie_bus_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("pcie_bus walker doesn't support non-global walks\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("devinfo", wsp) == -1) {
		mdb_warn("couldn't walk \"devinfo\"");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
pcie_bus_walk_step(mdb_walk_state_t *wsp)
{
	const struct dev_info *devi;
	uintptr_t bus_addr;
	struct pcie_bus bus;

	if (wsp->walk_layer == NULL) {
		mdb_warn("missing layered walk info\n");
		return (WALK_ERR);
	}

	devi = wsp->walk_layer;
	if (!pcie_bus_match(devi, &bus_addr)) {
		return (WALK_NEXT);
	}

	if (mdb_vread(&bus, sizeof (bus), bus_addr) == -1) {
		mdb_warn("failed to read pcie_bus_t at %p", bus_addr);
		return (WALK_NEXT);
	}

	return (wsp->walk_callback(bus_addr, &bus, wsp->walk_cbdata));
}

/*
 * Decode a BDF (Bus/Device/Function) value.
 */

/* The maximum size of a string produced by pcie_bdf() */
#define	PCIE_BDF_BUFSZ	sizeof ("XX/XX/X")

static const char *
pcie_bdf(pcie_req_id_t bdf, char *buf, size_t len)
{

	if (bdf == PCIE_INVALID_BDF) {
		(void) strlcpy(buf, "INVBDF", len);
	} else {
		uint_t bus, dev, func;

		bus = (bdf & PCIE_REQ_ID_BUS_MASK) >> PCIE_REQ_ID_BUS_SHIFT;
		dev = (bdf & PCIE_REQ_ID_DEV_MASK) >> PCIE_REQ_ID_DEV_SHIFT;
		func = (bdf & PCIE_REQ_ID_FUNC_MASK) >> PCIE_REQ_ID_FUNC_SHIFT;

		mdb_snprintf(buf, len, "%r/%r/%r", bus, dev, func);
	}

	return (buf);
}

static const mdb_bitmask_t pf_affected_bits[] = {
	{ "ROOT", PF_AFFECTED_ROOT, PF_AFFECTED_ROOT },
	{ "SELF", PF_AFFECTED_SELF, PF_AFFECTED_SELF },
	{ "PARENT", PF_AFFECTED_PARENT, PF_AFFECTED_PARENT },
	{ "CHILDREN", PF_AFFECTED_CHILDREN, PF_AFFECTED_CHILDREN },
	{ "BDF", PF_AFFECTED_BDF, PF_AFFECTED_BDF },
	{ "AER", PF_AFFECTED_AER, PF_AFFECTED_AER },
	{ "SAER", PF_AFFECTED_SAER, PF_AFFECTED_SAER },
	{ "ADDR", PF_AFFECTED_ADDR, PF_AFFECTED_ADDR },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t pf_severity_bits[] = {
	{ "NO_ERROR", PF_ERR_NO_ERROR, PF_ERR_NO_ERROR },
	{ "CE", PF_ERR_CE, PF_ERR_CE },
	{ "NO_PANIC", PF_ERR_NO_PANIC, PF_ERR_NO_PANIC },
	{ "MATCHED_DEVICE", PF_ERR_MATCHED_DEVICE, PF_ERR_MATCHED_DEVICE },
	{ "MATCHED_RC", PF_ERR_MATCHED_RC, PF_ERR_MATCHED_RC },
	{ "MATCHED_PARENT", PF_ERR_MATCHED_PARENT, PF_ERR_MATCHED_PARENT },
	{ "PANIC", PF_ERR_PANIC, PF_ERR_PANIC },
	{ "PANIC_DEADLOCK", PF_ERR_PANIC_DEADLOCK, PF_ERR_PANIC_DEADLOCK },
	{ "BAD_RESPONSE", PF_ERR_BAD_RESPONSE, PF_ERR_BAD_RESPONSE },
	{ "MATCH_DOM", PF_ERR_MATCH_DOM, PF_ERR_MATCH_DOM },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t pcie_devsts_bits[] = {
	{ "CE", PCIE_DEVSTS_CE_DETECTED, PCIE_DEVSTS_CE_DETECTED },
	{ "NFE", PCIE_DEVSTS_NFE_DETECTED, PCIE_DEVSTS_NFE_DETECTED },
	{ "FE", PCIE_DEVSTS_FE_DETECTED, PCIE_DEVSTS_FE_DETECTED },
	{ "UR", PCIE_DEVSTS_UR_DETECTED, PCIE_DEVSTS_UR_DETECTED },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t pcie_aer_uce_bits[] = {
	{ "TRAINING", PCIE_AER_UCE_TRAINING, PCIE_AER_UCE_TRAINING },
	{ "DLP", PCIE_AER_UCE_DLP, PCIE_AER_UCE_DLP },
	{ "SD", PCIE_AER_UCE_SD, PCIE_AER_UCE_SD },
	{ "PTLP", PCIE_AER_UCE_PTLP, PCIE_AER_UCE_PTLP },
	{ "FCP", PCIE_AER_UCE_FCP, PCIE_AER_UCE_FCP },
	{ "TO", PCIE_AER_UCE_TO, PCIE_AER_UCE_TO },
	{ "CA", PCIE_AER_UCE_CA, PCIE_AER_UCE_CA },
	{ "UC", PCIE_AER_UCE_UC, PCIE_AER_UCE_UC },
	{ "RO", PCIE_AER_UCE_RO, PCIE_AER_UCE_RO },
	{ "MTLP", PCIE_AER_UCE_MTLP, PCIE_AER_UCE_MTLP },
	{ "ECRC", PCIE_AER_UCE_ECRC, PCIE_AER_UCE_ECRC },
	{ "UR", PCIE_AER_UCE_UR, PCIE_AER_UCE_UR },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t pcie_aer_ce_bits[] = {
	{ "RX_ERR", PCIE_AER_CE_RECEIVER_ERR, PCIE_AER_CE_RECEIVER_ERR },
	{ "BAD_TLP", PCIE_AER_CE_BAD_TLP, PCIE_AER_CE_BAD_TLP },
	{ "BAD_DLLP", PCIE_AER_CE_BAD_DLLP, PCIE_AER_CE_BAD_DLLP },
	{ "REPLAY_RO", PCIE_AER_CE_REPLAY_ROLLOVER,
	    PCIE_AER_CE_REPLAY_ROLLOVER },
	{ "REPLAY_TO", PCIE_AER_CE_REPLAY_TO, PCIE_AER_CE_REPLAY_TO },
	{ "AD_NFE", PCIE_AER_CE_AD_NFE, PCIE_AER_CE_AD_NFE },
	{ NULL, 0, 0 }
};

/*
 * Shadow structures for CTF reading. These contain only the fields we need
 * from the target structures, allowing compatibility across kernel versions.
 */
typedef struct {
	void		*pf_derr;
	void		*pf_fault;
	void		*pf_dq_head_p;
	void		*pf_dq_tail_p;
	uint32_t	pf_total;
} mdb_pf_impl_t;

typedef struct {
	uint16_t	pcie_err_status;
	void		*pcie_adv_regs;
} mdb_pf_pcie_err_regs_t;

typedef struct {
	uint32_t	pcie_ue_status;
	uint32_t	pcie_ce_status;
} mdb_pf_pcie_adv_err_regs_t;

typedef struct {
	boolean_t	pe_valid;
	uint32_t	pe_severity_flags;
	uint32_t	pe_orig_severity_flags;
	uint32_t	pe_severity_mask;
	void		*pe_affected_dev;
	void		*pe_bus_p;
	union {
		void	*pe_pcie_regs;
	} pe_ext;
	void		*pe_next;
} mdb_pf_data_t;

typedef struct {
	pcie_req_id_t	scan_bdf;
	uint64_t	scan_addr;
	boolean_t	full_scan;
} mdb_pf_root_fault_t;

typedef struct {
	pcie_req_id_t	bus_bdf;
	uint16_t	bus_dev_type;
	void		*bus_dip;
	void		*bus_rp_dip;
} mdb_pcie_bus_t;

typedef struct {
	uint16_t	pe_affected_flags;
} mdb_pf_affected_dev_t;

void
pcie_pf_impl_help(void)
{
	mdb_printf(
"Display PCIe fabric error scan results from a pf_impl_t structure.\n"
"\n"
"This dcmd is used to analyze PCIe fatal errors in crash dumps. It displays\n"
"the error data queue and decoded PCIe error registers from a fabric scan.\n"
"\n"
"When called without an address, the dcmd uses the cached pcie_faulty_pf_impl\n"
"global variable, which is automatically populated when pf_scan_fabric()\n"
"detects a fatal error (PF_ERR_FATAL_FLAGS). This cache is specifically\n"
"designed for post-mortem debugging, as ereports may be lost if errorq_dump\n"
"overflows.\n"
"\n"
"When called with an address, the dcmd analyzes the pf_impl_t structure at\n"
"that address. This is useful for examining old crash dumps where the address\n"
"of the pf_impl_t is known, or for analyzing non-fatal error scenarios.\n"
"\n"
"%<b>OPTIONS%</b>\n"
"  -v    Verbose mode. Display additional per-device information including\n"
"        pe_valid status, original severity flags, severity mask, and device\n"
"        info pointers.\n"
"\n"
"%<b>EXAMPLES%</b>\n"
"  ::pcie_fatal_errors              Display cached fatal error info\n"
"  ::pcie_fatal_errors -v           Display with verbose details\n"
"  addr::pcie_fatal_errors          Analyze pf_impl_t at specific address\n");
}

int
pcie_pf_impl_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_pf_impl_t impl;
	mdb_pf_data_t pfd;
	uintptr_t pfd_addr;
	bool opt_v = false;
	int count = 0;
	char bdf[PCIE_BDF_BUFSZ];

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, true, &opt_v,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	/*
	 * If no address is provided, use the cached global pcie_faulty_pf_impl
	 */
	if ((flags & DCMD_ADDRSPEC) == 0) {
		GElf_Sym sym;

		if (mdb_lookup_by_name("pcie_faulty_pf_impl", &sym) != 0) {
			mdb_warn("failed to lookup pcie_faulty_pf_impl "
			    "symbol");
			return (DCMD_ERR);
		}
		addr = (uintptr_t)sym.st_value;
	}

	if ((flags & DCMD_PIPE_OUT) != 0) {
		mdb_printf("%lr", addr);
		return (DCMD_OK);
	}

	if (mdb_ctf_vread(&impl, "pf_impl_t", "mdb_pf_impl_t", addr, 0) == -1) {
		mdb_warn("failed to read pf_impl_t at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * Check if the structure has been populated. If pf_dq_head_p is NULL,
	 * no fatal error was recorded.
	 */
	if (impl.pf_dq_head_p == NULL && impl.pf_derr == NULL) {
		mdb_printf("No fatal PCIe errors recorded.\n");
		return (DCMD_OK);
	}

	mdb_printf("pf_impl_t (%p) summary:\n", addr);
	mdb_printf("  pf_derr:       %p\n", impl.pf_derr);
	mdb_printf("  pf_fault:      %p\n", impl.pf_fault);
	mdb_printf("  pf_dq_head_p:  %p\n", impl.pf_dq_head_p);
	mdb_printf("  pf_dq_tail_p:  %p\n", impl.pf_dq_tail_p);
	mdb_printf("  pf_total:      %r\n", impl.pf_total);

	if (impl.pf_fault != NULL) {
		mdb_pf_root_fault_t fault;

		if (mdb_ctf_vread(&fault,
		    "pf_root_fault_t", "mdb_pf_root_fault_t",
		    (uintptr_t)impl.pf_fault, 0) == -1) {
			mdb_warn("failed to read pf_root_fault_t at %p",
			    impl.pf_fault);
		} else {
			mdb_printf("\nRoot Fault Information:\n");
			mdb_printf("  scan_bdf:      %04r (%s)\n",
			    fault.scan_bdf,
			    pcie_bdf(fault.scan_bdf, bdf, sizeof (bdf)));
			mdb_printf("  scan_addr:     %016r\n",
			    fault.scan_addr);
			mdb_printf("  full_scan:     %s\n",
			    fault.full_scan ? "true" : "false");
		}
	}

	mdb_printf("\nError Data Queue:\n");
	mdb_printf("%<u>%-4s %-16s %-17s %-7s %-16s %-16s%</u>\n",
	    "#", "pf_data_t", "BDF", "DevType", "Severity", "Affected");

	for (pfd_addr = (uintptr_t)impl.pf_dq_head_p; pfd_addr != 0;
	    pfd_addr = (uintptr_t)pfd.pe_next) {
		mdb_pf_affected_dev_t affected;
		mdb_pcie_bus_t bus;
		uint16_t affected_flags = 0;

		if (mdb_ctf_vread(&pfd, "pf_data_t", "mdb_pf_data_t",
		    pfd_addr, 0) == -1) {
			mdb_warn("failed to read pf_data_t at %p", pfd_addr);
			break;
		}

		if (pfd.pe_bus_p != NULL &&
		    mdb_ctf_vread(&bus, "pcie_bus_t", "mdb_pcie_bus_t",
		    (uintptr_t)pfd.pe_bus_p, 0) != -1) {
			mdb_printf("%-4r %016p %05r (%8s) %8r ",
			    count, pfd_addr, bus.bus_bdf,
			    pcie_bdf(bus.bus_bdf, bdf, sizeof (bdf)),
			    bus.bus_dev_type);
		} else {
			mdb_printf("%-4r %016p %-15s %-8s ",
			    count, pfd_addr, "????", "????");
		}
		count++;

		mdb_printf("%b ", pfd.pe_severity_flags, pf_severity_bits);

		if (pfd.pe_affected_dev != NULL && mdb_ctf_vread(&affected,
		    "pf_affected_dev_t", "mdb_pf_affected_dev_t",
		    (uintptr_t)pfd.pe_affected_dev, 0) != -1) {
			affected_flags = affected.pe_affected_flags;
		}
		mdb_printf("%hb\n", affected_flags, pf_affected_bits);

		if (opt_v == 0)
			continue;

		if (pfd.pe_bus_p != NULL) {
			mdb_printf("      pe_valid:          %s\n",
			    pfd.pe_valid ? "true" : "false");
			mdb_printf("      pe_affected:       %08r <%hb>\n",
			    affected_flags, affected_flags, pf_affected_bits);
			mdb_printf("      pe_severity:       %08r <%b>\n",
			    pfd.pe_severity_flags,
			    pfd.pe_severity_flags, pf_severity_bits);
			mdb_printf("      pe_orig_severity:  %08r <%b>\n",
			    pfd.pe_orig_severity_flags,
			    pfd.pe_orig_severity_flags, pf_severity_bits);
			mdb_printf("      pe_severity_mask:  %08r <%b>\n",
			    pfd.pe_severity_mask,
			    pfd.pe_severity_mask, pf_severity_bits);
			mdb_printf("      bus_dip:           %p\n",
			    bus.bus_dip);
			mdb_printf("      bus_rp_dip:        %p\n",
			    bus.bus_rp_dip);
		}

		/* Display PCIe-specific error information if available */
		if (pfd.pe_ext.pe_pcie_regs != NULL) {
			mdb_pf_pcie_err_regs_t pcie_regs;
			mdb_pf_pcie_adv_err_regs_t adv_regs;

			if (mdb_ctf_vread(&pcie_regs, "pf_pcie_err_regs_t",
			    "mdb_pf_pcie_err_regs_t",
			    (uintptr_t)pfd.pe_ext.pe_pcie_regs, 0) != -1) {
				if (pcie_regs.pcie_err_status != 0) {
					mdb_printf("      pcie_err_status: "
					    "  %08r <%hb>\n",
					    pcie_regs.pcie_err_status,
					    pcie_regs.pcie_err_status,
					    pcie_devsts_bits);
				}

				if (pcie_regs.pcie_adv_regs != NULL &&
				    mdb_ctf_vread(&adv_regs,
				    "pf_pcie_adv_err_regs_t",
				    "mdb_pf_pcie_adv_err_regs_t",
				    (uintptr_t)pcie_regs.pcie_adv_regs,
				    0) != -1) {
					if (adv_regs.pcie_ue_status != 0) {
						mdb_printf("      AER UCE: "
						    "          %08r <%b>\n",
						    adv_regs.pcie_ue_status,
						    adv_regs.pcie_ue_status,
						    pcie_aer_uce_bits);
					}
					if (adv_regs.pcie_ce_status != 0) {
						mdb_printf("      AER CE:  "
						    "          %08r <%b>\n",
						    adv_regs.pcie_ce_status,
						    adv_regs.pcie_ce_status,
						    pcie_aer_ce_bits);
					}
				}
			}
		}

	}

	mdb_printf("\nTotal errors in queue: %r\n", count);

	return (DCMD_OK);
}

int
pcie_bdf_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char buf[PCIE_BDF_BUFSZ];

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (addr > UINT16_MAX) {
		mdb_warn("bdf value too large, range [0,%r]\n",
		    UINT16_MAX);
		return (DCMD_ERR);
	}

	mdb_printf("%s\n", pcie_bdf((pcie_req_id_t)addr, buf, sizeof (buf)));

	return (DCMD_OK);
}
