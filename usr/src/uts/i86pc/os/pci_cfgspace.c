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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * PCI configuration space access routines
 */

#include <sys/systm.h>
#include <sys/psw.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/pci_cfgacc.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

#if defined(__xpv)
int pci_max_nbus = 0xFE;
#else
int pci_max_nbus = 0xFF;
#endif
int pci_bios_cfg_type = PCI_MECHANISM_UNKNOWN;
int pci_bios_maxbus;
int pci_bios_mech;
int pci_bios_vers;

/*
 * These two variables can be used to force a configuration mechanism or
 * to force which function is used to probe for the presence of the PCI bus.
 */
int	PCI_CFG_TYPE = 0;
int	PCI_PROBE_TYPE = 0;

/*
 * No valid mcfg_mem_base by default, and accessing pci config space
 * in mem-mapped way is disabled.
 *
 * Other bits in the kernel uses these, so they've been extended for
 * PCI segment support until those other bits can (hopefully) be
 * reworked.
 */
uint64_t *mcfg_mem_base;
uint16_t *mcfg_segments;
uint8_t *mcfg_bus_start;
uint8_t *mcfg_bus_end;
uint16_t mcfg_n_segments;

/*
 * Maximum offset in config space when not using MMIO
 */
uint_t pci_iocfg_max_offset = 0xff;

/*
 * These function pointers lead to the actual implementation routines
 * for configuration space access.  Normally they lead to either the
 * pci_mech1_* or pci_mech2_* routines, but they can also lead to
 * routines that work around chipset bugs.
 * These functions are accessing pci config space via I/O way.
 * Pci_cfgacc_get/put functions shoul be used as more common interfaces,
 * which also provide accessing pci config space via mem-mapped way.
 */
uint8_t (*pci_getb_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg);
uint16_t (*pci_getw_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg);
uint32_t (*pci_getl_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg);
void (*pci_putb_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg,
    uint8_t val);
void (*pci_putw_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg,
    uint16_t val);
void (*pci_putl_func)(uint8_t bus, uint8_t dev, uint8_t func, uint16_t reg,
    uint32_t val);

extern void (*pci_cfgacc_acc_p)(pci_cfgacc_req_t *req);

extern void pci_cfgacc_mmio_init(void);

/*
 * Internal routines
 */
static int pci_check(void);
static void pci_init_mmio(void);

#if !defined(__xpv)
static int pci_check_bios(void);
static int pci_get_cfg_type(void);
#endif

/* for legacy io-based config space access */
kmutex_t pcicfg_mutex;

/* for mmio-based config space access */
kmutex_t pcicfg_mmio_mutex;

/* ..except Orion and Neptune, which have to have their own */
kmutex_t pcicfg_chipset_mutex;

void
pci_cfgspace_init(void)
{
	mutex_init(&pcicfg_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(15));
	mutex_init(&pcicfg_mmio_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(DISP_LEVEL));
	mutex_init(&pcicfg_chipset_mutex, NULL, MUTEX_SPIN,
	    (ddi_iblock_cookie_t)ipltospl(15));
	if (!pci_check()) {
		mutex_destroy(&pcicfg_mutex);
		mutex_destroy(&pcicfg_mmio_mutex);
		mutex_destroy(&pcicfg_chipset_mutex);
	}
}

/*
 * This code determines if this system supports PCI/PCIE and which
 * type of configuration access method is used
 */
static int
pci_check(void)
{
	/*
	 * Only do this once.  NB:  If this is not a PCI system, and we
	 * get called twice, we can't detect it and will probably die
	 * horribly when we try to ask the BIOS whether PCI is present.
	 * This code is safe *ONLY* during system startup when the
	 * BIOS is still available.
	 */
	if (pci_bios_cfg_type != PCI_MECHANISM_UNKNOWN)
		return (TRUE);

#if defined(__xpv)
	/*
	 * only support PCI config mechanism 1 in i86xpv. This should be fine
	 * since the other ones are workarounds for old broken H/W which won't
	 * be supported in i86xpv anyway.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		pci_bios_cfg_type = PCI_MECHANISM_1;
		pci_getb_func = pci_mech1_getb;
		pci_getw_func = pci_mech1_getw;
		pci_getl_func = pci_mech1_getl;
		pci_putb_func = pci_mech1_putb;
		pci_putw_func = pci_mech1_putw;
		pci_putl_func = pci_mech1_putl;

		/*
		 * Since we can't get the BIOS info in i86xpv, we will do an
		 * exhaustive search of all PCI buses. We have to do this until
		 * we start using the PCI information in ACPI.
		 */
		pci_bios_maxbus = pci_max_nbus;
	}
#else /* !__xpv */

	pci_bios_cfg_type = pci_check_bios();

	if (pci_bios_cfg_type == PCI_MECHANISM_NONE) {
		/*
		 * Default to mechanism 1, and scan all PCI buses
		 */
		pci_bios_cfg_type = PCI_MECHANISM_1;
		pci_bios_maxbus = pci_max_nbus;
	}

	switch (pci_get_cfg_type()) {
	case PCI_MECHANISM_1:
		if (pci_is_broken_orion()) {
			pci_getb_func = pci_orion_getb;
			pci_getw_func = pci_orion_getw;
			pci_getl_func = pci_orion_getl;
			pci_putb_func = pci_orion_putb;
			pci_putw_func = pci_orion_putw;
			pci_putl_func = pci_orion_putl;
		} else if (pci_check_amd_ioecs()) {
			pci_getb_func = pci_mech1_amd_getb;
			pci_getw_func = pci_mech1_amd_getw;
			pci_getl_func = pci_mech1_amd_getl;
			pci_putb_func = pci_mech1_amd_putb;
			pci_putw_func = pci_mech1_amd_putw;
			pci_putl_func = pci_mech1_amd_putl;
			pci_iocfg_max_offset = 0xfff;
		} else {
			pci_getb_func = pci_mech1_getb;
			pci_getw_func = pci_mech1_getw;
			pci_getl_func = pci_mech1_getl;
			pci_putb_func = pci_mech1_putb;
			pci_putw_func = pci_mech1_putw;
			pci_putl_func = pci_mech1_putl;
		}
		break;

	case PCI_MECHANISM_2:
		if (pci_check_neptune()) {
			/*
			 * The BIOS for some systems with the Intel
			 * Neptune chipset seem to default to #2 even
			 * though the chipset can do #1.  Override
			 * the BIOS so that MP systems will work
			 * correctly.
			 */

			pci_getb_func = pci_neptune_getb;
			pci_getw_func = pci_neptune_getw;
			pci_getl_func = pci_neptune_getl;
			pci_putb_func = pci_neptune_putb;
			pci_putw_func = pci_neptune_putw;
			pci_putl_func = pci_neptune_putl;
		} else {
			pci_getb_func = pci_mech2_getb;
			pci_getw_func = pci_mech2_getw;
			pci_getl_func = pci_mech2_getl;
			pci_putb_func = pci_mech2_putb;
			pci_putw_func = pci_mech2_putw;
			pci_putl_func = pci_mech2_putl;
		}
		break;

	default:
		return (FALSE);
	}

	pci_init_mmio();

#endif /* __xpv */

	/* See pci_cfgacc.c */
	pci_cfgacc_acc_p = pci_cfgacc_acc;

	return (TRUE);
}

#if !defined(__xpv)

static int
pci_check_bios(void)
{
	struct bop_regs regs;
	uint32_t	carryflag;
	uint16_t	ax, dx;

	/*
	 * This mechanism uses a legacy BIOS call to detect PCI configuration,
	 * but such calls are not available on systems with UEFI firmware.
	 * For UEFI systems we must assume some reasonable defaults and scan
	 * all possible buses.
	 */
	if (BOP_GETPROPLEN(bootops, "efi-systab") > 0) {
		pci_bios_mech = 1;
		pci_bios_vers = 0;
		pci_bios_maxbus = pci_max_nbus;
		return (PCI_MECHANISM_1);
	}

	bzero(&regs, sizeof (regs));
	regs.eax.word.ax = (PCI_FUNCTION_ID << 8) | PCI_BIOS_PRESENT;

	BOP_DOINT(bootops, 0x1a, &regs);
	carryflag = regs.eflags & PS_C;
	ax = regs.eax.word.ax;
	dx = regs.edx.word.dx;

	/* the carry flag must not be set */
	if (carryflag != 0)
		return (PCI_MECHANISM_NONE);

	if (dx != ('P' | 'C'<<8))
		return (PCI_MECHANISM_NONE);

	/* ah (the high byte of ax) must be zero */
	if ((ax & 0xff00) != 0)
		return (PCI_MECHANISM_NONE);

	pci_bios_mech = (ax & 0x3);
	pci_bios_vers = regs.ebx.word.bx;

	/*
	 * Several BIOS implementations have known problems where they don't end
	 * up correctly telling us to scan all PCI buses in the system. In
	 * particular, many on-die CPU PCI devices are on a last bus that is
	 * sometimes not enumerated. As such, do not trust the BIOS.
	 */
	pci_bios_maxbus = pci_max_nbus;

	switch (pci_bios_mech) {
	default:	/* ?!? */
	case 0:		/* supports neither? */
		return (PCI_MECHANISM_NONE);

	case 1:
	case 3:		/* supports both */
		return (PCI_MECHANISM_1);

	case 2:
		return (PCI_MECHANISM_2);
	}
}

static int
pci_get_cfg_type(void)
{
	/* Check to see if the config mechanism has been set in /etc/system */
	switch (PCI_CFG_TYPE) {
	default:
	case 0:
		break;
	case 1:
		return (PCI_MECHANISM_1);
	case 2:
		return (PCI_MECHANISM_2);
	case -1:
		return (PCI_MECHANISM_NONE);
	}

	/* call one of the PCI detection algorithms */
	switch (PCI_PROBE_TYPE) {
	default:
	case 0:
		/* From pci_check() and pci_check_bios() */
		return (pci_bios_cfg_type);
	case -1:
		return (PCI_MECHANISM_NONE);
	}
}

static void
pci_init_mmio(void)
{
	uint64_t *ecfg;
	size_t len;
	int ecfglen;

	ecfglen = do_bsys_getproplen(bootops, MCFG_PROPNAME);
	if (ecfglen <= 0)
		return;

	/*
	 * For each entry in the MCFG table, there should be 4 values --
	 * the physicall address of the configuration space, the segment
	 * number, the starting bus, and the ending bus.
	 */
	if (ecfglen % (4 * sizeof (uint64_t)) != 0) {
		return;
	}

	/*
	 * We let this get cleaned up once we clean up the initial boot
	 * mappings.
	 */
	ecfg = (uint64_t *)BOP_ALLOC(bootops, NULL, ecfglen, sizeof (uint64_t));

	if (do_bsys_getprop(bootops, MCFG_PROPNAME, ecfg) < 0)
		return;

	mcfg_n_segments = ecfglen / (4 * sizeof (uint64_t));

	/*
	 * Since the early boot alloactor isn't very sophisticated, we
	 * try to minimize allocations by doing this as one big chunk.
	 * Logically the memory can be thought as:
	 *
	 * 	uint64_t	base_address[mcfg_n_segment];
	 * 	uint16_t        segments[mcfg_n_segment];
	 * 	uint8_t		bus_start[mcfg_n_segment];
	 * 	uint8_t		bus_end[mcfg_n_segment];
	 *
	 * Which will pack nicely on x86 (no gaps).
	 *
	 * Eventually, it would be nice to eliminate the mcfg_xxx variables
	 * altogether and directly reference the ACPI_MCFG_ALLOCATION entries
	 * when needed instead of making what is in effect a copy of it.
	 */
	len = mcfg_n_segments * (sizeof (uint64_t) + sizeof (uint16_t) +
	    sizeof (uint8_t) + sizeof (uint8_t));
	mcfg_mem_base = (uint64_t *)BOP_ALLOC(bootops, (caddr_t)MISC_VA_BASE,
	    len, sizeof (uint64_t) /* alignment */);
	mcfg_segments = (uint16_t *)(mcfg_mem_base + mcfg_n_segments);
	mcfg_bus_start = (uint8_t *)(mcfg_segments + mcfg_n_segments);
	mcfg_bus_end = (uint8_t *)(mcfg_bus_start + mcfg_n_segments);

	for (uint_t i = 0; i < mcfg_n_segments; i++) {
		mcfg_mem_base[i] = ecfg[i * 4];
		mcfg_segments[i] = (uint16_t)ecfg[(i * 4) + 1];
		mcfg_bus_start[i] = (uint8_t)ecfg[(i * 4) + 2];
		mcfg_bus_end[i] = (uint8_t)ecfg[(i * 4) + 3];
#ifdef DEBUG
		bop_printf(NULL, "MCFG [%u]:\taddr = 0x%p\n", i,
		    (void *)mcfg_mem_base[i]);
		bop_printf(NULL, "\t\tsegment = %u\n", mcfg_segments[i]);
		bop_printf(NULL, "\t\tbus range = 0x%x - 0x%x\n",
		    mcfg_bus_start[i], mcfg_bus_end[i]);
#endif
	}

	/*
	 * We leave the pci_{get,put}{b,w,l}_func pointers using the legacy
	 * mechanism1 pointers for access to the segment 0 configuration space.
	 * Most consumers will ultimately access PCI config space
	 * via the pci_cfgacc_acc_p pointer which can do either MMIO or
	 * IO based cfgspace access as appropriate (and can access the
	 * configuration space for non-zero PCI segments). This allows the
	 * existing code that depends on IO space access for working around
	 * legacy hardware issues to stay mostly if not completely unmodified
	 * until we have an opportunity to revisit the PCI probing code in
	 * detail.
	 */

	pci_cfgacc_mmio_init();
}
#endif	/* __xpv */
