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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2024 Oxide Computer Company
 * Copyright 2026 RackTop Systems, Inc.
 */

#include <sys/systm.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/cmn_err.h>
#include <sys/bootconf.h>
#include <vm/hat_i86.h>
#include <vm/seg_kmem.h>
#include <vm/kboot_mmu.h>

/* The size of the extended PCI space for each B/D/F */
#define	PCIE_DEV_CFG_SPACE_SIZE	(PCI_CONF_HDR_SIZE << 4)

#define	PCI_BDF_BUS(bdf)	((((uint16_t)bdf) & 0xff00) >> 8)
#define	PCI_BDF_DEV(bdf)	((((uint16_t)bdf) & 0xf8) >> 3)
#define	PCI_BDF_FUNC(bdf)	(((uint16_t)bdf) & 0x7)

/*
 * Generic PCI constants.  Probably these should be in pci.h.
 */
#define	PCI_MAX_BUSES		256
#define	PCI_MAX_DEVS		32
#define	PCI_MAX_FUNCS		8

/* The total size of the PCIE extended configuration space */
#define	PCIE_CFG_SPACE_SIZE	(1024 * 1024 * PCI_MAX_BUSES)
#define	PCIE_CFG_SPACE_ALIGN	(1024 * 1024 * 2)

/* patchable variables */
volatile boolean_t pci_cfgacc_force_io = B_FALSE;

extern uintptr_t alloc_vaddr(size_t, paddr_t);
extern void *device_arena_alloc(size_t, int);

void pci_cfgacc_acc(pci_cfgacc_req_t *);

boolean_t pci_cfgacc_find_workaround(uint16_t);

/*
 * IS_P2ALIGNED() is used to make sure offset is 'size'-aligned, so
 * it's guaranteed that the access will not cross 4k page boundary.
 * Thus only 1 page is allocated for all config space access, and the
 * virtual address of that page is cached in pci_cfgacc_virt_base.
 */
static caddr_t *pci_cfgacc_virt_base = NULL;

static void
pci_cfgacc_io(pci_cfgacc_req_t *req)
{
	uint8_t bus, dev, func;
	uint16_t ioacc_offset;	/* 4K config access with IO ECS */

	bus = PCI_BDF_BUS(req->bdf);
	dev = PCI_BDF_DEV(req->bdf);
	func = PCI_BDF_FUNC(req->bdf);
	ioacc_offset = req->offset;

	switch (req->size) {
	case 1:
		if (req->write)
			(*pci_putb_func)(bus, dev, func,
			    ioacc_offset, VAL8(req));
		else
			VAL8(req) = (*pci_getb_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 2:
		if (req->write)
			(*pci_putw_func)(bus, dev, func,
			    ioacc_offset, VAL16(req));
		else
			VAL16(req) = (*pci_getw_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 4:
		if (req->write)
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset, VAL32(req));
		else
			VAL32(req) = (*pci_getl_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 8:
		if (req->write) {
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset, VAL64(req) & 0xffffffff);
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset + 4, VAL64(req) >> 32);
		} else {
			VAL64(req) = (*pci_getl_func)(bus, dev, func,
			    ioacc_offset);
			VAL64(req) |= (uint64_t)(*pci_getl_func)(bus, dev, func,
			    ioacc_offset + 4) << 32;
		}
		break;
	}
}

/*
 * Each of our access functions uses inline assembly to perform the direct
 * access to memory-mapped config space.  This is necessary to guarantee that
 * the value to be stored into config space is in %rax or the value to be read
 * from config space will be placed in %rax.  AMD publication 56255 rev. 3.03
 * sec. 2.1.4.1 imposes three requirements for memory-mapped (ECAM) config space
 * accesses:
 *
 * 1. "MMIO configuration space accesses must use the uncacheable (UC) memory
 *    type."
 * 2. "Instructions used to read MMIO configuration space are required to take
 *    the following form:
 *        mov eax/ax/al, any_address_mode;
 *    Instructions used to write MMIO configuration space are required to take
 *    the following form:
 *        mov any_address_mode, eax/ax/al;
 *    No other source/target registers may be used other than eax/ax/al."
 * 3. "In addition, all such accesses are required not to cross any naturally
 *    aligned DW boundary."
 *
 * "Access to MMIO configuration space registers that do not meet these
 * requirements result in undefined behavior."
 *
 * These requirements, or substantially identical phrasings of them, have been
 * carried into all known subsequent PPRs, including those for Rome, Milan,
 * Genoa, and Turin processor families.
 *
 * The first of these is guaranteed here by our device mapping (in
 * pcie_cfgspace_{init,remap}() and by hat_devload()) and in the KDI by
 * kdi_prw(); see the comment there for additional details.
 *
 * The second is guaranteed by our use of inline assembly with the "a"
 * constraint: if we are storing to config space, we force gcc to first load
 * from our source buffer into the A register the value to be stored into config
 * space; if we are loading from config space, we force gcc to perform that load
 * using the A register as a target, then store the contents to our destination
 * buffer.
 *
 * The third constraint is guaranteed by pcie_access_check(), except with
 * respect to 64-bit accesses which are not currently used.  Our check is
 * actually slightly more strict than AMD requires: we enforce natural
 * alignment.  This guarantees we satisfy the constraint, but it would also be
 * legal to read a 16-bit quantity at offset 1 from the start of a
 * 4-byte-aligned region.  We don't allow that because it's very unlikely to be
 * useful or correct.
 *
 * The write (store to cfg space) variants may need the store inline assembly to
 * be volatile because the output is not used in the function and we cannot be
 * certain the compiler won't move or eliminate the store.  The read variants
 * return the output so they don't have this problem.
 */

static inline uint8_t
mmio_read_uint8(caddr_t addr)
{
	volatile uint8_t *u8p = (volatile uint8_t *)addr;
	uint8_t rv;

	__asm__("movb	%1, %0\n" : "=a" (rv) : "m" (*u8p) :);
	return (rv);
}

static inline void
mmio_write_uint8(caddr_t addr, uint8_t val)
{
	volatile uint8_t *u8p = (volatile uint8_t *)addr;
	__asm__ __volatile__("movb	%1, %0\n" : "=m" (*u8p) : "a" (val) :);
}

static inline uint16_t
mmio_read_uint16(caddr_t addr)
{
	volatile uint16_t *u16p = (volatile uint16_t *)addr;
	uint16_t rv;

	__asm__("movw	%1, %0\n" : "=a" (rv) : "m" (*u16p) :);
	return (rv);
}

static inline void
mmio_write_uint16(caddr_t addr, uint16_t val)
{
	volatile uint16_t *u16p = (volatile uint16_t *)addr;
	__asm__ __volatile__("movw	%1, %0\n" : "=m" (*u16p) : "a" (val) :);
}

static inline uint32_t
mmio_read_uint32(caddr_t addr)
{
	volatile uint32_t *u32p = (volatile uint32_t *)addr;
	uint32_t rv;

	__asm__("movl	%1, %0\n" : "=a" (rv) : "m" (*u32p) :);
	return (rv);
}

static inline void
mmio_write_uint32(caddr_t addr, uint32_t val)
{
	volatile uint32_t *u32p = (volatile uint32_t *)addr;
	__asm__ __volatile__("movl	%1, %0\n" : "=m" (*u32p) : "a" (val) :);
}

static inline uint64_t
mmio_read_uint64(caddr_t addr)
{
	volatile uint64_t *u64p = (volatile uint64_t *)addr;
	uint64_t rv;

	__asm__("movq	%1, %0\n" : "=a" (rv) : "m" (*u64p) :);
	return (rv);
}

static inline void
mmio_write_uint64(caddr_t addr, uint64_t val)
{
	volatile uint64_t *u64p = (volatile uint64_t *)addr;
	__asm__ __volatile__("movq	%1, %0\n" : "=m" (*u64p) : "a" (val) :);
}

static void
pci_cfgacc_mmio(pci_cfgacc_req_t *req)
{
	caddr_t vaddr;
	uint_t i;
	int seg = 0;

	/*
	 * We assume access without a dip is legacy stuff to segment 0
	 */
	if (req->rcdip != NULL) {
		seg = ddi_prop_get_int(DDI_DEV_T_ANY, req->rcdip, 0,
		    "pci-segment", 0);
	}

	/* pci_cfgacc_valid() made sure our segment value is valid */
	vaddr = 0;
	for (i = 0; i < mcfg_n_segments; i++) {
		if (mcfg_segments[i] == seg) {
			vaddr = pci_cfgacc_virt_base[i];
			break;
		}
	}
	ASSERT(vaddr != 0);

	vaddr += (uint64_t)req->bdf << 12;
	vaddr += req->offset;

	switch (req->size) {
	case 1:
		if (req->write)
			mmio_write_uint8(vaddr, VAL8(req));
		else
			VAL8(req) = mmio_read_uint8(vaddr);
		break;
	case 2:
		if (req->write)
			mmio_write_uint16(vaddr, VAL16(req));
		else
			VAL16(req) = mmio_read_uint16(vaddr);
		break;
	case 4:
		if (req->write)
			mmio_write_uint32(vaddr, VAL32(req));
		else
			VAL32(req) = mmio_read_uint32(vaddr);
		break;
	case 8:
		if (req->write)
			mmio_write_uint64(vaddr, VAL64(req));
		else
			VAL64(req) = mmio_read_uint64(vaddr);
		break;
	}
}

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req, size_t cfgspc_size)
{
	int sz = req->size;
	int seg = 0;
	uint_t idx = 0;
	uint8_t bus, dev, func;

	bus = PCI_BDF_BUS(req->bdf);
	dev = PCI_BDF_DEV(req->bdf);
	func = PCI_BDF_FUNC(req->bdf);

	/*
	 * Due to the advent of ARIs we want to make sure that we're not overly
	 * stringent here. ARIs retool how the bits are used for the device and
	 * function. This means that if dev == 0, allow func to be up to 0xff.
	 */
	if (dev != 0 && func >= PCI_MAX_FUNCTIONS) {
		cmn_err(CE_WARN, "illegal PCI request for invalid function "
		    "B/D/F = %u/%u/%u", bus, dev, func);
		return (B_FALSE);
	}

	if (req->rcdip != NULL) {
		seg = ddi_prop_get_int(DDI_DEV_T_ANY, req->rcdip, 0,
		    "pci-segment", 0);

		/* IO access is limited to segment 0 */
		if (seg > 0 && req->ioacc) {
			cmn_err(CE_WARN, "illegal PCI request to iospace from "
			    "non-zero segment: seg: %u offset = %x size = %d",
			    seg, req->offset, sz);
			return (B_FALSE);
		}

		for (idx = 0; idx < mcfg_n_segments; idx++) {
			if (mcfg_segments[idx] == seg)
				break;
		}

		if (idx >= mcfg_n_segments || mcfg_mem_base[idx] == 0) {
			cmn_err(CE_WARN, "illegal PCI segment value %d", seg);
			return (B_FALSE);
		}

		if (bus < mcfg_bus_start[idx] || bus > mcfg_bus_end[idx]) {
			cmn_err(CE_WARN, "illegal PCI request to invalid "
			    "bus %u on segment %d", bus, seg);
			return (B_FALSE);
		}
	}

	if (IS_P2ALIGNED(req->offset, sz) &&
	    (req->offset + sz - 1 < cfgspc_size) &&
	    ((sz & 0xf) && ISP2(sz)))
		return (B_TRUE);

	cmn_err(CE_WARN, "illegal PCI request: offset = %x, size = %d",
	    req->offset, sz);

	return (B_FALSE);
}

void
pci_cfgacc_check_io(pci_cfgacc_req_t *req)
{
	int seg = 0;

	/*
	 * We assume access without a dip is legacy stuff to segment 0
	 */
	if (req->rcdip != NULL) {
		seg = ddi_prop_get_int(DDI_DEV_T_ANY, req->rcdip, 0,
		    "pci-segment", 0);
	}

	/* cfg access via IO space is not possible for segments > 0 */
	if (seg > 0)
		return;

	/* We assume the first segment is segment 0 */
	if (pci_cfgacc_force_io || mcfg_mem_base == NULL ||
	    mcfg_mem_base[0] == 0 || pci_cfgacc_find_workaround(req->bdf)) {
		req->ioacc = B_TRUE;
	}
}

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	if (!req->write)
		VAL64(req) = PCI_EINVAL64;

	pci_cfgacc_check_io(req);

	if (req->ioacc) {
		if (pci_cfgacc_valid(req, pci_iocfg_max_offset + 1))
			pci_cfgacc_io(req);
	} else {
		if (pci_cfgacc_valid(req, PCIE_DEV_CFG_SPACE_SIZE))
			pci_cfgacc_mmio(req);
	}
}

void
pci_cfgacc_mmio_init(void)
{
	uintptr_t offset;
	uint_t i;

	if (mcfg_mem_base == NULL)
		return;

	pci_cfgacc_virt_base = (caddr_t *)BOP_ALLOC(bootops,
	    (caddr_t)MISC_VA_BASE, mcfg_n_segments * sizeof (caddr_t),
	    sizeof (uint64_t));

	for (i = 0; i < mcfg_n_segments; i++) {
#ifdef __xpv
		paddr_t phys_addr = mcfg_mem_base[i];

		/*
		 * XXX: Do we need to do anything else due to the size of
		 * ECAM?
		 */
		phys_addr = pfn_to_pa(xen_assign_pfn(mmu_btop(phys_addr))) |
		    (phys_addr & MMU_PAGEOFFSET);
#endif

		pci_cfgacc_virt_base[i] =
		    (caddr_t)alloc_vaddr(PCIE_CFG_SPACE_SIZE,
		    PCIE_CFG_SPACE_ALIGN);

		for (offset = 0; offset < PCIE_CFG_SPACE_SIZE;
		    offset += PCIE_CFG_SPACE_ALIGN) {
			kbm_map((uintptr_t)pci_cfgacc_virt_base[i] + offset,
			    mcfg_mem_base[i] + offset, 0, 0);
		}
	}
}

/*
 * Called once the device arena has been setup. The original bootstrap address
 * range is torn down when we tear down that hat, so we don't bother umapping
 * the original mapping.
 */
void
pci_cfgacc_mmio_remap(void)
{
	uint64_t *ecfg;
	void *new_va;
	pfn_t pfn;
	uint_t i;
	int len;

	/*
	 * We're called, we still can't use ddi_prop_xxx for lookups just yet
	 * but we at least have the VM system going so we can now allocate
	 * more permanent memory for these
	 */
	len = do_bsys_getproplen(bootops, MCFG_PROPNAME);
	if (len <= 0 || len % (4 * sizeof (uint64_t) != 0))
		return;

	/* Make len represent the # of uint64_t entries in ecfg */
	len /= sizeof (uint64_t);

	ecfg = kmem_zalloc(len * sizeof (uint64_t), KM_SLEEP);

	if (do_bsys_getprop(bootops, MCFG_PROPNAME, ecfg) < 0) {
		kmem_free(ecfg, len * sizeof (uint64_t));
		return;
	}

	pci_cfgacc_virt_base = kmem_zalloc(sizeof (caddr_t) * (len / 4),
	    KM_SLEEP);

	mcfg_mem_base = kmem_zalloc((len / 4) *
	    (sizeof (uint64_t) + sizeof (uint16_t) + sizeof (uint8_t) +
	    sizeof (uint8_t)), KM_SLEEP);
	mcfg_segments = (uint16_t *)(mcfg_mem_base + mcfg_n_segments);
	mcfg_bus_start = (uint8_t *)(mcfg_segments + mcfg_n_segments);
	mcfg_bus_end = (uint8_t *)(mcfg_bus_start + mcfg_n_segments);

	for (i = 0; i < len; i += 4) {
		new_va = vmem_alloc(heap_arena, PCIE_CFG_SPACE_SIZE, VM_SLEEP);
		pfn = mmu_btop(ecfg[i]);

		hat_devload(kas.a_hat, new_va, PCIE_CFG_SPACE_SIZE, pfn,
		   PROT_READ | PROT_WRITE | HAT_STRICTORDER,
		   HAT_LOAD_LOCK);
		pci_cfgacc_virt_base[i] = (caddr_t)new_va;

		mcfg_mem_base[i] = ecfg[i];
		mcfg_segments[i] = (uint16_t)ecfg[i + 1];
		mcfg_bus_start[i] = (uint8_t)ecfg[i + 2];
		mcfg_bus_end[i] = (uint8_t)ecfg[i + 3];

#ifdef DEBUG
		cmn_err(CE_CONT, "%s: mapping PCI segment %lu cfgspace 0x%p to "
		    "vaddr 0x%p - 0x%p\n", __func__, ecfg[i + 1],
		    (void *)ecfg[i], pci_cfgacc_virt_base[i],
		    pci_cfgacc_virt_base[i] + PCIE_CFG_SPACE_SIZE - 1);
#endif
	}

	kmem_free(ecfg, len * sizeof (uint64_t));
}

typedef	struct cfgacc_bus_range {
	struct cfgacc_bus_range *next;
	uint16_t bdf;
	uchar_t	secbus;
	uchar_t	subbus;
} cfgacc_bus_range_t;

cfgacc_bus_range_t *pci_cfgacc_bus_head = NULL;

#define	BUS_INSERT(prev, el) \
	el->next = *prev; \
	*prev = el;

#define	BUS_REMOVE(prev, el) \
	*prev = el->next;

/*
 * This function is only supposed to be called in device tree setup time,
 * thus no lock is needed.
 */
void
pci_cfgacc_add_workaround(uint16_t bdf, uchar_t secbus, uchar_t subbus)
{
	cfgacc_bus_range_t	*entry;

	entry = kmem_zalloc(sizeof (cfgacc_bus_range_t), KM_SLEEP);
	entry->bdf = bdf;
	entry->secbus = secbus;
	entry->subbus = subbus;
	BUS_INSERT(&pci_cfgacc_bus_head, entry);
}

boolean_t
pci_cfgacc_find_workaround(uint16_t bdf)
{
	cfgacc_bus_range_t	*entry;
	uchar_t			bus;

	for (entry = pci_cfgacc_bus_head; entry != NULL;
	    entry = entry->next) {
		if (bdf == entry->bdf) {
			/* found a device which is known to be broken */
			return (B_TRUE);
		}

		bus = PCI_BDF_BUS(bdf);
		if ((bus != 0) && (bus >= entry->secbus) &&
		    (bus <= entry->subbus)) {
			/*
			 * found a device whose parent/grandparent is
			 * known to be broken.
			 */
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}
