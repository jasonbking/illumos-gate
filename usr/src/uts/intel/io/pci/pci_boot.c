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
 * Copyright 2019 Western Digital Corporation
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2026 Oxide Computer Company
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * PCI bus enumeration and device programming are done in several passes. The
 * following is a high level overview of this process.
 *
 * pci_enumerate(reprogram=0)
 *				The main entry point to PCI bus enumeration is
 *				pci_enumerate(). This function is invoked
 *				twice, once to set up the PCI portion of the
 *				device tree, and then a second time to
 *				reprogram any devices which were not set up by
 *				the system firmware. On this first call, the
 *				reprogram parameter is set to 0.
 *   pci_init()
 *   				Creates the initial root complex (bus 0).
 *   				No programming of any hardware is done at
 *   				this time. This merely allows access to the
 *   				appropriate PCI configuration space for
 *   				fixups/device enumeration/etc
 *
 *   add_pci_fixes()
 *	enumerate_bus_devs(CONFIG_FIX)
 *	    <foreach bus>
 *	        process_devfunc(CONFIG_FIX)
 *				Some devices need a specific action taking in
 *				order for subsequent enumeration to be
 *				successful. add_pci_fixes() retrieves the
 *				vendor and device IDs for each item on the bus
 *				and applies fixes as required. It also creates
 *				a list which is used by undo_pci_fixes() to
 *				reverse the process later.
 *   pci_setup_tree()
 *	enumerate_bus_devs(CONFIG_INFO)
 *	    <foreach bus>
 *	        process_devfunc(CONFIG_INFO)
 *	            <set up most device properties>
 *				The next stage is to enumerate the bus and set
 *				up the bulk of the properties for each device.
 *				This is where the generic properties such as
 *				'device-id' are created.
 *		    <if PPB device>
 *			add_ppb_props()
 *				For a PCI-to-PCI bridge (ppb) device, any
 *				memory ranges for IO, memory or pre-fetchable
 *				memory that have been programmed by the system
 *				firmware (BIOS/EFI) are retrieved and stored in
 *				bus-specific lists (pci_bus_res[bus].io_avail,
 *				mem_avail and pmem_avail). The contents of
 *				these lists are used to set the initial 'ranges'
 *				property on the ppb device. Later, as children
 *				are found for this bridge, resources will be
 *				removed from these avail lists as necessary.
 *
 *				If the IO or memory ranges have not been
 *				programmed by this point, indicated by the
 *				appropriate bit in the control register being
 *				unset or, in the memory case only, by the base
 *				address being 0, then the range is explicitly
 *				disabled here by setting base > limit for
 *				the resource. Since a zero address is
 *				technically valid for the IO case, the base
 *				address is not checked for IO.
 *
 *				This is an initial pass so the ppb devices can
 *				still be reprogrammed later in fix_ppb_res().
 *		    <else>
 *			<add to list of non-PPB devices for the bus>
 *				Any non-PPB device on the bus is recorded in a
 *				bus-specific list, to be set up (and possibly
 *				reprogrammed) later.
 *		    add_reg_props(CONFIG_INFO)
 *				The final step in this phase is to add the
 *				initial 'reg' and 'assigned-addresses'
 *				properties to all devices. At the same time,
 *				any IO or memory ranges which have been
 *				assigned to the bus are moved from the avail
 *				list to the corresponding used one. If no
 *				resources have been assigned to a device at
 *				this stage, then it is flagged for subsequent
 *				reprogramming.
 *     undo_pci_fixes()
 *				Any fixes which were applied in add_pci_fixes()
 *				are now undone before returning, using the
 *				undo list which was created earier.
 *
 * pci_enumerate(reprogram=1)
 *				The second bus enumeration pass is to take care
 *				of any devices that were not set up by the
 *				system firmware. These devices were flagged
 *				during the first pass. This pass is bracketed
 *				by the same pci fix application and removal as
 *				the first.
 *   add_pci_fixes()
 *				As for first pass.
 *   pci_reprogram()
 *	pci_prd_root_complex_iter()
 *				The platform is asked to tell us of all root
 *				complexes that it knows about (e.g. using the
 *				_BBN method via ACPI). This will include buses
 *				that we've already discovered and those that we
 *				potentially haven't. Anything that has not been
 *				previously discovered (or inferred to exist) is
 *				then added to the system.
 *	<foreach ROOT bus>
 *	    populate_bus_res()
 *				Find resources associated with this root bus
 *				based on what the platform provides through the
 *				pci platform interfaces defined in
 *				sys/plat/pci_prd.h. On i86pc this is driven by
 *				ACPI and BIOS tables.
 *	<foreach bus>
 *	    fix_ppb_res()
 *				Reprogram pci(e) bridges which have not already
 *				had resources assigned, or which are under a
 *				bus that has been flagged for reprogramming.
 *				If the parent bus has not been flagged, then IO
 *				space is reprogrammed only if there are no
 *				assigned IO resources. Memory space is
 *				reprogrammed only if there is both no assigned
 *				ordinary memory AND no assigned pre-fetchable
 *				memory. However, if memory reprogramming is
 *				necessary then both ordinary and prefetch are
 *				done together so that both memory ranges end up
 *				in the avail lists for add_reg_props() to find
 *				later.
 *	    enumerate_bus_devs(CONFIG_NEW)
 *		<foreach non-PPB device on the bus>
 *		    add_reg_props(CONFIG_NEW)
 *				Using the list of non-PPB devices on the bus
 *				which was assembled during the first pass, add
 *				or update the 'reg' and 'assigned-address'
 *				properties for these devices. For devices which
 *				have been flagged for reprogramming or have no
 *				assigned resources, this is where resources are
 *				finally assigned and programmed into the
 *				device. This can result in these properties
 *				changing from their previous values.
 *	<foreach bus>
 *	    add_bus_available_prop()
 *				Finally, the 'available' properties is set on
 *				each device, representing that device's final
 *				unallocated (available) IO and memory ranges.
 *   undo_pci_fixes()
 *				As for first pass.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/pci_props.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/bootconf.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/psw.h>
#include "../../../../common/pci/pci_strings.h"
#include <sys/apic.h>
#include <io/pciex/pcie_nvidia.h>
#include <sys/hotplug/pci/pciehpc_acpi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/iommulib.h>
#include <sys/devcache.h>
#include <sys/pci_cfgacc_x86.h>
#include <sys/plat/pci_prd.h>

#define	dcmn_err	if (pci_boot_debug != 0) cmn_err
#define	bus_debug(bus)	(pci_boot_debug != 0 && pci_debug_bus_start != -1 && \
	    pci_debug_bus_end != -1 && (bus) >= pci_debug_bus_start && \
	    (bus) <= pci_debug_bus_end)
#define	MSGHDR		"!%s[%02x/%02x/%x]: "

#define	CONFIG_INFO	0
#define	CONFIG_UPDATE	1
#define	CONFIG_NEW	2
#define	CONFIG_FIX	3
#define	COMPAT_BUFSIZE	512

#define	PPB_IO_ALIGNMENT	0x1000		/* 4K aligned */
#define	PPB_MEM_ALIGNMENT	0x100000	/* 1M aligned */
/* round down to nearest power of two */
#define	P2LE(align)					\
	{						\
		uint_t i = 0;				\
		while (align >>= 1)			\
			i++;				\
		align = 1ULL << i;			\
	}						\

/*
 * Determining the size of a PCI BAR is done by writing all 1s to the base
 * register and then reading the value back. The retrieved value will either
 * be zero, indicating that the BAR is unimplemented, or a mask in which
 * the significant bits for the required memory space are 0.
 * For example, a 32-bit BAR could return 0xfff00000 which equates to a
 * length of 0x100000 (1MiB). The following macro does that conversion.
 * The input value must have already had the lower encoding bits cleared.
 */
#define	BARMASKTOLEN(value) ((((value) ^ ((value) - 1)) + 1) >> 1)

typedef enum {
	RES_IO,
	RES_MEM,
	RES_PMEM
} mem_res_t;

/*
 * In order to disable an IO or memory range on a bridge, the range's base must
 * be set to a value greater than its limit. The following values are used for
 * this purpose.
 */
#define	PPB_DISABLE_IORANGE_BASE	0x9fff
#define	PPB_DISABLE_IORANGE_LIMIT	0x1000
#define	PPB_DISABLE_MEMRANGE_BASE	0x9ff00000
#define	PPB_DISABLE_MEMRANGE_LIMIT	0x100fffff

/* See AMD-8111 Datasheet Rev 3.03, Page 149: */
#define	LPC_IO_CONTROL_REG_1	0x40
#define	AMD8111_ENABLENMI	(uint8_t)0x80
#define	DEVID_AMD8111_LPC	0x7468

struct pci_fixundo {
	uint16_t		seg;
	uint8_t			bus;
	uint8_t			dev;
	uint8_t			fn;
	void			(*undofn)(uint16_t, uint8_t, uint8_t, uint8_t);
	struct pci_fixundo	*next;
};

struct pci_devfunc {
	struct pci_devfunc *next;
	dev_info_t *dip;
	uchar_t dev;
	uchar_t func;
	boolean_t reprogram;	/* this device needs to be reprogrammed */
};

extern int apic_nvidia_io_max;
static uchar_t max_dev_pci = 32;	/* PCI standard */
int pci_boot_maxbus;

int pci_boot_debug = 0;
int pci_debug_bus_start = -1;
int pci_debug_bus_end = -1;

static struct pci_fixundo *undolist = NULL;
static int num_root_bus = 0;	/* count of root buses */
extern void pci_cfgacc_add_workaround(uint16_t, uchar_t, uchar_t);
extern dev_info_t *pcie_get_rc_dip(dev_info_t *);

/*
 * Module prototypes
 */
static boolean_t enumerate_bus_devs(uint16_t seg, uchar_t bus, void *arg);
static void create_root_bus_dip(uint16_t seg, uchar_t bus);
static void process_devfunc(dev_info_t *, uchar_t, uchar_t, uchar_t, int);
static boolean_t add_reg_props(dev_info_t *, uchar_t, uchar_t, uchar_t, int,
    boolean_t);
static void add_ppb_props(dev_info_t *, uint16_t, uchar_t, uchar_t, uchar_t,
    boolean_t, boolean_t);
static void add_bus_range_prop(uint16_t, uint8_t);
static void add_ranges_prop(uint16_t, uchar_t, boolean_t);
static boolean_t add_bus_available_prop(uint16_t, uint8_t, void *);
static int get_pci_cap(dev_info_t *dip, pcie_req_id_t bdf, uint8_t cap_id);
static boolean_t fix_ppb_res(uint16_t, uint8_t, void *);
static void alloc_res_array(void);
static void create_ioapic_node(int bus, int dev, int fn, ushort_t vendorid,
    ushort_t deviceid);
static void populate_bus_res(uint16_t seg, uchar_t bus);
static void ck804_fix_aer_ptr(dev_info_t *, pcie_req_id_t);

static int pci_unitaddr_cache_valid(void);
static int pci_bus_unitaddr(int);
static void pci_unitaddr_cache_create(void);

static int pci_cache_unpack_nvlist(nvf_handle_t, nvlist_t *, char *);
static int pci_cache_pack_nvlist(nvf_handle_t, nvlist_t **);
static void pci_cache_free_list(nvf_handle_t);

/* set non-zero to force PCI peer-bus renumbering */
int pci_bus_always_renumber = 0;

/*
 * used to register ISA resource usage which must not be made
 * "available" from other PCI node' resource maps
 */
static struct {
	struct memlist *io_used;
	struct memlist *mem_used;
} isa_res;

/*
 * PCI unit-address cache management
 */
static nvf_ops_t pci_unitaddr_cache_ops = {
	"/etc/devices/pci_unitaddr_persistent",	/* path to cache */
	pci_cache_unpack_nvlist,		/* read in nvlist form */
	pci_cache_pack_nvlist,			/* convert to nvlist form */
	pci_cache_free_list,			/* free data list */
	NULL					/* write complete callback */
};

typedef struct {
	list_node_t	pua_nodes;
	int		pua_index;
	int		pua_addr;
} pua_node_t;

nvf_handle_t	puafd_handle;
int		pua_cache_valid = 0;

static void dump_memlists_impl(struct pci_bus_resource *);
static struct pci_bus_resource *get_bus_res(uint16_t, uint8_t);

static inline void
dump_memlists(const char *tag, uint16_t seg, uchar_t bus)
{
	if (bus_debug(bus)) {
		printf("Memlist dump at %s - bus %x\n", tag, bus);
		dump_memlists_impl(get_bus_res(seg, bus));
	}
}

static struct pci_bus_resource *
get_bus_res(uint16_t segment, uint8_t bus)
{
	uint_t i, idx;
	uint32_t min_bus, max_bus;
	uint16_t max_seg;

	max_seg = pci_prd_max_segment();
	min_bus = pci_prd_min_bus(segment);
	max_bus = pci_prd_max_bus(segment);

	if (min_bus == UINT32_MAX || max_bus == UINT32_MAX ||
	    segment > max_seg || bus < min_bus || bus > max_bus) {
		return (NULL);
	}

	for (i = idx = 0; i < segment; i++) {
		if (pci_prd_min_bus(i) != UINT32_MAX) {
			idx++;
		}
	}

	return (&pci_bus_res[idx][bus]);
}

dev_info_t *
pci_boot_bus_to_dip(uint16_t seg, uint32_t busno)
{
	struct pci_bus_resource *res;

	if (busno > UINT8_MAX)
		return (NULL);

	res = get_bus_res(seg, busno);
	if (res == NULL)
		return (NULL);

	return (res->dip);
}

static dev_info_t *
get_rcdip(uint16_t seg)
{
	struct pci_bus_resource *r;
	uint_t min_bus;

	min_bus = pci_prd_min_bus(seg);
	if (min_bus == UINT32_MAX) {
		return (NULL);
	}

	r = get_bus_res(seg, min_bus);
	if (r == NULL) {
		return (NULL);
	}

	ASSERT3P(r->dip, !=, NULL);
	return (r->dip);
}

static uint16_t
get_segment(dev_info_t *dip)
{
	int seg;

	seg = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "pci-segment", 0);

	/* We set it, so this should be valid */
	ASSERT3S(seg, >=, 0);
	ASSERT3S(seg, <=, UINT16_MAX);
	return (seg);
}

static void
iter_buses(boolean_t (*cb)(uint16_t, uint8_t, void *), void *arg)
{
	uint32_t seg, bus, min_bus, max_bus;

	for (seg = 0; seg != UINT32_MAX; seg = pci_prd_next_segment(seg)) {
		min_bus = pci_prd_min_bus(seg);
		max_bus = pci_prd_max_bus(seg);

		ASSERT3U(min_bus, !=, UINT32_MAX);
		ASSERT3U(max_bus, !=, UINT32_MAX);

		for (bus = min_bus; bus <= max_bus; bus++) {
			if (!cb(seg, bus, arg))
				return;
		}
	}
}

static void
print_memlist(const struct memlist *list)
{
	printf("0x%p content: ", (const void *)list);
	for (; list != NULL; list = list->ml_next)
		printf("(0x%lx, 0x%lx) ", list->ml_address, list->ml_size);
	printf("\n");
}

static void
dump_memlists_impl(struct pci_bus_resource *r)
{
	if (r->io_used != NULL) {
		printf("    io_used ");
		print_memlist(r->io_used);
	}
	if (r->io_avail != NULL) {
		printf("    io_avail ");
		print_memlist(r->io_avail);
	}
	if (r->mem_used != NULL) {
		printf("    mem_used ");
		print_memlist(r->mem_used);
	}
	if (r->mem_avail != NULL) {
		printf("    mem_avail ");
		print_memlist(r->mem_avail);
	}
	if (r->pmem_used != NULL) {
		printf("    pmem_used ");
		print_memlist(r->pmem_used);
	}
	if (r->pmem_avail != NULL) {
		printf("    pmem_avail ");
		print_memlist(r->pmem_avail);
	}
}

static boolean_t
pci_rc_scan_cb(uint16_t seg, uint32_t busno, void *arg)
{
	struct pci_bus_resource *r;
	uint32_t max_bus = pci_prd_max_bus(seg);

	if (busno == UINT32_MAX || max_bus == UINT32_MAX ||
	    busno > max_bus) {
		dcmn_err(CE_NOTE, "platform root complex scan returned bus "
		    "with invalid bus id: 0x%x on segment %u", busno, seg);
		return (B_TRUE);
	}

	r = get_bus_res(seg, busno);

	if (r->par_bus == UCHAR_MAX && r->dip == NULL) {
		create_root_bus_dip(seg, (uchar_t)busno);
	}

	return (B_TRUE);
}

static void
pci_unitaddr_cache_init(void)
{

	puafd_handle = nvf_register_file(&pci_unitaddr_cache_ops);
	ASSERT(puafd_handle);

	list_create(nvf_list(puafd_handle), sizeof (pua_node_t),
	    offsetof(pua_node_t, pua_nodes));

	rw_enter(nvf_lock(puafd_handle), RW_WRITER);
	(void) nvf_read_file(puafd_handle);
	rw_exit(nvf_lock(puafd_handle));
}

/*
 * Format of /etc/devices/pci_unitaddr_persistent:
 *
 * The persistent record of unit-address assignments contains
 * a list of name/value pairs, where name is a string representation
 * of the "index value" of the PCI root-bus and the value is
 * the assigned unit-address.
 *
 * The "index value" is simply the zero-based index of the PCI
 * root-buses ordered by physical bus number; first PCI bus is 0,
 * second is 1, and so on.
 */

static int
pci_cache_unpack_nvlist(nvf_handle_t hdl, nvlist_t *nvl, char *name)
{
	long		index;
	int32_t		value;
	nvpair_t	*np;
	pua_node_t	*node;

	np = NULL;
	while ((np = nvlist_next_nvpair(nvl, np)) != NULL) {
		/* name of nvpair is index value */
		if (ddi_strtol(nvpair_name(np), NULL, 10, &index) != 0)
			continue;

		if (nvpair_value_int32(np, &value) != 0)
			continue;

		node = kmem_zalloc(sizeof (pua_node_t), KM_SLEEP);
		node->pua_index = index;
		node->pua_addr = value;
		list_insert_tail(nvf_list(hdl), node);
	}

	pua_cache_valid = 1;
	return (DDI_SUCCESS);
}

static int
pci_cache_pack_nvlist(nvf_handle_t hdl, nvlist_t **ret_nvl)
{
	int		rval;
	nvlist_t	*nvl, *sub_nvl;
	list_t		*listp;
	pua_node_t	*pua;
	char		buf[13];

	ASSERT(RW_WRITE_HELD(nvf_lock(hdl)));

	rval = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != DDI_SUCCESS) {
		nvf_error("%s: nvlist alloc error %d\n",
		    nvf_cache_name(hdl), rval);
		return (DDI_FAILURE);
	}

	sub_nvl = NULL;
	rval = nvlist_alloc(&sub_nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != DDI_SUCCESS)
		goto error;

	listp = nvf_list(hdl);
	for (pua = list_head(listp); pua != NULL;
	    pua = list_next(listp, pua)) {
		(void) snprintf(buf, sizeof (buf), "%d", pua->pua_index);
		rval = nvlist_add_int32(sub_nvl, buf, pua->pua_addr);
		if (rval != DDI_SUCCESS)
			goto error;
	}

	rval = nvlist_add_nvlist(nvl, "table", sub_nvl);
	if (rval != DDI_SUCCESS)
		goto error;
	nvlist_free(sub_nvl);

	*ret_nvl = nvl;
	return (DDI_SUCCESS);

error:
	nvlist_free(sub_nvl);
	ASSERT(nvl);
	nvlist_free(nvl);
	*ret_nvl = NULL;
	return (DDI_FAILURE);
}

static void
pci_cache_free_list(nvf_handle_t hdl)
{
	list_t		*listp;
	pua_node_t	*pua;

	ASSERT(RW_WRITE_HELD(nvf_lock(hdl)));

	listp = nvf_list(hdl);
	while ((pua = list_remove_head(listp)) != NULL) {
		kmem_free(pua, sizeof (pua_node_t));
	}
}


static int
pci_unitaddr_cache_valid(void)
{

	/* read only, no need for rw lock */
	return (pua_cache_valid);
}


static int
pci_bus_unitaddr(int index)
{
	pua_node_t	*pua;
	list_t		*listp;
	int		addr;

	rw_enter(nvf_lock(puafd_handle), RW_READER);

	addr = -1;	/* default return if no match */
	listp = nvf_list(puafd_handle);
	for (pua = list_head(listp); pua != NULL;
	    pua = list_next(listp, pua)) {
		if (pua->pua_index == index) {
			addr = pua->pua_addr;
			break;
		}
	}

	rw_exit(nvf_lock(puafd_handle));
	return (addr);
}

static void
pci_unitaddr_cache_create(void)
{
	int		i, index;
	pua_node_t	*node;
	list_t		*listp;

	rw_enter(nvf_lock(puafd_handle), RW_WRITER);

	index = 0;
	listp = nvf_list(puafd_handle);
	for (i = 0; i <= pci_boot_maxbus; i++) {
		struct pci_bus_resource *r = get_bus_res(0, i);

		/* skip non-root (peer) PCI busses */
		if (r->par_bus != (uchar_t)-1 || r->dip == NULL)
			continue;
		node = kmem_zalloc(sizeof (pua_node_t), KM_SLEEP);
		node->pua_index = index++;
		node->pua_addr = r->root_addr;
		list_insert_tail(listp, node);
	}

	(void) nvf_mark_dirty(puafd_handle);
	rw_exit(nvf_lock(puafd_handle));
	nvf_wake_daemon();
}

static boolean_t
pci_init_scan_cb(uint16_t seg, uint32_t busno, void *arg __unused)
{
	/* We already handled segment 0 in pci_init() */
	if (seg == 0) {
		return (B_TRUE);
	}

	/*
	 * For all other segments, we only want the first bus in the
	 * segment since that's the root complex
	 */
	if (busno != pci_prd_min_bus(seg)) {
		return (B_TRUE);
	}

	create_root_bus_dip(seg, busno);
	return (B_TRUE);
}


void
pci_init(void)
{
	alloc_res_array();

	/*
	 * create_root_bus_dip() requires root_addr[bus] is assigned,
	 * so we do that now
	 */
	pci_bus_res[0][0].root_addr = 0;
	create_root_bus_dip(0, 0);

	/*
	 * Create the root complex dips for all of the additional PCI
	 * segments.
	 */
	pci_prd_root_complex_iter(pci_init_scan_cb, NULL);
}

/*
 * Enumerate all PCI devices
 */
void
pci_setup_tree(void)
{
	/* We assigned addr 0 in pci_init(), so start with 1 */
	uint_t i, seg, min_bus, max_bus, root_bus_addr = 1;

	(void) enumerate_bus_devs(0, 0, (intptr_t)CONFIG_INFO);

	/*
	 * Now enumerate peer busses
	 *
	 * We loop till pci_boot_maxbus. On most systems, there is
	 * one more bus at the high end, which implements the ISA
	 * compatibility bus. We don't care about that.
	 *
	 * Note: In the old (bootconf) enumeration, the peer bus
	 *	address did not use the bus number, and there were
	 *	too many peer busses created. The root_bus_addr is
	 *	used to maintain the old peer bus address assignment.
	 *	However, we stop enumerating phantom peers with no
	 *	device below.
	 */
	max_bus = pci_prd_max_bus(0);
	ASSERT3U(max_bus, !=, UINT32_MAX);

	for (i = 1; i <= max_bus; i++) {
		if (pci_bus_res[0][i].dip == NULL) {
			pci_bus_res[0][i].root_addr = root_bus_addr++;
		}
		(void) enumerate_bus_devs(0, i, (intptr_t)CONFIG_INFO);
	}

	/*
	 * We just handled segment 0 above, so handle the rest of the segments.
	 * Since PCI segments postdate bootconf, there are no legacy bus
	 * numbers we have to preserve for those segments.
	 */
	for (seg = pci_prd_next_segment(0); seg != UINT32_MAX;
	    seg = pci_prd_next_segment(seg)) {
		min_bus = pci_prd_min_bus(seg);
		max_bus = pci_prd_max_bus(seg);

		for (i = min_bus; i <= max_bus; i++) {
			(void) enumerate_bus_devs(seg, i,
			    (intptr_t)CONFIG_INFO);
		}
	}
}

void
pci_register_isa_resources(int type, uint32_t base, uint32_t size)
{
	memlist_rsrc_add((type == 1) ? &isa_res.io_used : &isa_res.mem_used,
	    base, size);
}

/*
 * Remove the resources which are already used by devices under a subtractive
 * bridge from the bus's resources lists, because they're not available, and
 * shouldn't be allocated to other buses.  This is necessary because tracking
 * resources for subtractive bridges is not complete.  (Subtractive bridges only
 * track some of their claimed resources, not "the rest of the address space" as
 * they should, so that allocation to peer non-subtractive PPBs is easier.  We
 * need a fully-capable global resource allocator).
 */
static boolean_t
remove_subtractive_res(uint16_t seg, uint8_t bus, void *arg __unused)
{
	struct pci_bus_resource *r, *r2;
	struct memlist *list;
	uint_t i;
	uint16_t min_bus, max_bus;

	r = get_bus_res(seg, bus);

	if (r->subtractive)
		return (B_TRUE);

	min_bus = pci_prd_min_bus(seg);
	max_bus = pci_prd_max_bus(seg);

	/* remove used io ports */
	list = r->io_used;
	while (list != NULL) {
		for (i = min_bus; i <= max_bus; i++) {
			r2 = get_bus_res(seg, i);

			memlist_rsrc_delete(&r2->io_avail,
			    list->ml_address, list->ml_size);
		}
		list = list->ml_next;
	}

	/* remove used mem resource */
	list = r->mem_used;
	while (list != NULL) {
		for (i = min_bus; i <= max_bus; i++) {
			r2 = get_bus_res(seg, i);

			memlist_rsrc_delete(&r2->mem_avail,
			    list->ml_address, list->ml_size);
			memlist_rsrc_delete(&r2->pmem_avail,
			    list->ml_address, list->ml_size);
		}
		list = list->ml_next;
	}

	/* remove used prefetchable mem resource */
	list = r->pmem_used;
	while (list != NULL) {
		for (i = min_bus; i <= max_bus; i++) {
			r2 = get_bus_res(seg, i);

			memlist_rsrc_delete(&r2->pmem_avail,
			    list->ml_address, list->ml_size);
			memlist_rsrc_delete(&r2->mem_avail,
			    list->ml_address, list->ml_size);
		}
		list = list->ml_next;
	}

	return (B_TRUE);
}

/*
 * Set up (or complete the setup of) the bus_avail resource list
 */
static void
setup_bus_res(uint16_t seg, int bus)
{
	struct pci_bus_resource *r = get_bus_res(seg, bus);
	uchar_t par_bus;

	if (r->dip == NULL)	/* unused bus */
		return;

	/*
	 * Set up bus_avail if not already filled in by populate_bus_res()
	 */
	if (r->bus_avail == NULL) {
		ASSERT(r->sub_bus >= bus);
		memlist_rsrc_add(&r->bus_avail, bus, r->sub_bus - bus + 1);
	}

	ASSERT(r->bus_avail != NULL);

	/*
	 * Remove resources from parent bus node if this is not a
	 * root bus.
	 */
	par_bus = r->par_bus;
	if (par_bus != (uchar_t)-1) {
		struct pci_bus_resource *par_bus_res;

		par_bus_res = get_bus_res(seg, par_bus);

		ASSERT(par_bus_res->bus_avail != NULL);
		memlist_rsrc_delete_list(&par_bus_res->bus_avail, r->bus_avail);
	}

	/* remove self from bus_avail */;
	memlist_rsrc_delete(&r->bus_avail, bus, 1);
}

/*
 * Return the bus from which resources should be allocated. A device under a
 * subtractive PPB can allocate resources from its parent bus if there are no
 * resources available on its own bus, so iterate up the chain until resources
 * are found or the root is reached.
 */
static uchar_t
resolve_alloc_bus(uint16_t seg, uchar_t bus, mem_res_t type)
{
	struct pci_bus_resource *r;

	r = get_bus_res(seg, bus);
	while (r->subtractive) {
		if (type == RES_IO && r->io_avail != NULL)
			break;
		if (type == RES_MEM && r->mem_avail != NULL)
			break;
		if (type == RES_PMEM && r->pmem_avail != NULL)
			break;
		/* Has the root bus been reached? */
		if (r->par_bus == (uchar_t)-1)
			break;
		bus = r->par_bus;
		r = get_bus_res(seg, bus);
	}

	return (bus);
}

/*
 * Each root port has a record of the number of PCIe bridges that is under it
 * and the amount of memory that is has available which is not otherwise
 * required for BARs.
 *
 * This function finds the root port for a given bus and returns the amount of
 * spare memory that is available for allocation to any one of its bridges. In
 * general, not all bridges end up being reprogrammed, so this is usually an
 * underestimate. A smarter allocator could account for this by building up a
 * better picture of the topology.
 */
static uint64_t
get_per_bridge_avail(uint16_t seg, uchar_t bus)
{
	struct pci_bus_resource *r;
	uchar_t par_bus;

	r = get_bus_res(seg, bus);
	par_bus = r->par_bus;
	while (par_bus != (uchar_t)-1) {
		bus = par_bus;
		r = get_bus_res(seg, bus);
		par_bus = r->par_bus;
	}

	if (r->mem_buffer == 0 || r->num_bridge == 0) {
		return (0);
	}

	return (r->mem_buffer / r->num_bridge);
}

/*
 * Return the list of resources of the given type still available on the given
 * bus, or NULL if we may not allocate from it at all.
 */
static struct memlist **
parbus_res_avail(uint16_t seg, uchar_t parbus, mem_res_t type)
{
	struct pci_bus_resource *r;
	struct memlist **list;

	r = get_bus_res(seg, parbus);

	/*
	 * Skip root(peer) buses in multiple-root-bus systems when
	 * ACPI resource discovery was not successfully done; the
	 * initial resources set on each root bus might not be correctly
	 * accounted for in this case.
	 */
	if (r->par_bus == (uchar_t)-1 &&
	    num_root_bus > 1 && !pci_prd_multi_root_ok()) {
		return (NULL);
	}

	parbus = resolve_alloc_bus(seg, parbus, type);
	r = get_bus_res(seg, parbus);

	switch (type) {
	case RES_IO:
		list = &r->io_avail;
		break;
	case RES_MEM:
		list = &r->mem_avail;
		break;
	case RES_PMEM:
		list = &r->pmem_avail;
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	return (list);
}

/*
 * Claim a span from the parent bus, which is removed from its available list on
 * success.  Returns whether one was found and leaves *addrp alone if not.
 */
static boolean_t
lookup_parbus_res(uint16_t seg, uchar_t parbus, uint64_t size, uint64_t align,
    mem_res_t type, uint64_t *addrp)
{
	struct memlist **list;

	list = parbus_res_avail(seg, parbus, type);

	if (list == NULL)
		return (B_FALSE);

	return (memlist_rsrc_claim(list, size, align, addrp) ==
	    MEML_SPANOP_OK);
}

/*
 * Allocate a resource from the parent bus
 */
static boolean_t
get_parbus_res(uint16_t seg, uchar_t parbus, uchar_t bus, uint64_t size,
    uint64_t align, mem_res_t type, uint64_t *addrp)
{
	struct pci_bus_resource *par_res, *res;
	struct memlist **par_avail, **par_used, **avail, **used;
	uint64_t addr;

	parbus = resolve_alloc_bus(seg, parbus, type);

	par_res = get_bus_res(seg, parbus);
	res = get_bus_res(seg, bus);

	switch (type) {
	case RES_IO:
		par_avail = &par_res->io_avail;
		par_used = &par_res->io_used;
		avail = &res->io_avail;
		used = &res->io_used;
		break;
	case RES_MEM:
		par_avail = &par_res->mem_avail;
		par_used = &par_res->mem_used;
		avail = &res->mem_avail;
		used = &res->mem_used;
		break;
	case RES_PMEM:
		par_avail = &par_res->pmem_avail;
		par_used = &par_res->pmem_used;
		avail = &res->pmem_avail;
		used = &res->pmem_used;
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	/* Return any existing resources to the parent bus */
	memlist_rsrc_subsume(used, avail);
	for (struct memlist *m = *avail; m != NULL; m = m->ml_next) {
		memlist_rsrc_delete(par_used, m->ml_address, m->ml_size);
		memlist_rsrc_add(par_avail, m->ml_address, m->ml_size);
	}
	memlist_rsrc_free(avail);

	if (!lookup_parbus_res(seg, parbus, size, align, type, &addr))
		return (B_FALSE);

	/*
	 * The system may have provided a 64-bit non-PF memory region to the
	 * parent bus, but we cannot use that for programming a bridge. Since
	 * the memlists are kept sorted by base address and searched in order,
	 * then if we received a 64-bit address here we know that the request
	 * is unsatisfiable from the available 32-bit ranges.
	 */
	if (type == RES_MEM &&
	    (addr >= UINT32_MAX || addr >= UINT32_MAX - size)) {
		/*
		 * Return the span to the parent bus' available list.
		 */
		memlist_rsrc_add(par_avail, addr, size);
		return (B_FALSE);
	}

	memlist_rsrc_add(par_used, addr, size);
	memlist_rsrc_add(avail, addr, size);

	*addrp = addr;

	return (B_TRUE);
}

/*
 * given a cap_id, return its cap_id location in config space
 */
static int
get_pci_cap(dev_info_t *dip, pcie_req_id_t bdf, uint8_t cap_id)
{
	uint8_t curcap, cap_id_loc;
	uint16_t status;
	int location = -1;

	/*
	 * Need to check the Status register for ECP support first.
	 * Also please note that for type 1 devices, the
	 * offset could change. Should support type 1 next.
	 */
	status = pci_cfgacc_get16(dip, bdf, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		return (-1);
	}
	cap_id_loc = pci_cfgacc_get8(dip, bdf, PCI_CONF_CAP_PTR);

	/* Walk the list of capabilities */
	while (cap_id_loc && cap_id_loc != (uint8_t)-1) {
		curcap = pci_cfgacc_get8(dip, bdf, cap_id_loc);

		if (curcap == cap_id) {
			location = cap_id_loc;
			break;
		}
		cap_id_loc = pci_cfgacc_get8(dip, bdf, cap_id_loc + 1);
	}
	return (location);
}

/*
 * Does this resource element live in the legacy VGA range?
 */

static boolean_t
is_vga(struct memlist *elem, mem_res_t type)
{
	switch (type) {
	case RES_IO:
		if ((elem->ml_address == 0x3b0 && elem->ml_size == 0xc) ||
		    (elem->ml_address == 0x3c0 && elem->ml_size == 0x20)) {
			return (B_TRUE);
		}
		break;
	case RES_MEM:
		if (elem->ml_address == 0xa0000 && elem->ml_size == 0x20000)
			return (B_TRUE);
		break;
	case RES_PMEM:
		break;
	}
	return (B_FALSE);
}

/*
 * Does this entire resource list consist only of legacy VGA resources?
 */

static boolean_t
list_is_vga_only(struct memlist *l, mem_res_t type)
{
	if (l == NULL) {
		return (B_FALSE);
	}

	do {
		if (!is_vga(l, type))
			return (B_FALSE);
	} while ((l = l->ml_next) != NULL);
	return (B_TRUE);
}

/*
 * Find the start and end addresses that cover the range for all list entries,
 * excluding legacy VGA addresses. Relies on the list being sorted.
 */
static void
pci_res_span(struct memlist *list, mem_res_t type, uint64_t *basep,
    uint64_t *limitp)
{
	*limitp = *basep = 0;

	for (; list != NULL; list = list->ml_next) {
		if (is_vga(list, type))
			continue;

		if (*basep == 0)
			*basep = list->ml_address;

		if (list->ml_address + list->ml_size >= *limitp)
			*limitp = list->ml_address + list->ml_size - 1;
	}
}

static void
set_ppb_res(dev_info_t *dip, pcie_req_id_t bdf, mem_res_t type,
    uint64_t base, uint64_t limit)
{
	char *tag;

	switch (type) {
	case RES_IO: {
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put8(dip, bdf, PCI_BCNF_IO_BASE_LOW,
		    (uint8_t)((base >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));
		pci_cfgacc_put8(dip, bdf, PCI_BCNF_IO_LIMIT_LOW,
		    (uint8_t)((limit >> PCI_BCNF_IO_SHIFT) & PCI_BCNF_IO_MASK));

		uint8_t val = pci_cfgacc_get8(dip, bdf, PCI_BCNF_IO_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			pci_cfgacc_put16(dip, bdf, PCI_BCNF_IO_BASE_HI,
			    base >> 16);
			pci_cfgacc_put16(dip, bdf, PCI_BCNF_IO_LIMIT_HI,
			    limit >> 16);
		} else {
			VERIFY0(base >> 16);
			VERIFY0(limit >> 16);
		}

		tag = "I/O";
		break;
	}

	case RES_MEM:
		VERIFY0(base >> 32);
		VERIFY0(limit >> 32);

		pci_cfgacc_put16(dip, bdf, PCI_BCNF_MEM_BASE,
		    (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(dip, bdf, PCI_BCNF_MEM_LIMIT,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		tag = "MEM";
		break;

	case RES_PMEM: {
		pci_cfgacc_put16(dip, bdf, PCI_BCNF_PF_BASE_LOW,
		    (uint16_t)((base >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));
		pci_cfgacc_put16(dip, bdf, PCI_BCNF_PF_LIMIT_LOW,
		    (uint16_t)((limit >> PCI_BCNF_MEM_SHIFT) &
		    PCI_BCNF_MEM_MASK));

		uint16_t val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_PF_BASE_LOW);
		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			pci_cfgacc_put32(dip, bdf, PCI_BCNF_PF_BASE_HIGH,
			    base >> 32);
			pci_cfgacc_put32(dip, bdf, PCI_BCNF_PF_LIMIT_HIGH,
			    limit >> 32);
		} else {
			VERIFY0(base >> 32);
			VERIFY0(limit >> 32);
		}

		tag = "PMEM";
		break;
	}

	default:
		panic("Invalid resource type %d", type);
	}

	if (base > limit) {
		uint8_t bus = (bdf >> 8) & 0xff;
		uint8_t dev = (bdf >> 3) & 0x1f;
		uint8_t func = bdf & 0x7;

		cmn_err(CE_NOTE, MSGHDR "DISABLE %4s range",
		    "ppb", bus, dev, func, tag);
	} else {
		uint8_t bus = (bdf >> 8) & 0xff;
		uint8_t dev = (bdf >> 3) & 0x1f;
		uint8_t func = bdf & 0x7;

		cmn_err(CE_NOTE,
		    MSGHDR "PROGRAM %4s range 0x%lx ~ 0x%lx",
		    "ppb", bus, dev, func, tag, base, limit);
	}
}

static void
fetch_ppb_res(dev_info_t *dip, pcie_req_id_t bdf, mem_res_t type,
    uint64_t *basep, uint64_t *limitp)
{
	uint64_t val, base, limit;

	switch (type) {
	case RES_IO:
		val = pci_cfgacc_get8(dip, bdf, PCI_BCNF_IO_LIMIT_LOW);
		limit = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT) |
		    PCI_BCNF_IO_LIMIT_BITS;
		val = pci_cfgacc_get8(dip, bdf, PCI_BCNF_IO_BASE_LOW);
		base = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_IO_BASE_HI);
			base |= val << 16;
			val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_IO_LIMIT_HI);
			limit |= val << 16;
		}
		VERIFY0(base >> 32);
		break;

	case RES_MEM:
		val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_MEM_LIMIT);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_MEM_BASE);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);
		VERIFY0(base >> 32);
		break;

	case RES_PMEM:
		val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_PF_LIMIT_LOW);
		limit = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
		    PCI_BCNF_MEM_LIMIT_BITS;
		val = pci_cfgacc_get16(dip, bdf, PCI_BCNF_PF_BASE_LOW);
		base = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);

		if ((val & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
			val = pci_cfgacc_get32(dip, bdf, PCI_BCNF_PF_BASE_HIGH);
			base |= val << 32;
			val = pci_cfgacc_get32(dip, bdf,
			   PCI_BCNF_PF_LIMIT_HIGH);
			limit |= val << 32;
		}
		break;
	default:
		panic("Invalid resource type %d", type);
	}

	*basep = base;
	*limitp = limit;
}

/*
 * Assign valid resources to unconfigured pci(e) bridges. We are trying
 * to reprogram the bridge when its
 *		i)   SECBUS == SUBBUS	||
 *		ii)  IOBASE > IOLIM	||
 *		iii) MEMBASE > MEMLIM && PMEMBASE > PMEMLIM
 * This must be done after one full pass through the PCI tree to collect
 * all firmware-configured resources, so that we know what resources are
 * free and available to assign to the unconfigured PPBs.
 */
static boolean_t
fix_ppb_res(uint16_t seg, uint8_t secbus, void *arg)
{
	uchar_t bus, dev, func;
	uchar_t parbus, subbus;
	struct {
		uint64_t base;
		uint64_t limit;
		uint64_t size;
		uint64_t align;
	} io, mem, pmem;
	uint64_t addr = 0;
	int *regp = NULL;
	uint_t reglen, buscount;
	int rv, cap_ptr, physhi;
	dev_info_t *dip;
	uint16_t cmd_reg;
	struct memlist *scratch_list;
	struct memlist **parbus_pmem;
	struct pci_bus_resource *sec_res, *par_res;
	boolean_t reprogram_io, reprogram_mem;
	boolean_t prog_sub = (boolean_t)(uintptr_t)arg;
	pcie_req_id_t bdf;

	sec_res = get_bus_res(seg, secbus);

	/* skip root (peer) PCI busses */
	if (sec_res->par_bus == (uchar_t)-1)
		return (B_TRUE);

	/* skip subtractive PPB when prog_sub is not TRUE */
	if (sec_res->subtractive && !prog_sub)
		return (B_TRUE);

	/* some entries may be empty due to discontiguous bus numbering */
	dip = pci_boot_bus_to_dip(seg, secbus);
	if (dip == NULL)
		return (B_TRUE);

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regp, &reglen);
	if (rv != DDI_PROP_SUCCESS || reglen == 0)
		return (B_TRUE);
	physhi = regp[0];
	ddi_prop_free(regp);

	func = (uchar_t)PCI_REG_FUNC_G(physhi);
	dev = (uchar_t)PCI_REG_DEV_G(physhi);
	bus = (uchar_t)PCI_REG_BUS_G(physhi);

	bdf = PCI_GETBDF(bus, dev, func);

	dump_memlists("fix_ppb_res start bus", seg, bus);
	dump_memlists("fix_ppb_res start secbus", seg, secbus);

	/*
	 * If pcie bridge, check to see if link is enabled
	 */
	cap_ptr = get_pci_cap(dip, bdf, PCI_CAP_ID_PCI_E);
	if (cap_ptr != -1) {
		uint16_t reg = pci_cfgacc_get16(dip, bdf,
		    (uint16_t)cap_ptr + PCIE_LINKCTL);
		if ((reg & PCIE_LINKCTL_LINK_DISABLE) != 0) {
			dcmn_err(CE_NOTE, MSGHDR "link is disabled",
			    "ppb", bus, dev, func);
			return (B_TRUE);
		}
	}

	subbus = pci_cfgacc_get8(dip, bdf, PCI_BCNF_SUBBUS);
	parbus = sec_res->par_bus;
	ASSERT(parbus == bus);
	cmd_reg = pci_cfgacc_get16(dip, bdf, PCI_CONF_COMM);

	par_res = get_bus_res(seg, parbus);

	/*
	 * If we have a Cardbus bridge, but no bus space
	 */
	if (sec_res->num_cbb != 0 &&
	    sec_res->bus_avail == NULL) {
		uchar_t range;

		/* normally there are 2 buses under a cardbus bridge */
		range = sec_res->num_cbb * 2;

		/*
		 * Try to find and allocate a bus-range starting at subbus+1
		 * from the parent of the PPB.
		 */
		for (; range != 0; range--) {
			uint64_t found;

			if (memlist_rsrc_claim_at(
			    &par_res->bus_avail,
			    subbus + 1, range, 1, &found) == MEML_SPANOP_OK) {
				break; /* find bus range resource at parent */
			}
		}
		if (range != 0) {
			memlist_rsrc_add(&sec_res->bus_avail,
			    subbus + 1, range);
			subbus = subbus + range;
			sec_res->sub_bus = subbus;
			pci_cfgacc_put8(dip, bdf, PCI_BCNF_SUBBUS, subbus);
			add_bus_range_prop(seg, secbus);

			cmn_err(CE_NOTE,
			    MSGHDR "PROGRAM cardbus buses 0x%x ~ 0x%x",
			    "cbb", bus, dev, func, secbus, subbus);
		}
	}

	buscount = subbus - secbus + 1;

	dcmn_err(CE_NOTE, MSGHDR
	    "secbus 0x%x existing sizes I/O 0x%x, MEM 0x%lx, PMEM 0x%lx",
	    "ppb", bus, dev, func, secbus,
	    sec_res->io_size, sec_res->mem_size, sec_res->pmem_size);

	/*
	 * If the bridge's I/O range needs to be reprogrammed, then the
	 * bridge is going to be allocated the greater of:
	 *  - 512 bytes per downstream bus;
	 *  - the amount required by its current children.
	 * rounded up to the next 4K.
	 */
	io.size = MAX(sec_res->io_size, buscount * 0x200);

	/*
	 * Similarly if the memory ranges need to be reprogrammed, then we'd
	 * like to assign some extra memory to the bridge in case there is
	 * anything hotplugged underneath later.
	 *
	 * We use the information gathered earlier relating to the number of
	 * bridges that must share the resource of this bus' root port, and how
	 * much memory is available that isn't already accounted for to
	 * determine how much to use.
	 *
	 * At least the existing `mem_size` must be allocated as that has been
	 * gleaned from enumeration.
	 */
	uint64_t avail = get_per_bridge_avail(seg, bus);

	mem.size = 0;
	if (avail > 0) {
		/* Try 32MiB first, then adjust down until it fits */
		for (uint_t i = 32; i > 0; i >>= 1) {
			if (avail >= buscount * PPB_MEM_ALIGNMENT * i) {
				mem.size = buscount * PPB_MEM_ALIGNMENT * i;
				dcmn_err(CE_NOTE, MSGHDR
				    "Allocating %uMiB",
				    "ppb", bus, dev, func, i);
				break;
			}
		}
	}
	mem.size = MAX(sec_res->mem_size, mem.size);

	/*
	 * For the PF memory range, illumos has not historically handed out
	 * any additional memory to bridges. However there are some
	 * hotpluggable devices which need 64-bit PF space and so we now always
	 * attempt to allocate at least 32 MiB. If there is enough space
	 * available from a parent then we will increase this to 512MiB.
	 * If we're later unable to find memory to satisfy this, we just move
	 * on and are no worse off than before.
	 */
	pmem.size = MAX(sec_res->pmem_size,
	    buscount * PPB_MEM_ALIGNMENT * 32);

	/*
	 * Check if the parent bus could allocate a 64-bit sized PF
	 * range and bump the minimum pmem.size to 512MB if so.
	 */
	parbus_pmem = parbus_res_avail(seg, parbus, RES_PMEM);
	if (parbus_pmem != NULL &&
	    memlist_find_span(*parbus_pmem, 1ULL << 32, PPB_MEM_ALIGNMENT,
	    NULL) == MEML_SPANOP_OK) {
		pmem.size = MAX(sec_res->pmem_size,
		    buscount * PPB_MEM_ALIGNMENT * 512);
	}

	/*
	 * I/O space needs to be 4KiB aligned, Memory space needs to be 1MiB
	 * aligned.
	 *
	 * We calculate alignment as the largest power of two less than the
	 * the sum of all children's size requirements, because this will
	 * align to the size of the largest child request within that size
	 * (which is always a power of two).
	 */
	io.size = P2ROUNDUP(io.size, PPB_IO_ALIGNMENT);
	mem.size = P2ROUNDUP(mem.size, PPB_MEM_ALIGNMENT);
	pmem.size = P2ROUNDUP(pmem.size, PPB_MEM_ALIGNMENT);

	io.align = io.size;
	P2LE(io.align);
	mem.align = mem.size;
	P2LE(mem.align);
	pmem.align = pmem.size;
	P2LE(pmem.align);

	/* Subtractive bridge */
	if (sec_res->subtractive && prog_sub) {
		/*
		 * We program an arbitrary amount of I/O and memory resource
		 * for the subtractive bridge so that child dynamic-resource-
		 * allocating devices (such as Cardbus bridges) have a chance
		 * of success.  Until we have full-tree resource rebalancing,
		 * dynamic resource allocation (thru busra) only looks at the
		 * parent bridge, so all PPBs must have some allocatable
		 * resource.  For non-subtractive bridges, the resources come
		 * from the base/limit register "windows", but subtractive
		 * bridges often don't program those (since they don't need to).
		 * If we put all the remaining resources on the subtractive
		 * bridge, then peer non-subtractive bridges can't allocate
		 * more space (even though this is probably most correct).
		 * If we put the resources only on the parent, then allocations
		 * from children of subtractive bridges will fail without
		 * special-case code for bypassing the subtractive bridge.
		 * This solution is the middle-ground temporary solution until
		 * we have fully-capable resource allocation.
		 */

		/*
		 * Add an arbitrary I/O resource to the subtractive PPB
		 */
		if (sec_res->io_avail == NULL) {
			if (get_parbus_res(seg, parbus, secbus, io.size,
			    io.align, RES_IO, &addr)) {
				add_ranges_prop(seg, secbus, B_TRUE);
				sec_res->io_reprogram =
				    par_res->io_reprogram;

				cmn_err(CE_NOTE,
				    MSGHDR "PROGRAM  I/O range 0x%lx ~ 0x%lx "
				    "(subtractive bridge)",
				    "ppb", bus, dev, func,
				    addr, addr + io.size - 1);
			}
		}
		/*
		 * Add an arbitrary memory resource to the subtractive PPB
		 */
		if (sec_res->mem_avail == NULL) {
			if (get_parbus_res(seg, parbus, secbus, mem.size,
			    mem.align, RES_MEM, &addr)) {
				add_ranges_prop(seg, secbus, B_TRUE);
				sec_res->mem_reprogram =
				    par_res->mem_reprogram;

				cmn_err(CE_NOTE,
				    MSGHDR "PROGRAM  MEM range 0x%lx ~ 0x%lx "
				    "(subtractive bridge)",
				    "ppb", bus, dev, func,
				    addr, addr + mem.size - 1);
			}
		}

		goto cmd_enable;
	}

	/*
	 * Retrieve the various configured ranges from the bridge.
	 */

	fetch_ppb_res(dip, bdf, RES_IO, &io.base, &io.limit);
	fetch_ppb_res(dip, bdf, RES_MEM, &mem.base, &mem.limit);
	fetch_ppb_res(dip, bdf, RES_PMEM, &pmem.base, &pmem.limit);

	/*
	 * Reprogram IO if:
	 *
	 *	- The list does not consist entirely of legacy VGA resources;
	 *
	 * and any of
	 *
	 *	- The parent bus is flagged for reprogramming;
	 *	- IO space is currently disabled in the command register;
	 *	- IO space is disabled via base/limit.
	 */
	scratch_list = memlist_rsrc_dup(sec_res->io_avail);
	memlist_rsrc_merge(sec_res->io_used, &scratch_list);

	reprogram_io = !list_is_vga_only(scratch_list, RES_IO) &&
	    (par_res->io_reprogram ||
	    (cmd_reg & PCI_COMM_IO) == 0 ||
	    io.base > io.limit);

	memlist_rsrc_free(&scratch_list);

	if (reprogram_io) {
		memlist_rsrc_subsume(&sec_res->io_used,
		    &sec_res->io_avail);

		if (sec_res->io_avail != NULL &&
		    !par_res->io_reprogram &&
		    !par_res->subtractive) {
			/* re-choose old io ports info */

			uint64_t base, limit;

			pci_res_span(sec_res->io_avail,
			    RES_IO, &base, &limit);
			io.base = (uint_t)base;
			io.limit = (uint_t)limit;

			/* 4K aligned */
			io.base = P2ALIGN(base, PPB_IO_ALIGNMENT);
			io.limit = P2ROUNDUP(io.limit, PPB_IO_ALIGNMENT) - 1;
			io.size = io.limit - io.base + 1;
			ASSERT3U(io.base, <=, io.limit);
			memlist_rsrc_free(&sec_res->io_avail);
			memlist_rsrc_add(&sec_res->io_avail, io.base,
			    io.size);
			memlist_rsrc_add(&par_res->io_used, io.base,
			    io.size);
			memlist_rsrc_delete(&par_res->io_avail,
			    io.base, io.size);
			sec_res->io_reprogram = B_TRUE;
		} else {
			/* get new io ports from parent bus */
			if (get_parbus_res(seg, parbus, secbus, io.size,
			    io.align, RES_IO, &addr)) {
				io.base = addr;
				io.limit = addr + io.size - 1;
				sec_res->io_reprogram = B_TRUE;
			}
		}

		if (sec_res->io_reprogram) {
			/* reprogram PPB regs */
			set_ppb_res(dip, bdf, RES_IO, io.base, io.limit);
			add_ranges_prop(seg, secbus, B_TRUE);
		}
	}

	/*
	 * Reprogram memory if:
	 *
	 *	- The list does not consist entirely of legacy VGA resources;
	 *
	 * and any of
	 *
	 *	- The parent bus is flagged for reprogramming;
	 *	- Mem space is currently disabled in the command register;
	 *	- Both mem and pmem space are disabled via base/limit.
	 *
	 * Always reprogram both mem and pmem together since this leaves
	 * resources in the 'avail' list for add_reg_props() to subsequently
	 * find and assign.
	 */
	scratch_list = memlist_rsrc_dup(sec_res->mem_avail);
	memlist_rsrc_merge(sec_res->mem_used, &scratch_list);

	reprogram_mem = !list_is_vga_only(scratch_list, RES_MEM) &&
	    (par_res->mem_reprogram ||
	    (cmd_reg & PCI_COMM_MAE) == 0 ||
	    (mem.base > mem.limit && pmem.base > pmem.limit));

	memlist_rsrc_free(&scratch_list);

	if (reprogram_mem) {
		/* Mem range */
		memlist_rsrc_subsume(&sec_res->mem_used,
		    &sec_res->mem_avail);

		/*
		 * At this point, if the parent bus has not been
		 * reprogrammed and there is memory in this bus' available
		 * pool, then it can just be re-used. Otherwise a new range
		 * is requested from the parent bus - note that
		 * get_parbus_res() also takes care of constructing new
		 * avail and used lists for the bus.
		 *
		 * For a subtractive parent bus, always request a fresh
		 * memory range.
		 */
		if (sec_res->mem_avail != NULL &&
		    !par_res->mem_reprogram &&
		    !par_res->subtractive) {
			/* re-choose old mem resource */
			pci_res_span(sec_res->mem_avail,
			    RES_MEM, &mem.base, &mem.limit);

			mem.base = P2ALIGN(mem.base, PPB_MEM_ALIGNMENT);
			mem.limit = P2ROUNDUP(mem.limit, PPB_MEM_ALIGNMENT) - 1;
			mem.size = mem.limit + 1 - mem.base;
			ASSERT3U(mem.base, <=, mem.limit);
			memlist_rsrc_free(&sec_res->mem_avail);
			memlist_rsrc_add(&sec_res->mem_avail,
			    mem.base, mem.size);
			memlist_rsrc_add(&par_res->mem_used,
			    mem.base, mem.size);
			memlist_rsrc_delete(&par_res->mem_avail,
			    mem.base, mem.size);
			sec_res->mem_reprogram = B_TRUE;
		} else {
			/* get new mem resource from parent bus */
			if (get_parbus_res(seg, parbus, secbus, mem.size,
			    mem.align, RES_MEM, &addr)) {
				mem.base = addr;
				mem.limit = addr + mem.size - 1;
				sec_res->mem_reprogram = B_TRUE;
			}
		}

		/* Prefetch mem */
		memlist_rsrc_subsume(&sec_res->pmem_used,
		    &sec_res->pmem_avail);

		/* Same logic as for non-prefetch memory, see above */
		if (sec_res->pmem_avail != NULL &&
		    !par_res->mem_reprogram &&
		    !par_res->subtractive) {
			/* re-choose old mem resource */

			pci_res_span(sec_res->pmem_avail,
			    RES_PMEM, &pmem.base, &pmem.limit);

			pmem.base = P2ALIGN(pmem.base, PPB_MEM_ALIGNMENT);
			pmem.limit = P2ROUNDUP(pmem.limit, PPB_MEM_ALIGNMENT)
			    - 1;
			pmem.size = pmem.limit + 1 - pmem.base;
			ASSERT3U(pmem.base, <=, pmem.limit);
			memlist_rsrc_free(&sec_res->pmem_avail);
			memlist_rsrc_add(&sec_res->pmem_avail,
			    pmem.base, pmem.size);
			memlist_rsrc_add(&par_res->pmem_used,
			    pmem.base, pmem.size);
			memlist_rsrc_delete(&par_res->pmem_avail,
			    pmem.base, pmem.size);
			sec_res->mem_reprogram = B_TRUE;
		} else {
			/* get new mem resource from parent bus */
			if (get_parbus_res(seg, parbus, secbus, pmem.size,
			    pmem.align, RES_PMEM, &addr)) {
				pmem.base = addr;
				pmem.limit = addr + pmem.size - 1;
				sec_res->mem_reprogram = B_TRUE;
			}
		}

		if (sec_res->mem_reprogram) {
			set_ppb_res(dip, bdf, RES_MEM, mem.base, mem.limit);
			set_ppb_res(dip, bdf, RES_PMEM, pmem.base, pmem.limit);
			add_ranges_prop(seg, secbus, B_TRUE);
		}
	}

cmd_enable:
	dump_memlists("fix_ppb_res end bus", seg, bus);
	dump_memlists("fix_ppb_res end secbus", seg, secbus);

	if (sec_res->io_avail != NULL)
		cmd_reg |= PCI_COMM_IO | PCI_COMM_ME;
	if (sec_res->mem_avail != NULL ||
	    sec_res->pmem_avail != NULL) {
		cmd_reg |= PCI_COMM_MAE | PCI_COMM_ME;
	}
	pci_cfgacc_put16(dip, bdf, PCI_CONF_COMM, cmd_reg);

	return (B_TRUE);
}

static boolean_t
pci_do_reconfig(uint16_t seg, uint8_t bus, void *arg __unused)
{
	struct pci_bus_resource *r;

	r = get_bus_res(seg, bus);

	/*
	 * Reprogram the subtractive PPB. At this time, all its
	 * siblings should have got their resources already.
	 */
	if (r->subtractive)
		(void) fix_ppb_res(seg, bus, (void *)(uintptr_t)B_TRUE);

	/* configure devices not configured by firmware */
	(void) enumerate_bus_devs(seg, bus, (void *)(intptr_t)CONFIG_NEW);

	return (B_TRUE);
}

/*
 * Fix-up unit-address assignments if cache is available
 */
static void
pci_fix_unit_address(void)
{
	struct pci_bus_resource *r;
	int	pci_regs[] = {0, 0, 0};
	int	new_addr;
	int	index = 0;
	uint_t	bus, max_bus;

	if (!pci_unitaddr_cache_valid()) {
		pci_unitaddr_cache_create();
		return;
	}

	max_bus = pci_prd_max_bus(0);

	/* For segment 0, we always assume buses start at 0 */
	for (bus = 0; bus <= max_bus; bus++) {
		r = get_bus_res(0, bus);

		/* skip non-root (peer) PCI busses */
		if ((r->par_bus != (uchar_t)-1) || (r->dip == NULL))
			continue;

		new_addr = pci_bus_unitaddr(index);
		if (r->root_addr != new_addr) {
			/* update reg property for node */
			pci_regs[0] = r->root_addr = new_addr;
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    r->dip, "reg", (int *)pci_regs, 3);
		}
		index++;
	}
}

void
pci_reprogram(void)
{
	char *onoff;
	struct pci_bus_resource *r;
	int i, pci_reconfig = 1;
	int bus;

	/*
	 * Ask platform code for all of the root complexes it knows about in
	 * case we have missed anything in the scan. This is to ensure that we
	 * have them show up in the devinfo tree. This scan should find any
	 * existing entries as well. After this, go through each bus and
	 * ask the platform if it wants to change the name of the slot.
	 */
	pci_prd_root_complex_iter(pci_rc_scan_cb, NULL);
	for (bus = 0; bus <= pci_boot_maxbus; bus++) {
		r = get_bus_res(0, bus);
		pci_prd_slot_name(0, bus, r->dip);
	}

	pci_unitaddr_cache_init();
	pci_fix_unit_address();

	/*
	 * Do root-bus resource discovery
	 */
	for (bus = 0; bus <= pci_boot_maxbus; bus++) {
		r = get_bus_res(0, bus);

		/* skip non-root (peer) PCI busses */
		if (r->par_bus != (uchar_t)-1)
			continue;

		/*
		 * 1. find resources associated with this root bus
		 */
		populate_bus_res(0, bus);

		/*
		 * 2. Exclude <1M address range here in case below reserved
		 * ranges for BIOS data area, ROM area etc are wrongly reported
		 * in ACPI resource producer entries for PCI root bus.
		 *	00000000 - 000003FF	RAM
		 *	00000400 - 000004FF	BIOS data area
		 *	00000500 - 0009FFFF	RAM
		 *	000A0000 - 000BFFFF	VGA RAM
		 *	000C0000 - 000FFFFF	ROM area
		 */
		memlist_rsrc_delete(&r->mem_avail, 0, 0x100000);
		memlist_rsrc_delete(&r->pmem_avail, 0, 0x100000);

		/*
		 * 3. Calculate the amount of "spare" 32-bit memory so that we
		 * can use that later to determine how much additional memory
		 * to allocate to bridges in order that they have a better
		 * chance of supporting a device being hotplugged under them.
		 *
		 * This is a root bus and the previous CONFIG_INFO pass has
		 * populated `mem_size` with the sum of all of the BAR sizes
		 * for all devices underneath, possibly adjusted up to allow
		 * for alignment when it is later allocated. This pass has also
		 * recorded the number of child bridges found under this bus in
		 * `num_bridge`. To calculate the memory which can be used for
		 * additional bridge allocations we sum up the contents of the
		 * `mem_avail` list and subtract `mem_size`.
		 *
		 * When programming child bridges later in fix_ppb_res(), the
		 * bridge count and spare memory values cached against the
		 * relevant root port are used to determine how much memory to
		 * be allocated.
		 */
		if (r->num_bridge > 0) {
			uint64_t mem = 0;

			for (struct memlist *ml = r->mem_avail;
			    ml != NULL; ml = ml->ml_next) {
				if (ml->ml_address < UINT32_MAX)
					mem += ml->ml_size;
			}

			if (mem > r->mem_size)
				mem -= r->mem_size;
			else
				mem = 0;

			r->mem_buffer = mem;

			dcmn_err(CE_NOTE,
			    "Bus 0x%02x, bridges 0x%x, buffer mem 0x%lx",
			    bus, r->num_bridge, mem);
		}

		/*
		 * 4. Remove used PCI and ISA resources from bus resource map
		 */

		memlist_rsrc_delete_list(&r->io_avail, r->io_used);
		memlist_rsrc_delete_list(&r->mem_avail, r->mem_used);
		memlist_rsrc_delete_list(&r->pmem_avail, r->pmem_used);
		memlist_rsrc_delete_list(&r->mem_avail, r->pmem_used);
		memlist_rsrc_delete_list(&r->pmem_avail, r->mem_used);

		memlist_rsrc_delete_list(&r->io_avail, isa_res.io_used);
		memlist_rsrc_delete_list(&r->mem_avail, isa_res.mem_used);
	}

	memlist_rsrc_free(&isa_res.io_used);
	memlist_rsrc_free(&isa_res.mem_used);

	/* add bus-range property for root/peer bus nodes */
	for (i = 0; i <= pci_boot_maxbus; i++) {
		r = get_bus_res(0, i);

		/* create bus-range property on root/peer buses */
		if (r->par_bus == (uchar_t)-1)
			add_bus_range_prop(0, i); /* XXX */

		/* setup bus range resource on each bus */
		setup_bus_res(0, i);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "pci-reprog", &onoff) == DDI_SUCCESS) {
		if (strcmp(onoff, "off") == 0) {
			pci_reconfig = 0;
			cmn_err(CE_NOTE, "pci device reprogramming disabled");
		}
		ddi_prop_free(onoff);
	}

	iter_buses(remove_subtractive_res, NULL);

	if (pci_reconfig) {
		/* reprogram the non-subtractive PPBs */
		iter_buses(fix_ppb_res, (uintptr_t)B_FALSE);

		iter_buses(pci_do_reconfig, NULL);
	}

	/* All dev programmed, so we can create available prop */
	iter_buses(add_bus_available_prop, NULL);
}

/*
 * populate bus resources
 */
static void
populate_bus_res(uint16_t seg, uchar_t bus)
{
	struct pci_bus_resource *r;

	r = get_bus_res(seg, bus);

	r->pmem_avail = pci_prd_find_resource(seg, bus, PCI_PRD_R_PREFETCH);
	r->mem_avail = pci_prd_find_resource(seg, bus, PCI_PRD_R_MMIO);
	r->io_avail = pci_prd_find_resource(seg, bus, PCI_PRD_R_IO);
	r->bus_avail = pci_prd_find_resource(seg, bus, PCI_PRD_R_BUS);

	dump_memlists("populate_bus_res", seg, bus);

	/*
	 * attempt to initialize sub_bus from the largest range-end
	 * in the bus_avail list
	 */
	if (r->bus_avail != NULL) {
		struct memlist *entry;
		int current;

		entry = r->bus_avail;
		while (entry != NULL) {
			current = entry->ml_address + entry->ml_size - 1;
			if (current > r->sub_bus)
				r->sub_bus = current;
			entry = entry->ml_next;
		}
	}

	if (bus == 0) {
		/*
		 * Special treatment of bus 0:
		 * If no IO/MEM resource from ACPI/MPSPEC/HRT, copy
		 * pcimem from boot and make I/O space the entire range
		 * starting at 0x100.
		 */
		if (r->mem_avail == NULL) {
			r->mem_avail =
			    memlist_rsrc_dup(bootops->boot_mem->pcimem);
		}
		/* Exclude 0x00 to 0xff of the I/O space, used by all PCs */
		if (r->io_avail == NULL) {
			memlist_rsrc_add(&r->io_avail, 0x100, 0xff00);
		}
	}

	/*
	 * Create 'ranges' property here before any resources are
	 * removed from the resource lists
	 */
	add_ranges_prop(seg, bus, B_FALSE);
}

/*
 * Create top-level bus dips, i.e. /pci@0,0, /pci@1,0...
 */
static void
create_root_bus_dip(uint16_t seg, uchar_t bus)
{
	dev_info_t *dip;
	struct pci_bus_resource *res;
	int pci_regs[] = {0, 0, 0};

	res = get_bus_res(seg, bus);

	ASSERT(res->par_bus == (uchar_t)-1);

	num_root_bus++;
	ndi_devi_alloc_sleep(ddi_root_node(), "pci",
	    (pnode_t)DEVI_SID_NODEID, &dip);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);
	pci_regs[0] = res->root_addr;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)pci_regs, 3);

	/*
	 * If system has PCIe bus, then create different properties
	 */
	if (create_pcie_root_bus(bus, dip) == B_FALSE)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pci");

	/*
	 * We want all of the root complexes to have their pci-segment
	 * property set before we start enumerating any children. We're
	 * still early enough in the boot process that the options dip
	 * won't exist, so we need to ensure looking up the pci-segment
	 * property will terminate prior to reaching the root nexus (or
	 * panic will ensue).
	 */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "pci-segment", seg);

	(void) ndi_devi_bind_driver(dip, 0);
	res->dip = dip;
}

/*
 * For any fixed configuration (often compatability) pci devices
 * and those with their own expansion rom, create device nodes
 * to hold the already configured device details.
 */
static boolean_t
enumerate_bus_devs(uint16_t seg, uchar_t bus, void *arg)
{
	struct pci_devfunc *devlist = NULL, *entry;
	struct pci_bus_resource *res;
	dev_info_t *rcdip;
	int config_op = (intptr_t)arg;
	uchar_t dev, func, nfunc, header;
	ushort_t venid;

	if (bus_debug(bus)) {
		if (config_op == CONFIG_NEW) {
			dcmn_err(CE_NOTE, "configuring pci segment %u bus 0x%x",
			    seg, bus);
		} else if (config_op == CONFIG_FIX) {
			dcmn_err(CE_NOTE,
			    "fixing devices on pci segment %u bus 0x%x",
			    seg, bus);
		} else {
			dcmn_err(CE_NOTE, "enumerating pci segment %u bus 0x%x",
			    seg, bus);
		}
	}

	rcdip = get_rcdip(seg);
	res = get_bus_res(seg, bus);

	if (config_op == CONFIG_NEW) {
		devlist = (struct pci_devfunc *)res->privdata;
		while (devlist) {
			entry = devlist;
			devlist = entry->next;
			if (entry->reprogram ||
			    res->io_reprogram ||
			    res->mem_reprogram) {
				/* reprogram device(s) */
				(void) add_reg_props(entry->dip, bus,
				    entry->dev, entry->func, CONFIG_NEW, 0);
			}
			kmem_free(entry, sizeof (*entry));
		}
		res->privdata = NULL;
		return (B_TRUE);
	}

	for (dev = 0; dev < max_dev_pci; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {
			uint16_t bdf = PCI_GETBDF(bus, dev, func);

			venid = pci_cfgacc_get16(rcdip, bdf, PCI_CONF_VENID);

			if ((venid == 0xffff) || (venid == 0)) {
				/* no function at this address */
				continue;
			}

			header = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_HEADER);
			if (header == 0xff) {
				continue; /* illegal value */
			}

			/*
			 * according to some mail from Microsoft posted
			 * to the pci-drivers alias, their only requirement
			 * for a multifunction device is for the 1st
			 * function to have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI)) {
				nfunc = 8;
			}

			if (config_op == CONFIG_FIX ||
			    config_op == CONFIG_INFO) {
				/*
				 * Create the node, unconditionally, on the
				 * first pass only.  It may still need
				 * resource assignment, which will be
				 * done on the second, CONFIG_NEW, pass.
				 */
				process_devfunc(rcdip, bus, dev, func,
				    config_op);
			}
		}
	}

	/* percolate bus used resources up through parents to root */
	if (config_op == CONFIG_INFO) {
		struct pci_bus_resource *par_res;
		int par_bus;

		par_bus = res->par_bus;
		while (par_bus != (uchar_t)-1) {
			par_res = get_bus_res(seg, par_bus);

			memlist_rsrc_merge(res->io_used,
			    &par_res->io_used);
			memlist_rsrc_merge(res->mem_used,
			    &par_res->mem_used);
			memlist_rsrc_merge(res->pmem_used,
			    &par_res->pmem_used);

			par_res->num_bridge += res->num_bridge;

			par_bus = par_res->par_bus;
			res = par_res;
		}
	}

	return (B_TRUE);
}

/*
 * As a workaround for devices which is_pciide() (below, which see) would not
 * match due to device issues, check an undocumented device tree property
 * 'pci-ide', the value of which is a 1275 device identifier.
 *
 * Should a device matching this (in normal 'compatible' order) be found, and
 * the device not otherwise bound, it will be have its node name changed to
 * 'pci-ide' so the pci-ide driver will attach.
 *
 * This can be set via `eeprom pci-ide=pciXXXX,YYYY` (see eeprom(8)) or
 * otherwise added to bootenv.rc.
 */
static boolean_t
check_pciide_prop(uchar_t revid, ushort_t venid, ushort_t devid,
    ushort_t subvenid, ushort_t subdevid)
{
	static int prop_exist = -1;
	static char *pciide_str;
	char compat[32];

	if (prop_exist == -1) {
		prop_exist = (ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    ddi_root_node(), DDI_PROP_DONTPASS, "pci-ide",
		    &pciide_str) == DDI_SUCCESS);
	}

	if (!prop_exist)
		return (B_FALSE);

	/* compare property value against various forms of compatible */
	if (subvenid) {
		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x.%x",
		    venid, devid, subvenid, subdevid, revid);
		if (strcmp(pciide_str, compat) == 0)
			return (B_TRUE);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x",
		    venid, devid, subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (B_TRUE);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x",
		    subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (B_TRUE);
	}
	(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x",
	    venid, devid, revid);
	if (strcmp(pciide_str, compat) == 0)
		return (B_TRUE);

	(void) snprintf(compat, sizeof (compat), "pci%x,%x", venid, devid);
	if (strcmp(pciide_str, compat) == 0)
		return (B_TRUE);

	return (B_FALSE);
}

static boolean_t
is_pciide(const pci_prop_data_t *prop)
{
	struct ide_table {
		ushort_t venid;
		ushort_t devid;
	};

	/*
	 * Devices which need to be matched specially as pci-ide because of
	 * various device issues.  Commonly their specification as being
	 * PCI_MASS_OTHER or PCI_MASS_SATA despite our using them in ATA mode.
	 */
	static struct ide_table ide_other[] = {
		{0x1095, 0x3112}, /* Silicon Image 3112 SATALink/SATARaid */
		{0x1095, 0x3114}, /* Silicon Image 3114 SATALink/SATARaid */
		{0x1095, 0x3512}, /* Silicon Image 3512 SATALink/SATARaid */
		{0x1095, 0x680},  /* Silicon Image PCI0680 Ultra ATA-133 */
		{0x1283, 0x8211} /* Integrated Technology Express 8211F */
	};

	if (prop->ppd_class != PCI_CLASS_MASS)
		return (B_FALSE);

	if (prop->ppd_subclass == PCI_MASS_IDE) {
		return (B_TRUE);
	}

	if (check_pciide_prop(prop->ppd_rev, prop->ppd_vendid,
	    prop->ppd_devid, prop->ppd_subvid, prop->ppd_subsys)) {
		return (B_TRUE);
	}

	if (prop->ppd_subclass != PCI_MASS_OTHER &&
	    prop->ppd_subclass != PCI_MASS_SATA) {
		return (B_FALSE);
	}

	for (size_t i = 0; i < ARRAY_SIZE(ide_other); i++) {
		if (ide_other[i].venid == prop->ppd_vendid &&
		    ide_other[i].devid == prop->ppd_devid)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static void
add_undofix_entry(uint16_t seg, uint8_t bus, uint8_t dev, uint8_t fn,
    void (*undofn)(uint16_t, uint8_t, uint8_t, uint8_t))
{
	struct pci_fixundo *newundo;

	newundo = kmem_alloc(sizeof (struct pci_fixundo), KM_SLEEP);

	/*
	 * Adding an item to this list means that we must turn its NMIENABLE
	 * bit back on at a later time.
	 */
	newundo->seg = seg;
	newundo->bus = bus;
	newundo->dev = dev;
	newundo->fn = fn;
	newundo->undofn = undofn;
	newundo->next = undolist;

	/* add to the undo list in LIFO order */
	undolist = newundo;
}

void
add_pci_fixes(void)
{
	iter_buses(enumerate_bus_devs, (void *)(intptr_t)CONFIG_FIX);
}

void
undo_pci_fixes(void)
{
	struct pci_fixundo *nextundo;
	uint16_t seg;
	uint8_t bus, dev, fn;

	/*
	 * All fixes in the undo list are performed unconditionally.  Future
	 * fixes may require selective undo.
	 */
	while (undolist != NULL) {
		seg = undolist->seg;
		bus = undolist->bus;
		dev = undolist->dev;
		fn = undolist->fn;

		(*(undolist->undofn))(seg, bus, dev, fn);

		nextundo = undolist->next;
		kmem_free(undolist, sizeof (struct pci_fixundo));
		undolist = nextundo;
	}
}

static void
undo_amd8111_pci_fix(uint16_t seg, uint8_t bus, uint8_t dev, uint8_t fn)
{
	dev_info_t *dip;
	pcie_req_id_t bdf;
	uint8_t val8;

	dip = get_rcdip(seg);
	bdf = PCI_GETBDF(bus, dev, fn);

	val8 = pci_cfgacc_get8(dip, bdf, LPC_IO_CONTROL_REG_1);
	/*
	 * The NMIONERR bit is turned back on to allow the SMM BIOS
	 * to handle more critical PCI errors (e.g. PERR#).
	 */
	val8 |= AMD8111_ENABLENMI;
	pci_cfgacc_put8(dip, bdf, LPC_IO_CONTROL_REG_1, val8);
}

static void
pci_fix_amd8111(uint16_t seg, uint8_t bus, uint8_t dev, uint8_t fn)
{
	dev_info_t *dip;
	pcie_req_id_t bdf;
	uint8_t val8;

	dip = get_rcdip(seg);
	bdf = PCI_GETBDF(bus, dev, fn);

	val8 = pci_cfgacc_get8(dip, bdf, LPC_IO_CONTROL_REG_1);

	if ((val8 & AMD8111_ENABLENMI) == 0)
		return;

	/*
	 * We reset NMIONERR in the LPC because master-abort on the PCI
	 * bridge side of the 8111 will cause NMI, which might cause SMI,
	 * which sometimes prevents all devices from being enumerated.
	 */
	val8 &= ~AMD8111_ENABLENMI;

	pci_cfgacc_put8(dip, bdf, LPC_IO_CONTROL_REG_1, val8);

	add_undofix_entry(seg, bus, dev, fn, undo_amd8111_pci_fix);
}

static void
set_devpm_d0(dev_info_t *rcdip, pcie_req_id_t bdf)
{
	uint16_t status;
	uint8_t header;
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t pmcsr;

	status = pci_cfgacc_get16(rcdip, bdf, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return;	/* No capabilities list */

	header = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_HEADER);
	header &= PCI_HEADER_TYPE_M;
	if (header == PCI_HEADER_CARDBUS)
		cap_ptr = pci_cfgacc_get8(rcdip, bdf, PCI_CBUS_CAP_PTR);
	else
		cap_ptr = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_CAP_PTR);
	/*
	 * Walk the capabilities list searching for a PM entry.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL && cap_ptr >= PCI_CAP_PTR_OFF) {
		cap_ptr &= PCI_CAP_PTR_MASK;
		cap_id = pci_cfgacc_get8(rcdip, bdf, cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PM) {
			pmcsr = pci_cfgacc_get16(rcdip, bdf,
			    cap_ptr + PCI_PMCSR);
			pmcsr &= ~(PCI_PMCSR_STATE_MASK);
			pmcsr |= PCI_PMCSR_D0; /* D0 state */
			pci_cfgacc_put16(rcdip, bdf, cap_ptr + PCI_PMCSR,
			    pmcsr);
			break;
		}
		cap_ptr = pci_cfgacc_get8(rcdip, bdf,
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}

}

static void
process_devfunc(dev_info_t *rcdip, uchar_t bus, uchar_t dev, uchar_t func,
    int config_op)
{
	pci_prop_data_t prop_data;
	pci_prop_failure_t prop_ret;
	dev_info_t *dip;
	boolean_t reprogram = B_FALSE;
	boolean_t pciide = B_FALSE;
	int power[2] = {1, 1};
	struct pci_devfunc *devlist = NULL, *entry = NULL;
	gfx_entry_t *gfxp;
	pcie_req_id_t bdf;
	struct pci_bus_resource *res;
	uint16_t seg;

	prop_ret = pci_prop_data_fill(rcdip, NULL, bus, dev, func, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to get basic PCI data: 0x%x",
		    "pci", bus, dev, func, prop_ret);
		return;
	}

	bdf = PCI_GETBDF(bus, dev, func);

	seg = get_segment(rcdip);
	res = get_bus_res(seg, bus);

	if (prop_data.ppd_header == PCI_HEADER_CARDBUS &&
	    config_op == CONFIG_INFO) {
		/* Record the # of cardbus bridges found on the bus */
		res->num_cbb++;
	}

	if (config_op == CONFIG_FIX) {
		if (prop_data.ppd_vendid == VENID_AMD &&
		    prop_data.ppd_devid == DEVID_AMD8111_LPC) {
			uint16_t seg = get_segment(rcdip);

			pci_fix_amd8111(seg, bus, dev, func);
		}
		return;
	}

	/* make sure parent bus dip has been created */
	if (res->dip == NULL) {
		uint16_t seg = get_segment(rcdip);

		create_root_bus_dip(seg, bus);
	}

	ndi_devi_alloc_sleep(res->dip, DEVI_PSEUDO_NEXNAME,
	    DEVI_SID_NODEID, &dip);
	prop_ret = pci_prop_name_node(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to set node name: 0x%x; "
		    "devinfo node not created", "pci", bus, dev, func,
		    prop_ret);
		(void) ndi_devi_free(dip);
		return;
	}

	bdf = PCI_GETBDF(bus, dev, func);
	/*
	 * Record BAD AMD bridges which don't support MMIO config access.
	 */
	if (IS_BAD_AMD_NTBRIDGE(prop_data.ppd_vendid, prop_data.ppd_devid) ||
	    IS_AMD_8132_CHIP(prop_data.ppd_vendid, prop_data.ppd_devid)) {
		uchar_t secbus = 0;
		uchar_t subbus = 0;

		if (pci_prop_class_is_pcibridge(&prop_data)) {
			secbus = pci_cfgacc_get8(rcdip, bdf, PCI_BCNF_SECBUS);
			subbus = pci_cfgacc_get8(rcdip, bdf, PCI_BCNF_SUBBUS);
		}
		pci_cfgacc_add_workaround(bdf, secbus, subbus);
	}

	/*
	 * Only populate bus_t if this device is sitting under a PCIE root
	 * complex.  Some particular machines have both a PCIE root complex and
	 * a PCI hostbridge, in which case only devices under the PCIE root
	 * complex will have their bus_t populated.
	 */
	if (pcie_get_rc_dip(dip) != NULL) {
		ck804_fix_aer_ptr(dip, bdf);
		(void) pcie_init_bus(dip, bdf, PCIE_BUS_INITIAL);
	}

	/*
	 * Go through and set all of the devinfo proprties on this function.
	 */
	prop_ret = pci_prop_set_common_props(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to set properties: 0x%x; "
		    "devinfo node not created", "pci", bus, dev, func,
		    prop_ret);
		if (pcie_get_rc_dip(dip) != NULL) {
			pcie_fini_bus(dip, PCIE_BUS_FINAL);
		}
		(void) ndi_devi_free(dip);
		return;
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "power-consumption", power, 2);

	/* Set the device PM state to D0 */
	set_devpm_d0(rcdip, bdf);

	if (pci_prop_class_is_pcibridge(&prop_data)) {
		boolean_t pciex = (prop_data.ppd_flags & PCI_PROP_F_PCIE) != 0;
		boolean_t is_pci_bridge = pciex &&
		    prop_data.ppd_pcie_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI;
		add_ppb_props(dip, seg, bus, dev, func, pciex, is_pci_bridge);
	} else {
		/*
		 * Record the non-PPB devices on the bus for possible
		 * reprogramming at 2nd bus enumeration.
		 * Note: PPB reprogramming is done in fix_ppb_res()
		 */
		devlist = (struct pci_devfunc *)res->privdata;
		entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
		entry->dip = dip;
		entry->dev = dev;
		entry->func = func;
		entry->next = devlist;
		res->privdata = entry;
	}

	if (pci_prop_class_is_ioapic(&prop_data)) {
		create_ioapic_node(bus, dev, func, prop_data.ppd_vendid,
		    prop_data.ppd_devid);
	}

	/* check for NVIDIA CK8-04/MCP55 based LPC bridge */
	if (NVIDIA_IS_LPC_BRIDGE(prop_data.ppd_vendid, prop_data.ppd_devid) &&
	    dev == 1 && func == 0) {
		add_nvidia_isa_bridge_props(dip, bus, dev, func);
		/* each LPC bridge has an integrated IOAPIC */
		apic_nvidia_io_max++;
	}

	prop_ret = pci_prop_set_compatible(dip, &prop_data);
	if (prop_ret != PCI_PROP_OK) {
		cmn_err(CE_WARN, MSGHDR "failed to set compatible property: "
		    "0x%x;  device may not bind to a driver", "pci", bus, dev,
		    func, prop_ret);
	}

	/*
	 * See if this device is a controller that advertises
	 * itself to be a standard ATA task file controller, or one that
	 * has been hard coded.
	 *
	 * If it is, check if any other higher precedence driver listed in
	 * driver_aliases will claim the node by calling
	 * ddi_compatible_driver_major.  If so, clear pciide and do not
	 * create a pci-ide node or any other special handling.
	 *
	 * If another driver does not bind, set the node name to pci-ide
	 * and then let the special pci-ide handling for registers and
	 * child pci-ide nodes proceed below.
	 */
	if (is_pciide(&prop_data)) {
		if (ddi_compatible_driver_major(dip, NULL) == (major_t)-1) {
			(void) ndi_devi_set_nodename(dip, "pci-ide", 0);
			pciide = B_TRUE;
		}
	}

	DEVI_SET_PCI(dip);
	reprogram = add_reg_props(dip, bus, dev, func, config_op, pciide);
	(void) ndi_devi_bind_driver(dip, 0);

	/* special handling for pci-ide */
	if (pciide) {
		dev_info_t *cdip;

		/*
		 * Create properties specified by P1275 Working Group
		 * Proposal #414 Version 1
		 */
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pci-ide");
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#address-cells", 1);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#size-cells", 0);

		/* allocate two child nodes */
		ndi_devi_alloc_sleep(dip, "ide",
		    (pnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 0);
		(void) ndi_devi_bind_driver(cdip, 0);
		ndi_devi_alloc_sleep(dip, "ide",
		    (pnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 1);
		(void) ndi_devi_bind_driver(cdip, 0);

		reprogram = B_FALSE;	/* don't reprogram pci-ide bridge */
	}

	if (pci_prop_class_is_vga(&prop_data)) {
		gfxp = kmem_zalloc(sizeof (*gfxp), KM_SLEEP);
		gfxp->g_dip = dip;
		gfxp->g_prev = NULL;
		gfxp->g_next = gfx_devinfo_list;
		gfx_devinfo_list = gfxp;
		if (gfxp->g_next)
			gfxp->g_next->g_prev = gfxp;
	}

	if (reprogram && (entry != NULL))
		entry->reprogram = B_TRUE;
}

/*
 * Adjust the reg properties for a dual channel PCI-IDE device.
 *
 * NOTE: don't do anything that changes the order of the hard-decodes
 * and programmed BARs. The kernel driver depends on these values
 * being in this order regardless of whether they're for a 'native'
 * mode BAR or not.
 */
/*
 * config info for pci-ide devices
 */
static struct {
	uchar_t  native_mask;	/* 0 == 'compatibility' mode, 1 == native */
	uchar_t  bar_offset;	/* offset for alt status register */
	ushort_t addr;		/* compatibility mode base address */
	ushort_t length;	/* number of ports for this BAR */
} pciide_bar[] = {
	{ 0x01, 0, 0x1f0, 8 },	/* primary lower BAR */
	{ 0x01, 2, 0x3f6, 1 },	/* primary upper BAR */
	{ 0x04, 0, 0x170, 8 },	/* secondary lower BAR */
	{ 0x04, 2, 0x376, 1 }	/* secondary upper BAR */
};

static boolean_t
pciide_adjust_bar(uchar_t progcl, uint_t bar, uint_t *basep, uint_t *lenp)
{
	boolean_t hard_decode = B_FALSE;

	/*
	 * Adjust the base and len for the BARs of the PCI-IDE
	 * device's primary and secondary controllers. The first
	 * two BARs are for the primary controller and the next
	 * two BARs are for the secondary controller. The fifth
	 * and sixth bars are never adjusted.
	 */
	if (bar <= 3) {
		*lenp = pciide_bar[bar].length;

		if (progcl & pciide_bar[bar].native_mask) {
			*basep += pciide_bar[bar].bar_offset;
		} else {
			*basep = pciide_bar[bar].addr;
			hard_decode = B_TRUE;
		}
	}

	/*
	 * if either base or len is zero make certain both are zero
	 */
	if (*basep == 0 || *lenp == 0) {
		*basep = 0;
		*lenp = 0;
		hard_decode = B_FALSE;
	}

	return (hard_decode);
}

/*
 * Where op is one of:
 *   CONFIG_INFO	- first pass, gather what is there.
 *   CONFIG_UPDATE	- second pass, adjust/allocate regions.
 *   CONFIG_NEW		- third pass, allocate regions.
 *
 * Returns:
 *	-1	Skip this BAR
 *	 0	Properties have been assigned
 *	 1	Properties have been assigned, reprogramming required
 */
static int
add_bar_reg_props(dev_info_t *dip, int op, uchar_t bus, uchar_t dev,
    uchar_t func, uint_t bar, ushort_t offset, pci_regspec_t *regs,
    pci_regspec_t *assigned, ushort_t *bar_sz, boolean_t pciide)
{
	uint8_t baseclass, subclass, progclass;
	uint32_t base, devloc;
	uint16_t command = 0;
	pcie_req_id_t bdf;
	int reprogram = 0;
	uint64_t value;
	struct pci_bus_resource *res;
	uint16_t seg;

	seg = get_segment(dip);
	res = get_bus_res(seg, bus);

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	bdf = PCI_GETBDF(bus, dev, func);

	baseclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_BASCLASS);
	subclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_SUBCLASS);
	progclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_PROGCLASS);

	/*
	 * Determine the size of the BAR by writing 0xffffffff to the base
	 * register and reading the value back before restoring the original.
	 *
	 * For non-bridges, disable I/O and Memory access while doing this to
	 * avoid difficulty with USB emulation (see OHCI spec1.0a appendix B
	 * "Host Controller Mapping"). Doing this for bridges would have the
	 * side-effect of making the bridge transparent to secondary-bus
	 * activity (see sections 4.1-4.3 of the PCI-PCI Bridge Spec V1.2).
	 */
	base = pci_cfgacc_get32(dip, bdf, offset);

	if (baseclass != PCI_CLASS_BRIDGE) {
		command = (uint_t)pci_cfgacc_get16(dip, bdf, PCI_CONF_COMM);
		pci_cfgacc_put16(dip, bdf, PCI_CONF_COMM,
		    command & ~(PCI_COMM_MAE | PCI_COMM_IO));
	}

	pci_cfgacc_put32(dip, bdf, offset, 0xffffffff);
	value = pci_cfgacc_get32(dip, bdf, offset);
	pci_cfgacc_put32(dip, bdf, offset, base);

	if (baseclass != PCI_CLASS_BRIDGE)
		pci_cfgacc_put16(dip, bdf, PCI_CONF_COMM, command);

	/* I/O Space */
	if ((pciide && bar < 4) || (base & PCI_BASE_SPACE_IO) != 0) {
		struct memlist **io_avail = &res->io_avail;
		struct memlist **io_used = &res->io_used;
		boolean_t hard_decode = B_FALSE;
		uint_t type, len;

		*bar_sz = PCI_BAR_SZ_32;
		value &= PCI_BASE_IO_ADDR_M;
		len = BARMASKTOLEN(value);

		/* XXX Adjust first 4 IDE registers */
		if (pciide) {
			if (subclass != PCI_MASS_IDE) {
				progclass = (PCI_IDE_IF_NATIVE_PRI |
				    PCI_IDE_IF_NATIVE_SEC);
			}
			hard_decode = pciide_adjust_bar(progclass, bar,
			    &base, &len);
		} else if (value == 0) {
			/* skip base regs with size of 0 */
			return (-1);
		}

		regs->pci_phys_hi = PCI_ADDR_IO | devloc;
		if (hard_decode) {
			regs->pci_phys_hi |= PCI_RELOCAT_B;
			regs->pci_phys_low = base & PCI_BASE_IO_ADDR_M;
		} else {
			regs->pci_phys_hi |= offset;
			regs->pci_phys_low = 0;
		}
		assigned->pci_phys_hi = PCI_RELOCAT_B | regs->pci_phys_hi;
		regs->pci_size_low = assigned->pci_size_low = len;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_IO_ADDR_M;
		base &= PCI_BASE_IO_ADDR_M;

		/*
		 * A device under a subtractive PPB can allocate resources from
		 * its parent bus if there is no resource available on its own
		 * bus.
		 */
		if (op == CONFIG_NEW && res->subtractive &&
		    *io_avail == NULL) {
			uchar_t res_bus;

			res_bus = resolve_alloc_bus(seg, bus, RES_IO);
			io_avail = &get_bus_res(seg, res_bus)->io_avail;
		}

		if (op == CONFIG_INFO) {	/* first pass */
			/* take out of the resource map of the bus */
			if (base != 0) {
				memlist_rsrc_delete(io_avail, base, len);
				memlist_rsrc_add(io_used, base, len);
			} else {
				reprogram = 1;
			}
			dcmn_err(CE_NOTE,
			    MSGHDR "BAR%u  I/O FWINIT 0x%x ~ 0x%x",
			    "pci", bus, dev, func, bar, base, len);
			res->io_size += len;
		} else if ((*io_avail != NULL && base == 0) ||
		    res->io_reprogram) {
			uint64_t found;

			if (memlist_rsrc_claim(io_avail, len, len, &found) !=
			    MEML_SPANOP_OK) {
				base = 0;
				cmn_err(CE_WARN, MSGHDR "BAR%u I/O "
				    "failed to find length 0x%x",
				    "pci", bus, dev, func, bar, len);
			} else {
				uint32_t nbase;

				base = (uint32_t)found;

				cmn_err(CE_NOTE, "!" MSGHDR "BAR%u  "
				    "I/O REPROG 0x%x ~ 0x%x",
				    "pci", bus, dev, func,
				    bar, base, len);
				pci_cfgacc_put32(dip, bdf, offset, base | type);
				nbase = pci_cfgacc_get32(dip, bdf, offset);
				nbase &= PCI_BASE_IO_ADDR_M;

				if (base != nbase) {
					cmn_err(CE_NOTE, "!" MSGHDR "BAR%u  "
					    "I/O REPROG 0x%x ~ 0x%x "
					    "FAILED READBACK 0x%x",
					    "pci", bus, dev, func,
					    bar, base, len, nbase);
					pci_cfgacc_put32(dip, bdf, offset, 0);
					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_IO bit */
						command = pci_cfgacc_get16(dip,
						    bdf, PCI_CONF_COMM);
						command &= ~PCI_COMM_IO;
						pci_cfgacc_put16(dip, bdf,
						    PCI_CONF_COMM, command);
					}
					memlist_rsrc_add(io_avail, base, len);
					base = 0;
				} else {
					memlist_rsrc_add(io_used, base, len);
				}
			}
		}
		assigned->pci_phys_low = base;

	} else {	/* Memory space */
		struct memlist **mem_avail = &res->mem_avail;
		struct memlist **mem_used = &res->mem_used;
		struct memlist **pmem_avail = &res->pmem_avail;
		struct memlist **pmem_used = &res->pmem_used;
		uint_t type, base_hi, phys_hi;
		uint64_t len, fbase;

		if ((base & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
			*bar_sz = PCI_BAR_SZ_64;
			base_hi = pci_cfgacc_get32(dip, bdf, offset + 4);
			pci_cfgacc_put32(dip, bdf, offset + 4, 0xffffffff);
			value |= (uint64_t)pci_cfgacc_get32(dip, bdf,
			    offset + 4) << 32;
			pci_cfgacc_put32(dip, bdf, offset + 4, base_hi);
			phys_hi = PCI_ADDR_MEM64;
			value &= PCI_BASE_M_ADDR64_M;
		} else {
			*bar_sz = PCI_BAR_SZ_32;
			base_hi = 0;
			phys_hi = PCI_ADDR_MEM32;
			value &= PCI_BASE_M_ADDR_M;
		}

		/* skip base regs with size of 0 */
		if (value == 0)
			return (-1);

		len = BARMASKTOLEN(value);
		regs->pci_size_low = assigned->pci_size_low = len & 0xffffffff;
		regs->pci_size_hi = assigned->pci_size_hi = len >> 32;

		phys_hi |= devloc | offset;
		if (base & PCI_BASE_PREF_M)
			phys_hi |= PCI_PREFETCH_B;

		/*
		 * A device under a subtractive PPB can allocate resources from
		 * its parent bus if there is no resource available on its own
		 * bus.
		 */
		if (op == CONFIG_NEW && res->subtractive) {
			uchar_t res_bus = bus;

			if ((phys_hi & PCI_PREFETCH_B) != 0 &&
			    *pmem_avail == NULL) {
				res_bus = resolve_alloc_bus(seg, bus, RES_PMEM);
				pmem_avail =
				    &get_bus_res(seg, res_bus)->pmem_avail;
				mem_avail =
				    &get_bus_res(seg, res_bus)->mem_avail;
			} else if (*mem_avail == NULL) {
				res_bus = resolve_alloc_bus(seg, bus, RES_MEM);
				pmem_avail =
				    &get_bus_res(seg, res_bus)->pmem_avail;
				mem_avail =
				    &get_bus_res(seg, res_bus)->mem_avail;
			}
		}

		regs->pci_phys_hi = assigned->pci_phys_hi = phys_hi;
		assigned->pci_phys_hi |= PCI_RELOCAT_B;

		/*
		 * 'type' holds the non-address part of the base to be re-added
		 * to any new address in the programming step below.
		 */
		type = base & ~PCI_BASE_M_ADDR_M;
		base &= PCI_BASE_M_ADDR_M;

		fbase = (((uint64_t)base_hi) << 32) | base;

		if (op == CONFIG_INFO) {

			dcmn_err(CE_NOTE,
			    MSGHDR "BAR%u %sMEM FWINIT 0x%lx ~ 0x%lx%s",
			    "pci", bus, dev, func, bar,
			    (phys_hi & PCI_PREFETCH_B) ? "P" : " ",
			    fbase, len,
			    *bar_sz == PCI_BAR_SZ_64 ? " (64-bit)" : "");

			/* take out of the resource map of the bus */
			if (fbase != 0) {
				/* remove from PMEM and MEM space */
				memlist_rsrc_delete(mem_avail, fbase, len);
				memlist_rsrc_delete(pmem_avail, fbase, len);
				/* only note as used in correct map */
				if ((phys_hi & PCI_PREFETCH_B) != 0) {
					memlist_rsrc_add(pmem_used, fbase, len);
				} else {
					memlist_rsrc_add(mem_used, fbase, len);
				}
			} else {
				reprogram = 1;
				/*
				 * If we need to reprogram this because we
				 * don't have a BAR assigned, we need to
				 * actually increase the amount of memory that
				 * we request to take into account alignment.
				 * This is a bit gross, but by doubling the
				 * request size we are more likely to get the
				 * size that we need. A more involved fix would
				 * require a smarter and more involved
				 * allocator (something we will need
				 * eventually).
				 */
				len *= 2;
			}

			if (phys_hi & PCI_PREFETCH_B)
				res->pmem_size += len;
			else
				res->mem_size += len;
		} else if (res->mem_reprogram || (fbase == 0 &&
		    (*mem_avail != NULL || *pmem_avail != NULL))) {
			boolean_t pf = B_FALSE, got = B_FALSE;

			fbase = 0;

			/*
			 * When desired, attempt a prefetchable allocation first
			 */
			if ((phys_hi & PCI_PREFETCH_B) != 0) {
				got = memlist_rsrc_claim(pmem_avail, len, len,
				    &fbase) == MEML_SPANOP_OK;
				pf = got;
			}
			/*
			 * If prefetchable allocation was not desired, or
			 * failed, attempt ordinary memory allocation.
			 */
			if (!got) {
				got = memlist_rsrc_claim(mem_avail, len, len,
				    &fbase) == MEML_SPANOP_OK;
			}

			base_hi = fbase >> 32;
			base = fbase & 0xffffffff;

			if (!got) {
				cmn_err(CE_WARN, MSGHDR "BAR%u MEM "
				    "failed to find length 0x%lx",
				    "pci", bus, dev, func, bar, len);
			} else {
				uint64_t nbase, nbase_hi = 0;

				cmn_err(CE_NOTE, "!" MSGHDR "BAR%u "
				    "%s%s REPROG 0x%lx ~ 0x%lx",
				    "pci", bus, dev, func, bar,
				    pf ? "PMEM" : "MEM",
				    *bar_sz == PCI_BAR_SZ_64 ? "64" : "",
				    fbase, len);
				pci_cfgacc_put32(dip, bdf, offset, base | type);
				nbase = pci_cfgacc_get32(dip, bdf, offset);

				if (*bar_sz == PCI_BAR_SZ_64) {
					pci_cfgacc_put32(dip, bdf,
					    offset + 4, base_hi);
					nbase_hi = pci_cfgacc_get32(dip, bdf,
					    offset + 4);
				}

				nbase &= PCI_BASE_M_ADDR_M;

				if (base != nbase || base_hi != nbase_hi) {
					cmn_err(CE_NOTE, "!" MSGHDR "BAR%u "
					    "%s%s REPROG 0x%lx ~ 0x%lx "
					    "FAILED READBACK 0x%lx",
					    "pci", bus, dev, func, bar,
					    pf ? "PMEM" : "MEM",
					    *bar_sz == PCI_BAR_SZ_64 ?
					    "64" : "",
					    fbase, len,
					    nbase_hi << 32 | nbase);

					pci_cfgacc_put32(dip, bdf, offset, 0);
					if (*bar_sz == PCI_BAR_SZ_64) {
						pci_cfgacc_put32(dip, bdf,
						    offset + 4, 0);
					}

					if (baseclass != PCI_CLASS_BRIDGE) {
						/* Disable PCI_COMM_MAE bit */
						command = pci_cfgacc_get16(dip,
						    bdf, PCI_CONF_COMM);
						command &= ~PCI_COMM_MAE;
						pci_cfgacc_put16(dip, bdf,
						    PCI_CONF_COMM, command);
					}

					memlist_rsrc_add(
					    pf ? pmem_avail : mem_avail, fbase,
					    len);
					base = base_hi = 0;
				} else {
					if (pf) {
						memlist_rsrc_add(pmem_used,
						    fbase, len);
						memlist_rsrc_delete(pmem_avail,
						    fbase, len);
					} else {
						memlist_rsrc_add(mem_used,
						    fbase, len);
						memlist_rsrc_delete(mem_avail,
						    fbase, len);
					}
				}
			}
		}

		assigned->pci_phys_mid = base_hi;
		assigned->pci_phys_low = base;
	}

	dcmn_err(CE_NOTE, MSGHDR "BAR%u ---- %08x.%x.%x.%x.%x",
	    "pci", bus, dev, func, bar,
	    assigned->pci_phys_hi,
	    assigned->pci_phys_mid,
	    assigned->pci_phys_low,
	    assigned->pci_size_hi,
	    assigned->pci_size_low);

	return (reprogram);
}

/*
 * Add the "reg" and "assigned-addresses" property
 */
static boolean_t
add_reg_props(dev_info_t *dip, uchar_t bus, uchar_t dev, uchar_t func,
    int op, boolean_t pciide)
{
	uchar_t baseclass, subclass, progclass, header;
	uint_t bar, value, devloc, base;
	pcie_req_id_t bdf;
	ushort_t bar_sz, offset, end;
	int max_basereg, reprogram = B_FALSE;

	struct memlist **io_avail, **io_used;
	struct memlist **mem_avail, **mem_used;
	struct memlist **pmem_avail;

	pci_regspec_t regs[16] = {{0}};
	pci_regspec_t assigned[15] = {{0}};
	int nreg, nasgn;
	uint16_t seg;

	struct pci_bus_resource *res;

	seg = get_segment(dip);
	res = get_bus_res(seg, bus);

	io_avail = &res->io_avail;
	io_used = &res->io_used;
	mem_avail = &res->mem_avail;
	mem_used = &res->mem_used;
	pmem_avail = &res->pmem_avail;

	dump_memlists("add_reg_props start", seg, bus);

	bdf = PCI_GETBDF(bus, dev, func);
	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	regs[0].pci_phys_hi = devloc;
	nreg = 1;	/* rest of regs[0] is all zero */
	nasgn = 0;

	baseclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_BASCLASS);
	subclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_SUBCLASS);
	progclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_PROGCLASS);
	header = pci_cfgacc_get8(dip, bdf, PCI_CONF_HEADER);
	header &= PCI_HEADER_TYPE_M;

	switch (header) {
	case PCI_HEADER_ZERO:
		max_basereg = PCI_BASE_NUM;
		break;
	case PCI_HEADER_PPB:
		max_basereg = PCI_BCNF_BASE_NUM;
		break;
	case PCI_HEADER_CARDBUS:
		max_basereg = PCI_CBUS_BASE_NUM;
		reprogram = B_TRUE;
		break;
	default:
		max_basereg = 0;
		break;
	}

	end = PCI_CONF_BASE0 + max_basereg * sizeof (uint_t);
	for (bar = 0, offset = PCI_CONF_BASE0; offset < end;
	    bar++, offset += bar_sz) {
		int ret;

		ret = add_bar_reg_props(dip, op, bus, dev, func, bar, offset,
		    &regs[nreg], &assigned[nasgn], &bar_sz, pciide);

		if (bar_sz == PCI_BAR_SZ_64)
			bar++;

		if (ret == -1)		/* Skip BAR */
			continue;

		if (ret == 1)
			reprogram = B_TRUE;

		nreg++;
		nasgn++;
	}

	switch (header) {
	case PCI_HEADER_ZERO:
		offset = PCI_CONF_ROM;
		break;
	case PCI_HEADER_PPB:
		offset = PCI_BCNF_ROM;
		break;
	default: /* including PCI_HEADER_CARDBUS */
		goto done;
	}

	/*
	 * Add the expansion rom memory space
	 * Determine the size of the ROM base reg; don't write reserved bits
	 * ROM isn't in the PCI memory space.
	 */
	base = pci_cfgacc_get32(dip, bdf, offset);
	pci_cfgacc_put32(dip, bdf, offset, PCI_BASE_ROM_ADDR_M);
	value = pci_cfgacc_get32(dip, bdf, offset);
	pci_cfgacc_put32(dip, bdf, offset, base);
	if (value & PCI_BASE_ROM_ENABLE)
		value &= PCI_BASE_ROM_ADDR_M;
	else
		value = 0;

	if (value != 0) {
		uint_t len;

		regs[nreg].pci_phys_hi = (PCI_ADDR_MEM32 | devloc) + offset;
		assigned[nasgn].pci_phys_hi = (PCI_RELOCAT_B |
		    PCI_ADDR_MEM32 | devloc) + offset;
		base &= PCI_BASE_ROM_ADDR_M;
		assigned[nasgn].pci_phys_low = base;
		len = BARMASKTOLEN(value);
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = len;
		nreg++, nasgn++;
		/* take it out of the memory resource */
		if (base != 0) {
			memlist_rsrc_delete(mem_avail, base, len);
			memlist_rsrc_add(mem_used, base, len);
			res->mem_size += len;
		}
	}

	/*
	 * Account for "legacy" (alias) video adapter resources
	 */

	/* add the three hard-decode, aliased address spaces for VGA */
	if ((baseclass == PCI_CLASS_DISPLAY && subclass == PCI_DISPLAY_VGA) ||
	    (baseclass == PCI_CLASS_NONE && subclass == PCI_NONE_VGA)) {

		/* VGA hard decode 0x3b0-0x3bb */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3b0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0xc;
		nreg++, nasgn++;
		memlist_rsrc_delete(io_avail, 0x3b0, 0xc);
		memlist_rsrc_add(io_used, 0x3b0, 0xc);
		res->io_size += 0xc;

		/* VGA hard decode 0x3c0-0x3df */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3c0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x20;
		nreg++, nasgn++;
		memlist_rsrc_delete(io_avail, 0x3c0, 0x20);
		memlist_rsrc_add(io_used, 0x3c0, 0x20);
		res->io_size += 0x20;

		/* Video memory */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_MEM32 | devloc);
		regs[nreg].pci_phys_low =
		    assigned[nasgn].pci_phys_low = 0xa0000;
		regs[nreg].pci_size_low =
		    assigned[nasgn].pci_size_low = 0x20000;
		nreg++, nasgn++;
		/* remove from MEM and PMEM space */
		memlist_rsrc_delete(mem_avail, 0xa0000, 0x20000);
		memlist_rsrc_delete(pmem_avail, 0xa0000, 0x20000);
		memlist_rsrc_add(mem_used, 0xa0000, 0x20000);
		res->mem_size += 0x20000;
	}

	/* add the hard-decode, aliased address spaces for 8514 */
	if ((baseclass == PCI_CLASS_DISPLAY) &&
	    (subclass == PCI_DISPLAY_VGA) &&
	    (progclass & PCI_DISPLAY_IF_8514)) {

		/* hard decode 0x2e8 */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2e8;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x1;
		nreg++, nasgn++;
		memlist_rsrc_delete(io_avail, 0x2e8, 0x1);
		memlist_rsrc_add(io_used, 0x2e8, 0x1);
		res->io_size += 0x1;

		/* hard decode 0x2ea-0x2ef */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2ea;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x6;
		nreg++, nasgn++;
		memlist_rsrc_delete(io_avail, 0x2ea, 0x6);
		memlist_rsrc_add(io_used, 0x2ea, 0x6);
		res->io_size += 0x6;
	}

done:
	dump_memlists("add_reg_props end", seg, bus);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)regs, nreg * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, nasgn * sizeof (pci_regspec_t) / sizeof (int));

	return (reprogram);
}

static void
add_ppb_props(dev_info_t *dip, uint16_t seg, uchar_t bus, uchar_t dev,
    uchar_t func, boolean_t pciex, boolean_t is_pci_bridge)
{
	char *dev_type;
	struct pci_bus_resource *res, *sec_res;
	int i;
	uint_t cmd_reg;
	struct {
		uint64_t base;
		uint64_t limit;
	} io, mem, pmem;
	pcie_req_id_t bdf;
	uchar_t secbus, subbus;
	uchar_t progclass;

	bdf = PCI_GETBDF(bus, dev, func);

	/*
	 * On x86, the pci_cfgacc_xxx() functions use the dip to read
	 * the 'pci-segment' property on the given dip or ancestors
	 * (i.e. they don't use any other properties to restrict
	 * access to the PCI config space for the given bdf). Since either
	 * the dip or one of its ancestors will have the pci-segment property
	 * set, we can use them to access the correct config space for this
	 * PCI-PCI bridge.
	 */
	secbus = pci_cfgacc_get8(dip, bdf, PCI_BCNF_SECBUS);
	subbus = pci_cfgacc_get8(dip, bdf, PCI_BCNF_SUBBUS);

	ASSERT3U(secbus, <=, subbus);

	res = get_bus_res(seg, bus);
	sec_res = get_bus_res(seg, secbus);

	dump_memlists("add_ppb_props start bus", seg, bus);
	dump_memlists("add_ppb_props start secbus", seg, secbus);

	/*
	 * Check if it's a subtractive PPB.
	 */
	progclass = pci_cfgacc_get8(dip, bdf, PCI_CONF_PROGCLASS);
	if (progclass == PCI_BRIDGE_PCI_IF_SUBDECODE)
		sec_res->subtractive = B_TRUE;

	/*
	 * pci_boot_maxbus always gets set to the maximum these days,
	 * it should not be possible to get a child bus with a value
	 * larger than the max.
	 */
	VERIFY3U(subbus, <=, pci_boot_maxbus);

	ASSERT(sec_res->dip == NULL);
	sec_res->dip = dip;
	sec_res->par_bus = bus;

	dev_type = (pciex && !is_pci_bridge) ? "pciex" : "pci";

	/* set up bus number hierarchy */
	sec_res->sub_bus = subbus;
	/*
	 * Keep track of the largest subordinate bus number (this is essential
	 * for peer busses because there is no other way of determining its
	 * subordinate bus number).
	 */
	if (subbus > res->sub_bus)
		res->sub_bus = subbus;
	/*
	 * Loop through subordinate busses, initializing their parent bus
	 * field to this bridge's parent.  The subordinate busses' parent
	 * fields may very well be further refined later, as child bridges
	 * are enumerated.  (The value is to note that the subordinate busses
	 * are not peer busses by changing their par_bus fields to anything
	 * other than -1.)
	 */
	for (i = secbus + 1; i <= subbus; i++)
		get_bus_res(seg, i)->par_bus = bus;

	/*
	 * Update the number of bridges on the bus.
	 */
	if (!is_pci_bridge)
		res->num_bridge++;

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", dev_type);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);

	/*
	 * Collect bridge window specifications, and use them to populate
	 * the "avail" resources for the bus.  Not all of those resources will
	 * end up being available; this is done top-down, and so the initial
	 * collection of windows populates the 'ranges' property for the
	 * bus node.  Later, as children are found, resources are removed from
	 * the 'avail' list, so that it becomes the freelist for
	 * this point in the tree.  ranges may be set again after bridge
	 * reprogramming in fix_ppb_res(), in which case it's set from
	 * used + avail.
	 *
	 * According to PPB spec, the base register should be programmed
	 * with a value bigger than the limit register when there are
	 * no resources available. This applies to io, memory, and
	 * prefetchable memory.
	 */

	cmd_reg = (uint_t)pci_cfgacc_get16(dip, bdf, PCI_CONF_COMM);
	fetch_ppb_res(dip, bdf, RES_IO, &io.base, &io.limit);
	fetch_ppb_res(dip, bdf, RES_MEM, &mem.base, &mem.limit);
	fetch_ppb_res(dip, bdf, RES_PMEM, &pmem.base, &pmem.limit);

	if (pci_boot_debug != 0) {
		dcmn_err(CE_NOTE, MSGHDR " I/O FWINIT 0x%lx ~ 0x%lx%s",
		    "ppb", bus, dev, func, io.base, io.limit,
		    io.base > io.limit ? " (disabled)" : "");
		dcmn_err(CE_NOTE, MSGHDR " MEM FWINIT 0x%lx ~ 0x%lx%s",
		    "ppb", bus, dev, func, mem.base, mem.limit,
		    mem.base > mem.limit ? " (disabled)" : "");
		dcmn_err(CE_NOTE, MSGHDR "PMEM FWINIT 0x%lx ~ 0x%lx%s",
		    "ppb", bus, dev, func, pmem.base, pmem.limit,
		    pmem.base > pmem.limit ? " (disabled)" : "");
	}

	/*
	 * I/O range
	 *
	 * If the command register I/O enable bit is not set then we assume
	 * that the I/O windows have been left unconfigured by system firmware.
	 * In that case we leave it disabled and additionally set base > limit
	 * to indicate there are there are no initial resources available and
	 * to trigger later reconfiguration.
	 */
	if ((cmd_reg & PCI_COMM_IO) == 0) {
		io.base = PPB_DISABLE_IORANGE_BASE;
		io.limit = PPB_DISABLE_IORANGE_LIMIT;
		set_ppb_res(dip, bdf, RES_IO, io.base, io.limit);
	} else if (io.base < io.limit) {
		uint64_t size = io.limit - io.base + 1;

		memlist_rsrc_add(&sec_res->io_avail, io.base, size);
		memlist_rsrc_add(&res->io_used, io.base, size);
		memlist_rsrc_delete(&res->io_avail, io.base, size);
	}

	/*
	 * Memory range
	 *
	 * It is possible that the mem range will also have been left
	 * unconfigured by system firmware. As for the I/O range, we check for
	 * this by looking at the relevant bit in the command register (Memory
	 * Access Enable in this case) but we also check if the base address is
	 * 0, indicating that it is still at PCIe defaults. While 0 technically
	 * could be a valid base address, it is unlikely.
	 */
	if ((cmd_reg & PCI_COMM_MAE) == 0 || mem.base == 0) {
		mem.base = PPB_DISABLE_MEMRANGE_BASE;
		mem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
		set_ppb_res(dip, bdf, RES_MEM, mem.base, mem.limit);
	} else if (mem.base < mem.limit) {
		uint64_t size = mem.limit - mem.base + 1;

		memlist_rsrc_add(&sec_res->mem_avail, mem.base,
		    size);
		memlist_rsrc_add(&res->mem_used, mem.base, size);
		/* remove from parent resource list */
		memlist_rsrc_delete(&res->mem_avail, mem.base,
		    size);
		memlist_rsrc_delete(&res->pmem_avail, mem.base,
		    size);
	}

	/*
	 * Prefetchable range - as per MEM range above.
	 */
	if ((cmd_reg & PCI_COMM_MAE) == 0 || pmem.base == 0) {
		pmem.base = PPB_DISABLE_MEMRANGE_BASE;
		pmem.limit = PPB_DISABLE_MEMRANGE_LIMIT;
		set_ppb_res(dip, bdf, RES_PMEM, pmem.base, pmem.limit);
	} else if (pmem.base < pmem.limit) {
		uint64_t size = pmem.limit - pmem.base + 1;

		memlist_rsrc_add(&sec_res->pmem_avail, pmem.base, size);
		memlist_rsrc_add(&res->pmem_used, pmem.base, size);
		/* remove from parent resource list */
		memlist_rsrc_delete(&res->pmem_avail, pmem.base, size);
		memlist_rsrc_delete(&res->mem_avail, pmem.base, size);
	}

	/*
	 * Add VGA legacy resources to the bridge's pci_bus_res if it
	 * has VGA_ENABLE set.  Note that we put them in 'avail',
	 * because that's used to populate the ranges prop; they'll be
	 * removed from there by the VGA device once it's found.  Also,
	 * remove them from the parent's available list and note them as
	 * used in the parent.
	 */

	if (pci_cfgacc_get16(dip, bdf, PCI_BCNF_BCNTRL) &
	    PCI_BCNF_BCNTRL_VGA_ENABLE) {

		memlist_rsrc_add(&sec_res->io_avail, 0x3b0, 0xc);
		memlist_rsrc_add(&res->io_used, 0x3b0, 0xc);
		memlist_rsrc_delete(&res->io_avail, 0x3b0, 0xc);

		memlist_rsrc_add(&sec_res->io_avail, 0x3c0, 0x20);
		memlist_rsrc_add(&res->io_used, 0x3c0, 0x20);
		memlist_rsrc_delete(&res->io_avail, 0x3c0, 0x20);

		memlist_rsrc_add(&sec_res->mem_avail, 0xa0000,
		    0x20000);
		memlist_rsrc_add(&res->mem_used, 0xa0000, 0x20000);
		memlist_rsrc_delete(&res->mem_avail, 0xa0000,
		    0x20000);
	}
	add_bus_range_prop(seg, secbus);
	add_ranges_prop(seg, secbus, B_TRUE);

	dump_memlists("add_ppb_props end bus", seg, bus);
	dump_memlists("add_ppb_props end secbus", seg, secbus);
}

static void
add_bus_range_prop(uint16_t seg, uint8_t bus)
{
	struct pci_bus_resource *res;
	int bus_range[2];

	res = get_bus_res(seg, bus);
	if (res == NULL || res->dip == NULL)
		return;

	bus_range[0] = bus;
	bus_range[1] = res->sub_bus;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, res->dip,
	    "bus-range", (int *)bus_range, 2);
}

/*
 * Handle both PCI root and PCI-PCI bridge range properties;
 * the 'ppb' argument selects PCI-PCI bridges versus root.
 */
static void
memlist_to_ranges(void **rp, struct memlist *list, const int bus,
    const uint32_t type, boolean_t ppb)
{
	ppb_ranges_t *ppb_rp = *rp;
	pci_ranges_t *pci_rp = *rp;

	while (list != NULL) {
		uint32_t newtype = type;

		/*
		 * If this is in fact a 64-bit address, adjust the address
		 * type code to match.
		 */
		if (list->ml_address + (list->ml_size - 1) > UINT32_MAX) {
			if ((type & PCI_ADDR_MASK) == PCI_ADDR_IO) {
				cmn_err(CE_WARN, "Found invalid 64-bit I/O "
				    "space address 0x%lx+0x%lx on bus %x",
				    list->ml_address, list->ml_size, bus);
				list = list->ml_next;
				continue;
			}
			newtype &= ~PCI_ADDR_MASK;
			newtype |= PCI_ADDR_MEM64;
		}

		if (ppb) {
			ppb_rp->child_high = ppb_rp->parent_high = newtype;
			ppb_rp->child_mid = ppb_rp->parent_mid =
			    (uint32_t)(list->ml_address >> 32);
			ppb_rp->child_low = ppb_rp->parent_low =
			    (uint32_t)list->ml_address;
			ppb_rp->size_high = (uint32_t)(list->ml_size >> 32);
			ppb_rp->size_low = (uint32_t)list->ml_size;
			*rp = ++ppb_rp;
		} else {
			pci_rp->child_high = newtype;
			pci_rp->child_mid = pci_rp->parent_high =
			    (uint32_t)(list->ml_address >> 32);
			pci_rp->child_low = pci_rp->parent_low =
			    (uint32_t)list->ml_address;
			pci_rp->size_high = (uint32_t)(list->ml_size >> 32);
			pci_rp->size_low = (uint32_t)list->ml_size;
			*rp = ++pci_rp;
		}
		list = list->ml_next;
	}
}

static void
add_ranges_prop(uint16_t seg, uchar_t bus, boolean_t ppb)
{
	size_t total, alloc_size;
	void	*rp, *next_rp;
	struct memlist *iolist, *memlist, *pmemlist;
	struct pci_bus_resource *res;

	res = get_bus_res(seg, bus);

	/* no devinfo node - unused bus, return */
	if (res->dip == NULL)
		return;

	dump_memlists("add_ranges_prop", seg, bus);

	iolist = memlist = pmemlist = (struct memlist *)NULL;

	memlist_rsrc_merge(res->io_avail, &iolist);
	memlist_rsrc_merge(res->io_used, &iolist);
	memlist_rsrc_merge(res->mem_avail, &memlist);
	memlist_rsrc_merge(res->mem_used, &memlist);
	memlist_rsrc_merge(res->pmem_avail, &pmemlist);
	memlist_rsrc_merge(res->pmem_used, &pmemlist);

	total = memlist_count(iolist);
	total += memlist_count(memlist);
	total += memlist_count(pmemlist);

	/* no property is created if no ranges are present */
	if (total == 0)
		return;

	alloc_size = total *
	    (ppb ? sizeof (ppb_ranges_t) : sizeof (pci_ranges_t));

	next_rp = rp = kmem_alloc(alloc_size, KM_SLEEP);

	memlist_to_ranges(&next_rp, iolist, bus,
	    PCI_ADDR_IO | PCI_RELOCAT_B, ppb);
	memlist_to_ranges(&next_rp, memlist, bus,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B, ppb);
	memlist_to_ranges(&next_rp, pmemlist, bus,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B | PCI_PREFETCH_B, ppb);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, res->dip,
	    "ranges", (int *)rp, alloc_size / sizeof (int));

	kmem_free(rp, alloc_size);
	memlist_rsrc_free(&iolist);
	memlist_rsrc_free(&memlist);
	memlist_rsrc_free(&pmemlist);
}

static size_t
memlist_to_spec(struct pci_phys_spec *sp, const uint16_t seg, const int8_t bus,
    struct memlist *list, const uint32_t type)
{
	size_t i = 0;

	while (list != NULL) {
		uint32_t newtype = type;

		/*
		 * If this is in fact a 64-bit address, adjust the address
		 * type code to match.
		 */
		if (list->ml_address + (list->ml_size - 1) > UINT32_MAX) {
			if ((type & PCI_ADDR_MASK) == PCI_ADDR_IO) {
				cmn_err(CE_WARN, "Found invalid 64-bit I/O "
				    "space address 0x%lx+0x%lx on segment %u "
				    "bus 0x%x",
				    list->ml_address, list->ml_size, seg, bus);
				list = list->ml_next;
				continue;
			}
			newtype &= ~PCI_ADDR_MASK;
			newtype |= PCI_ADDR_MEM64;
		}

		sp->pci_phys_hi = newtype;
		sp->pci_phys_mid = (uint32_t)(list->ml_address >> 32);
		sp->pci_phys_low = (uint32_t)list->ml_address;
		sp->pci_size_hi = (uint32_t)(list->ml_size >> 32);
		sp->pci_size_low = (uint32_t)list->ml_size;

		list = list->ml_next;
		sp++, i++;
	}
	return (i);
}

static boolean_t
add_bus_available_prop(uint16_t seg, uint8_t bus, void *arg __unused)
{
	size_t i, count;
	struct pci_bus_resource *r;
	struct pci_phys_spec *sp;

	r = get_bus_res(seg, bus);

	/* no devinfo node - unused bus, return */
	if (r->dip == NULL)
		return (B_TRUE);

	count = memlist_count(r->io_avail) +
	    memlist_count(r->mem_avail) +
	    memlist_count(r->pmem_avail);

	if (count == 0)		/* nothing available */
		return (B_TRUE);

	sp = kmem_alloc(count * sizeof (*sp), KM_SLEEP);
	i = memlist_to_spec(&sp[0], seg, bus, r->io_avail,
	    PCI_ADDR_IO | PCI_RELOCAT_B);
	i += memlist_to_spec(&sp[i], seg, bus, r->mem_avail,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B);
	i += memlist_to_spec(&sp[i], seg, bus, r->pmem_avail,
	    PCI_ADDR_MEM32 | PCI_RELOCAT_B | PCI_PREFETCH_B);
	ASSERT3U(i, ==, count);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, r->dip,
	    "available", (int *)sp,
	    i * sizeof (struct pci_phys_spec) / sizeof (int));
	kmem_free(sp, count * sizeof (*sp));

	return (B_TRUE);
}

static void
alloc_res_array(void)
{
	size_t sz;
	uint_t i, j, idx, n_seg, max_seg, max_bus;

	n_seg = pci_prd_num_segments();
	max_seg = pci_prd_max_segment();

	/*
	 * Segment 0 always exists, even on systems without an MCFG table.
	 */
	if (n_seg == 0)
		n_seg = 1;

	sz = n_seg * sizeof (struct pci_bus_resource *);
	pci_bus_res = kmem_zalloc(sz, KM_SLEEP);

	for (i = idx = 0; i <= max_seg; i++) {
		/* XXX: need a better way of detecting discontiguous segments */
		max_bus = pci_prd_max_bus(i);
		if (max_bus == UINT32_MAX) {
			continue;
		}

		/*
		 * XXX: Since it appears permissible to have a range of buses
		 * that doesn't start at zero (e.g. [5, 13]) for a given
		 * segment, we might want to eventually be smarter about
		 * sizing
		 */
		sz = (max_bus + 1) * sizeof (struct pci_bus_resource);

		pci_bus_res[idx] = kmem_zalloc(sz, KM_SLEEP);

		for (j = 0; j <= max_bus; j++) {
			pci_bus_res[idx][j].par_bus = UCHAR_MAX;
			pci_bus_res[idx][j].root_addr = UCHAR_MAX;
			pci_bus_res[idx][j].sub_bus = j;
		}

		idx++;
	}
}

static void
create_ioapic_node(int bus, int dev, int fn, ushort_t vendorid,
    ushort_t deviceid)
{
	static dev_info_t *ioapicsnode = NULL;
	static int numioapics = 0;
	dev_info_t *ioapic_node;
	uint64_t physaddr;
	uint32_t lobase, hibase = 0;

	/* BAR 0 contains the IOAPIC's memory-mapped I/O address */
	lobase = (*pci_getl_func)(bus, dev, fn, PCI_CONF_BASE0);

	/* We (and the rest of the world) only support memory-mapped IOAPICs */
	if ((lobase & PCI_BASE_SPACE_M) != PCI_BASE_SPACE_MEM)
		return;

	if ((lobase & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL)
		hibase = (*pci_getl_func)(bus, dev, fn, PCI_CONF_BASE0 + 4);

	lobase &= PCI_BASE_M_ADDR_M;

	physaddr = (((uint64_t)hibase) << 32) | lobase;

	/*
	 * Create a nexus node for all IOAPICs under the root node.
	 */
	if (ioapicsnode == NULL) {
		if (ndi_devi_alloc(ddi_root_node(), IOAPICS_NODE_NAME,
		    (pnode_t)DEVI_SID_NODEID, &ioapicsnode) != NDI_SUCCESS) {
			return;
		}
		(void) ndi_devi_online(ioapicsnode, 0);
	}

	/*
	 * Create a child node for this IOAPIC
	 */
	ioapic_node = ddi_add_child(ioapicsnode, IOAPICS_CHILD_NAME,
	    DEVI_SID_NODEID, numioapics++);
	if (ioapic_node == NULL) {
		return;
	}

	/* Vendor and Device ID */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, ioapic_node,
	    IOAPICS_PROP_VENID, vendorid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, ioapic_node,
	    IOAPICS_PROP_DEVID, deviceid);

	/* device_type */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, ioapic_node,
	    "device_type", IOAPICS_DEV_TYPE);

	/* reg */
	(void) ndi_prop_update_int64(DDI_DEV_T_NONE, ioapic_node,
	    "reg", physaddr);
}

/*
 * Enable reporting of AER capability next pointer.
 * This needs to be done only for CK8-04 devices
 * by setting NV_XVR_VEND_CYA1 (offset 0xf40) bit 13
 * NOTE: BIOS is disabling this, it needs to be enabled temporarily
 *
 * This function is adapted from npe_ck804_fix_aer_ptr(), and is
 * called from pci_boot.c.
 */
static void
ck804_fix_aer_ptr(dev_info_t *dip, pcie_req_id_t bdf)
{
	dev_info_t *rcdip;
	ushort_t cya1;

	rcdip = pcie_get_rc_dip(dip);
	ASSERT(rcdip != NULL);

	if ((pci_cfgacc_get16(rcdip, bdf, PCI_CONF_VENID) ==
	    NVIDIA_VENDOR_ID) &&
	    (pci_cfgacc_get16(rcdip, bdf, PCI_CONF_DEVID) ==
	    NVIDIA_CK804_DEVICE_ID) &&
	    (pci_cfgacc_get8(rcdip, bdf, PCI_CONF_REVID) >=
	    NVIDIA_CK804_AER_VALID_REVID)) {
		cya1 = pci_cfgacc_get16(rcdip, bdf, NVIDIA_CK804_VEND_CYA1_OFF);
		if (!(cya1 & ~NVIDIA_CK804_VEND_CYA1_ERPT_MASK))
			(void) pci_cfgacc_put16(rcdip, bdf,
			    NVIDIA_CK804_VEND_CYA1_OFF,
			    cya1 | NVIDIA_CK804_VEND_CYA1_ERPT_VAL);
	}
}
