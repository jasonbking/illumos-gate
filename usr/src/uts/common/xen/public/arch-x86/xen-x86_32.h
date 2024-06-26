/******************************************************************************
 * xen-x86_32.h
 *
 * Guest OS interface to x86 32-bit Xen.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2004-2007, K A Fraser
 */

#ifndef __XEN_PUBLIC_ARCH_X86_XEN_X86_32_H__
#define __XEN_PUBLIC_ARCH_X86_XEN_X86_32_H__

/*
 * Hypercall interface:
 *  Input:  %ebx, %ecx, %edx, %esi, %edi (arguments 1-5)
 *  Output: %eax
 * Access is via hypercall page (set up by guest loader or via a Xen MSR):
 *  call hypercall_page + hypercall-number * 32
 * Clobbered: Argument registers (e.g., 2-arg hypercall clobbers %ebx,%ecx)
 */

/*
 * Direct hypercall interface:
 * As above, except the entry sequence to the hypervisor is:
 *  mov $hypercall-number*32,%eax ; int $0x82
 */
#if !defined(_ASM)
#define TRAP_INSTR "int $0x82"
#else
#define TRAP_INSTR int $0x82
#endif

/*
 * These flat segments are in the Xen-private section of every GDT. Since these
 * are also present in the initial GDT, many OSes will be able to avoid
 * installing their own GDT.
 */
#define FLAT_RING1_CS 0xe019    /* GDT index 259 */
#define FLAT_RING1_DS 0xe021    /* GDT index 260 */
#define FLAT_RING1_SS 0xe021    /* GDT index 260 */
#define FLAT_RING3_CS 0xe02b    /* GDT index 261 */
#define FLAT_RING3_DS 0xe033    /* GDT index 262 */
#define FLAT_RING3_SS 0xe033    /* GDT index 262 */

#define FLAT_KERNEL_CS FLAT_RING1_CS
#define FLAT_KERNEL_DS FLAT_RING1_DS
#define FLAT_KERNEL_SS FLAT_RING1_SS
#define FLAT_USER_CS    FLAT_RING3_CS
#define FLAT_USER_DS    FLAT_RING3_DS
#define FLAT_USER_SS    FLAT_RING3_SS

#define __HYPERVISOR_VIRT_START_PAE    0xF5800000
#define __MACH2PHYS_VIRT_START_PAE     0xF5800000
#define __MACH2PHYS_VIRT_END_PAE       0xF6800000
#define HYPERVISOR_VIRT_START_PAE      \
    mk_unsigned_long(__HYPERVISOR_VIRT_START_PAE)
#define MACH2PHYS_VIRT_START_PAE       \
    mk_unsigned_long(__MACH2PHYS_VIRT_START_PAE)
#define MACH2PHYS_VIRT_END_PAE         \
    mk_unsigned_long(__MACH2PHYS_VIRT_END_PAE)

/* Non-PAE bounds are obsolete. */
#define __HYPERVISOR_VIRT_START_NONPAE 0xFC000000
#define __MACH2PHYS_VIRT_START_NONPAE  0xFC000000
#define __MACH2PHYS_VIRT_END_NONPAE    0xFC400000
#define HYPERVISOR_VIRT_START_NONPAE   \
    mk_unsigned_long(__HYPERVISOR_VIRT_START_NONPAE)
#define MACH2PHYS_VIRT_START_NONPAE    \
    mk_unsigned_long(__MACH2PHYS_VIRT_START_NONPAE)
#define MACH2PHYS_VIRT_END_NONPAE      \
    mk_unsigned_long(__MACH2PHYS_VIRT_END_NONPAE)

#define __HYPERVISOR_VIRT_START __HYPERVISOR_VIRT_START_PAE
#define __MACH2PHYS_VIRT_START  __MACH2PHYS_VIRT_START_PAE
#define __MACH2PHYS_VIRT_END    __MACH2PHYS_VIRT_END_PAE

#ifndef HYPERVISOR_VIRT_START
#define HYPERVISOR_VIRT_START mk_unsigned_long(__HYPERVISOR_VIRT_START)
#endif

#define MACH2PHYS_VIRT_START  mk_unsigned_long(__MACH2PHYS_VIRT_START)
#define MACH2PHYS_VIRT_END    mk_unsigned_long(__MACH2PHYS_VIRT_END)
#define MACH2PHYS_NR_ENTRIES  ((MACH2PHYS_VIRT_END-MACH2PHYS_VIRT_START)>>2)
#ifndef machine_to_phys_mapping
#define machine_to_phys_mapping ((unsigned long *)MACH2PHYS_VIRT_START)
#endif

/* 32-/64-bit invariability for control interfaces (domctl/sysctl). */
#if defined(__XEN__) || defined(__XEN_TOOLS__)
#undef ___DEFINE_XEN_GUEST_HANDLE

#ifdef __GNUC__

#define ___DEFINE_XEN_GUEST_HANDLE(name, type)                  \
    typedef struct { type *p; }                                 \
        __guest_handle_ ## name;                                \
    typedef struct { union { type *p; uint64_aligned_t q; }; }  \
        __guest_handle_64_ ## name

#else /* __GNUC__ */

/*
 * Workaround for 6671857.
 */
#define ___DEFINE_XEN_GUEST_HANDLE(name, type)                  \
    typedef struct { type *p; }                                 \
        __guest_handle_ ## name;                                \
    typedef struct { union { type *p; uint64_aligned_t q; } u; }\
        __guest_handle_64_ ## name

#endif /* __GNUC__ */

#undef set_xen_guest_handle
#define set_xen_guest_handle(hnd, val)                      \
    do { if ( sizeof(hnd) == 8 ) *(uint64_t *)&(hnd) = 0;   \
         (hnd).p = val;                                     \
    } while ( 0 )
#define uint64_aligned_t uint64_t __attribute__((aligned(8)))
#define __XEN_GUEST_HANDLE_64(name) __guest_handle_64_ ## name
#define XEN_GUEST_HANDLE_64(name) __XEN_GUEST_HANDLE_64(name)
#endif

#ifndef __ASSEMBLY__

struct cpu_user_regs {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint16_t error_code;    /* private */
    uint16_t entry_vector;  /* private */
    uint32_t eip;
    uint16_t cs;
    uint8_t  saved_upcall_mask;
    uint8_t  _pad0;
    uint32_t eflags;        /* eflags.IF == !saved_upcall_mask */
    uint32_t esp;
    uint16_t ss, _pad1;
    uint16_t es, _pad2;
    uint16_t ds, _pad3;
    uint16_t fs, _pad4;
    uint16_t gs, _pad5;
};
typedef struct cpu_user_regs cpu_user_regs_t;
DEFINE_XEN_GUEST_HANDLE(cpu_user_regs_t);

/*
 * Page-directory addresses above 4GB do not fit into architectural %cr3.
 * When accessing %cr3, or equivalent field in vcpu_guest_context, guests
 * must use the following accessor macros to pack/unpack valid MFNs.
 */
#define xen_pfn_to_cr3(pfn) (((unsigned)(pfn) << 12) | ((unsigned)(pfn) >> 20))
#define xen_cr3_to_pfn(cr3) (((unsigned)(cr3) >> 12) | ((unsigned)(cr3) << 20))

struct arch_vcpu_info {
    unsigned long cr2;
    unsigned long pad[5]; /* sizeof(vcpu_info_t) == 64 */
};
typedef struct arch_vcpu_info arch_vcpu_info_t;

struct xen_callback {
    unsigned long cs;
    unsigned long eip;
};
typedef struct xen_callback xen_callback_t;

/*
 * Structure used to capture the register state at panic time.  This struct
 * is built to mimic a similar structure in Solaris.  If there is interest
 * in making this panic implementation an official part of Xen, this should
 * be made more platform-neutral.
 */
struct panic_regs {
	unsigned long pad1;
	unsigned long pad2;

	unsigned long gs;
	unsigned long fs;
	unsigned long es;
	unsigned long ds;
	unsigned long edi;
	unsigned long esi;
	unsigned long ebp;
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx;
	unsigned long ecx;
	unsigned long eax;
	unsigned long pad3;
	unsigned long pad4;
	unsigned long eip;
	unsigned long cs;
	unsigned long efl;
	unsigned long pad5;
	unsigned long ss;
};

#endif /* !__ASSEMBLY__ */

/* Offsets of each field in the xen_panic_regs structure.  */
#define PANIC_REG_PAD1		0
#define PANIC_REG_PAD2		4
#define PANIC_REG_GS		8
#define PANIC_REG_FS		12
#define PANIC_REG_ES		16
#define PANIC_REG_DS		20
#define PANIC_REG_EDI		24
#define PANIC_REG_ESI		28
#define PANIC_REG_EBP		32
#define PANIC_REG_ESP		36
#define PANIC_REG_EBX		40
#define PANIC_REG_EDX		44
#define PANIC_REG_ECX		48
#define PANIC_REG_EAX		52
#define PANIC_REG_PAD3		56
#define PANIC_REG_PAD4		60
#define PANIC_REG_EIP		64
#define PANIC_REG_CS		68
#define PANIC_REG_EFL		72
#define PANIC_REG_PAD5		76
#define PANIC_REG_SS		80
#define PANIC_REG_STRUCT_SIZE	84

#endif /* __XEN_PUBLIC_ARCH_X86_XEN_X86_32_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
