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
 * Copyright 2020 Joyent, Inc.
 */

#include <inttypes.h>
#include <sys/regset.h>

typedef struct dwarf_regmap {
	uint_t	dr_nregs;
	uint_t	dr_cfa_reg;
	uint_t	dr_map[];
} dwarf_regmap_t;

typedef struct cie_info {
	uint32_t	cie_len;
	uint32_t	cie_id;
	uint32_t	cie_calgn;
	uint32_t	cie_dalgn;
	uint32_t	cie_rinstr;
	uint32_t	cie_ninstrs;
	uint8_t		*cie_instrs;
} cie_info_t __packed;

typedef struct fde_info {
	uint32_t	fde_len;
	uintptr_t	fde_base;
	uint32_t	fde_ninstrs;
	uint8_t		*fde_instrs;
} fde_info_t __packed;

typedef struct eh_frame_hdr {
	uint8_t efh_vers;
	uint8_t efh_exfmt;
	uint8_t efh_fdefmt;
	uint8_t efh_tblfmt;
} eh_frame_hdr_t __packed;

typedef struct cfa_rule {
	boolean_t	cr_valid;
	boolean_t	cr_usereg;
	boolean_t	cr_deref;
	uint32_t	cr_reg;
	int32_t		cr_off;
} cfa_rule_t __packed;

static dwarf_regmap_t amd64_regmap = {
	.dr_nregs = 17,
	.dr_cfa_reg = 7,	/* RBP */
	.dr_map = {
		REG_RAX,
		REG_RDX,
		REG_RCX,
		REG_RBX,
		REG_RSI,
		REG_RDI,
		REG_RBP,
		REG_RSP,
		REG_R8,
		REG_R9,
		REG_R10,
		REG_R11,
		REG_R12,
		REG_R13,
		REG_R14,
		REG_R15,
		REG_RIP
	}
};

static dwarf_regmap_t i386_regmap = {
	.dr_nregs = 10
	.dr_cfa_reg = 5 /* EBP */
	.dr_map = {
		EAX,
		ECX,
		EDX,
		EBX,
		ESP,
		EBP,
		ESI,
		EDI,
		EFL,
		TRAPNO,
		/* ST0 would be here, but is not used */
	}
};

boolean_t
pehstack_step(struct ps_prochandle *P, prgregset_t regs,
    const dwarf_regmap_t *rmap)
{
	return (B_FALSE);
}

int
Pehstack_iter(struct ps_prochandle *P, const prgregset_t regs,
    proc_stack_f *func, void *arg)
{
	const dwarf_regmap_t *rmap = &amd64_regmap;
	prgregset_t gregs = { 0 };
	int rv = 0;
	boolean_t more = B_FALSE;

	(void) memcpy(gregs, regs, sizeof (gregs));

	if (elf_version(EV_CURRENT) == EV_NONE) {
		dprintf("libproc ELF version is more recent than libelf\n");
		return (-1);
	}

	if (P->status.pr_dmodel != PR_MODEL_LP64)
		rmap = &i386_regmap;

	do {
		if ((rv = func(arg, gregs, 0, NULL)) != 0)
			break;

		more = pehstack_step(P, regs, rmap);
	} while (more);
		
	return (rv);
}
