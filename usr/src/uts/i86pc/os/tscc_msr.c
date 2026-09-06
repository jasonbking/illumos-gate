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
 * Copyright 2026 Jason King
 */

#include <sys/debug.h>
#include <sys/tsc.h>
#include <sys/prom_debug.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>

#define	HUNDRED_MHZ	100000000

/*
 * Note that for the Xeon-D and Xeon E5, 2.16 of the Intel SDM
 * references Table 1-26. However, from context, this appears to be
 * a typo (at least in the version consulted) if one looks at Table 1-26.
 * It almost certainly from the context means Table 2-26.
 */
static const struct intel_msr_info {
	uint_t		imi_family;
	uint_t		imi_model;
	uint64_t	imi_scale;
} intel_msr_tbl[] = {
	/* SDM Section 2.8 Nehalem */
	{ 0x6, INTC_MODEL_NEHALEM, 133330000 },
	{ 0x6, INTC_MODEL_NEHALEM2, 133330000 },
	{ 0x6, INTC_MODEL_NEHALEM_EX, 133330000 },
	{ 0x6, INTC_MODEL_NEHALEM_EP, 133330000 },

	/* SDM 2.11 Sandy Bridge */
	{ 0x6, INTC_MODEL_SANDYBRIDGE,		HUNDRED_MHZ },
	{ 0x6, INTC_MODEL_SANDYBRIDGE_XEON,	HUNDRED_MHZ },

	/* SDM 2.12 Ivy Bridge */
	{ 0x6, INTC_MODEL_IVYBRIDGE,		HUNDRED_MHZ },
	/* SDM 2.12.1 Ivy Bridge E */
	{ 0x6, INTC_MODEL_IVYBRIDGE_XEON,	HUNDRED_MHZ },

	/* SDM 2.13 Haswell */
	{ 0x6, INTC_MODEL_HASWELL,		HUNDRED_MHZ }, 
	{ 0x6, INTC_MODEL_HASWELL_ULT,		HUNDRED_MHZ },
	{ 0x6, INTC_MODEL_HASWELL_GT3E,		HUNDRED_MHZ },
	{ 0x6, INTC_MODEL_HASWELL_XEON,		HUNDRED_MHZ },

	/* SDM 2.16 Xeon E5 V4 (Broadwell) */
	{ 0x6, INTC_MODEL_BROADWELL_XEON,	HUNDRED_MHZ },
	{ 0x6, INTC_MODEL_BROADWELL_XEON_D,	HUNDRED_MHZ },

	/* SDM 2.17.6 Xeon Scalable */
	{ 0x6, INTC_MODEL_SKYLAKE_XEON,		HUNDRED_MHZ },

	/* SDM 2.17.11 Xeon 6 E-Core (Sierra Forest) */
	{ 0x6, INTC_MODEL_SIERRA_FOREST,	HUNDRED_MHZ },

	/* SDM 2.18 Knights Mill */
	{ 0x6, INTC_MODEL_KNIGHTS_MILL,		HUNDRED_MHZ },
	{ 0x6, INTC_MODEL_KNIGHTS_LANDING,	HUNDRED_MHZ },
};

static const struct intel_msr_info *
tsc_calibrate_msr_get_intel(void)
{
	const struct intel_msr_info *e = intel_msr_tbl;
	uint_t family, model, i;

	family = cpuid_getfamily(CPU);
	model = cpuid_getmodel(CPU);

	for (i = 0; i < ARRAY_SIZE(intel_msr_tbl); i++, e++) {
		if (e->imi_family != family)
			continue;
		if (e->imi_model != model)
			continue;
		return (e);
	}

	return (NULL);
}

static boolean_t
tsc_calibrate_msr_intel(uint64_t *freqp)
{
	const struct intel_msr_info	*e;
	uint64_t			base;

	ASSERT3U(cpuid_getvendor(CPU), ==, X86_VENDOR_Intel);

	e = tsc_calibrate_msr_get_intel();
	if (e == NULL)
		return (B_FALSE);

	/*
	 * For all of the supported platforms, the maximum non-turbo
	 * ratio is the ratio of the invariant TSC frequency.
	 * Multiplying by the scale value for the particular
	 * CPU family/model yields the TSC frequency in Hz.
	 */
	base = rdmsr(MSR_IA32_PLATFORM_INFO);
	base = IA32_PLAT_INFO_MAX_NONTURBO_RATIO(base);

	*freqp = base * e->imi_scale;

	return (B_TRUE);
}

static boolean_t
tsc_calibrate_msr(uint64_t *freqp)
{
	switch (cpuid_getvendor(CPU)) {
	case X86_VENDOR_Intel:
		return (tsc_calibrate_msr_intel(freqp));
	default:
		return (B_FALSE);
	}
}

static tsc_calibrate_t tsc_calibration_msr = {
	.tscc_source = "MSR",
	.tscc_preference = 75,
	.tscc_calibrate = tsc_calibrate_msr,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_msr);

