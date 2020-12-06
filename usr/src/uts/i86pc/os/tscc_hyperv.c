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
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/tsc.h>
#include <sys/x86_archext.h>
#include <sys/prom_debug.h>
#include <sys/cpuvar.h>

/*
 * HyperV provides a 10MHz timer via reading an MSR. This is preferred to
 * using the i8254 PIT timer since it's more reliable, and second generation
 * VMs do not even include a PIT timer.
 */

#define	HYPERV_SAMPLE_PERIOD	(100)	/* in us */

static boolean_t
tsc_calibrate_hyperv(uint64_t *freqp)
{
	if (platform_type != HW_MICROSOFT)
		return (B_FALSE);

	/* XXX: Other checks */

	PRM_POINT("Attempting to use HyperV MSR for TSC calibration...");

	uint64_t now, end, amt;
	uint64_t tsc_start, tsc_end, tsc_ticks;

	now = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	end = now + HYPERV_SAMPLE_PERIOD * 10;
	tsc_start = tsc_read();

	while (end < now)
		end = rdmsr(HV_X64_MSR_TIME_REF_COUNT);

	tsc_end = tsc_read();

	/*
	 * We likely did not finish exactly HYPERV_SAMPLE_PERIOD us later.
	 * Calculate the actual duration of the sample.
	 */
	amt = end - now;

	tsc_ticks = tsc_end - tsc_start;

	*freqp = tsc_ticks * MICROSEC / amt;
	return (B_TRUE);
}

static tsc_calibrate_t tsc_calibration_hyperv = {
	.tscc_source = "hyperv",
	.tscc_quality = 1000,
	.tscc_calibrate = tsc_calibrate_hyperv,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_hyperv);
