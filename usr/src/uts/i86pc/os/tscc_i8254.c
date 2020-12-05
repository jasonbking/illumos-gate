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

#include <sys/pit.h>
#include <sys/tsc.h>
#include <sys/archsystm.h>
#include <sys/prom_debug.h>

extern uint64_t freq_tsc(uint32_t *);

static boolean_t
tsc_calibrate_i8254(uint64_t *freqp)
{
	uint64_t processor_clks;
	ulong_t flags;
	uint32_t pit_counter;

	PRM_POINT("Attempting to use i8254 PIT timer for TSC calibration...");

	flags = clear_int_flag();
	processor_clks = freq_tsc(&pit_counter);
	restore_int_flag(flags);

	if (pit_counter == 0 || processor_clks == 0 ||
	    processor_clks > (((uint64_t)-1) / PIT_HZ)) {
		return (B_FALSE);
	}

	*freqp = ((uint64_t)PIT_HZ * processor_clks) / pit_counter;
	return (B_TRUE);
}

static tsc_calibrate_t tsc_calibration_i8254 = {
	.tscc_source = "pit",
	.tscc_quality = 10,
	.tscc_calibrate = tsc_calibrate_i8254,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_i8254);
