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

#ifndef _TSC_H
#define	_TSC_H

#ifndef _ASM
#include <sys/linker_set.h>
#include <sys/types.h>
#endif

/*
 * flags to patch tsc_read routine.
 */
#define	TSC_NONE		0x0
#define	TSC_RDTSC_CPUID		0x1
#define	TSC_RDTSC_MFENCE	0x2
#define	TSC_RDTSC_LFENCE	0x3
#define	TSC_TSCP		0x4

#ifndef _ASM
/* An arbitrary limit, but should be sufficiently large */
#define	TSC_CALIBRATE_NAME_LEN	32

typedef struct tsc_calibrate {
	char		tscc_source[TSC_CALIBRATE_NAME_LEN];
	uint_t		tscc_quality;
	boolean_t	(*tscc_calibrate)(uint64_t *);
} tsc_calibrate_t;
#define	TSC_CALIBRATION_SOURCE(x) DATA_SET(tsc_calibration_set, x)

extern tsc_calibrate_t *tsc_calibration_source;
uint64_t tsc_calibrate(void);
uint64_t tsc_get_freq(void);

#endif /* _ASM */

#endif /* _TSC_H */
