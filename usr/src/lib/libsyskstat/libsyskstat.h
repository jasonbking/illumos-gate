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
 */
#ifndef _SYSKSTAT_H
#define	_SYSKSTAT_H
#endif

#include <inttypes.h>
#include <kstat.h>

#ifndef __cplusplus
extern "C"
#endif

typedef struct kstat_field {
	char	*ksf_name;
	int	ksf_hint;
} kstat_field_t;
#define	KSTAT_FIELD_INIT(_n) { .ksf_name = _n, .ksf_hint = -1 }

typedef struct kstat_instance {
	char		ksi_name[KSTAT_STRLEN];
	int		ksi_instance;
	kstat_t		*ksi_ksp;
	uint64_t	*ksi_data[2];
	hrtime_t	ksi_snaptime[2];
	int		ksi_gen;
	struct kstat_instance *ksi_next;
} kstat_instance_t;

kstat_ctl_t *kstat_open_nofail(void);
int kstat_field_hint(kstat_t *, kstat_field_t *);
void kstat_instances_update(kstat_ctl_t *, kstat_instance_t **,
    boolean_t (*)(kstat_t *));
void kstat_instances_read(kstat_ctl_t *, kstat_instance_t *, size_t,
    kstat_field_t *);

uint64_t kstat_inst_value(kstat_instance_t *, int);
uint64_t kstat_inst_sum(kstat_instance_t *, size_t, ...);
uint64_t kstat_inst_diff(kstat_instance_t *, int);
uint64_t kstat_inst_delta(kstat_instance_t *, size_t, ...);

#ifndef __cplusplus
}
#endif

#endif /* _SYSKSTAT_H */
