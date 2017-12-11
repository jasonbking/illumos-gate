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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <alloca.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <time.h>
#include <libsyskstat.h>

#define	RETRY_DELAY	200

kstat_ctl_t *
kstat_open_nofail(void)
{
	kstat_ctl_t *kcp;

	if ((kcp = kstat_open()) == NULL)
		kstat_fatal("kstat_open");

	return (kcp);
}

int
kstat_field_hint(kstat_t *ksp, kstat_field_t *field)
{
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	assert(ksp->ks_type == KSTAT_TYPE_NAMED);

	for (i = 0; i < ksp->ks_ndata; i++) {
		if (strcmp(field->ksf_name, nm[i].name) == 0)
			return (field->ksf_hint = i);
	}

	kstat_fatal("could not find field '%s' in %s:%d",
	    field->ksf_name, ksp->ks_name, ksp->ks_instance);

	return (0);
}

static int
kstat_instances_compare(const void *lhs, const void *rhs)
{
	kstat_instance_t *l = *((kstat_instance_t **)lhs);
	kstat_instance_t *r = *((kstat_instance_t **)rhs);
	int rval;

	if ((rval = strcmp(l->ksi_name, r->ksi_name)) != 0)
		return (rval);

	if (l->ksi_instance < r->ksi_instance)
		return (-1);

	if (l->ksi_instance > r->ksi_instance)
		return (1);

	return (0);
}

void
kstat_instances_update(kstat_ctl_t *kcp, kstat_instance_t **instances,
    boolean_t (*interested)(kstat_t *))
{
	int ninstances = 0, i;
	kstat_instance_t **sorted, *ksi, *next;
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(kcp)) == 0 && *head != NULL)
		return;

	if (kid == -1)
		kstat_fatal("failed to update kstat chain");

	for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next)
		ksi->ksi_ksp = NULL;

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		kstat_instance_t *last = NULL;

		if (!interested(ksp))
			continue;

		/*
		 * Now look to see if we have this instance and name.  (Yes,
		 * this is a linear search; we're assuming that this list is
		 * modest in size.)
		 */
		for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next) {
			last = ksi;

			if (ksi->ksi_instance != ksp->ks_instance)
				continue;

			if (strcmp(ksi->ksi_name, ksp->ks_name) != 0)
				continue;

			ksi->ksi_ksp = ksp;
			ninstances++;
			break;
		}

		if (ksi != NULL)
			continue;

		if ((ksi = malloc(sizeof (kstat_instance_t))) == NULL)
			kstat_fatal(
			    "could not allocate memory for stat instance");

		bzero(ksi, sizeof (kstat_instance_t));
		(void) strlcpy(ksi->ksi_name, ksp->ks_name, KSTAT_STRLEN);
		ksi->ksi_instance = ksp->ks_instance;
		ksi->ksi_ksp = ksp;
		ksi->ksi_next = NULL;

		if (last == NULL) {
			VERIFY3P(*head, ==, NULL);
			*head = ksi;
		} else {
			last->ksi_next = ksi;
		}

		ninstances++;
	}

	/*
	 * Now we know how many instances we have; iterate back over them,
	 * pruning the stale ones and adding the active ones to a holding
	 * array in which to sort them.
	 */
	sorted = (void *)alloca(ninstances * sizeof (kstat_instance_t *));
	ninstances = 0;

	for (ksi = *head; ksi != NULL; ksi = next) {
		next = ksi->ksi_next;

		if (ksi->ksi_ksp == NULL) {
			free(ksi);
		} else {
			sorted[ninstances++] = ksi;
		}
	}

	if (ninstances == 0) {
		*head = NULL;
		return;
	}

	qsort(sorted, ninstances, sizeof (kstat_instance_t *),
	    kstat_instances_compare);

	*head = sorted[0];

	for (i = 0; i < ninstances; i++) {
		ksi = sorted[i];
		ksi->ksi_next = i < ninstances - 1 ? sorted[i + 1] : NULL;
	}
}

void
kstat_instances_read(kstat_ctl_t *kcp, kstat_instance_t *instance,
    kstat_field_t *kfp)
{
}

void
kstat_fatal(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	verr(EXIT_FAILURE, msg, ap);
	va_end(ap);
}

hrtime_t
kstat_inst_tdelta(kstat_instance_t *ksi)
{
	int gen = ksi->ksi_gen;

	return (ksi->ksi_snaptime[gen ^ 1] - ksi->ksi_snaptime[gen]);
}

uint64_t
kstat_inst_value(kstat_instance_t *instances, int idx)
{
}

uint64_t
kstat_inst_diff(kstat_instance_t *instances, int idx)
{
}

uint64_t
kstat_inst_sum(kstat_instance_t *instances, int n, ...)
{
}

uint64_t
kstat_inst_delta(kstat_instance_t *instances, int n, ...)
{
}
