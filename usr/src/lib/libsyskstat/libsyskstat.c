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
		err(EXIT_FAILURE, "kstat_open");

	return (kcp);
}

int
kstat_field_hint(kstat_t *ksp, kstat_field_t *field)
{
	VERIFY3U(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	for (i = 0; i < ksp->ks_ndata; i++) {
		if (strcmp(field->ksf_name, nm[i].name) == 0)
			return (field->ksf_hint = i);
	}

	errx(EXIT_FAILURE"could not find field '%s' in %s:%d",
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
		err(EXIT_FAILURE, "failed to update kstat chain");

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
			err(EXIT_FAILURE,
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
    size_t nfields, kstat_field_t *kfp)
{
	kstat_instance_t *ksi;
	int i;

	for (ksi = instances; ksi != NULL; ksi = ksi->ksi_next) {
		kstat_t *ksp = ksi->ksi_ksp;

		if (ksp == NULL)
			continue;

		if (kstat_read(kcp, ksp, NULL) == -1) {
			if (errno != ENXIO) {
				err(EXIT_FAILURE, "failed to read kstat %s:%d",
				    ksi->ksi_name, ksi->ksi_instance);
			}

			/*
			 * Our kstat has been removed since the update;
			 * NULL it out to prevent us from trying to read
			 * it again (and to indicate that it should not be
			 * displayed) and drive on.
			 */
			ksi->ksi_ksp = NULL;
			continue;
		}
	}

	if (ksp->ks_type != KSTAT_TYPE_NAMED) {
		err(EXIT_FAILURE, "%s:%d is not a named kstat",
		    ksi->ksi_name, ksi->ksi_instnance);
	}

	if (ksi->ksi_data[0] == NULL) {
		uint64_t *data;

		if ((data = calloc(nfields * 2, sizeof (uint64_t))) == NULL)
		       err(EXIT_FAILURE, "could not allocate memory");

		ksi->ksi_data[0] = data;
		ksi->ksi_data[1] = &data[nfields];
	}

	for (i = 0; i < nfields; i++) {
		kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
		kstat_field_t *field = &fields[i];
		int hint = field->ksf_hint;

		if (hint < 0 || hint >= ksp->ks_ndata ||
		    strcmp(field->ksf_name, nm[hint].name) != 0) {
			hint = kstat_field_hint(ksp, field);
		}

		switch (nm[hint].data_type) {
		case KSTAT_DATA_CHAR:
			ksi->ksi_data[ksi->ksi_gen][i] =
			    (uint64_t)(uintptr_t)
			    nm[hint].value.charc;
			break;
		case KSTAT_DATA_STRING:
			ksi->ksi_data[ksi->ksi_gen][i] =
			    (uint64_t)(uintptr_t)KSTAT_NAME_STR_PTR(&nm[hint]);
			break;
		case KSTAT_DATA_UINT64:
			ksi->ksi_data[ksi->ksi_gen][i] =
			    nm[hint].value.ui64;
			break;
		default:
			/* Type not supported */
			VERIFY(0);
		}

		ksi->ksi_snaptime[ksi->ksi_gen] = ksp->ks_snaptime;
		ksi->ksi_gen ^= 1;
	}
}

hrtime_t
kstat_inst_tdelta(kstat_instance_t *ksi)
{
	int gen = ksi->ksi_gen;

	return (ksi->ksi_snaptime[gen ^ 1] - ksi->ksi_snaptime[gen]);
}

uint64_t
kstat_inst_value(kstat_instance_t *inst, int idx)
{
	return (inst->ksi_data[inst->ksi_gen][idx]);
}

uint64_t
kstat_inst_diff(kstat_instance_t *inst, int idx)
{
	uint64_t v1 = inst->ksi_data[inst->ksi_gen][idx];
	uint64_t v2 = inst->ksi_data[inst->ksi_gen ^ 1][idx];

	return (v1 - v2);
}

static uint64_t
kstat_inst_vsum(kstat_instance_t *inst, size_t n, va_list ap)
{
	uint64_t sum = 0;

	for (size_t i = 0; i < n; i++) {
		int idx = va_arg(ap, int);
		sum += kstat_inst_diff(inst, idx);
	}

	return (sum);
}

uint64_t
kstat_inst_sum(kstat_instance_t *inst, size_t n, ...)
{
	uint64_t sum;
	va_list ap;

	va_start(ap, n);
	sum = kstat_inst_vsum(inst, n, ap);
	va_end(ap);

	return (sum);
}

uint64_t
kstat_inst_delta(kstat_instance_t *inst, size_t n, ...)
{
	uint64_t sum;
	hrtime_t tdelta;
	va_list ap;

	va_start(ap, n);
	sum = kstat_inst_vsum(inst, n, ap);
	va_end(ap);

	tdelta = kstat_inst_tdelta(inst);

	sum *= (uint64_t)NANOSEC;
	sum += tdelta / 2;
	sum /= tdelta;

	return (sum);
}
