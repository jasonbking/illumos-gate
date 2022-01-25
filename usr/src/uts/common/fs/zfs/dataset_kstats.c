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
 * Copyright (c) 2018 by Delphix. All rights reserved.
 * Copyright 2022 Jason King
 */

#include <sys/dataset_kstats.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/spa.h>

static int
dataset_kstats_update(kstat_t *ksp, int rw)
{
	dataset_kstats_t *dk = ksp->ks_private;
	ASSERT3P(dk->dk_kstats->ks_data, ==, ksp->ks_data);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	dataset_kstat_values_t *dkv = dk->dk_kstats->ks_data;
	dkv->dkv_writes.value.ui64 =
	    aggsum_value(&dk->dk_aggsums.das_writes);
	dkv->dkv_nwritten.value.ui64 =
	    aggsum_value(&dk->dk_aggsums.das_nwritten);
	dkv->dkv_reads.value.ui64 =
	    aggsum_value(&dk->dk_aggsums.das_reads);
	dkv->dkv_nread.value.ui64 =
	    aggsum_value(&dk->dk_aggsums.das_nread);

	return (0);
}

void
dataset_kstats_create(dataset_kstats_t *dk, objset_t *objset)
{
	/*
	 * There should not be anything wrong with having kstats for
	 * snapshots. Since we are not sure how useful they would be
	 * though nor how much their memory overhead would matter in
	 * a filesystem with many snapshots, we skip them for now.
	 */
	if (dmu_objset_is_snapshot(objset))
		return;

	/*
	 * While other platforms have ported the kstat framework for
	 * OpenZFS support, they also increased the size of KSTAT_STRLEN
	 * to 255. However we cannot increase the value of KSTAT_STRLEN
	 * from its current value (31) without breaking binary compatibility.
	 * Therefore, we use the spa guid to form the module name, and include
	 * the pool name as a named kstat for each dataset instead.
	 *
	 * This does mean our kstats look slightly different, though mostly
	 * in just how the particular kstat is mapped back to a dataset.
	 */
	char kstat_module_name[KSTAT_STRLEN];
	int n = snprintf(kstat_module_name, sizeof (kstat_module_name),
	    "zpool-0x%" PRIx64, spa_guid(dmu_objset_spa(objset)));
	if (n < 0) {
		zfs_dbgmsg("failed to create dataset kstat for objset %lld: "
		    " snprintf() for kstat module name returned %d",
		    (unsigned long long)dmu_objset_id(objset), n);
		return;
	} else if (n >= KSTAT_STRLEN) {
		zfs_dbgmsg("failed to create dataset kstat for objset %lld: "
		    "kstat module name length (%d) exceeds limit (%d)",
		    (unsigned long long)dmu_objset_id(objset),
		    n, KSTAT_STRLEN);
		return;
	}

	char kstat_name[KSTAT_STRLEN];
	n = snprintf(kstat_name, sizeof (kstat_name), "objset-0x%llx",
	    (unsigned long long)dmu_objset_id(objset));
	if (n < 0) {
		zfs_dbgmsg("failed to create dataset kstat for objset %lld: "
		    " snprintf() for kstat name returned %d",
		    (unsigned long long)dmu_objset_id(objset), n);
		return;
	}
	ASSERT3U(n, <, KSTAT_STRLEN);

	kstat_t *kstat = kstat_create(kstat_module_name, 0, kstat_name,
	    "dataset", KSTAT_TYPE_NAMED,
	    sizeof (dataset_kstat_values_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (kstat == NULL)
		return;

	dataset_kstat_values_t *dk_kstats =
	    kmem_alloc(sizeof (*dk_kstats), KM_SLEEP);

	kstat_named_init(&dk_kstats->dkv_pool, "pool_name", KSTAT_DATA_STRING);
	kstat_named_init(&dk_kstats->dkv_ds_name, "dataset_name",
	    KSTAT_DATA_STRING);
	kstat_named_init(&dk_kstats->dkv_writes, "writes", KSTAT_DATA_UINT64);
	kstat_named_init(&dk_kstats->dkv_nwritten, "nwritten",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&dk_kstats->dkv_reads, "reads", KSTAT_DATA_UINT64);
	kstat_named_init(&dk_kstats->dkv_nread, "nread", KSTAT_DATA_UINT64);

	/* Add space for pool and dataset names */
	kstat->ks_data_size += 2 * ZFS_MAX_DATASET_NAME_LEN;

	kstat->ks_data = dk_kstats;
	kstat->ks_update = dataset_kstats_update;
	kstat->ks_private = dk;

	kstat_install(kstat);
	dk->dk_kstats = kstat;

	aggsum_init(&dk->dk_aggsums.das_writes, 0);
	aggsum_init(&dk->dk_aggsums.das_nwritten, 0);
	aggsum_init(&dk->dk_aggsums.das_reads, 0);
	aggsum_init(&dk->dk_aggsums.das_nread, 0);

	kstat_named_setstr(&dk_kstats->dkv_pool,
	    spa_name(dmu_objset_spa(objset)));

	char *ds_name = kmem_zalloc(ZFS_MAX_DATASET_NAME_LEN, KM_SLEEP);

	dsl_dataset_name(objset->os_dsl_dataset, ds_name);
	kstat_named_setstr(&dk_kstats->dkv_ds_name, ds_name);
}

void
dataset_kstats_destroy(dataset_kstats_t *dk)
{
	if (dk->dk_kstats == NULL)
		return;

	dataset_kstat_values_t *dkv = dk->dk_kstats->ks_data;
	kmem_free(KSTAT_NAMED_STR_PTR(&dkv->dkv_ds_name),
	    ZFS_MAX_DATASET_NAME_LEN);
	kmem_free(dkv, sizeof (*dkv));

	kstat_delete(dk->dk_kstats);
	dk->dk_kstats = NULL;

	aggsum_fini(&dk->dk_aggsums.das_writes);
	aggsum_fini(&dk->dk_aggsums.das_nwritten);
	aggsum_fini(&dk->dk_aggsums.das_reads);
	aggsum_fini(&dk->dk_aggsums.das_nread);
}

void
dataset_kstats_update_write_kstats(dataset_kstats_t *dk,
    int64_t nwritten)
{
	ASSERT3S(nwritten, >=, 0);

	if (dk->dk_kstats == NULL)
		return;

	aggsum_add(&dk->dk_aggsums.das_writes, 1);
	aggsum_add(&dk->dk_aggsums.das_nwritten, nwritten);
}

void
dataset_kstats_update_read_kstats(dataset_kstats_t *dk,
    int64_t nread)
{
	ASSERT3S(nread, >=, 0);

	if (dk->dk_kstats == NULL)
		return;

	aggsum_add(&dk->dk_aggsums.das_reads, 1);
	aggsum_add(&dk->dk_aggsums.das_nread, nread);
}
