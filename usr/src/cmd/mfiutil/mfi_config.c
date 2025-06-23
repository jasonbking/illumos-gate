/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2008, 2009 Yahoo!, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright 2024 RackTop Systems, Inc.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#ifdef DEBUG
#endif
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/scsi/adapters/mfi/mfi.h>
#include <sys/scsi/adapters/mfi/mfi_ld.h>
#include <sys/scsi/adapters/mfi/mfi_pd.h>

#include "mfiutil.h"

static int	add_spare(int ac, char **av);
static int	remove_spare(int ac, char **av);

static long
dehumanize(const char *value)
{
	char    *vtp;
	long    iv;

	if (value == NULL)
		return (0);
	iv = strtol(value, &vtp, 0);
	if (vtp == value || (vtp[0] != '\0' && vtp[1] != '\0')) {
		return (0);
	}
	switch (vtp[0]) {
	case 't': case 'T':
		iv *= 1024;
		/*FALLTHRU*/
	case 'g': case 'G':
		iv *= 1024;
		/*FALLTHRU*/
	case 'm': case 'M':
		iv *= 1024;
		/*FALLTHRU*/
	case 'k': case 'K':
		iv *= 1024;
		/*FALLTHRU*/
	case '\0':
		break;
	default:
		return (0);
	}
	return (iv);
}

int
mfi_config_read(int fd, mfi_config_data_t **configp)
{
	return (mfi_config_read_opcode(fd, MFI_DCMD_CFG_READ, configp, NULL,
	    0));
}

int
mfi_config_read_opcode(int fd, uint32_t opcode, mfi_config_data_t **configp,
    uint8_t *mbox, size_t mboxlen)
{
	mfi_config_data_t *config;
	uint32_t config_size;
	int error;

	/*
	 * Keep fetching the config in a loop until we have a large enough
	 * buffer to hold the entire configuration.
	 */
	config = NULL;
	config_size = 1024;
fetch:
	config = reallocf(config, config_size);
	if (config == NULL)
		return (-1);
	if (mfi_dcmd_command(fd, opcode, config,
	    config_size, mbox, mboxlen, NULL) < 0) {
		error = errno;
		free(config);
		errno = error;
		return (-1);
	}

	if (config->cd_size > config_size) {
		config_size = config->cd_size;
		goto fetch;
	}

	*configp = config;
	return (0);
}

static mfi_array_t *
mfi_config_lookup_array(mfi_config_data_t *config, uint16_t array_ref)
{
	mfi_array_t *ar;
	char *p;
	int i;

	p = (char *)config->cd_array;
	for (i = 0; i < config->cd_array_cnt; i++) {
		ar = (mfi_array_t *)p;
		if (ar->ar_ref == array_ref)
			return (ar);
		p += config->cd_array_size;
	}

	return (NULL);
}

static mfi_ld_config_t *
mfi_config_lookup_volume(mfi_config_data_t *config, uint8_t target_id)
{
	mfi_ld_config_t *ld;
	char *p;
	int i;

	p = (char *)config->cd_array +
	    config->cd_array_cnt * config->cd_array_size;
	for (i = 0; i < config->cd_ld_cnt; i++) {
		ld = (mfi_ld_config_t *)p;
		if (ld->lc_props.lp_ld.lr_tgtid == target_id)
			return (ld);
		p += config->cd_ld_size;
	}

	return (NULL);
}

static int
clear_config(int ac __unused, char **av __unused)
{
	mfi_ld_list_t list;
	int ch, error, fd;
	uint_t i;

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (!mfi_reconfig_supported(mfi_device)) {
		warnx("The current %s driver does not support "
		    "configuration changes.", mfi_device);
		close(fd);
		return (EOPNOTSUPP);
	}

	if (mfi_ld_get_list(fd, &list, NULL) < 0) {
		error = errno;
		warn("Failed to get volume list");
		close(fd);
		return (error);
	}

	for (i = 0; i < list.ll_ld_count; i++) {
		if (mfi_volume_busy(fd, list.ll_ld[i].ld_ref.lr_tgtid)) {
			warnx("Volume %s is busy and cannot be deleted",
			    mfi_volume_name(fd, list.ll_ld[i].ld_ref.lr_tgtid));
			close(fd);
			return (EBUSY);
		}
	}

	printf(
	    "Are you sure you wish to clear the configuration on %s? [y/N] ",
	    mfi_device);
	ch = getchar();
	if (ch != 'y' && ch != 'Y') {
		printf("\nAborting\n");
		close(fd);
		return (0);
	}

	if (mfi_dcmd_command(fd, MFI_DCMD_CFG_CLEAR, NULL, 0, NULL, 0, NULL) <
	    0) {
		error = errno;
		warn("Failed to clear configuration");
		close(fd);
		return (error);
	}

	printf("%s: Configuration cleared\n", mfi_device);
	close(fd);

	return (0);
}
MFI_COMMAND(top, clear, clear_config);

#define	MAX_DRIVES_PER_ARRAY MFI_MAX_ROW_SIZE
#define	MFI_ARRAY_SIZE sizeof (mfi_array_t)

#define	RT_RAID0	0
#define	RT_RAID1	1
#define	RT_RAID5	2
#define	RT_RAID6	3
#define	RT_JBOD		4
#define	RT_CONCAT	5
#define	RT_RAID10	6
#define	RT_RAID50	7
#define	RT_RAID60	8

static int
compare_int(const void *one, const void *two)
{
	int first, second;

	first = *(const int *)one;
	second = *(const int *)two;

	return (first - second);
}

static struct raid_type_entry {
	const char *name;
	int	raid_type;
} raid_type_table[] = {
	{ "raid0",	RT_RAID0 },
	{ "raid-0",	RT_RAID0 },
	{ "raid1",	RT_RAID1 },
	{ "raid-1",	RT_RAID1 },
	{ "mirror",	RT_RAID1 },
	{ "raid5",	RT_RAID5 },
	{ "raid-5",	RT_RAID5 },
	{ "raid6",	RT_RAID6 },
	{ "raid-6",	RT_RAID6 },
	{ "jbod",	RT_JBOD },
	{ "concat",	RT_CONCAT },
	{ "raid10",	RT_RAID10 },
	{ "raid1+0",	RT_RAID10 },
	{ "raid-10",	RT_RAID10 },
	{ "raid-1+0",	RT_RAID10 },
	{ "raid50",	RT_RAID50 },
	{ "raid5+0",	RT_RAID50 },
	{ "raid-50",	RT_RAID50 },
	{ "raid-5+0",	RT_RAID50 },
	{ "raid60",	RT_RAID60 },
	{ "raid6+0",	RT_RAID60 },
	{ "raid-60",	RT_RAID60 },
	{ "raid-6+0",	RT_RAID60 },
	{ NULL,		0 },
};

struct config_id_state {
	int	array_count;
	int	log_drv_count;
	int	*arrays;
	int	*volumes;
	uint16_t array_ref;
	uint8_t	target_id;
};

struct array_info {
	int	drive_count;
	mfi_pd_info_t *drives;
	mfi_array_t *array;
};

/* Parse a comma-separated list of drives for an array. */
static int
parse_array(int fd, int raid_type, char *array_str, struct array_info *info)
{
	mfi_pd_info_t *pinfo;
	uint16_t device_id;
	char *cp;
	uint_t count;
	int error;

	cp = array_str;
	for (count = 0; cp != NULL; count++) {
		cp = strchr(cp, ',');
		if (cp != NULL) {
			cp++;
			if (*cp == ',') {
				warnx("Invalid drive list '%s'", array_str);
				return (EINVAL);
			}
		}
	}

	/* Validate the number of drives for this array. */
	if (count >= MAX_DRIVES_PER_ARRAY) {
		warnx("Too many drives for a single array: max is %d",
		    MAX_DRIVES_PER_ARRAY);
		return (EINVAL);
	}
	switch (raid_type) {
	case RT_RAID1:
	case RT_RAID10:
		if (count % 2 != 0) {
			warnx("RAID1 and RAID10 require an even number of "
			    "drives in each array");
			return (EINVAL);
		}
		break;
	case RT_RAID5:
	case RT_RAID50:
		if (count < 3) {
			warnx("RAID5 and RAID50 require at least 3 drives in "
			    "each array");
			return (EINVAL);
		}
		break;
	case RT_RAID6:
	case RT_RAID60:
		if (count < 4) {
			warnx("RAID6 and RAID60 require at least 4 drives in "
			    "each array");
			return (EINVAL);
		}
		break;
	}

	/* Validate each drive. */
	info->drives = calloc(count, sizeof (mfi_pd_info_t));
	if (info->drives == NULL) {
		warnx("malloc failed");
		return (ENOMEM);
	}
	info->drive_count = count;
	for (pinfo = info->drives; (cp = strsep(&array_str, ",")) != NULL;
	    pinfo++) {
		error = mfi_lookup_drive(fd, cp, &device_id);
		if (error) {
			free(info->drives);
			info->drives = NULL;
			return (error);
		}

		if (mfi_pd_get_info(fd, device_id, pinfo, NULL) < 0) {
			error = errno;
			warn("Failed to fetch drive info for drive %s", cp);
			free(info->drives);
			info->drives = NULL;
			return (error);
		}

		if (pinfo->pd_fw_state != MFI_PD_STATE_UNCONFIGURED_GOOD) {
			warnx("Drive %u is not available", device_id);
			free(info->drives);
			info->drives = NULL;
			return (EINVAL);
		}

		if (pinfo->pd_ddf_type.pd_is_foreign) {
			warnx("Drive %u is foreign", device_id);
			free(info->drives);
			info->drives = NULL;
			return (EINVAL);
		}
	}

	return (0);
}

/*
 * Find the next free array ref assuming that 'array_ref' is the last
 * one used.  'array_ref' should be 0xffff for the initial test.
 */
static uint16_t
find_next_array(struct config_id_state *state)
{
	int i;

	/* Assume the current one is used. */
	state->array_ref++;

	/* Find the next free one. */
	for (i = 0; i < state->array_count; i++)
		if (state->arrays[i] == state->array_ref)
			state->array_ref++;
	return (state->array_ref);
}

/*
 * Find the next free volume ID assuming that 'target_id' is the last
 * one used.  'target_id' should be 0xff for the initial test.
 */
static uint8_t
find_next_volume(struct config_id_state *state)
{
	int i;

	/* Assume the current one is used. */
	state->target_id++;

	/* Find the next free one. */
	for (i = 0; i < state->log_drv_count; i++)
		if (state->volumes[i] == state->target_id)
			state->target_id++;
	return (state->target_id);
}

/* Populate an array with drives. */
static void
build_array(int fd __unused, char *arrayp, struct array_info *array_info,
    struct config_id_state *state, int verbose)
{
	mfi_array_t *ar = (mfi_array_t *)arrayp;
	int i;

	ar->ar_size = array_info->drives[0].pd_coerced_size;
	ar->ar_ndrive = array_info->drive_count;
	ar->ar_ref = find_next_array(state);
	for (i = 0; i < array_info->drive_count; i++) {
		if (verbose)
			printf("Adding drive %s to array %u\n",
			    mfi_drive_name(NULL,
			    array_info->drives[i].pd_ref.pr_dev_id,
			    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS),
			    ar->ar_ref);
		if (ar->ar_size > array_info->drives[i].pd_coerced_size)
			ar->ar_size = array_info->drives[i].pd_coerced_size;
		ar->ar_pd[i].pd_ref = array_info->drives[i].pd_ref;
		ar->ar_pd[i].pd_fw_state = MFI_PD_STATE_ONLINE;
	}
	array_info->array = ar;
}

/*
 * Create a volume that spans one or more arrays.
 */
static void
build_volume(char *volumep, int narrays, struct array_info *arrays,
    int raid_type, long stripe_size, struct config_id_state *state, int verbose)
{
	mfi_ld_config_t *ld = (mfi_ld_config_t *)volumep;
	mfi_array_t *ar;
	int i;

	/* properties */
	ld->lc_props.lp_ld.lr_tgtid = find_next_volume(state);
	ld->lc_props.lp_ld.lr_seqnum = 0;
	ld->lc_props.lp_def_cache_policy = MFI_LD_CACHE_ALLOW_WRITE_CACHE |
	    MFI_LD_CACHE_WRITE_BACK;
	ld->lc_props.lp_access_policy = MFI_LD_ACCESS_RW;
	ld->lc_props.lp_disk_cache_policy = MFI_PD_CACHE_UNCHANGED;
	ld->lc_props.lp_cur_cache_policy = MFI_LD_CACHE_ALLOW_WRITE_CACHE |
	    MFI_LD_CACHE_WRITE_BACK;
	ld->lc_props.lp_no_bgi = 0;

	/* params */
	switch (raid_type) {
	case RT_RAID0:
	case RT_JBOD:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID0;
		ld->lc_params.lp_raid_lvl_qual = 0;
		ld->lc_params.lp_secondary_raid_lvl = 0;
		break;
	case RT_RAID1:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID1;
		ld->lc_params.lp_raid_lvl_qual = 0;
		ld->lc_params.lp_secondary_raid_lvl = 0;
		break;
	case RT_RAID5:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID5;
		ld->lc_params.lp_raid_lvl_qual = 3;
		ld->lc_params.lp_secondary_raid_lvl = 0;
		break;
	case RT_RAID6:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID6;
		ld->lc_params.lp_raid_lvl_qual = 3;
		ld->lc_params.lp_secondary_raid_lvl = 0;
		break;
	case RT_CONCAT:
		ld->lc_params.lp_primary_raid_lvl = DDF_CONCAT;
		ld->lc_params.lp_raid_lvl_qual = 0;
		ld->lc_params.lp_secondary_raid_lvl = 0;
		break;
	case RT_RAID10:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID1;
		ld->lc_params.lp_raid_lvl_qual = 0;
		ld->lc_params.lp_secondary_raid_lvl = 3; /* XXX? */
		break;
	case RT_RAID50:
		/*
		 * XXX: This appears to work though the card's BIOS
		 * complains that the configuration is foreign.  The
		 * BIOS setup does not allow for creation of RAID-50
		 * or RAID-60 arrays.  The only nested array
		 * configuration it allows for is RAID-10.
		 */
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID5;
		ld->lc_params.lp_raid_lvl_qual = 3;
		ld->lc_params.lp_secondary_raid_lvl = 3; /* XXX? */
		break;
	case RT_RAID60:
		ld->lc_params.lp_primary_raid_lvl = DDF_RAID6;
		ld->lc_params.lp_raid_lvl_qual = 3;
		ld->lc_params.lp_secondary_raid_lvl = 3; /* XXX? */
		break;
	}

	/*
	 * Stripe size is encoded as (2 ^ N) * 512 = stripe_size.  Use
	 * ffs() to simulate log2(stripe_size).
	 */
	ld->lc_params.lp_stripe_size = ffs(stripe_size) - 1 - 9;
	ld->lc_params.lp_ndrive = arrays[0].array->ar_ndrive;
	ld->lc_params.lp_span_depth = narrays;
	ld->lc_params.lp_state = MFI_LD_STATE_OPTIMAL;
	ld->lc_params.lp_init_state = MFI_LD_PARAMS_INIT_NO;
	ld->lc_params.lp_is_consistent = 0;

	/* spans */
	for (i = 0; i < narrays; i++) {
		ar = arrays[i].array;
		if (verbose)
			printf("Adding array %u to volume %u\n", ar->ar_ref,
			    ld->lc_props.lp_ld.lr_tgtid);
		ld->lc_span[i].s_start_block = 0;
		ld->lc_span[i].s_num_blocks = ar->ar_size;
		ld->lc_span[i].s_array_ref = ar->ar_ref;
	}
}

static int
create_volume(int ac, char **av)
{
	mfi_config_data_t *config;
	mfi_array_t *ar;
	mfi_ld_config_t *ld;
	struct config_id_state state;
	size_t config_size;
	char *p, *cfg_arrays, *cfg_volumes;
	int error, fd, i, raid_type;
	int narrays, nvolumes, arrays_per_volume;
	struct array_info *arrays;
	long stripe_size;
#ifdef DEBUG
	int dump;
#endif
	int ch, verbose;

	/*
	 * Backwards compat.  Map 'create volume' to 'create' and
	 * 'create spare' to 'add'.
	 */
	if (ac > 1) {
		if (strcmp(av[1], "volume") == 0) {
			av++;
			ac--;
		} else if (strcmp(av[1], "spare") == 0) {
			av++;
			ac--;
			return (add_spare(ac, av));
		}
	}

	if (ac < 2) {
		warnx("create volume: volume type required");
		return (EINVAL);
	}

	bzero(&state, sizeof (state));
	config = NULL;
	arrays = NULL;
	narrays = 0;
	error = 0;

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (!mfi_reconfig_supported(mfi_device)) {
		warnx("The current %s(4) driver does not support "
		    "configuration changes.", mfi_device);
		error = EOPNOTSUPP;
		goto error;
	}

	/* Lookup the RAID type first. */
	raid_type = -1;
	for (i = 0; raid_type_table[i].name != NULL; i++)
		if (strcasecmp(raid_type_table[i].name, av[1]) == 0) {
			raid_type = raid_type_table[i].raid_type;
			break;
		}

	if (raid_type == -1) {
		warnx("Unknown or unsupported volume type %s", av[1]);
		error = EINVAL;
		goto error;
	}

	/* Parse any options. */
	optind = 2;
#ifdef DEBUG
	dump = 0;
#endif
	verbose = 0;
	stripe_size = 64 * 1024;

	while ((ch = getopt(ac, av, "ds:v")) != -1) {
		switch (ch) {
#ifdef DEBUG
		case 'd':
			dump = 1;
			break;
#endif
		case 's':
			stripe_size = dehumanize(optarg);
			if ((stripe_size < 512) || (!ISP2(stripe_size)))
				stripe_size = 64 * 1024;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			error = EINVAL;
			goto error;
		}
	}
	ac -= optind;
	av += optind;

	/* Parse all the arrays. */
	narrays = ac;
	if (narrays == 0) {
		warnx("At least one drive list is required");
		error = EINVAL;
		goto error;
	}
	switch (raid_type) {
	case RT_RAID0:
	case RT_RAID1:
	case RT_RAID5:
	case RT_RAID6:
	case RT_CONCAT:
		if (narrays != 1) {
			warnx("Only one drive list can be specified");
			error = EINVAL;
			goto error;
		}
		break;
	case RT_RAID10:
	case RT_RAID50:
	case RT_RAID60:
		if (narrays < 1) {
			warnx("RAID10, RAID50, and RAID60 require at least "
			    "two drive lists");
			error = EINVAL;
			goto error;
		}
		if (narrays > MFI_MAX_SPAN_DEPTH) {
			warnx("Volume spans more than %d arrays",
			    MFI_MAX_SPAN_DEPTH);
			error = EINVAL;
			goto error;
		}
		break;
	}
	arrays = calloc(narrays, sizeof (*arrays));
	if (arrays == NULL) {
		warnx("malloc failed");
		error = ENOMEM;
		goto error;
	}
	for (i = 0; i < narrays; i++) {
		error = parse_array(fd, raid_type, av[i], &arrays[i]);
		if (error)
			goto error;
	}

	switch (raid_type) {
	case RT_RAID10:
	case RT_RAID50:
	case RT_RAID60:
		for (i = 1; i < narrays; i++) {
			if (arrays[i].drive_count != arrays[0].drive_count) {
				warnx("All arrays must contain the same "
				    "number of drives");
				error = EINVAL;
				goto error;
			}
		}
		break;
	}

	/*
	 * Fetch the current config and build sorted lists of existing
	 * array and volume identifiers.
	 */
	if (mfi_config_read(fd, &config) < 0) {
		error = errno;
		warn("Failed to read configuration");
		goto error;
	}
	p = (char *)config->cd_array;
	state.array_ref = 0xffff;
	state.target_id = 0xff;
	state.array_count = config->cd_array_cnt;
	if (config->cd_array_cnt > 0) {
		state.arrays = calloc(config->cd_array_cnt, sizeof (int));
		if (state.arrays == NULL) {
			warnx("malloc failed");
			error = ENOMEM;
			goto error;
		}
		for (i = 0; i < config->cd_array_cnt; i++) {
			ar = (mfi_array_t *)p;
			state.arrays[i] = ar->ar_ref;
			p += config->cd_array_size;
		}
		qsort(state.arrays, config->cd_array_cnt, sizeof (int),
		    compare_int);
	} else
		state.arrays = NULL;
	state.log_drv_count = config->cd_ld_cnt;
	if (config->cd_ld_cnt) {
		state.volumes = calloc(config->cd_ld_cnt, sizeof (int));
		if (state.volumes == NULL) {
			warnx("malloc failed");
			error = ENOMEM;
			goto error;
		}
		for (i = 0; i < config->cd_ld_cnt; i++) {
			ld = (mfi_ld_config_t *)p;
			state.volumes[i] = ld->lc_props.lp_ld.lr_tgtid;
			p += config->cd_ld_size;
		}
		qsort(state.volumes, config->cd_ld_cnt, sizeof (int),
		    compare_int);
	} else
		state.volumes = NULL;
	free(config);

	/* Determine the size of the configuration we will build. */
	switch (raid_type) {
	case RT_RAID0:
	case RT_RAID1:
	case RT_RAID5:
	case RT_RAID6:
	case RT_CONCAT:
	case RT_JBOD:
		/* Each volume spans a single array. */
		nvolumes = narrays;
		break;
	case RT_RAID10:
	case RT_RAID50:
	case RT_RAID60:
		/* A single volume spans multiple arrays. */
		nvolumes = 1;
		break;
	default:
		/* Pacify gcc. */
		abort();
	}

	config_size = sizeof (mfi_config_data_t) +
	    sizeof (mfi_ld_config_t) * nvolumes + MFI_ARRAY_SIZE * narrays;
	config = calloc(1, config_size);
	if (config == NULL) {
		warnx("malloc failed");
		error = ENOMEM;
		goto error;
	}
	config->cd_size = config_size;
	config->cd_array_cnt = narrays;
	config->cd_array_size = MFI_ARRAY_SIZE;	/* XXX: Firmware hardcode */
	config->cd_ld_cnt = nvolumes;
	config->cd_ld_size = sizeof (mfi_ld_config_t);
	config->cd_spare_cnt = 0;
	config->cd_spare_size = 40;		/* XXX: Firmware hardcode */
	cfg_arrays = (char *)config->cd_array;
	cfg_volumes = cfg_arrays + config->cd_array_size * narrays;

	/* Build the arrays. */
	for (i = 0; i < narrays; i++) {
		build_array(fd, cfg_arrays, &arrays[i], &state, verbose);
		cfg_arrays += config->cd_array_size;
	}

	/* Now build the volume(s). */
	arrays_per_volume = narrays / nvolumes;
	for (i = 0; i < nvolumes; i++) {
		build_volume(cfg_volumes, arrays_per_volume,
		    &arrays[i * arrays_per_volume], raid_type, stripe_size,
		    &state, verbose);
		cfg_volumes += config->cd_ld_size;
	}

#ifdef DEBUG
	if (dump)
		dump_config(fd, config, NULL);
#endif

	/* Send the new config to the controller. */
	if (mfi_dcmd_command(fd, MFI_DCMD_CFG_ADD, config, config_size,
	    NULL, 0, NULL) < 0) {
		error = errno;
		warn("Failed to add volume");
		/* FALLTHROUGH */
	}

error:
	/* Clean up. */
	free(config);
	free(state.volumes);
	free(state.arrays);
	if (arrays != NULL) {
		for (i = 0; i < narrays; i++)
			free(arrays[i].drives);
		free(arrays);
	}
	close(fd);

	return (error);
}
MFI_COMMAND(top, create, create_volume);

static int
delete_volume(int ac, char **av)
{
	mfi_ld_info_t info;
	int error, fd;
	uint8_t target_id, mbox[4];

	/*
	 * Backwards compat.  Map 'delete volume' to 'delete' and
	 * 'delete spare' to 'remove'.
	 */
	if (ac > 1) {
		if (strcmp(av[1], "volume") == 0) {
			av++;
			ac--;
		} else if (strcmp(av[1], "spare") == 0) {
			av++;
			ac--;
			return (remove_spare(ac, av));
		}
	}

	if (ac != 2) {
		warnx("delete volume: volume required");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (!mfi_reconfig_supported(mfi_device)) {
		warnx("The current %s(4) driver does not support "
		    "configuration changes.", mfi_device);
		close(fd);
		return (EOPNOTSUPP);
	}

	if (mfi_lookup_volume(fd, av[1], &target_id) < 0) {
		error = errno;
		warn("Invalid volume %s", av[1]);
		close(fd);
		return (error);
	}

	if (mfi_ld_get_info(fd, target_id, &info, NULL) < 0) {
		error = errno;
		warn("Failed to get info for volume %d", target_id);
		close(fd);
		return (error);
	}

	if (mfi_volume_busy(fd, target_id)) {
		warnx("Volume %s is busy and cannot be deleted",
		    mfi_volume_name(fd, target_id));
		close(fd);
		return (EBUSY);
	}

	mbox_store_ldref(mbox, &info.li_config.lc_props.lp_ld);
	if (mfi_dcmd_command(fd, MFI_DCMD_LD_DELETE, NULL, 0, mbox,
	    sizeof (mbox), NULL) < 0) {
		error = errno;
		warn("Failed to delete volume");
		close(fd);
		return (error);
	}

	close(fd);

	return (0);
}
MFI_COMMAND(top, delete, delete_volume);

static int
add_spare(int ac, char **av)
{
	mfi_pd_info_t info;
	mfi_config_data_t *config;
	mfi_array_t *ar;
	mfi_ld_config_t *ld;
	mfi_spare_t *spare;
	uint16_t device_id;
	uint8_t target_id;
	char *p;
	int error, fd, i;

	if (ac < 2) {
		warnx("add spare: drive required");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	config = NULL;
	spare = NULL;
	error = mfi_lookup_drive(fd, av[1], &device_id);
	if (error)
		goto error;

	if (mfi_pd_get_info(fd, device_id, &info, NULL) < 0) {
		error = errno;
		warn("Failed to fetch drive info");
		goto error;
	}

	if (info.pd_fw_state != MFI_PD_STATE_UNCONFIGURED_GOOD) {
		warnx("Drive %u is not available", device_id);
		error = EINVAL;
		goto error;
	}

	if (ac > 2) {
		if (mfi_lookup_volume(fd, av[2], &target_id) < 0) {
			error = errno;
			warn("Invalid volume %s", av[2]);
			goto error;
		}
	}

	if (mfi_config_read(fd, &config) < 0) {
		error = errno;
		warn("Failed to read configuration");
		goto error;
	}

	spare = malloc(sizeof (mfi_spare_t) + sizeof (uint16_t) *
	    config->cd_array_cnt);
	if (spare == NULL) {
		warnx("malloc failed");
		error = ENOMEM;
		goto error;
	}
	bzero(spare, sizeof (mfi_spare_t));
	spare->s_pd_ref = info.pd_ref;

	if (ac == 2) {
		/* Global spare backs all arrays. */
		p = (char *)config->cd_array;
		for (i = 0; i < config->cd_array_cnt; i++) {
			ar = (mfi_array_t *)p;
			if (ar->ar_size > info.pd_coerced_size) {
				warnx("Spare isn't large enough for array %u",
				    ar->ar_ref);
				error = EINVAL;
				goto error;
			}
			p += config->cd_array_size;
		}
		spare->s_array_cnt = 0;
	} else  {
		/*
		 * Dedicated spares only back the arrays for a
		 * specific volume.
		 */
		ld = mfi_config_lookup_volume(config, target_id);
		if (ld == NULL) {
			warnx("Did not find volume %d", target_id);
			error = EINVAL;
			goto error;
		}

		spare->s_type |= MFI_SPARE_DEDICATED;
		spare->s_array_cnt = ld->lc_params.lp_span_depth;
		for (i = 0; i < ld->lc_params.lp_span_depth; i++) {
			ar = mfi_config_lookup_array(config,
			    ld->lc_span[i].s_array_ref);
			if (ar == NULL) {
				warnx("Missing array; inconsistent config?");
				error = ENXIO;
				goto error;
			}
			if (ar->ar_size > info.pd_coerced_size) {
				warnx("Spare isn't large enough for array %u",
				    ar->ar_ref);
				error = EINVAL;
				goto error;
			}
			spare->s_array_ref[i] = ar->ar_ref;
		}
	}

	if (mfi_dcmd_command(fd, MFI_DCMD_CFG_MAKE_SPARE, spare,
	    sizeof (mfi_spare_t) + sizeof (uint16_t) * spare->s_array_cnt,
	    NULL, 0, NULL) < 0) {
		error = errno;
		warn("Failed to assign spare");
		/* FALLTHROUGH. */
	}

error:
	free(spare);
	free(config);
	close(fd);

	return (error);
}
MFI_COMMAND(top, add, add_spare);

static int
remove_spare(int ac, char **av)
{
	mfi_pd_info_t info;
	int error, fd;
	uint16_t device_id;
	uint8_t mbox[4];

	if (ac != 2) {
		warnx("remove spare: drive required");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	error = mfi_lookup_drive(fd, av[1], &device_id);
	if (error) {
		close(fd);
		return (error);
	}

	/* Get the info for this drive. */
	if (mfi_pd_get_info(fd, device_id, &info, NULL) < 0) {
		error = errno;
		warn("Failed to fetch info for drive %u", device_id);
		close(fd);
		return (error);
	}

	if (info.pd_fw_state != MFI_PD_STATE_HOT_SPARE) {
		warnx("Drive %u is not a hot spare", device_id);
		close(fd);
		return (EINVAL);
	}

	mbox_store_pdref(mbox, &info.pd_ref);
	if (mfi_dcmd_command(fd, MFI_DCMD_CFG_REMOVE_SPARE, NULL, 0, mbox,
	    sizeof (mbox), NULL) < 0) {
		error = errno;
		warn("Failed to delete spare");
		close(fd);
		return (error);
	}

	close(fd);

	return (0);
}
MFI_COMMAND(top, remove, remove_spare);

/* Display raw data about a config. */
void
dump_config(int fd, mfi_config_data_t *config, const char *msg_prefix)
{
	mfi_array_t *ar;
	mfi_ld_config_t *ld;
	mfi_spare_t *sp;
	mfi_pd_info_t pinfo;
	uint16_t device_id;
	char *p;
	int i, j;

	if (NULL == msg_prefix)
		msg_prefix = "Configuration (Debug)";

	printf(
	    "%s %s: %d arrays, %d volumes, %d spares\n", mfi_device,
	    msg_prefix, config->cd_array_cnt, config->cd_ld_cnt,
	    config->cd_spare_cnt);
	printf("  array size: %u\n", config->cd_array_size);
	printf("  volume size: %u\n", config->cd_ld_size);
	printf("  spare size: %u\n", config->cd_spare_size);
	p = (char *)config->cd_array;

	for (i = 0; i < config->cd_array_cnt; i++) {
		ar = (mfi_array_t *)p;
		printf("    array %u of %u drives:\n", ar->ar_ref,
		    ar->ar_ndrive);
		printf("      size = %ju\n", (uintmax_t)ar->ar_size);
		for (j = 0; j < ar->ar_ndrive; j++) {
			device_id = ar->ar_pd[j].pd_ref.pr_dev_id;
			if (device_id == 0xffff) {
				printf("        drive MISSING\n");
				continue;
			}

			printf("        drive %u %s\n", device_id,
			    mfi_pdstate(ar->ar_pd[j].pd_fw_state));
			if (mfi_pd_get_info(fd, device_id, &pinfo, NULL) >= 0) {
				printf("          raw size: %ju\n",
				    (uintmax_t)pinfo.pd_raw_size);
				printf("          non-coerced size: %ju\n",
				    (uintmax_t)pinfo.pd_non_coerced_size);
				printf("          coerced size: %ju\n",
				    (uintmax_t)pinfo.pd_coerced_size);
			}
		}
		p += config->cd_array_size;
	}

	for (i = 0; i < config->cd_ld_cnt; i++) {
		ld = (mfi_ld_config_t *)p;
		printf("    volume %s ",
		    mfi_volume_name(fd, ld->lc_props.lp_ld.lr_tgtid));
		printf("%s %s",
		    mfi_raid_level(ld->lc_params.lp_primary_raid_lvl,
		    ld->lc_params.lp_secondary_raid_lvl),
		    mfi_ldstate(ld->lc_params.lp_state));
		if (ld->lc_props.lp_name[0] != '\0')
			printf(" <%s>", ld->lc_props.lp_name);
		printf("\n");
		printf("      primary raid level: %u\n",
		    ld->lc_params.lp_primary_raid_lvl);
		printf("      raid level qualifier: %u\n",
		    ld->lc_params.lp_raid_lvl_qual);
		printf("      secondary raid level: %u\n",
		    ld->lc_params.lp_secondary_raid_lvl);
		printf("      stripe size: %u\n", ld->lc_params.lp_stripe_size);
		printf("      num drives: %u\n", ld->lc_params.lp_ndrive);
		printf("      init state: %u\n", ld->lc_params.lp_init_state);
		printf("      consistent: %u\n",
		    ld->lc_params.lp_is_consistent);
		printf("      no bgi: %u\n", ld->lc_props.lp_no_bgi);
		printf("      spans:\n");
		for (j = 0; j < ld->lc_params.lp_span_depth; j++) {
			printf("        array %u @ ",
			    ld->lc_span[j].s_array_ref);
			printf("%ju : %ju\n",
			    (uintmax_t)ld->lc_span[j].s_start_block,
			    (uintmax_t)ld->lc_span[j].s_num_blocks);
		}
		p += config->cd_ld_size;
	}

	for (i = 0; i < config->cd_spare_cnt; i++) {
		sp = (mfi_spare_t *)p;
		printf("    %s spare %u ",
		    sp->s_type & MFI_SPARE_DEDICATED ? "dedicated" : "global",
		    sp->s_pd_ref.pr_dev_id);
		printf("%s", mfi_pdstate(MFI_PD_STATE_HOT_SPARE));
		printf(" backs:\n");
		for (j = 0; j < sp->s_array_cnt; j++)
			printf("        array %u\n", sp->s_array_ref[j]);
		p += config->cd_spare_size;
	}
}

#ifdef DEBUG
static int
debug_config(int ac, char **av)
{
	mfi_config_data_t *config;
	int error, fd;

	if (ac != 1) {
		warnx("debug: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDWR);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	/* Get the config from the controller. */
	if (mfi_config_read(fd, &config) < 0) {
		error = errno;
		warn("Failed to get config");
		close(fd);
		return (error);
	}

	/* Dump out the configuration. */
	dump_config(fd, config, NULL);
	free(config);
	close(fd);

	return (0);
}
MFI_COMMAND(top, debug, debug_config);
#endif
