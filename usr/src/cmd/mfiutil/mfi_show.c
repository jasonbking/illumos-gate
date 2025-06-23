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

#include <sys/types.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <libcmdutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/scsi/adapters/mfi/mfi.h>
#include <sys/scsi/adapters/mfi/mfi_bbu.h>
#include <sys/scsi/adapters/mfi/mfi_ld.h>
#include <sys/scsi/adapters/mfi/mfi_pd.h>

#include "mfiutil.h"

static const char *foreign_state = " (FOREIGN)";

MFI_TABLE(top, show);

void
format_stripe(char *buf, size_t buflen, uint8_t stripe)
{
	nicenum_scale((1 << stripe) * 512, 0, buf, buflen, 0);
}

static int
show_adapter(int ac, char **av __unused)
{
	mfi_ctrl_info_t info;
	char stripe[5];
	int error, fd, comma;

	if (ac != 1) {
		warnx("show adapter: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (mfi_ctrl_get_info(fd, &info, NULL) < 0) {
		error = errno;
		warn("Failed to get controller info");
		close(fd);
		return (error);
	}
	printf("%s Adapter:\n", mfi_device);
	printf("    Product Name: %.80s\n", info.ci_product_name);
	printf("   Serial Number: %.32s\n", info.ci_serial_no);
	if (info.ci_package_version[0] != '\0')
		printf("        Firmware: %s\n", info.ci_package_version);
	printf("     RAID Levels:");
#ifdef DEBUG
	printf(" (%#x)", info.ci_raid_levels);
#endif
	comma = 0;
	if (info.ci_raid_levels.rl_raid_level_0) {
		printf(" JBOD, RAID0");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_1) {
		printf("%s RAID1", comma ? "," : "");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_5) {
		printf("%s RAID5", comma ? "," : "");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_1E) {
		printf("%s RAID1E", comma ? "," : "");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_6) {
		printf("%s RAID6", comma ? "," : "");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_0 &&
	    info.ci_raid_levels.rl_raid_level_1) {
		printf("%s RAID10", comma ? "," : "");
		comma = 1;
	}
	if (info.ci_raid_levels.rl_raid_level_0 &&
	    info.ci_raid_levels.rl_raid_level_5) {
		printf("%s RAID50", comma ? "," : "");
		comma = 1;
	}
	printf("\n");
	printf("  Battery Backup: ");
	if (info.ci_hw_present.hw_bbu)
		printf("present\n");
	else
		printf("not present\n");
	if (info.ci_hw_present.hw_nvram)
		printf("           NVRAM: %uK\n", info.ci_nvram_size);
	printf("  Onboard Memory: %uM\n", info.ci_memory_size);
	format_stripe(stripe, sizeof (stripe),
	    info.ci_raid_opts.raid_stripe_sz_min);
	printf("  Minimum Stripe: %s\n", stripe);
	format_stripe(stripe, sizeof (stripe),
	    info.ci_raid_opts.raid_stripe_sz_max);
	printf("  Maximum Stripe: %s\n", stripe);

	close(fd);

	return (0);
}
MFI_COMMAND(show, adapter, show_adapter);

static int
show_battery(int ac, char **av __unused)
{
	mfi_bbu_capacity_t cap;
	mfi_bbu_design_info_t design;
	mfi_bbu_properties_t props;
	mfi_bbu_status_t stat;
	uint8_t status;
	int comma, error, fd, show_capacity, show_props;
	char buf[32];

	if (ac != 1) {
		warnx("show battery: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (mfi_dcmd_command(fd, MFI_DCMD_BBU_GET_CAPACITY_INFO, &cap,
	    sizeof (cap), NULL, 0, &status) < 0) {
		error = errno;
		warn("Failed to get capacity info");
		close(fd);
		return (error);
	}
	if (status == MFI_STAT_NO_HW_PRESENT) {
		printf("%s: No battery present\n", mfi_device);
		close(fd);
		return (0);
	}
	show_capacity = (status == MFI_STAT_OK);

	if (mfi_dcmd_command(fd, MFI_DCMD_BBU_GET_DESIGN_INFO, &design,
	    sizeof (design), NULL, 0, NULL) < 0) {
		error = errno;
		warn("Failed to get design info");
		close(fd);
		return (error);
	}

	if (mfi_dcmd_command(fd, MFI_DCMD_BBU_GET_STATUS, &stat, sizeof (stat),
	    NULL, 0, NULL) < 0) {
		error = errno;
		warn("Failed to get status");
		close(fd);
		return (error);
	}

	if (mfi_bbu_get_props(fd, &props, &status) < 0) {
		error = errno;
		warn("Failed to get properties");
		close(fd);
		return (error);
	}
	show_props = (status == MFI_STAT_OK);

	printf("%s: Battery State:\n", mfi_device);
	printf("     Manufacture Date: %d/%d/%d\n",
	    design.bbu_mfg_date >> 5 & 0x0f, design.bbu_mfg_date & 0x1f,
	    design.bbu_mfg_date >> 9 & 0xffff);
	printf("        Serial Number: %d\n", design.bbu_serial_number);
	printf("         Manufacturer: %s\n", design.bbu_mfg_name);
	printf("                Model: %s\n", design.bbu_dev_name);
	printf("            Chemistry: %s\n", design.bbu_dev_chemistry);
	printf("      Design Capacity: %d mAh\n", design.bbu_design_cap);
	if (show_capacity) {
		printf(" Full Charge Capacity: %d mAh\n",
		    cap.bbu_full_charge_cap);
		printf("     Current Capacity: %d mAh\n",
		    cap.bbu_rem_cap);
		printf("        Charge Cycles: %d\n", cap.bbu_cycle_count);
		printf("       Current Charge: %d%%\n", cap.bbu_rel_charge);
	}
	printf("       Design Voltage: %d mV\n", design.bbu_design_voltage);
	printf("      Current Voltage: %d mV\n", stat.bbu_voltage);
	printf("          Temperature: %d C\n", stat.bbu_temp);
	if (show_props) {
		mfi_autolearn_period(props.bbu_auto_learn_period, buf,
		    sizeof (buf));
		printf("     Autolearn period: %s\n", buf);
		if (props.bbu_auto_learn_mode != 0)
			snprintf(buf, sizeof (buf), "never");
		else
			mfi_next_learn_time(props.bbu_next_learn_time, buf,
			    sizeof (buf));
		printf("      Next learn time: %s\n", buf);
		printf(" Learn delay interval: %u hour%s\n",
		    props.bbu_learn_delay_interval,
		    props.bbu_learn_delay_interval != 1 ? "s" : "");
		mfi_autolearn_mode(props.bbu_auto_learn_mode, buf,
		    sizeof (buf));
		printf("       Autolearn mode: %s\n", buf);
		if (props.bbu_mode != 0)
			printf("             BBU Mode: %d\n", props.bbu_mode);
	}
	printf("               Status:");
	comma = 0;
	if (stat.bbu_state_pack_missing) {
		printf(" PACK_MISSING");
		comma = 1;
	}
	if (stat.bbu_state_voltage_low) {
		printf("%s VOLTAGE_LOW", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_temperature_high) {
		printf("%s TEMPERATURE_HIGH", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_charging) {
		printf("%s CHARGING", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_discharging) {
		printf("%s DISCHARGING", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_learn_cyc_req) {
		printf("%s LEARN_CYCLE_REQUESTED", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_learn_cyc_active) {
		printf("%s LEARN_CYCLE_ACTIVE", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_learn_cyc_fail) {
		printf("%s LEARN_CYCLE_FAIL", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_learn_cyc_timeout) {
		printf("%s LEARN_CYCLE_TIMEOUT", comma ? "," : "");
		comma = 1;
	}
	if (stat.bbu_state_i2c_err_detect) {
		printf("%s I2C_ERROR_DETECT", comma ? "," : "");
		comma = 1;
	}

	if (!comma)
		printf(" normal");
	printf("\n");
	switch (stat.bbu_type) {
	case MFI_BBU_TYPE_BBU:
		printf("      State of Health: %s\n",
		    stat.bbu_state.bbu_healthy ? "good" : "bad");
		break;
	}

	close(fd);

	return (0);
}
MFI_COMMAND(show, battery, show_battery);

void
print_ld(mfi_ld_info_t *info, int state_len)
{
	mfi_ld_parameters_t *params = &info->li_config.lc_params;
	const char *level;
	char size[6], stripe[5];

	nicenum_scale(info->li_size * 512, 0, size, sizeof (size), 0);
	format_stripe(stripe, sizeof (stripe),
	    info->li_config.lc_params.lp_stripe_size);
	level = mfi_raid_level(params->lp_primary_raid_lvl,
	    params->lp_secondary_raid_lvl);
	if (state_len > 0)
		printf("(%6s) %-8s %6s %-*s", size, level, stripe, state_len,
		    mfi_ldstate(params->lp_state));
	else
		printf("(%s) %s %s %s", size, level, stripe,
		    mfi_ldstate(params->lp_state));
}

void
print_pd(mfi_pd_info_t *info, int state_len)
{
	const char *s;
	char buf[256];

	nicenum_scale(info->pd_raw_size * 512, 0, buf, 6, 0);
	printf("(%6s) ", buf);
	if (info->pd_ddf_type.pd_is_foreign) {
		sprintf(buf, "%s%s", mfi_pdstate(info->pd_fw_state),
		    foreign_state);
		s = buf;
	} else
		s = mfi_pdstate(info->pd_fw_state);
	if (state_len > 0)
		printf("%-*s", state_len, s);
	else
		printf("%s", s);
	s = mfi_pd_inq_string(info);
	if (s != NULL)
		printf(" %s", s);
}

static int
show_config(int ac, char **av __unused)
{
	mfi_config_data_t *config;
	mfi_array_t *ar;
	mfi_ld_config_t *ld;
	mfi_spare_t *sp;
	mfi_ld_info_t linfo;
	mfi_pd_info_t pinfo;
	uint16_t device_id;
	char *p;
	int error, fd, i, j;

	if (ac != 1) {
		warnx("show config: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
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
	printf("%s Configuration: %d arrays, %d volumes, %d spares\n",
	    mfi_device, config->cd_array_cnt, config->cd_ld_cnt,
	    config->cd_spare_cnt);
	p = (char *)config->cd_array;

	for (i = 0; i < config->cd_array_cnt; i++) {
		ar = (mfi_array_t *)p;
		printf("    array %u of %u drives:\n", ar->ar_ref,
		    ar->ar_ndrive);
		for (j = 0; j < ar->ar_ndrive; j++) {
			device_id = ar->ar_pd[j].pd_ref.pr_dev_id;
			printf("        drive %s ", mfi_drive_name(NULL,
			    device_id,
			    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS));
			if (device_id != 0xffff) {
				if (mfi_pd_get_info(fd, device_id, &pinfo,
				    NULL) < 0)
					printf("%s", mfi_pdstate(
					    ar->ar_pd[j].pd_fw_state));
				else
					print_pd(&pinfo, -1);
			}
			printf("\n");
		}
		p += config->cd_array_size;
	}

	for (i = 0; i < config->cd_ld_cnt; i++) {
		ld = (mfi_ld_config_t *)p;
		printf("    volume %s ",
		    mfi_volume_name(fd, ld->lc_props.lp_ld.lr_tgtid));
		if (mfi_ld_get_info(fd, ld->lc_props.lp_ld.lr_tgtid, &linfo,
		    NULL) < 0) {
			printf("%s %s",
			    mfi_raid_level(ld->lc_params.lp_primary_raid_lvl,
			    ld->lc_params.lp_secondary_raid_lvl),
			    mfi_ldstate(ld->lc_params.lp_state));
		} else
			print_ld(&linfo, -1);
		if (ld->lc_props.lp_name[0] != '\0')
			printf(" <%s>", ld->lc_props.lp_name);
		printf(" spans:\n");
		for (j = 0; j < ld->lc_params.lp_span_depth; j++)
			printf("        array %u\n",
			    ld->lc_span[j].s_array_ref);
		p += config->cd_ld_size;
	}

	for (i = 0; i < config->cd_spare_cnt; i++) {
		sp = (mfi_spare_t *)p;
		printf("    %s spare %s ", sp->s_type & MFI_SPARE_DEDICATED ?
		    "dedicated" : "global",
		    mfi_drive_name(NULL, sp->s_pd_ref.pr_dev_id,
		    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS));
		if (mfi_pd_get_info(fd, sp->s_pd_ref.pr_dev_id, &pinfo, NULL) <
		    0)
			printf("%s", mfi_pdstate(MFI_PD_STATE_HOT_SPARE));
		else
			print_pd(&pinfo, -1);
		if (sp->s_type & MFI_SPARE_DEDICATED) {
			printf(" backs:\n");
			for (j = 0; j < sp->s_array_cnt; j++)
				printf("        array %u\n",
				    sp->s_array_ref[j]);
		} else
			printf("\n");
		p += config->cd_spare_size;
	}
	free(config);
	close(fd);

	return (0);
}
MFI_COMMAND(show, config, show_config);

static int
show_volumes_ld_helper(int fd, mfi_ld_list_t list, uint_t i, int state_len)
{
	mfi_ld_info_t info;
	int error;

	if (mfi_ld_get_info(fd, list.ll_ld[i].ld_ref.lr_tgtid, &info, NULL) <
	    0) {
		error = errno;
		warn("Failed to get info for volume %d",
		    list.ll_ld[i].ld_ref.lr_tgtid);
		close(fd);
		return (error);
	}
	printf("%6s ",
	    mfi_volume_name(fd, list.ll_ld[i].ld_ref.lr_tgtid));
	print_ld(&info, state_len);
	switch (info.li_config.lc_props.lp_cur_cache_policy &
	    (MFI_LD_CACHE_ALLOW_WRITE_CACHE | MFI_LD_CACHE_ALLOW_READ_CACHE)) {
	case 0:
		printf(" Disabled");
		break;
	case MFI_LD_CACHE_ALLOW_READ_CACHE:
		printf(" Reads   ");
		break;
	case MFI_LD_CACHE_ALLOW_WRITE_CACHE:
		printf(" Writes  ");
		break;
	case MFI_LD_CACHE_ALLOW_WRITE_CACHE | MFI_LD_CACHE_ALLOW_READ_CACHE:
		printf(" Enabled ");
		break;
	}
	if (info.li_config.lc_props.lp_name[0] != '\0')
		printf(" <%s>", info.li_config.lc_props.lp_name);
	printf("\n");

	return (0);
}

static int
show_volumes(int ac, char **av __unused)
{
	mfi_ld_list_t list;
	int error, fd;
	uint_t i, len, state_len;

	if (ac != 1) {
		warnx("show volumes: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	/* Get the logical drive list from the controller. */
	if (mfi_ld_get_list(fd, &list, NULL) < 0) {
		error = errno;
		warn("Failed to get volume list");
		close(fd);
		return (error);
	}

	/* List the volumes. */
	printf("%s Volumes:\n", mfi_device);
	state_len = strlen("State");
	for (i = 0; i < list.ll_ld_count; i++) {
		len = strlen(mfi_ldstate(list.ll_ld[i].ld_state));
		if (len > state_len)
			state_len = len;
	}
	printf("  Id     Size    Level   Stripe ");
	len = state_len - strlen("State");
	for (i = 0; i < (len + 1) / 2; i++)
		printf(" ");
	printf("State");
	for (i = 0; i < len / 2; i++)
		printf(" ");
	printf("  Cache   Name\n");
	for (i = 0; i < list.ll_ld_count; i++) {
		error = show_volumes_ld_helper(fd, list, i, state_len);
		if (error != 0) {
			close(fd);
			return (error);
		}
	}
	close(fd);

	return (0);
}
MFI_COMMAND(show, volumes, show_volumes);

static int
show_drives(int ac, char **av __unused)
{
	mfi_pd_list_t *list;
	mfi_pd_info_t info;
	uint_t i, len, state_len;
	int error, fd;

	if (ac != 1) {
		warnx("show drives: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	list = NULL;
	if (mfi_pd_get_list(fd, &list, NULL) < 0) {
		error = errno;
		warn("Failed to get drive list");
		goto error;
	}

	/* Walk the list of drives to determine width of state column. */
	state_len = 0;
	for (i = 0; i < list->pl_count; i++) {
		if (list->pl_addr[i].pa_scsi_dev_type != 0)
			continue;

		if (mfi_pd_get_info(fd, list->pl_addr[i].pa_dev_id, &info,
		    NULL) < 0) {
			error = errno;
			warn("Failed to fetch info for drive %u",
			    list->pl_addr[i].pa_dev_id);
			goto error;
		}
		len = strlen(mfi_pdstate(info.pd_fw_state));
		if (info.pd_ddf_type.pd_is_foreign)
			len += strlen(foreign_state);
		if (len > state_len)
			state_len = len;
	}

	/* List the drives. */
	printf("%s Physical Drives:\n", mfi_device);
	for (i = 0; i < list->pl_count; i++) {

		/* Skip non-hard disks. */
		if (list->pl_addr[i].pa_scsi_dev_type != 0)
			continue;

		/* Fetch details for this drive. */
		if (mfi_pd_get_info(fd, list->pl_addr[i].pa_dev_id, &info,
		    NULL) < 0) {
			error = errno;
			warn("Failed to fetch info for drive %u",
			    list->pl_addr[i].pa_dev_id);
			goto error;
		}

		printf("%s ", mfi_drive_name(&info, list->pl_addr[i].pa_dev_id,
		    MFI_DNAME_DEVICE_ID));
		print_pd(&info, state_len);
		printf(" %s", mfi_drive_name(&info, list->pl_addr[i].pa_dev_id,
		    MFI_DNAME_ES));
		printf("\n");
	}
	error = 0;
error:
	free(list);
	close(fd);

	return (error);
}
MFI_COMMAND(show, drives, show_drives);

static int
show_firmware(int ac, char **av __unused)
{
	mfi_ctrl_info_t info;
	mfi_image_comp_t header;
	int error, fd;
	uint_t i;

	if (ac != 1) {
		warnx("show firmware: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (mfi_ctrl_get_info(fd, &info, NULL) < 0) {
		error = errno;
		warn("Failed to get controller info");
		close(fd);
		return (error);
	}

	if (info.ci_package_version[0] != '\0')
		printf("%s Firmware Package Version: %s\n", mfi_device,
		    info.ci_package_version);
	printf("%s Firmware Images:\n", mfi_device);
	strcpy(header.ic_name, "Name");
	strcpy(header.ic_version, "Version");
	strcpy(header.ic_build_date, "Date");
	strcpy(header.ic_build_time, "Time");
	scan_firmware(&header);
	if (info.ci_image_component_count > 8)
		info.ci_image_component_count = 8;
	for (i = 0; i < info.ci_image_component_count; i++)
		scan_firmware(&info.ci_image_component[i]);
	if (info.ci_pending_image_component_count > 8)
		info.ci_pending_image_component_count = 8;
	for (i = 0; i < info.ci_pending_image_component_count; i++)
		scan_firmware(&info.ci_pending_image_component[i]);
	display_firmware(&header, "Status");
	for (i = 0; i < info.ci_image_component_count; i++)
		display_firmware(&info.ci_image_component[i], "active");
	for (i = 0; i < info.ci_pending_image_component_count; i++)
		display_firmware(&info.ci_pending_image_component[i],
		    "pending");

	close(fd);

	return (0);
}
MFI_COMMAND(show, firmware, show_firmware);

static int
show_progress(int ac, char **av __unused)
{
	mfi_ld_list_t llist;
	mfi_pd_list_t *plist;
	mfi_ld_info_t linfo;
	mfi_pd_info_t pinfo;
	int busy, error, fd;
	uint_t i;
	uint16_t device_id;
	uint8_t target_id;

	if (ac != 1) {
		warnx("show progress: extra arguments");
		return (EINVAL);
	}

	fd = mfi_open(mfi_device, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("mfi_open");
		return (error);
	}

	if (mfi_ld_get_list(fd, &llist, NULL) < 0) {
		error = errno;
		warn("Failed to get volume list");
		close(fd);
		return (error);
	}
	if (mfi_pd_get_list(fd, &plist, NULL) < 0) {
		error = errno;
		warn("Failed to get drive list");
		close(fd);
		return (error);
	}

	busy = 0;
	for (i = 0; i < llist.ll_ld_count; i++) {
		target_id = llist.ll_ld[i].ld_ref.lr_tgtid;
		if (mfi_ld_get_info(fd, target_id, &linfo, NULL) < 0) {
			error = errno;
			warn("Failed to get info for volume %s",
			    mfi_volume_name(fd, target_id));
			free(plist);
			close(fd);
			return (error);
		}
		if (linfo.li_progress.lp_active_cc) {
			printf("volume %s ", mfi_volume_name(fd, target_id));
			mfi_display_progress("Consistency Check",
			    &linfo.li_progress.lp_cc);
			busy = 1;
		}
		if (linfo.li_progress.lp_active_bgi) {
			printf("volume %s ", mfi_volume_name(fd, target_id));
			mfi_display_progress("Background Init",
			    &linfo.li_progress.lp_bgi);
			busy = 1;
		}
		if (linfo.li_progress.lp_active_fgi) {
			printf("volume %s ", mfi_volume_name(fd, target_id));
			mfi_display_progress("Foreground Init",
			    &linfo.li_progress.lp_fgi);
			busy = 1;
		}
		if (linfo.li_progress.lp_active_recon) {
			printf("volume %s ", mfi_volume_name(fd, target_id));
			mfi_display_progress("Reconstruction",
			    &linfo.li_progress.lp_recon);
			busy = 1;
		}
	}

	for (i = 0; i < plist->pl_count; i++) {
		if (plist->pl_addr[i].pa_scsi_dev_type != 0)
			continue;

		device_id = plist->pl_addr[i].pa_dev_id;
		if (mfi_pd_get_info(fd, device_id, &pinfo, NULL) < 0) {
			error = errno;
			warn("Failed to fetch info for drive %u", device_id);
			free(plist);
			close(fd);
			return (error);
		}

		if (pinfo.pd_progress.pp_active_rbld) {
			printf("drive %s ", mfi_drive_name(NULL, device_id,
			    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS));
			mfi_display_progress("Rebuild",
			    &pinfo.pd_progress.pp_rbld);
			busy = 1;
		}
		if (pinfo.pd_progress.pp_active_patrol) {
			printf("drive %s ", mfi_drive_name(NULL, device_id,
			    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS));
			mfi_display_progress("Patrol Read",
			    &pinfo.pd_progress.pp_patrol);
			busy = 1;
		}
		if (pinfo.pd_progress.pp_active_clear) {
			printf("drive %s ", mfi_drive_name(NULL, device_id,
			    MFI_DNAME_DEVICE_ID|MFI_DNAME_HONOR_OPTS));
			mfi_display_progress("Clear",
			    &pinfo.pd_progress.pp_clear);
			busy = 1;
		}
	}

	free(plist);
	close(fd);

	if (!busy)
		printf("No activity in progress for adapter %s\n",
		    mfi_device);

	return (0);
}
MFI_COMMAND(show, progress, show_progress);

static int
show_foreign(int ac, char **av)
{
	return (display_format(ac, av, 0 /* normal display */,
	    MFI_DCMD_CFG_FOREIGN_DISPLAY));
}
MFI_COMMAND(show, foreign, show_foreign);
