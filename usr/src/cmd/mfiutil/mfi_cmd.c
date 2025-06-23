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
 * Copyright 2024-2026 RackTop Systems Inc.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <paths.h>

#include <sys/scsi/adapters/mfi/mfi.h>
#include <sys/scsi/adapters/mfi/mfi_ioctl.h>
#include <sys/scsi/adapters/mfi/mfi_ld.h>

#include <libdevinfo.h>

#include "mfiutil.h"

static const char *mfi_status_codes[] = {
	"Command completed successfully",
	"Invalid command",
	"Invalid DMCD opcode",
	"Invalid parameter",
	"Invalid Sequence Number",
	"Abort isn't possible for the requested command",
	"Application 'host' code not found",
	"Application in use",
	"Application not initialized",
	"Array index invalid",
	"Array row not empty",
	"Configuration resource conflict",
	"Device not found",
	"Drive too small",
	"Flash memory allocation failed",
	"Flash download already in progress",
	"Flash operation failed",
	"Bad flash image",
	"Incomplete flash image",
	"Flash not open",
	"Flash not started",
	"Flush failed",
	"Specified application doesn't have host-resident code",
	"Volume consistency check in progress",
	"Volume initialization in progress",
	"Volume LBA out of range",
	"Maximum number of volumes are already configured",
	"Volume is not OPTIMAL",
	"Volume rebuild in progress",
	"Volume reconstruction in progress",
	"Volume RAID level is wrong for requested operation",
	"Too many spares assigned",
	"Scratch memory not available",
	"Error writing MFC data to SEEPROM",
	"Required hardware is missing",
	"Item not found",
	"Volume drives are not within an enclosure",
	"Drive clear in progress",
	"Drive type mismatch (SATA vs SAS)",
	"Patrol read disabled",
	"Invalid row index",
	"SAS Config - Invalid action",
	"SAS Config - Invalid data",
	"SAS Config - Invalid page",
	"SAS Config - Invalid type",
	"SCSI command completed with error",
	"SCSI I/O request failed",
	"SCSI RESERVATION_CONFLICT",
	"One or more flush operations during shutdown failed",
	"Firmware time is not set",
	"Wrong firmware or drive state",
	"Volume is offline",
	"Peer controller rejected request",
	"Unable to inform peer of communication changes",
	"Volume reservation already in progress",
	"I2C errors were detected",
	"PCI errors occurred during XOR/DMA operation",
	"Diagnostics failed",
	"Unable to process command as boot messages are pending",
	"Foreign configuration is incomplete"
};

const char *
mfi_status(uint_t status_code)
{
	static char buffer[16];

	if (status_code == MFI_STAT_INVALID_STATUS)
		return ("Invalid status");
	if (status_code < sizeof (mfi_status_codes) / sizeof (char *))
		return (mfi_status_codes[status_code]);
	snprintf(buffer, sizeof (buffer), "Status: 0x%02x", status_code);
	return (buffer);
}

const char *
mfi_raid_level(uint8_t primary_level, uint8_t secondary_level)
{
	static char buf[16];

	switch (primary_level) {
	case DDF_RAID0:
		return ("RAID-0");
	case DDF_RAID1:
		if (secondary_level != 0)
			return ("RAID-10");
		else
			return ("RAID-1");
	case DDF_RAID1E:
		return ("RAID-1E");
	case DDF_RAID3:
		return ("RAID-3");
	case DDF_RAID5:
		if (secondary_level != 0)
			return ("RAID-50");
		else
			return ("RAID-5");
	case DDF_RAID5E:
		return ("RAID-5E");
	case DDF_RAID5EE:
		return ("RAID-5EE");
	case DDF_RAID6:
		if (secondary_level != 0)
			return ("RAID-60");
		else
			return ("RAID-6");
	case DDF_JBOD:
		return ("JBOD");
	case DDF_CONCAT:
		return ("CONCAT");
	default:
		sprintf(buf, "LVL 0x%02x", primary_level);
		return (buf);
	}
}

/*
 * On FreeBSD this uses the MFIIO_QUERY_DISK ioctl to find out the device name
 * of the volume, which only works with its mfi driver. For mrsas, the target
 * ID is used.
 *
 * As illumos doesn't support this ioctl at all, just use the target ID here.
 */
const char *
mfi_volume_name(int fd, uint8_t target_id)
{
	static char buf[4];

	snprintf(buf, sizeof (buf), "%d", target_id);
	return (buf);
}

/*
 * On FreeBSD this uses the MFIIO_QUERY_DISK ioctl to find out whether the
 * volume is opened/mounted. This only works with its mfi driver, for mrsas
 * devices it is always assumed the device isn't open/mounted.
 *
 * As illumos doesn't support this ioctl at all, just assume the device isn't
 * open/mounted.
 */
int
mfi_volume_busy(int fd, uint8_t target_id)
{
	return (0);
}

/*
 * Check if the running kernel supports changing the RAID
 * configuration of the mfi controller.
 *
 * In FreeBSD, this only works with the mfi driver, not mrsas.
 * On Illumos we assume that this is supported.
 */
int
mfi_reconfig_supported(const char *dev)
{
	return (1);
}

/*
 * On FreeBSD, this uses the MFIIO_QUERY_DISK ioctl to translate a device name
 * to a volume target ID. This only works with mfi, not with mrsas.
 *
 * As illumos doesn't support this ioctl at all, we don't support translating
 * device names.
 */
int
mfi_lookup_volume(int fd, const char *name, uint8_t *target_id)
{
	char *cp;
	long val;

	/* If it's a valid number, treat it as a raw target ID. */
	errno = 0;
	val = strtol(name, &cp, 0);
	if (cp != name && *cp == '\0' && errno != ERANGE &&
	    val >= 0 && val <= UINT8_MAX) {
		*target_id = val;
		return (0);
	}

	errno = EINVAL;
	return (-1);
}

int
mfi_dcmd_command(int fd, uint32_t opcode, void *buf, size_t bufsize,
    uint8_t *mbox, size_t mboxlen, uint8_t *statusp)
{
	mfi_ioctl_t ioc;
	mfi_header_t *hdr = &ioc.ioc_frame.mf_hdr;
	mfi_dcmd_payload_t *dcmd = &ioc.ioc_frame.mf_dcmd;
	int r;

	if ((mboxlen > sizeof (dcmd->md_mbox_8)) ||
	    (mboxlen == 0 && mbox != NULL) ||
	    (mboxlen != 0 && mbox == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	bzero(&ioc, sizeof (ioc));

	hdr->mh_cmd = MFI_CMD_DCMD;
	hdr->mh_timeout = 0;
	hdr->mh_flags = MFI_FRAME_DIR_BOTH;
	hdr->mh_data_xfer_len = bufsize;
	hdr->mh_sge_count = 1;

	dcmd->md_opcode = opcode;
#ifdef __LP64__
	dcmd->md_sgl.ms64_length = bufsize;
	dcmd->md_sgl.ms64_phys_addr = (uintptr_t)buf;
#else
	dcmd->md_sgl.ms32_length = bufsize;
	dcmd->md_sgl.ms32_phys_addr = (uintptr_t)buf;
#endif

	if (mbox)
		bcopy(mbox, dcmd->md_mbox_8, mboxlen);

	r = ioctl(fd, MFI_IOCTL_FIRMWARE, &ioc);
	if (r < 0)
		return (r);

	if (statusp != NULL)
		*statusp = hdr->mh_cmd_status;
	else if (hdr->mh_cmd_status != MFI_STAT_OK) {
		warnx("Command failed: %s",
		    mfi_status(hdr->mh_cmd_status));
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
mfi_ctrl_get_info(int fd, mfi_ctrl_info_t *info, uint8_t *statusp)
{

	return (mfi_dcmd_command(fd, MFI_DCMD_CTRL_GET_INFO, info,
	    sizeof (mfi_ctrl_info_t), NULL, 0, statusp));
}

int
mfi_open(char *dev, int acs)
{
	char *devpath = dev;
	int ret;

	if (dev[0] != '/') {
		di_node_t root, node;
		di_minor_t minor;
		char *name, *path;
		unsigned int mfi_unit;
		char mfi_type[8];

		if (sscanf(dev, "%7[aclmrs_]%u", mfi_type, &mfi_unit) != 2)
			errx(1, "sscanf: %s %u\n", mfi_type, mfi_unit);

		if (strcmp(mfi_type, "mrsas") == 0)
			strlcpy(mfi_type, "mr_sas", sizeof (mfi_type));

		if (asprintf(&name, "%d:lsirdctl", mfi_unit) < 0)
			err(1, NULL);

		root = di_init("/", DINFOCPYALL);
		if (root == DI_NODE_NIL)
			err(1, "Can't init libdevinfo");

		for (node = di_drv_first_node(mfi_type, root);
		    node != DI_NODE_NIL;
		    node = di_drv_next_node(node))
			if (di_instance(node) == mfi_unit)
				break;

		if (node == DI_NODE_NIL)
			errx(1, "device %s%d not found", mfi_type, mfi_unit);

		for (minor = di_minor_next(node, DI_MINOR_NIL);
		    minor != DI_MINOR_NIL;
		    minor = di_minor_next(node, minor))
			if (strcmp(name, di_minor_name(minor)) == 0)
				break;

		free(name);

		if (minor == DI_MINOR_NIL)
			errx(1, "no RAID control node found");

		path = di_devfs_minor_path(minor);
		asprintf(&devpath, "/devices%s", path);
		di_devfs_path_free(path);
		di_fini(root);
	}

	ret = open(devpath, acs);
	if (ret < 0)
		warn("Couldn't open %s", devpath);

	if (devpath != dev)
		free(devpath);

	return (ret);
}

static void
print_time_humanized(uint_t seconds)
{

	if (seconds > 3600) {
		printf("%u:", seconds / 3600);
	}
	if (seconds > 60) {
		seconds %= 3600;
		printf("%02u:%02u", seconds / 60, seconds % 60);
	} else {
		printf("%us", seconds);
	}
}

void
mfi_display_progress(const char *label, mfi_progress_t *prog)
{
	uint_t seconds;

	printf("%s: %.2f%% complete after ", label,
	    (float)prog->mp_progress * 100 / 0xffff);
	print_time_humanized(prog->mp_elapsed);
	if (prog->mp_progress != 0 && prog->mp_elapsed > 10) {
		printf(" finished in ");
		seconds = (0x10000 * (uint32_t)prog->mp_elapsed) /
		    prog->mp_progress - prog->mp_elapsed;
		print_time_humanized(seconds);
	}
	printf("\n");
}

int
mfi_table_handler(struct mfiutil_command **start, struct mfiutil_command **end,
    int ac, char **av)
{
	struct mfiutil_command **cmd;

	if (ac < 2) {
		warnx("The %s command requires a sub-command.", av[0]);
		return (EINVAL);
	}
	for (cmd = start; cmd < end; cmd++) {
		if (strcmp((*cmd)->name, av[1]) == 0)
			return ((*cmd)->handler(ac - 1, av + 1));
	}

	warnx("%s is not a valid sub-command of %s.", av[1], av[0]);
	return (ENOENT);
}
