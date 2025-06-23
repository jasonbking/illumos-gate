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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <paths.h>

#include "mfiutil.h"

SET_DECLARE(MFI_DATASET(top), struct mfiutil_command);

MFI_TABLE(top, start);
MFI_TABLE(top, stop);
MFI_TABLE(top, abort);

char *mfi_device = NULL;
uint_t mfi_opts;

static int fw_name_width, fw_version_width, fw_date_width, fw_time_width;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-de] [-D device] [-u unit] [-t type] <command> ...\n\n",
	    getprogname());
	fprintf(stderr, "\
Commands include:\n\
    version\n\
    show adapter              - display controller information\n\
    show battery              - display battery information\n\
    show config               - display RAID configuration\n\
    show drives               - list physical drives\n\
    show events               - display event log\n\
    show firmware             - list firmware images\n\
    show foreign              - display detected foreign volumes\n\
    show logstate             - display event log sequence numbers\n\
    show volumes              - list logical volumes\n\
    show patrol               - display patrol read status\n\
    show progress             - display status of active operations\n\
    fail <drive>              - fail a physical drive\n\
    good <drive>              - set a failed/SYSPD drive as UNCONFIGURED\n\
    rebuild <drive>           - mark failed drive ready for rebuild\n\
    syspd <drive>             - set drive into use as SYSPD JBOD\n\
    drive progress <drive>    - display status of active operations\n\
    drive clear <drive> <start|stop> - clear a drive with all 0x00\n\
    start rebuild <drive>\n\
    abort rebuild <drive>\n\
    locate <drive> <on|off>   - toggle drive LED\n\
    cache <volume> [command [setting]]\n\
    name <volume> <name>\n\
    volume progress <volume>  - display status of active operations\n\
    clear                     - clear volume configuration\n\
    create <type> [-v] [-s stripe_size] <drive>[,...] [<drive>[,...]]\n\
    delete <volume>\n\
    add <drive> [volume]      - add a hot spare\n\
    remove <drive>            - remove a hot spare\n\
    patrol <disable|auto|manual> [interval [start]]\n\
    start patrol              - start a patrol read\n\
    stop patrol               - stop a patrol read\n\
    foreign scan              - scan for foreign configurations\n\
    foreign clear             - clear all foreign configurations\n\
    foreign diag [volume]     - diagnostic display foreign configurations\n\
    foreign preview [volume]  - preview foreign configurations\n\
    foreign import [volume]   - import foreign configurations\n\
    flash <firmware>\n\
    start learn               - start a BBU relearn\n\
    bbu <setting> <value>     - set BBU properties\n\
    ctrlprop rebuild [rate]   - get/set the volume rebuild rate\n\
    ctrlprop alarm [0/1]      - enable/disable controller alarms\n");
#ifdef DEBUG
	fprintf(stderr,
	    "    debug                     - debug 'show config'\n");
#endif
	exit(1);
}

static int
version(int ac __unused, char **av __unused)
{

	printf("mfiutil version 1.0.15");
#ifdef DEBUG
	printf(" (DEBUG)");
#endif
	printf("\n");
	return (0);
}
MFI_COMMAND(top, version, version);

int
main(int ac, char **av)
{
	struct mfiutil_command **cmd;
	int ch, mfi_unit;
	const char *pn, *mfi_type = NULL;

	mfi_unit = 0;

	pn = getprogname();

	if (strcmp(pn, "mrsasutil") == 0)
		mfi_type = "mr_sas";
	else if (strcmp(pn, "lmrcutil") == 0)
		mfi_type = "lmrc";

	while ((ch = getopt(ac, av, "D:det:u:")) != -1) {
		switch (ch) {
		case 'D':
			mfi_device = optarg;
			break;
		case 'd':
			mfi_opts |= MFI_DNAME_DEVICE_ID;
			break;
		case 'e':
			mfi_opts |= MFI_DNAME_ES;
			break;
		case 'u':
			mfi_unit = atoi(optarg);
			break;
		case 't':
			mfi_type = optarg;
			break;
		case '?':
			usage();
		}
	}

	av += optind;
	ac -= optind;

	/* getopt() eats av[0], so we can't use mfi_table_handler() directly. */
	if (ac == 0)
		usage();

	SET_FOREACH(cmd, MFI_DATASET(top)) {
		if (strcmp((*cmd)->name, av[0]) == 0) {
			if ((*cmd)->handler != version && mfi_device == NULL) {
				if (mfi_type == NULL)
					errx(1, "MFI type not set. "
					    "Use \"-t type\" argument.");
				if (asprintf(&mfi_device, "%s%d", mfi_type,
				    mfi_unit) < 0)
					errx(1, "Can't allocate memory for "
					    "device name");
			}
			if ((*cmd)->handler(ac, av))
				return (1);
			else
				return (0);
		}
	}
	warnx("Unknown command %s.", av[0]);
	return (1);
}

void
scan_firmware(mfi_image_comp_t *comp)
{
	int len;

	len = strlen(comp->ic_name);
	if (fw_name_width < len)
		fw_name_width = len;
	len = strlen(comp->ic_version);
	if (fw_version_width < len)
		fw_version_width = len;
	len = strlen(comp->ic_build_date);
	if (fw_date_width < len)
		fw_date_width = len;
	len = strlen(comp->ic_build_time);
	if (fw_time_width < len)
		fw_time_width = len;
}

void
display_firmware(mfi_image_comp_t *comp, const char *tag)
{

	printf("%-*s  %-*s  %-*s  %-*s  %s\n", fw_name_width, comp->ic_name,
	    fw_version_width, comp->ic_version, fw_date_width,
	    comp->ic_build_date, fw_time_width, comp->ic_build_time, tag);
}
