#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Jason King
#

. $STF_SUITE/tests/functional/alias/alias.kshlib

#
# DESCRIPTION:
# A zone with a mix of aliased and non-aliased delegated datasets, all in
# the same pool, boots; its datasets are visible under the expected names;
# and it survives a reboot and a halt/boot cycle.
#
# STRATEGY:
# 1. Install the test zone (if not already installed).
# 2. Delegate DS1 (alias al1), DS2 (alias al2) and DS3 (no alias).
# 3. Boot the zone.  Verify al1, al2 and DS3 are visible inside it and that
#    the delegated datasets have zoned=on.
# 4. Reboot the zone and verify again.
# 5. Halt and boot the zone and verify again.
#

verify_runnable "global"

function cleanup
{
	alias_zone_reset
	alias_destroy_datasets $ALIAS_DS1 $ALIAS_DS2 $ALIAS_DS3
}

function check_zone
{
	typeset ds

	alias_zone_visible al1 al2 $ALIAS_DS3
	for ds in $ALIAS_DS1 $ALIAS_DS2 $ALIAS_DS3; do
		[[ $(get_prop zoned $ds) == on ]] || \
		    log_fail "$ds does not have zoned=on"
	done
}

log_assert "A zone with aliased and non-aliased datasets boots and reboots"
log_onexit cleanup

alias_zone_install
alias_create_datasets $ALIAS_DS1 $ALIAS_DS2 $ALIAS_DS3

alias_cmd_begin
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2 al2
alias_cmd_add_ds $ALIAS_DS3
alias_cmd "commit"
log_must alias_zonecfg_run
log_must zoneadm -z $TESTZONE verify

log_must alias_zone_boot
check_zone

alias_zone_reboot
check_zone

alias_zone_halt
log_must alias_zone_boot
check_zone

log_pass "A zone with aliased and non-aliased datasets boots and reboots"
