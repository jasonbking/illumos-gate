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
# A zone with no delegated datasets boots (zoneadmd still passes the kernel
# a packed, but empty, dataset nvlist), and datasets can be added to and
# removed from the zone between boots.
#
# STRATEGY:
# 1. Install the test zone with no dataset resources and boot it.  Verify
#    'zfs list' works in the zone and shows none of the test datasets.
# 2. Halt, delegate DS1 with alias al1, boot, and verify al1 is visible.
# 3. Halt, remove the dataset resource, boot, and verify al1 is gone.
#

verify_runnable "global"

function cleanup
{
	alias_zone_reset
	alias_destroy_datasets $ALIAS_DS1
}

log_assert "A zone with no delegated datasets boots"
log_onexit cleanup

alias_zone_install
alias_zone_reset
(($(alias_ds_count) == 0)) || log_fail "$TESTZONE has dataset resources"
alias_create_datasets $ALIAS_DS1

log_must alias_zone_boot
log_must zlogin $TESTZONE zfs list
alias_zone_not_visible al1 $ALIAS_DS1 $TESTPOOL/$TESTFS

alias_zone_halt
alias_cmd_begin
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd "commit"
log_must alias_zonecfg_run
log_must alias_zone_boot
alias_zone_visible al1

alias_zone_reset
log_must alias_zone_boot
log_must zlogin $TESTZONE zfs list
alias_zone_not_visible al1 $ALIAS_DS1

log_pass "A zone with no delegated datasets boots"
