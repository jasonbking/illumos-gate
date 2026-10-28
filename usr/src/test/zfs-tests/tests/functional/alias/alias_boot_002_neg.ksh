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
# zonecfg refuses to save invalid or conflicting dataset aliases, but a
# hand-edited configuration (or a brand hook) can still hand them to the
# kernel.  In that case zone_create(2) must fail with EINVAL, the zone must
# be left installed (not ready or running), and the zone must still boot
# once the configuration is corrected.
#
# STRATEGY:
# 1. Install the test zone and create the datasets used below, so that
#    'zoneadm verify' (run by 'zoneadm boot') accepts every configuration
#    and any failure comes from the kernel.
# 2. For each case, configure DS1 (alias al1), DS2 (alias al2) and DS3 (no
#    alias) with zonecfg, then edit the zone's XML to introduce:
#      - an alias containing '/'
#      - a duplicate alias
#      - an alias equal to the pool of the non-aliased dataset
#      - a non-aliased dataset nested beneath an aliased one
# 3. Verify 'zoneadm boot' fails with "Invalid argument", was not rejected
#    by 'zoneadm verify', and leaves the zone installed.
# 4. Restore a valid configuration and verify the zone boots.
#

verify_runnable "global"

typeset xmltmp="${TEST_BASE_DIR%%/}/alias_boot_002.xml.$$"

function cleanup
{
	alias_zone_reset
	alias_destroy_datasets $ALIAS_DS1 $ALIAS_DS2 $ALIAS_DS3
	rm -f $xmltmp
}

function base_config
{
	alias_zone_reset
	alias_cmd_begin
	alias_cmd_add_ds $ALIAS_DS1 al1
	alias_cmd_add_ds $ALIAS_DS2 al2
	alias_cmd_add_ds $ALIAS_DS3
	alias_cmd "commit"
	log_must alias_zonecfg_run
}

#
# Apply a sed(1) expression to the zone's XML configuration.
#
function edit_xml
{
	sed -e "$1" $ZONEXML > $xmltmp || log_fail "sed -e '$1' failed"
	cmp -s $xmltmp $ZONEXML && \
	    log_fail "sed -e '$1' did not change $ZONEXML"
	log_must cp $xmltmp $ZONEXML
}

#
# Verify the zone fails to boot because zone_create(2) rejected it.
#	$1	description of the configuration
#
function expect_boot_failure
{
	typeset what=$1
	typeset state

	if zoneadm -z $TESTZONE boot > $ALIAS_BOOT_OUT 2>&1; then
		alias_zone_visible al1
		log_fail "$TESTZONE booted with $what"
	fi
	cat $ALIAS_BOOT_OUT

	grep -q 'could not verify' $ALIAS_BOOT_OUT && \
	    log_fail "$what: rejected by zoneadm verify, not by the kernel"
	grep -q 'Invalid argument' $ALIAS_BOOT_OUT || \
	    log_fail "$what: boot did not fail with EINVAL"

	state=$(alias_zone_state)
	[[ $state == installed ]] || \
	    log_fail "$what: $TESTZONE left in state '$state'"
}

log_assert "zone boot fails cleanly when the kernel rejects its datasets"
log_onexit cleanup

alias_zone_install
alias_create_datasets $ALIAS_DS1 $ALIAS_DS2 $ALIAS_DS3 $ALIAS_DS1_NESTED

base_config
edit_xml 's|alias="al1"|alias="a/b"|'
expect_boot_failure "an alias containing '/'"

base_config
edit_xml 's|alias="al2"|alias="al1"|'
expect_boot_failure "a duplicate alias"

base_config
edit_xml "s|alias=\"al1\"|alias=\"$TESTPOOL\"|"
expect_boot_failure "an alias equal to the pool of a non-aliased dataset"

base_config
edit_xml "s|name=\"$ALIAS_DS3\"|name=\"$ALIAS_DS1_NESTED\"|"
expect_boot_failure "a dataset nested beneath an aliased dataset"

base_config
log_must alias_zone_boot
alias_zone_visible al1 al2 $ALIAS_DS3

log_pass "zone boot fails cleanly when the kernel rejects its datasets"
