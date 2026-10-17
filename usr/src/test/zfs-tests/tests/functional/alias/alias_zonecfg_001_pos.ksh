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
# A dataset resource can be configured with an alias, and the alias is
# displayed by 'info' and persisted in the zone's XML configuration.
#
# STRATEGY:
# 1. Configure a zone with an aliased dataset, a dataset without an alias,
#    and a dataset whose alias uses every non-alphanumeric character allowed
#    in a ZFS name component.
# 2. Verify 'info dataset' reports the expected alias for each dataset and
#    'alias not specified' for the un-aliased one.
# 3. Verify a dataset can be looked up by its alias.
# 4. Verify the aliases are written to the XML configuration.
# 5. Verify 'zonecfg verify' succeeds.
#

verify_runnable "global"

function cleanup
{
	alias_zone_cleanup
}

log_onexit cleanup
alias_zone_cleanup

log_assert "zonecfg dataset resources accept and persist an alias"

typeset odd_alias="a-b_c.d:e f"

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2
alias_cmd_add_ds $ALIAS_DS3 "$odd_alias"
alias_cmd "commit"
log_must alias_zonecfg_run
alias_zone_exists || log_fail "$TESTZONE was not configured"

(($(alias_ds_count) == 3)) || log_fail "expected 3 dataset resources"

alias_verify_ds $ALIAS_DS1 al1
alias_verify_ds $ALIAS_DS2 ""
alias_verify_ds $ALIAS_DS3 "$odd_alias"

[[ $(alias_ds_name al1) == $ALIAS_DS1 ]] || \
    log_fail "lookup by alias al1 did not return $ALIAS_DS1"
[[ $(alias_ds_name "$odd_alias") == $ALIAS_DS3 ]] || \
    log_fail "lookup by alias '$odd_alias' did not return $ALIAS_DS3"

grep "name=\"$ALIAS_DS1\"" $ZONEXML | grep -q 'alias="al1"' || \
    log_fail "alias for $ALIAS_DS1 not saved in $ZONEXML"
grep "name=\"$ALIAS_DS3\"" $ZONEXML | grep -qF "alias=\"$odd_alias\"" || \
    log_fail "alias for $ALIAS_DS3 not saved in $ZONEXML"
grep "name=\"$ALIAS_DS2\"" $ZONEXML | grep -q 'alias="[^"]' && \
    log_fail "unexpected alias for $ALIAS_DS2 in $ZONEXML"

log_must zonecfg -z $TESTZONE verify

log_pass "zonecfg dataset resources accept and persist an alias"
