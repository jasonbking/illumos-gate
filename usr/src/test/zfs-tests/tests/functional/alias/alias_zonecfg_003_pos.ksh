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
# Dataset resources can be selected, displayed and removed by alias, by
# name, or by both; when both are given they must refer to the same
# resource.
#
# STRATEGY:
# 1. Configure DS1 (alias al1), DS2 (alias al2) and DS3 (no alias).
# 2. Verify 'info dataset alias=...' finds only the matching resource and
#    a mismatched name/alias pair matches nothing.
# 3. Modify aliases via 'select dataset alias=...' and
#    'select dataset name=... alias=...'.
# 4. Verify 'select' and 'remove' with a mismatched name/alias pair fail
#    (in both resource orders) and change nothing.
# 5. Verify 'select'/'remove' of a nonexistent alias fail.
# 6. Remove a dataset by alias, then an aliased dataset by name only.
#

verify_runnable "global"

function cleanup
{
	alias_zone_cleanup
}

log_onexit cleanup
alias_zone_cleanup

log_assert "dataset resources can be selected and removed by alias"

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2 al2
alias_cmd_add_ds $ALIAS_DS3
alias_cmd "commit"
log_must alias_zonecfg_run

# info filtering
(($(alias_ds_count alias=al2) == 1)) || \
    log_fail "info dataset alias=al2 did not match exactly one resource"
[[ $(alias_ds_name al2) == $ALIAS_DS2 ]] || \
    log_fail "info dataset alias=al2 did not return $ALIAS_DS2"
(($(alias_ds_count name=$ALIAS_DS1 alias=al2) == 0)) || \
    log_fail "info with mismatched name/alias matched a resource"

# select by alias
alias_cmd_begin
alias_cmd "select dataset alias=al1" "set alias=al1new" "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS1 al1new
alias_verify_ds $ALIAS_DS2 al2

# select by name and alias
alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS2 alias=al2" "set alias=al2new" \
    "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS1 al1new
alias_verify_ds $ALIAS_DS2 al2new

#
# Mismatched name/alias pairs.  Try both orders, since the resource that
# appears first in the configuration should not influence the result.
#
for spec in "name=$ALIAS_DS1 alias=al2new" "name=$ALIAS_DS2 alias=al1new"; do
	alias_cmd_begin
	alias_cmd "select dataset $spec" "set alias=bogus" "end" "commit"
	log_mustnot alias_zonecfg_run

	alias_cmd_begin
	alias_cmd "remove dataset $spec" "commit"
	log_mustnot alias_zonecfg_run

	(($(alias_ds_count) == 3)) || \
	    log_fail "'$spec' changed the number of dataset resources"
	alias_verify_ds $ALIAS_DS1 al1new
	alias_verify_ds $ALIAS_DS2 al2new
	alias_verify_ds $ALIAS_DS3 ""
done

# nonexistent alias
alias_cmd_begin
alias_cmd "select dataset alias=nosuchalias" "set alias=bogus" "end" "commit"
log_mustnot alias_zonecfg_run
alias_cmd_begin
alias_cmd "remove dataset alias=nosuchalias" "commit"
log_mustnot alias_zonecfg_run
(($(alias_ds_count) == 3)) || log_fail "dataset count changed"

# remove by alias
alias_cmd_begin
alias_cmd "remove dataset alias=al2new" "commit"
log_must alias_zonecfg_run
(($(alias_ds_count) == 2)) || log_fail "remove by alias failed"
(($(alias_ds_count name=$ALIAS_DS2) == 0)) || \
    log_fail "$ALIAS_DS2 still configured after remove by alias"
alias_verify_ds $ALIAS_DS1 al1new

# remove an aliased dataset by name only
alias_cmd_begin
alias_cmd "remove dataset name=$ALIAS_DS1" "commit"
log_must alias_zonecfg_run
(($(alias_ds_count) == 1)) || log_fail "remove by name failed"
(($(alias_ds_count name=$ALIAS_DS3) == 1)) || \
    log_fail "wrong dataset removed"

log_pass "dataset resources can be selected and removed by alias"
