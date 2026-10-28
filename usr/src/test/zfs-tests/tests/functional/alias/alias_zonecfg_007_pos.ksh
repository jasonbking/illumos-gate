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
# Zone configurations written before dataset aliases existed (i.e. whose
# dataset elements have no 'alias' attribute) continue to work, as do
# dataset resources added in the current session that have not yet been
# written out and read back.
#
# STRATEGY:
# 1. Configure a zone with two datasets without aliases.
# 2. Strip any 'alias' attribute from the zone XML to mimic a legacy
#    configuration.
# 3. Verify 'info', 'verify' and 'export' work and report no aliases.
# 4. Add an alias to one legacy dataset via 'select'.
# 5. Strip the attribute again and remove the other legacy dataset by name.
# 6. In a single zonecfg session, add a dataset without an alias and run
#    'info dataset' and 'verify' before committing.
#

verify_runnable "global"

typeset xmltmp="${TEST_BASE_DIR%%/}/alias_legacy.xml.$$"

function cleanup
{
	alias_zone_cleanup
	rm -f $xmltmp
}

function strip_xml_aliases
{
	sed -e 's/ alias="[^"]*"//g' $ZONEXML > $xmltmp || \
	    log_fail "sed of $ZONEXML failed"
	log_must cp $xmltmp $ZONEXML
	grep -q 'alias=' $ZONEXML && \
	    log_fail "alias attribute still in $ZONEXML"
}

log_onexit cleanup
alias_zone_cleanup

log_assert "dataset resources without an alias attribute still work"

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1
alias_cmd_add_ds $ALIAS_DS2
alias_cmd "commit"
log_must alias_zonecfg_run

strip_xml_aliases

(($(alias_ds_count) == 2)) || log_fail "expected 2 dataset resources"
alias_verify_ds $ALIAS_DS1 ""
alias_verify_ds $ALIAS_DS2 ""
log_must zonecfg -z $TESTZONE verify
zonecfg -z $TESTZONE export | grep -q '^set alias=' && \
    log_fail "export of legacy configuration contains an alias"

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS1" "set alias=al1" "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS1 al1
alias_verify_ds $ALIAS_DS2 ""

strip_xml_aliases

alias_cmd_begin
alias_cmd "remove dataset name=$ALIAS_DS2" "commit"
log_must alias_zonecfg_run
(($(alias_ds_count) == 1)) || log_fail "remove of legacy dataset failed"

# A resource added in this session exists only in memory, without an
# alias attribute, until the configuration is saved and re-read.
alias_cmd_begin
alias_cmd "add dataset" "set name=$ALIAS_DS3" "end" "info dataset" "verify" \
    "commit"
log_must alias_zonecfg_run
grep -q "name: $ALIAS_DS3" $ALIAS_OUTFILE || \
    log_fail "'info dataset' did not show uncommitted $ALIAS_DS3"
(($(alias_ds_count) == 2)) || log_fail "expected 2 dataset resources"
alias_verify_ds $ALIAS_DS3 ""

log_pass "dataset resources without an alias attribute still work"
