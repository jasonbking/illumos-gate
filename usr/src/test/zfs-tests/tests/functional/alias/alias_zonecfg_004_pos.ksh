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
# 'clear alias' removes a dataset's alias, and an alias can be set again
# afterwards.
#
# STRATEGY:
# 1. Configure DS1 (alias al1) and DS2 (alias al2).
# 2. Clear DS1's alias; verify only DS1 changed, in 'info' and in the XML.
# 3. Set a new alias on DS1.
# 4. Clear and re-set DS2's alias within a single 'select'.
# 5. Remove DS2 by name and alias; verify DS1 is untouched.
#

verify_runnable "global"

function cleanup
{
	alias_zone_cleanup
}

log_onexit cleanup
alias_zone_cleanup

log_assert "'clear alias' removes a dataset alias"

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2 al2
alias_cmd "commit"
log_must alias_zonecfg_run

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS1" "clear alias" "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS1 ""
alias_verify_ds $ALIAS_DS2 al2
grep "name=\"$ALIAS_DS1\"" $ZONEXML | grep -q 'alias="[^"]' && \
    log_fail "alias for $ALIAS_DS1 still present in $ZONEXML"

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS1" "set alias=al1b" "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS1 al1b

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS2" "clear alias" "set alias=al2b" \
    "end" "commit"
log_must alias_zonecfg_run
alias_verify_ds $ALIAS_DS2 al2b

alias_cmd_begin
alias_cmd "remove dataset name=$ALIAS_DS2 alias=al2b" "commit"
log_must alias_zonecfg_run
(($(alias_ds_count) == 1)) || log_fail "expected 1 dataset resource"
alias_verify_ds $ALIAS_DS1 al1b

log_pass "'clear alias' removes a dataset alias"
