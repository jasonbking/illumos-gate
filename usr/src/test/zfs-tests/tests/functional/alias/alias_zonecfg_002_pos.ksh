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
# 'zonecfg export' includes dataset aliases, and re-importing the exported
# configuration reproduces the same dataset resources.
#
# STRATEGY:
# 1. Configure a zone with two aliased datasets (one alias containing a
#    space, so it must be quoted) and one dataset without an alias.
# 2. Export the configuration and verify exactly two 'set alias' lines
#    are present.
# 3. Delete the zone, re-create it from the exported file, and verify
#    'info dataset' output is unchanged.
#

verify_runnable "global"

typeset exportfile="${TEST_BASE_DIR%%/}/alias_export.$$"

function cleanup
{
	alias_zone_cleanup
	rm -f $exportfile
}

log_onexit cleanup
alias_zone_cleanup

log_assert "zonecfg export/import round-trips dataset aliases"

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2
alias_cmd_add_ds $ALIAS_DS3 "al 3"
alias_cmd "commit"
log_must alias_zonecfg_run

typeset before=$(zonecfg -z $TESTZONE info dataset)

log_must zonecfg -z $TESTZONE export -f $exportfile

typeset -i nalias=$(grep -c '^set alias=' $exportfile)
((nalias == 2)) || log_fail "expected 2 'set alias' lines, found $nalias"
grep -qx 'set alias=al1' $exportfile || \
    log_fail "'set alias=al1' missing from export"
grep -qx 'set alias="al 3"' $exportfile || \
    log_fail "'set alias=\"al 3\"' missing from export"

log_must zonecfg -z $TESTZONE delete -F
log_must zonecfg -z $TESTZONE -f $exportfile

typeset after=$(zonecfg -z $TESTZONE info dataset)
if [[ "$before" != "$after" ]]; then
	log_note "before:"
	print -r -- "$before"
	log_note "after:"
	print -r -- "$after"
	log_fail "dataset resources differ after export/import"
fi

log_pass "zonecfg export/import round-trips dataset aliases"
