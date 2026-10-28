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
# A dataset alias of up to ZFS_MAX_DATASET_NAME_LEN - 1 (255) characters is
# accepted and stored intact; longer aliases are rejected rather than
# silently truncated.
#
# STRATEGY:
# 1. Configure a dataset with a 255 character alias; verify it is stored
#    without modification.
# 2. Attempt to configure 256 and 300 character aliases, both at creation
#    and via 'select'.  Verify zonecfg fails and nothing (in particular, a
#    truncated alias) is committed.
#

verify_runnable "global"

function cleanup
{
	alias_zone_cleanup
}

log_onexit cleanup
alias_zone_cleanup

log_assert "long dataset aliases are rejected, not truncated"

function mkalias # length
{
	nawk -v n=$1 'BEGIN {
		s = ""
		for (i = 0; i < n; i++)
			s = s "a"
		print s
	}'
}

typeset a255=$(mkalias 255)
typeset a256=$(mkalias 256)
typeset a300=$(mkalias 300)

alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 $a255
alias_cmd "commit"
log_must alias_zonecfg_run
typeset got=$(alias_ds_alias $ALIAS_DS1)
((${#got} == 255)) || log_fail "255 character alias stored as ${#got} chars"
[[ $got == $a255 ]] || log_fail "255 character alias was modified"

for long in $a256 $a300; do
	alias_zone_cleanup
	alias_cmd_create
	alias_cmd_add_ds $ALIAS_DS1 $long
	alias_cmd "commit"
	log_mustnot alias_zonecfg_run
	if alias_zone_exists; then
		got=$(alias_ds_alias $ALIAS_DS1)
		log_fail "${#long} character alias committed as ${#got} chars"
	fi
done

alias_zone_cleanup
alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd "commit"
log_must alias_zonecfg_run

for long in $a256 $a300; do
	alias_cmd_begin
	alias_cmd "select dataset name=$ALIAS_DS1" "set alias=$long" "end" \
	    "commit"
	log_mustnot alias_zonecfg_run
	alias_verify_ds $ALIAS_DS1 al1
done

log_pass "long dataset aliases are rejected, not truncated"
