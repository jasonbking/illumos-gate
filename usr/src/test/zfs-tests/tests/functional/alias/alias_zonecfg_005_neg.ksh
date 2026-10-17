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
# zonecfg refuses to commit a dataset alias that is not a valid ZFS
# dataset name component.
#
# STRATEGY:
# 1. For each invalid alias, attempt to create a zone with a dataset using
#    that alias.  Verify zonecfg fails, reports the alias as invalid, and
#    the zone is not configured.
# 2. Configure a zone with a valid alias, then for each invalid alias try
#    to change it via 'select'.  Verify the commit fails and the original
#    alias is retained.
#

verify_runnable "global"

function cleanup
{
	alias_zone_cleanup
}

log_onexit cleanup
alias_zone_cleanup

log_assert "zonecfg rejects invalid dataset aliases"

set -A bad_aliases \
    'a/b' '/a' 'a/' 'a//b' \
    'a@b' 'a#b' 'a%b' \
    'a*b' 'a,b' 'a$b' 'a=b' 'a;b' 'a(b' 'a[b' 'a!b' 'a~b' "a'b"

for bad in "${bad_aliases[@]}"; do
	alias_zone_cleanup
	alias_cmd_create
	alias_cmd_add_ds $ALIAS_DS1 "$bad"
	alias_cmd "commit"
	log_mustnot alias_zonecfg_run
	alias_verify_invalid_msg "$bad"
	alias_zone_exists && log_fail "$TESTZONE configured with alias '$bad'"
done

alias_zone_cleanup
alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd "commit"
log_must alias_zonecfg_run

for bad in "${bad_aliases[@]}"; do
	alias_cmd_begin
	alias_cmd "select dataset name=$ALIAS_DS1" "set alias=\"$bad\"" "end" \
	    "commit"
	log_mustnot alias_zonecfg_run
	alias_verify_invalid_msg "$bad"
	alias_verify_ds $ALIAS_DS1 al1
done

log_pass "zonecfg rejects invalid dataset aliases"
