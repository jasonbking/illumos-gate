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
# Resource controls configured for a zone that also has an aliased dataset
# are applied when it boots.  (zoneadmd packs the rctls and the datasets
# into separate nvlists for zone_create(2); a bug in the rctl packing once
# caused rctls to be silently dropped.)
#
# STRATEGY:
# 1. Install the test zone.  Configure DS1 with alias al1, max-lwps=1500
#    and a zone.max-msg-ids rctl with a privileged limit of 1234.
# 2. Boot the zone.
# 3. Verify with prctl(1), from both the global zone and the zone itself,
#    that both rctls have the configured values.
# 4. Verify al1 is visible in the zone.
#

verify_runnable "global"

typeset -i lwps=1500
typeset -i msgids=1234

function cleanup
{
	alias_zone_reset
	if alias_zone_exists &&
	    zonecfg -z $TESTZONE info rctl | grep -q '^rctl:'; then
		log_must zonecfg -z $TESTZONE "remove -F rctl"
	fi
	alias_destroy_datasets $ALIAS_DS1
}

#
# Print the privileged value of rctl $1 for $TESTZONE, as seen by running
# prctl(1) with the optional command prefix in $2 (e.g. zlogin).
#
function rctl_value
{
	typeset rctl=$1
	typeset prefix=$2

	$prefix prctl -P -n $rctl -i zone $TESTZONE | \
	    nawk -v r=$rctl '$1 == r && $2 == "privileged" { print $3 }'
}

function check_rctl
{
	typeset rctl=$1
	typeset -i expected=$2
	typeset gz ngz

	gz=$(rctl_value $rctl)
	ngz=$(rctl_value $rctl "zlogin $TESTZONE")
	[[ $gz == $expected ]] || \
	    log_fail "$rctl is '$gz' in the global zone, expected $expected"
	[[ $ngz == $expected ]] || \
	    log_fail "$rctl is '$ngz' in $TESTZONE, expected $expected"
}

log_assert "rctls are applied to a zone with an aliased dataset"
log_onexit cleanup

alias_zone_install
alias_create_datasets $ALIAS_DS1

alias_cmd_begin
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd "set max-lwps=$lwps"
alias_cmd "add rctl" "set name=zone.max-msg-ids" \
    "add value (priv=privileged,limit=$msgids,action=deny)" "end"
alias_cmd "commit"
log_must alias_zonecfg_run

log_must alias_zone_boot
check_rctl zone.max-lwps $lwps
check_rctl zone.max-msg-ids $msgids
alias_zone_visible al1

log_pass "rctls are applied to a zone with an aliased dataset"
