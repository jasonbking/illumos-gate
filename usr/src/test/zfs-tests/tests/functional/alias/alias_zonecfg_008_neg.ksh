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
# Within a zone, a dataset alias is presented as a top-level (pool) name.
# zonecfg must refuse configurations where a delegated dataset would be
# visible under more than one name, or two delegated datasets would be
# presented under the same top-level name:
#   - two datasets with the same alias
#   - an alias equal to the pool name of a delegated dataset without an
#     alias
#   - an aliased dataset that is an ancestor or descendant of another
#     delegated dataset
#
# STRATEGY:
# 1. Verify configurations without a conflict are accepted (several
#    aliased datasets in one pool alongside an unrelated non-aliased
#    dataset, an alias equal to a non-top-level component, a lone dataset
#    aliased to its own pool name).
# 2. Verify duplicate aliases are rejected.
# 3. Verify an alias matching a non-aliased dataset's pool is rejected,
#    regardless of resource order.
# 4. Verify nested delegations involving an aliased dataset are rejected.
# 5. Verify the same conflicts are rejected when introduced by modifying
#    an existing configuration.
#

verify_runnable "global"

typeset plain="$TESTPOOL/plain"

function cleanup
{
	alias_zone_cleanup
}

#
# Each argument is "name[:alias]".  Attempt to create the zone with those
# datasets and expect failure.
#
function expect_conflict
{
	typeset ds

	alias_zone_cleanup
	alias_cmd_create
	for ds in "$@"; do
		if [[ $ds == *:* ]]; then
			alias_cmd_add_ds ${ds%%:*} ${ds#*:}
		else
			alias_cmd_add_ds $ds
		fi
	done
	alias_cmd "commit"
	log_mustnot alias_zonecfg_run
	alias_zone_exists && log_fail "zone configured with: $*"
}

log_onexit cleanup
alias_zone_cleanup

log_assert "zonecfg rejects conflicting dataset aliases"

# Positive controls
alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2 al2
alias_cmd_add_ds $ALIAS_DS3 $TESTFS
alias_cmd_add_ds $plain
alias_cmd "commit"
log_must alias_zonecfg_run

alias_zone_cleanup
alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 $TESTPOOL
alias_cmd "commit"
log_must alias_zonecfg_run

# Duplicate aliases
expect_conflict $ALIAS_DS1:dup $ALIAS_DS2:dup

# Alias equals the pool of a non-aliased dataset (both orders)
expect_conflict $ALIAS_DS1:$TESTPOOL $plain
expect_conflict $plain $ALIAS_DS1:$TESTPOOL

# Nested delegations involving an alias
expect_conflict $ALIAS_DS1:al1 $TESTPOOL/$TESTFS
expect_conflict $TESTPOOL/$TESTFS $ALIAS_DS1:al1
expect_conflict $TESTPOOL/$TESTFS:top $ALIAS_DS1
expect_conflict $TESTPOOL/$TESTFS:top $ALIAS_DS1:al1

# The same conflicts introduced by modifying an existing configuration
alias_zone_cleanup
alias_cmd_create
alias_cmd_add_ds $ALIAS_DS1 al1
alias_cmd_add_ds $ALIAS_DS2 al2
alias_cmd_add_ds $plain
alias_cmd "commit"
log_must alias_zonecfg_run

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS2" "set alias=al1" "end" "commit"
log_mustnot alias_zonecfg_run
alias_verify_ds $ALIAS_DS2 al2

alias_cmd_begin
alias_cmd "select dataset name=$ALIAS_DS2" "set alias=$TESTPOOL" "end" \
    "commit"
log_mustnot alias_zonecfg_run
alias_verify_ds $ALIAS_DS2 al2

alias_cmd_begin
alias_cmd "add dataset" "set name=$ALIAS_DS3" "set alias=al1" "end" "commit"
log_mustnot alias_zonecfg_run

alias_cmd_begin
alias_cmd "add dataset" "set name=$TESTPOOL/$TESTFS" "end" "commit"
log_mustnot alias_zonecfg_run

(($(alias_ds_count) == 3)) || log_fail "a conflicting dataset was added"

log_pass "zonecfg rejects conflicting dataset aliases"
