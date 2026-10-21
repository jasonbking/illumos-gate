/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Jason King
 */

#ifndef _LLDP_SMF_H
#define	_LLDP_SMF_H

/*
 * A small interface to lldpd's SMF properties, for the property
 * subcommands (props.c).
 *
 * lldpd's property groups are defined on its service (LLDP_SVC), so that's
 * where changes are made; lldpd reads them through its instance's running
 * snapshot, which lsmf_refresh() updates. Values are passed as strings, in
 * their SMF text form ("30", "true", ...).
 */

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lsmf_type {
	LSMF_ASTRING,
	LSMF_COUNT,
	LSMF_BOOLEAN,
} lsmf_type_t;

/* A property's values */
typedef struct lsmf_vals {
	uint_t		lv_n;
	char		**lv_v;
} lsmf_vals_t;

/* Where to read from */
typedef enum lsmf_view {
	LSMF_RUNNING,	/* What lldpd uses: the running snapshot */
	LSMF_CURRENT,	/* The service's current (possibly unrefreshed) */
} lsmf_view_t;

bool lsmf_open(void);
void lsmf_close(void);

/*
 * Why the last call failed (as for scf_strerror()), and whether it was
 * because the caller isn't authorized.
 */
const char *lsmf_errmsg(void);
bool lsmf_denied(void);

/*
 * Read a property's values. *found is false (and vals empty) if the
 * property group or property doesn't exist.
 */
bool lsmf_get(lsmf_view_t, const char *, const char *, lsmf_vals_t *,
    bool *);
void lsmf_vals_free(lsmf_vals_t *);

/* The names of the property groups of type application */
bool lsmf_pgs(lsmf_view_t, char ***, uint_t *);
void lsmf_names_free(char **, uint_t);

/*
 * Change one property group: start, set and delete any number of
 * properties, then commit. With create, a missing property group is
 * created (type application), with modify_authorization and
 * value_authorization of solaris.smf.manage.lldp. lsmf_txn_commit()
 * returns whether the property group is now empty (apart from its
 * authorizations) in *emptyp, if emptyp isn't NULL.
 */
bool lsmf_txn_start(const char *, bool);
void lsmf_txn_set(const char *, lsmf_type_t, const char * const *, uint_t);
void lsmf_txn_delete(const char *);
bool lsmf_txn_commit(bool *);
void lsmf_txn_abort(void);

bool lsmf_pg_delete(const char *);

/* Have lldpd re-read its configuration */
bool lsmf_refresh(void);

/* The authorization for lldpd's properties */
#define	LSMF_AUTH		"solaris.smf.manage.lldp"
#define	LSMF_MODIFY_AUTH	"modify_authorization"
#define	LSMF_VALUE_AUTH		"value_authorization"

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_SMF_H */
