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

/*
 * lldpd's SMF properties, via libscf (see smf.h).
 */

#include <err.h>
#include <libintl.h>
#include <libscf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

#include "smf.h"

static scf_handle_t		*h;
static scf_service_t		*svc;
static scf_instance_t		*inst;
static scf_snapshot_t		*snap;		/* NULL if there's none */
static scf_propertygroup_t	*pg;
static scf_property_t		*prop;
static scf_iter_t		*iter;
static scf_value_t		*val;
static char			*buf;
static size_t			buflen;

/* The current transaction's changes */
typedef struct txn_op {
	char		*to_name;
	bool		to_delete;
	scf_type_t	to_type;
	char		**to_vals;
	uint_t		to_nvals;
} txn_op_t;

static char		*txn_pg;
static bool		txn_create;
static txn_op_t		*txn_ops;
static uint_t		txn_nops;

static scf_error_t	last_err = SCF_ERROR_NONE;

static bool
fail(void)
{
	last_err = scf_error();
	return (false);
}

const char *
lsmf_errmsg(void)
{
	return (scf_strerror(last_err));
}

bool
lsmf_denied(void)
{
	return (last_err == SCF_ERROR_PERMISSION_DENIED);
}

static char *
xstrdup(const char *s)
{
	char *p = strdup(s);

	if (p == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	return (p);
}

static void *
xcalloc(size_t n, size_t sz)
{
	void *p = calloc(n, sz);

	if (p == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	return (p);
}

bool
lsmf_open(void)
{
	ssize_t lim;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) != 0 ||
	    (svc = scf_service_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL) {
		return (fail());
	}

	if (scf_handle_decode_fmri(h, LLDP_SVC, NULL, svc, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != 0 ||
	    scf_handle_decode_fmri(h, LLDP_SVC_FMRI, NULL, NULL, inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		return (fail());
	}

	/* No running snapshot (it's never been run): use current values */
	if (scf_instance_get_snapshot(inst, "running", snap) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			return (fail());
		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	lim = MAX(scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH),
	    scf_limit(SCF_LIMIT_MAX_NAME_LENGTH));
	if (lim < 0)
		return (fail());
	buflen = lim + 1;
	buf = xcalloc(1, buflen);
	return (true);
}

void
lsmf_close(void)
{
	lsmf_txn_abort();
	scf_value_destroy(val);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_snapshot_destroy(snap);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	if (h != NULL) {
		(void) scf_handle_unbind(h);
		scf_handle_destroy(h);
	}
	free(buf);
}

/* Get the named property group into pg. Sets *found. */
static bool
get_pg(lsmf_view_t view, const char *name, bool *found)
{
	int ret;

	if (view == LSMF_RUNNING)
		ret = scf_instance_get_pg_composed(inst, snap, name, pg);
	else
		ret = scf_service_get_pg(svc, name, pg);

	*found = (ret == 0);
	if (ret == 0)
		return (true);
	return (scf_error() == SCF_ERROR_NOT_FOUND ? true : fail());
}

bool
lsmf_get(lsmf_view_t view, const char *pgname, const char *name,
    lsmf_vals_t *vals, bool *found)
{
	int ret;

	(void) memset(vals, '\0', sizeof (*vals));

	if (!get_pg(view, pgname, found))
		return (false);
	if (!*found)
		return (true);

	if (scf_pg_get_property(pg, name, prop) != 0) {
		*found = false;
		return (scf_error() == SCF_ERROR_NOT_FOUND ? true : fail());
	}

	if (scf_iter_property_values(iter, prop) != 0)
		return (fail());

	while ((ret = scf_iter_next_value(iter, val)) == 1) {
		if (scf_value_get_as_string(val, buf, buflen) < 0) {
			lsmf_vals_free(vals);
			return (fail());
		}
		vals->lv_v = reallocarray(vals->lv_v, vals->lv_n + 1,
		    sizeof (char *));
		if (vals->lv_v == NULL)
			err(EXIT_FAILURE, gettext("failed to allocate memory"));
		vals->lv_v[vals->lv_n++] = xstrdup(buf);
	}
	if (ret != 0) {
		lsmf_vals_free(vals);
		return (fail());
	}

	*found = true;
	return (true);
}

void
lsmf_vals_free(lsmf_vals_t *vals)
{
	for (uint_t i = 0; i < vals->lv_n; i++)
		free(vals->lv_v[i]);
	free(vals->lv_v);
	(void) memset(vals, '\0', sizeof (*vals));
}

bool
lsmf_pgs(lsmf_view_t view, char ***namesp, uint_t *np)
{
	char	**names = NULL;
	uint_t	n = 0;
	int	ret;

	if (view == LSMF_RUNNING) {
		ret = scf_iter_instance_pgs_typed_composed(iter, inst, snap,
		    SCF_GROUP_APPLICATION);
	} else {
		ret = scf_iter_service_pgs_typed(iter, svc,
		    SCF_GROUP_APPLICATION);
	}
	if (ret != 0)
		return (fail());

	while ((ret = scf_iter_next_pg(iter, pg)) == 1) {
		if (scf_pg_get_name(pg, buf, buflen) < 0) {
			lsmf_names_free(names, n);
			return (fail());
		}
		names = reallocarray(names, n + 1, sizeof (char *));
		if (names == NULL)
			err(EXIT_FAILURE, gettext("failed to allocate memory"));
		names[n++] = xstrdup(buf);
	}
	if (ret != 0) {
		lsmf_names_free(names, n);
		return (fail());
	}

	*namesp = names;
	*np = n;
	return (true);
}

void
lsmf_names_free(char **names, uint_t n)
{
	for (uint_t i = 0; i < n; i++)
		free(names[i]);
	free(names);
}

bool
lsmf_txn_start(const char *pgname, bool create)
{
	lsmf_txn_abort();
	txn_pg = xstrdup(pgname);
	txn_create = create;
	return (true);
}

static txn_op_t *
txn_op(const char *name)
{
	txn_op_t *op;

	txn_ops = reallocarray(txn_ops, txn_nops + 1, sizeof (txn_op_t));
	if (txn_ops == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	op = &txn_ops[txn_nops++];
	(void) memset(op, '\0', sizeof (*op));
	op->to_name = xstrdup(name);
	return (op);
}

void
lsmf_txn_set(const char *name, lsmf_type_t type, const char * const *vals,
    uint_t n)
{
	txn_op_t *op = txn_op(name);

	switch (type) {
	case LSMF_COUNT:
		op->to_type = SCF_TYPE_COUNT;
		break;
	case LSMF_BOOLEAN:
		op->to_type = SCF_TYPE_BOOLEAN;
		break;
	case LSMF_ASTRING:
	default:
		op->to_type = SCF_TYPE_ASTRING;
		break;
	}

	op->to_vals = xcalloc(MAX(n, 1), sizeof (char *));
	for (uint_t i = 0; i < n; i++)
		op->to_vals[i] = xstrdup(vals[i]);
	op->to_nvals = n;
}

void
lsmf_txn_delete(const char *name)
{
	txn_op(name)->to_delete = true;
}

void
lsmf_txn_abort(void)
{
	for (uint_t i = 0; i < txn_nops; i++) {
		free(txn_ops[i].to_name);
		for (uint_t j = 0; j < txn_ops[i].to_nvals; j++)
			free(txn_ops[i].to_vals[j]);
		free(txn_ops[i].to_vals);
	}
	free(txn_ops);
	free(txn_pg);
	txn_ops = NULL;
	txn_nops = 0;
	txn_pg = NULL;
}

/* Add the changes of op to tx */
static bool
txn_add(scf_transaction_t *tx, const txn_op_t *op, const char *name,
    scf_type_t type, const char * const *vals, uint_t n)
{
	scf_transaction_entry_t	*e;
	bool			exists;

	if ((e = scf_entry_create(h)) == NULL)
		return (fail());

	exists = (scf_pg_get_property(pg, name, prop) == 0);
	if (!exists && scf_error() != SCF_ERROR_NOT_FOUND) {
		scf_entry_destroy(e);
		return (fail());
	}

	if (op != NULL && op->to_delete) {
		/* Deleting what isn't there is nothing to do */
		if (!exists) {
			scf_entry_destroy(e);
			return (true);
		}
		if (scf_transaction_property_delete(tx, e, name) != 0) {
			scf_entry_destroy(e);
			return (fail());
		}
		return (true);
	}

	if ((exists ?
	    scf_transaction_property_change_type(tx, e, name, type) :
	    scf_transaction_property_new(tx, e, name, type)) != 0) {
		scf_entry_destroy(e);
		return (fail());
	}

	for (uint_t i = 0; i < n; i++) {
		scf_value_t *v = scf_value_create(h);

		if (v == NULL)
			return (fail());
		if (scf_value_set_from_string(v, type, vals[i]) != 0 ||
		    scf_entry_add_value(e, v) != 0) {
			scf_value_destroy(v);
			return (fail());
		}
	}
	return (true);
}

/* Is pg empty, apart from its authorizations? */
static bool
pg_empty(bool *emptyp)
{
	int ret;

	*emptyp = true;
	if (scf_pg_update(pg) == -1 || scf_iter_pg_properties(iter, pg) != 0)
		return (fail());

	while ((ret = scf_iter_next_property(iter, prop)) == 1) {
		if (scf_property_get_name(prop, buf, buflen) < 0)
			return (fail());
		if (strcmp(buf, LSMF_MODIFY_AUTH) != 0 &&
		    strcmp(buf, LSMF_VALUE_AUTH) != 0) {
			*emptyp = false;
		}
	}
	return (ret == 0 ? true : fail());
}

bool
lsmf_txn_commit(bool *emptyp)
{
	static const char *const auth[] = { LSMF_AUTH };
	scf_transaction_t	*tx = NULL;
	bool			created = false;
	bool			ok = false;
	int			ret;

	if (scf_service_get_pg(svc, txn_pg, pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND || !txn_create)
			goto done;
		if (scf_service_add_pg(svc, txn_pg, SCF_GROUP_APPLICATION, 0,
		    pg) != 0) {
			goto done;
		}
		created = true;
	}

	if ((tx = scf_transaction_create(h)) == NULL)
		goto done;

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0)
			goto done;

		/* So solaris.smf.manage.lldp can change it from now on */
		if (created &&
		    (!txn_add(tx, NULL, LSMF_MODIFY_AUTH, SCF_TYPE_ASTRING,
		    auth, 1) ||
		    !txn_add(tx, NULL, LSMF_VALUE_AUTH, SCF_TYPE_ASTRING,
		    auth, 1))) {
			goto done;
		}

		for (uint_t i = 0; i < txn_nops; i++) {
			const txn_op_t *op = &txn_ops[i];

			if (!txn_add(tx, op, op->to_name, op->to_type,
			    (const char * const *)op->to_vals, op->to_nvals))
				goto done;
		}

		ret = scf_transaction_commit(tx);
		if (ret == 1)
			break;
		if (ret == -1)
			goto done;

		/* Someone else changed it first: try again */
		scf_transaction_destroy_children(tx);
		scf_transaction_reset(tx);
		if (scf_pg_update(pg) == -1)
			goto done;
	}

	/* Committed; if we can't tell whether it's empty, assume it isn't */
	ok = true;
	if (emptyp != NULL && !pg_empty(emptyp))
		*emptyp = false;

done:
	if (!ok)
		last_err = scf_error();
	if (tx != NULL) {
		scf_transaction_destroy_children(tx);
		scf_transaction_destroy(tx);
	}
	lsmf_txn_abort();
	return (ok);
}

bool
lsmf_pg_delete(const char *pgname)
{
	if (scf_service_get_pg(svc, pgname, pg) != 0)
		return (scf_error() == SCF_ERROR_NOT_FOUND ? true : fail());
	if (scf_pg_delete(pg) != 0)
		return (scf_error() == SCF_ERROR_DELETED ? true : fail());
	return (true);
}

bool
lsmf_refresh(void)
{
	if (smf_refresh_instance(LLDP_SVC_FMRI) != 0)
		return (fail());
	return (true);
}
