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
 * Managing lldpd's configuration:
 *
 *	lldp set-agentprop -p prop=value [-p ...] link|default
 *	lldp reset-agentprop -p prop[,...] link|default
 *	lldp show-agentprop [-c] [-o field[,...]] [-p prop[,...]]
 *	    [link|default ...]
 *	lldp enable-agent [-m tx|rx|txrx] link|default ...
 *	lldp disable-agent link|default ...
 *	lldp set-sysprop -p prop=value [-p ...]
 *	lldp reset-sysprop -p prop[,...]
 *	lldp show-sysprop [-c] [-o field[,...]] [-p prop[,...]]
 *
 * These change lldpd's SMF properties (see lldpd.xml, and lldpd's
 * config.c), then refresh lldpd so it applies them. Agent properties are
 * set for every agent in the 'default' property group, or for one agent in
 * a property group named after its link's hardware name (a link is given by
 * its datalink name, which is mapped to that); system properties are in the
 * 'config' and 'daemon' property groups. Values are checked (against
 * liblldp's lldp_propinfo()) before anything is changed, since lldpd only
 * logs, and ignores, an invalid value.
 *
 * Multi-valued (flag) properties are set with comma separated values;
 * prop+=value and prop-=value add and remove values from the property's
 * current (effective) value.
 *
 * The show subcommands read the running snapshot (what lldpd is using).
 * Each value's SOURCE is where it comes from: the link's own property group
 * ('link'), the 'default' property group ('default'), or for system
 * properties, the property group ('set'), or lldpd's built-in default
 * ('builtin').
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

#include "lldp.h"
#include "smf.h"

#define	DEFAULT_TARGET	"default"

/* Where a value comes from */
typedef enum src {
	SRC_LINK,
	SRC_DEFAULT,
	SRC_SET,
	SRC_BUILTIN,
} src_t;

static const char *
src_str(src_t src)
{
	switch (src) {
	case SRC_LINK:
		return ("link");
	case SRC_DEFAULT:
		return ("default");
	case SRC_SET:
		return ("set");
	case SRC_BUILTIN:
	default:
		return ("builtin");
	}
}

/* An agent to change or show: 'default', or a link */
typedef struct target {
	bool	t_default;
	char	t_pg[MAXLINKNAMELEN];	/* Property group (hardware name) */
	char	t_link[MAXLINKNAMELEN];	/* As shown (datalink name) */
} target_t;

/* A -p prop=value (or prop+=value, prop-=value) */
typedef enum pset_op {
	PS_SET,
	PS_ADD,
	PS_REMOVE,
} pset_op_t;

typedef struct pset {
	const lldp_propinfo_t	*ps_pi;
	pset_op_t		ps_op;
	const char		*ps_value;
	lsmf_vals_t		ps_vals;	/* The values to set */
} pset_t;

static bool pg_exists(lsmf_view_t, const char *);

static void __NORETURN
smf_die(const char *what)
{
	if (lsmf_denied()) {
		errx(EXIT_FAILURE, gettext("%s: permission denied (this "
		    "requires the %s authorization)"), what, LSMF_AUTH);
	}
	errx(EXIT_FAILURE, "%s: %s", what, lsmf_errmsg());
}

static void
smf_open(void)
{
	if (!lsmf_open())
		smf_die(gettext("failed to access lldpd's SMF configuration"));
}

static void
vals_add(lsmf_vals_t *v, const char *s)
{
	char **p = reallocarray(v->lv_v, v->lv_n + 1, sizeof (char *));

	if (p == NULL || (p[v->lv_n] = strdup(s)) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	v->lv_v = p;
	v->lv_n++;
}

/* Split a comma separated list into vals */
static void
vals_split(lsmf_vals_t *v, const char *list)
{
	char *s, *tok, *last;

	if ((s = strdup(list)) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	for (tok = strtok_r(s, ",", &last); tok != NULL;
	    tok = strtok_r(NULL, ",", &last)) {
		vals_add(v, tok);
	}
	free(s);
}

static void
vals_join(const lsmf_vals_t *v, char *buf, size_t buflen)
{
	(void) strlcpy(buf, "", buflen);
	for (uint_t i = 0; i < v->lv_n; i++) {
		if (i > 0)
			(void) strlcat(buf, ",", buflen);
		(void) strlcat(buf, v->lv_v[i], buflen);
	}
}

/* The built-in default of a property, as values */
static void
builtin_vals(const lldp_propinfo_t *pi, lsmf_vals_t *v)
{
	char buf[512];

	(void) memset(v, '\0', sizeof (*v));

	/* A string's default is derived (or nothing); it has no value */
	if (pi->lpi_type == LLDP_PT_STRING)
		return;

	(void) lldp_propinfo_default_str(pi, buf, sizeof (buf));
	if (pi->lpi_type == LLDP_PT_FLAGS)
		vals_split(v, buf);
	else
		vals_add(v, buf);
}

/*
 * The value of an agent property for t: from its own property group, the
 * default property group, or built in. If nolink, the link's own value
 * is skipped (i.e. this is what it would be if it were reset).
 */
static void
agent_value(lsmf_view_t view, const target_t *t, const lldp_propinfo_t *pi,
    bool nolink, lsmf_vals_t *v, src_t *srcp)
{
	bool found;

	if (!t->t_default && !nolink) {
		if (!lsmf_get(view, t->t_pg, pi->lpi_name, v, &found))
			smf_die(gettext("failed to read properties"));
		if (found) {
			*srcp = SRC_LINK;
			return;
		}
	}

	if (!lsmf_get(view, LLDP_PG_DEFAULT, pi->lpi_name, v, &found))
		smf_die(gettext("failed to read properties"));
	if (found) {
		*srcp = SRC_DEFAULT;
		return;
	}

	builtin_vals(pi, v);
	*srcp = SRC_BUILTIN;
}

static void
sys_value(lsmf_view_t view, const lldp_propinfo_t *pi, lsmf_vals_t *v,
    src_t *srcp)
{
	bool found;

	if (!lsmf_get(view, pi->lpi_pg, pi->lpi_name, v, &found))
		smf_die(gettext("failed to read properties"));
	if (found) {
		*srcp = SRC_SET;
		return;
	}
	builtin_vals(pi, v);
	*srcp = SRC_BUILTIN;
}

/* The flags of a FLAGS property's values (unknown ones are ignored) */
static uint_t
vals_flags(const lldp_propinfo_t *pi, const lsmf_vals_t *v)
{
	uint_t flags = 0, f;

	for (uint_t i = 0; i < v->lv_n; i++) {
		if (lldp_prop_val(pi->lpi_names, v->lv_v[i], &f))
			flags |= f;
	}
	return (flags);
}

/* The values for flags, in canonical order ("none" for no flags) */
static void
flags_vals(const lldp_propinfo_t *pi, uint_t flags, lsmf_vals_t *v)
{
	char buf[512];

	(void) lldp_prop_flags_str(pi->lpi_names, flags, buf, sizeof (buf));
	vals_split(v, buf);
}

/*
 * Turn a -p value into the values to set, checking it's valid. For += and
 * -=, cur is the property's current value.
 */
static bool
pset_parse(pset_t *ps, const lsmf_vals_t *cur)
{
	const lldp_propinfo_t	*pi = ps->ps_pi;
	const char		*name = pi->lpi_name;
	const char		*value = ps->ps_value;
	char			names[512];
	uint_t			v;

	if (ps->ps_op != PS_SET && pi->lpi_type != LLDP_PT_FLAGS) {
		warnx(gettext("%s: += and -= are only for multi-valued "
		    "properties"), name);
		return (false);
	}

	switch (pi->lpi_type) {
	case LLDP_PT_STRING:
		if (*value == '\0') {
			warnx(gettext("%s: value can't be empty (use "
			    "reset-%s to unset it)"), name,
			    (pi->lpi_flags & LLDP_PI_SYSTEM) ?
			    "sysprop" : "agentprop");
			return (false);
		}
		if (strlen(value) > pi->lpi_max) {
			warnx(gettext("%s: value is too long (at most %u "
			    "bytes)"), name, pi->lpi_max);
			return (false);
		}
		vals_add(&ps->ps_vals, value);
		return (true);

	case LLDP_PT_COUNT: {
		char		*end;
		unsigned long	n;

		errno = 0;
		n = strtoul(value, &end, 10);
		if (*value == '\0' || *end != '\0' || errno != 0 ||
		    !isdigit((unsigned char)*value) || n < pi->lpi_min ||
		    n > pi->lpi_max) {
			warnx(gettext("%s: invalid value '%s' (must be %u-%u)"),
			    name, value, pi->lpi_min, pi->lpi_max);
			return (false);
		}
		(void) snprintf(names, sizeof (names), "%lu", n);
		vals_add(&ps->ps_vals, names);
		return (true);
	}

	case LLDP_PT_BOOLEAN:
		if (strcmp(value, "true") != 0 && strcmp(value, "false") != 0) {
			warnx(gettext("%s: invalid value '%s' (must be true "
			    "or false)"), name, value);
			return (false);
		}
		vals_add(&ps->ps_vals, value);
		return (true);

	case LLDP_PT_ENUM:
		if (!lldp_prop_val(pi->lpi_names, value, &v)) {
			(void) lldp_prop_names_str(pi->lpi_names, names,
			    sizeof (names));
			warnx(gettext("%s: invalid value '%s' (must be one of "
			    "%s)"), name, value, names);
			return (false);
		}
		vals_add(&ps->ps_vals, value);
		return (true);

	case LLDP_PT_FLAGS: {
		lsmf_vals_t	in = { 0 };
		uint_t		flags = 0;
		bool		none = false;

		vals_split(&in, value);
		for (uint_t i = 0; i < in.lv_n; i++) {
			if (strcmp(in.lv_v[i], "none") == 0) {
				none = true;
				continue;
			}
			if (!lldp_prop_val(pi->lpi_names, in.lv_v[i], &v)) {
				(void) lldp_prop_names_str(pi->lpi_names,
				    names, sizeof (names));
				warnx(gettext("%s: invalid value '%s' (must be "
				    "none, or any of %s)"), name, in.lv_v[i],
				    names);
				lsmf_vals_free(&in);
				return (false);
			}
			flags |= v;
		}
		lsmf_vals_free(&in);

		if ((none && (flags != 0 || ps->ps_op != PS_SET)) ||
		    (!none && flags == 0)) {
			warnx(gettext("%s: invalid value '%s'"), name, value);
			return (false);
		}

		if (ps->ps_op == PS_ADD)
			flags = vals_flags(pi, cur) | flags;
		else if (ps->ps_op == PS_REMOVE)
			flags = vals_flags(pi, cur) & ~flags;

		flags_vals(pi, flags, &ps->ps_vals);
		return (true);
	}
	}

	return (false);
}

static lsmf_type_t
pi_smf_type(const lldp_propinfo_t *pi)
{
	switch (pi->lpi_type) {
	case LLDP_PT_COUNT:
		return (LSMF_COUNT);
	case LLDP_PT_BOOLEAN:
		return (LSMF_BOOLEAN);
	default:
		return (LSMF_ASTRING);
	}
}

/*
 * Look up a property named in a -p, checking it's the right kind (system or
 * agent) for the subcommand.
 */
static const lldp_propinfo_t *
prop_lookup(const char *name, uint_t kind)
{
	const lldp_propinfo_t *pi = lldp_propinfo(name);

	if (pi == NULL || (pi->lpi_flags & kind) == 0) {
		warnx(gettext("unknown %s property '%s'"),
		    (kind == LLDP_PI_SYSTEM) ? gettext("system") :
		    gettext("agent"), name);
		return (NULL);
	}
	return (pi);
}

/*
 * The target named by an operand: 'default', or a link (by datalink name,
 * or by hardware name if it isn't a datalink, e.g. one that's been removed).
 */
static bool
target_get(const char *operand, target_t *t)
{
	int ret;

	(void) memset(t, '\0', sizeof (*t));

	if (strcmp(operand, DEFAULT_TARGET) == 0) {
		t->t_default = true;
		(void) strlcpy(t->t_pg, LLDP_PG_DEFAULT, sizeof (t->t_pg));
		(void) strlcpy(t->t_link, DEFAULT_TARGET, sizeof (t->t_link));
		return (true);
	}

	if (strlen(operand) >= sizeof (t->t_pg)) {
		warnx(gettext("invalid link name '%s'"), operand);
		return (false);
	}

	ret = link_hwname(operand, t->t_pg, sizeof (t->t_pg));
	switch (ret) {
	case 0:
		(void) strlcpy(t->t_link, operand, sizeof (t->t_link));
		return (true);
	case ENOTSUP:
		warnx(gettext("%s isn't a physical link (lldpd only has "
		    "agents for physical links)"), operand);
		return (false);
	default:
		/* Not a datalink: it may be a hardware name */
		if (!isdigit((unsigned char)operand[strlen(operand) - 1])) {
			warnx(gettext("no such link '%s'"), operand);
			return (false);
		}
		(void) strlcpy(t->t_pg, operand, sizeof (t->t_pg));
		link_name(operand, t->t_link, sizeof (t->t_link));

		/* E.g. a removed link's settings are fine; a typo isn't */
		if (!pg_exists(LSMF_CURRENT, t->t_pg) &&
		    strcmp(t->t_link, operand) == 0) {
			warnx(gettext("warning: there's no link %s; its "
			    "settings will apply to a link with that hardware "
			    "name"), operand);
		}
		return (true);
	}
}

static bool
pg_exists(lsmf_view_t view, const char *name)
{
	char	**names;
	uint_t	n;
	bool	ret = false;

	if (!lsmf_pgs(view, &names, &n))
		smf_die(gettext("failed to read properties"));
	for (uint_t i = 0; i < n; i++) {
		if (strcmp(names[i], name) == 0)
			ret = true;
	}
	lsmf_names_free(names, n);
	return (ret);
}

/* Apply a property group's changes, with a useful error if not allowed */
static void
txn_commit(const char *pg, bool creating, bool *emptyp)
{
	if (lsmf_txn_commit(emptyp))
		return;

	if (creating && lsmf_denied()) {
		errx(EXIT_FAILURE, gettext("permission denied: creating the "
		    "'%s' property group requires the "
		    "solaris.smf.modify.application authorization"), pg);
	}
	smf_die(gettext("failed to change properties"));
}

static int
refresh(void)
{
	if (lsmf_refresh())
		return (EXIT_SUCCESS);

	warnx(gettext("the change was made, but lldpd couldn't be refreshed "
	    "to apply it (%s); use 'svcadm refresh %s'"),
	    lsmf_denied() ? gettext("permission denied") : lsmf_errmsg(),
	    LLDP_SVC_FMRI);
	return (EXIT_FAILURE);
}

/* Parse "-p prop[,...]" (for reset and show) */
static void
props_list_add(lsmf_vals_t *v, const char *arg)
{
	vals_split(v, arg);
}

/*
 * Collect the -p prop=value options of a set subcommand into psets (of
 * kind), checking each.
 */
static bool
pset_add(pset_t **psetsp, uint_t *np, const char *arg, uint_t kind)
{
	const char		*eq = strchr(arg, '=');
	char			name[64];
	size_t			namelen;
	pset_op_t		op = PS_SET;
	const lldp_propinfo_t	*pi;
	pset_t			*ps;

	if (eq == NULL || eq == arg) {
		warnx(gettext("invalid property '%s' (must be prop=value)"),
		    arg);
		return (false);
	}

	namelen = eq - arg;
	if (eq[-1] == '+' || eq[-1] == '-') {
		op = (eq[-1] == '+') ? PS_ADD : PS_REMOVE;
		namelen--;
	}
	if (namelen == 0 || namelen >= sizeof (name)) {
		warnx(gettext("invalid property '%s'"), arg);
		return (false);
	}
	(void) memcpy(name, arg, namelen);
	name[namelen] = '\0';

	if ((pi = prop_lookup(name, kind)) == NULL)
		return (false);

	for (uint_t i = 0; i < *np; i++) {
		if ((*psetsp)[i].ps_pi == pi) {
			warnx(gettext("%s: given more than once"), name);
			return (false);
		}
	}

	ps = reallocarray(*psetsp, *np + 1, sizeof (pset_t));
	if (ps == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	*psetsp = ps;
	ps = &ps[(*np)++];
	(void) memset(ps, '\0', sizeof (*ps));
	ps->ps_pi = pi;
	ps->ps_op = op;
	ps->ps_value = eq + 1;
	return (true);
}

static void
psets_free(pset_t *psets, uint_t n)
{
	for (uint_t i = 0; i < n; i++)
		lsmf_vals_free(&psets[i].ps_vals);
	free(psets);
}

static const pset_t *
pset_find(const pset_t *psets, uint_t n, const char *name)
{
	for (uint_t i = 0; i < n; i++) {
		if (strcmp(psets[i].ps_pi->lpi_name, name) == 0)
			return (&psets[i]);
	}
	return (NULL);
}

/*
 * A *_id_type=local needs the matching *_id: either being set now, or
 * already set (for the same target).
 */
static bool
local_id_check(const pset_t *psets, uint_t n, const char *type_prop,
    const char *id_prop, bool (*has_id)(const void *), const void *arg)
{
	const pset_t *ps = pset_find(psets, n, type_prop);

	if (ps == NULL || strcmp(ps->ps_vals.lv_v[0], "local") != 0)
		return (true);
	if (pset_find(psets, n, id_prop) != NULL || has_id(arg))
		return (true);

	warnx(gettext("%s=local needs %s to be set too"), type_prop, id_prop);
	return (false);
}

static bool
link_has_port_id(const void *arg)
{
	const target_t	*t = arg;
	lsmf_vals_t	v;
	bool		found;

	if (!lsmf_get(LSMF_CURRENT, t->t_pg, "port_id", &v, &found))
		smf_die(gettext("failed to read properties"));
	lsmf_vals_free(&v);
	return (found);
}

static bool
sys_has_chassis_id(const void *arg __unused)
{
	lsmf_vals_t	v;
	bool		found;

	if (!lsmf_get(LSMF_CURRENT, LLDP_PG_CONFIG, "chassis_id", &v, &found))
		smf_die(gettext("failed to read properties"));
	lsmf_vals_free(&v);
	return (found);
}

/* Set the agent properties psets for t (without refreshing) */
static void
agent_set(const target_t *t, pset_t *psets, uint_t n)
{
	bool creating;

	for (uint_t i = 0; i < n; i++) {
		pset_t		*ps = &psets[i];
		lsmf_vals_t	cur = { 0 };
		src_t		src;

		if ((ps->ps_pi->lpi_flags & LLDP_PI_LINK_ONLY) &&
		    t->t_default) {
			errx(EXIT_FAILURE, gettext("%s can only be set for a "
			    "link"), ps->ps_pi->lpi_name);
		}

		if (ps->ps_op != PS_SET) {
			agent_value(LSMF_CURRENT, t, ps->ps_pi, false, &cur,
			    &src);
		}
		if (!pset_parse(ps, &cur))
			exit(EXIT_FAILURE);
		lsmf_vals_free(&cur);
	}

	if (!t->t_default && !local_id_check(psets, n, "port_id_type",
	    "port_id", link_has_port_id, t)) {
		exit(EXIT_FAILURE);
	}

	creating = !t->t_default && !pg_exists(LSMF_CURRENT, t->t_pg);

	(void) lsmf_txn_start(t->t_pg, !t->t_default);
	for (uint_t i = 0; i < n; i++) {
		lsmf_txn_set(psets[i].ps_pi->lpi_name,
		    pi_smf_type(psets[i].ps_pi),
		    (const char * const *)psets[i].ps_vals.lv_v,
		    psets[i].ps_vals.lv_n);
	}
	txn_commit(t->t_pg, creating, NULL);
}

int
do_set_agentprop(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("set-agentprop");
	pset_t			*psets = NULL;
	uint_t			n = 0;
	target_t		t;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":p:")) != -1) {
		switch (c) {
		case 'p':
			if (!pset_add(&psets, &n, optarg, LLDP_PI_AGENT))
				exit(EXIT_USAGE);
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (n == 0) {
		warnx(gettext("no properties given (-p)"));
		cmd_usage(cmd);
	}
	if (argc - optind != 1) {
		warnx(gettext("one link (or 'default') must be given"));
		cmd_usage(cmd);
	}

	smf_open();
	if (!target_get(argv[optind], &t))
		exit(EXIT_FAILURE);

	agent_set(&t, psets, n);
	ret = refresh();

	psets_free(psets, n);
	lsmf_close();
	return (ret);
}

/*
 * Reset (delete) agent properties of t. A link's property group that's left
 * empty is deleted (if we're allowed).
 */
static void
agent_reset(const target_t *t, const lsmf_vals_t *names)
{
	bool empty = false;

	for (uint_t i = 0; i < names->lv_n; i++) {
		const lldp_propinfo_t *pi = prop_lookup(names->lv_v[i],
		    LLDP_PI_AGENT);

		if (pi == NULL)
			exit(EXIT_USAGE);
		if ((pi->lpi_flags & LLDP_PI_LINK_ONLY) && t->t_default) {
			errx(EXIT_FAILURE, gettext("%s can only be set (or "
			    "reset) for a link"), pi->lpi_name);
		}
	}

	/* Nothing to reset */
	if (!pg_exists(LSMF_CURRENT, t->t_pg))
		return;

	(void) lsmf_txn_start(t->t_pg, false);
	for (uint_t i = 0; i < names->lv_n; i++)
		lsmf_txn_delete(names->lv_v[i]);
	txn_commit(t->t_pg, false, t->t_default ? NULL : &empty);

	/* Deleting it needs more than solaris.smf.manage.lldp; that's ok */
	if (empty)
		(void) lsmf_pg_delete(t->t_pg);
}

int
do_reset_agentprop(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("reset-agentprop");
	lsmf_vals_t		names = { 0 };
	target_t		t;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":p:")) != -1) {
		switch (c) {
		case 'p':
			props_list_add(&names, optarg);
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (names.lv_n == 0) {
		warnx(gettext("no properties given (-p)"));
		cmd_usage(cmd);
	}
	if (argc - optind != 1) {
		warnx(gettext("one link (or 'default') must be given"));
		cmd_usage(cmd);
	}

	smf_open();
	if (!target_get(argv[optind], &t))
		exit(EXIT_FAILURE);

	agent_reset(&t, &names);
	ret = refresh();

	lsmf_vals_free(&names);
	lsmf_close();
	return (ret);
}

/* enable-agent and disable-agent: set admin_status for each target */
static int
admin_status_set(const lldp_cmd_t *cmd, int argc, char **argv,
    const char *status)
{
	const lldp_propinfo_t	*pi = lldp_propinfo("admin_status");
	target_t		*ts;
	int			n = argc - optind;

	if (n < 1) {
		warnx(gettext("at least one link (or 'default') must be "
		    "given"));
		cmd_usage(cmd);
	}

	smf_open();

	/* Check them all before changing any */
	if ((ts = calloc(n, sizeof (target_t))) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));
	for (int i = 0; i < n; i++) {
		if (!target_get(argv[optind + i], &ts[i]))
			exit(EXIT_FAILURE);
	}

	for (int i = 0; i < n; i++) {
		pset_t ps = {
			.ps_pi = pi, .ps_op = PS_SET, .ps_value = status
		};

		agent_set(&ts[i], &ps, 1);
		lsmf_vals_free(&ps.ps_vals);
	}

	free(ts);
	n = refresh();
	lsmf_close();
	return (n);
}

int
do_enable_agent(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("enable-agent");
	const char		*mode = "txrx";
	uint_t			v;
	int			c;

	optind = 1;
	while ((c = getopt(argc, argv, ":m:")) != -1) {
		switch (c) {
		case 'm':
			mode = optarg;
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (!lldp_prop_val(LLDP_PROP_ADMIN_STATUS, mode, &v) ||
	    v == LLDP_LINK_DISABLED) {
		warnx(gettext("invalid mode '%s' (must be tx, rx, or txrx)"),
		    mode);
		cmd_usage(cmd);
	}

	return (admin_status_set(cmd, argc, argv, mode));
}

int
do_disable_agent(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("disable-agent");
	int			c;

	optind = 1;
	while ((c = getopt(argc, argv, ":")) != -1) {
		switch (c) {
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	return (admin_status_set(cmd, argc, argv, "disabled"));
}

int
do_set_sysprop(int argc, char **argv)
{
	static const char *const pgs[] = { LLDP_PG_CONFIG, LLDP_PG_DAEMON };
	const lldp_cmd_t	*cmd = cmd_lookup("set-sysprop");
	pset_t			*psets = NULL;
	uint_t			n = 0;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":p:")) != -1) {
		switch (c) {
		case 'p':
			if (!pset_add(&psets, &n, optarg, LLDP_PI_SYSTEM))
				exit(EXIT_USAGE);
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (n == 0) {
		warnx(gettext("no properties given (-p)"));
		cmd_usage(cmd);
	}
	if (argc - optind != 0) {
		warnx(gettext("unexpected argument '%s'"), argv[optind]);
		cmd_usage(cmd);
	}

	smf_open();

	for (uint_t i = 0; i < n; i++) {
		lsmf_vals_t none = { 0 };

		/* There are no multi-valued system properties (for += -=) */
		if (!pset_parse(&psets[i], &none))
			exit(EXIT_FAILURE);
	}
	if (!local_id_check(psets, n, "chassis_id_type", "chassis_id",
	    sys_has_chassis_id, NULL)) {
		exit(EXIT_FAILURE);
	}

	/* One transaction for each property group */
	for (size_t p = 0; p < ARRAY_SIZE(pgs); p++) {
		bool any = false;

		for (uint_t i = 0; i < n; i++) {
			if (strcmp(psets[i].ps_pi->lpi_pg, pgs[p]) != 0)
				continue;
			if (!any)
				(void) lsmf_txn_start(pgs[p], false);
			any = true;
			lsmf_txn_set(psets[i].ps_pi->lpi_name,
			    pi_smf_type(psets[i].ps_pi),
			    (const char * const *)psets[i].ps_vals.lv_v,
			    psets[i].ps_vals.lv_n);
		}
		if (any)
			txn_commit(pgs[p], false, NULL);
	}

	ret = refresh();
	psets_free(psets, n);
	lsmf_close();
	return (ret);
}

int
do_reset_sysprop(int argc, char **argv)
{
	static const char *const pgs[] = { LLDP_PG_CONFIG, LLDP_PG_DAEMON };
	const lldp_cmd_t	*cmd = cmd_lookup("reset-sysprop");
	lsmf_vals_t		names = { 0 };
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":p:")) != -1) {
		switch (c) {
		case 'p':
			props_list_add(&names, optarg);
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (names.lv_n == 0) {
		warnx(gettext("no properties given (-p)"));
		cmd_usage(cmd);
	}
	if (argc - optind != 0) {
		warnx(gettext("unexpected argument '%s'"), argv[optind]);
		cmd_usage(cmd);
	}

	for (uint_t i = 0; i < names.lv_n; i++) {
		if (prop_lookup(names.lv_v[i], LLDP_PI_SYSTEM) == NULL)
			exit(EXIT_USAGE);
	}

	smf_open();

	for (size_t p = 0; p < ARRAY_SIZE(pgs); p++) {
		bool any = false;

		for (uint_t i = 0; i < names.lv_n; i++) {
			const lldp_propinfo_t *pi =
			    lldp_propinfo(names.lv_v[i]);

			if (strcmp(pi->lpi_pg, pgs[p]) != 0)
				continue;
			if (!any)
				(void) lsmf_txn_start(pgs[p], false);
			any = true;
			lsmf_txn_delete(pi->lpi_name);
		}
		if (any)
			txn_commit(pgs[p], false, NULL);
	}

	ret = refresh();
	lsmf_vals_free(&names);
	lsmf_close();
	return (ret);
}

/*
 * show-agentprop and show-sysprop
 */
typedef struct prow {
	const char		*pr_link;	/* NULL for show-sysprop */
	const lldp_propinfo_t	*pr_pi;
	lsmf_vals_t		pr_vals;
	src_t			pr_src;
	lsmf_vals_t		pr_def;		/* The value if reset */
	bool			pr_def_builtin;
} prow_t;

typedef enum prop_field {
	PF_LINK,
	PF_PROPERTY,
	PF_VALUE,
	PF_SOURCE,
	PF_DEFAULT,
	PF_POSSIBLE,
} prop_field_t;

static void
possible_str(const lldp_propinfo_t *pi, char *buf, size_t buflen)
{
	char names[512];

	switch (pi->lpi_type) {
	case LLDP_PT_COUNT:
		(void) snprintf(buf, buflen, "%u-%u", pi->lpi_min, pi->lpi_max);
		break;
	case LLDP_PT_BOOLEAN:
		(void) strlcpy(buf, "true,false", buflen);
		break;
	case LLDP_PT_ENUM:
		(void) lldp_prop_names_str(pi->lpi_names, buf, buflen);
		break;
	case LLDP_PT_FLAGS:
		(void) lldp_prop_names_str(pi->lpi_names, names,
		    sizeof (names));
		(void) snprintf(buf, buflen, "none,%s", names);
		break;
	case LLDP_PT_STRING:
	default:
		(void) strlcpy(buf, "", buflen);
		break;
	}
}

static boolean_t
prop_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const prow_t *r = arg->ofmt_cbarg;

	buf[0] = '\0';

	switch (arg->ofmt_id) {
	case PF_LINK:
		if (r->pr_link != NULL)
			(void) strlcpy(buf, r->pr_link, buflen);
		break;
	case PF_PROPERTY:
		(void) strlcpy(buf, r->pr_pi->lpi_name, buflen);
		break;
	case PF_VALUE:
		vals_join(&r->pr_vals, buf, buflen);
		break;
	case PF_SOURCE:
		(void) strlcpy(buf, src_str(r->pr_src), buflen);
		break;
	case PF_DEFAULT:
		/* A string's default is described rather than a value */
		if (r->pr_def_builtin && r->pr_pi->lpi_type == LLDP_PT_STRING)
			(void) lldp_propinfo_default_str(r->pr_pi, buf, buflen);
		else
			vals_join(&r->pr_def, buf, buflen);
		break;
	case PF_POSSIBLE:
		possible_str(r->pr_pi, buf, buflen);
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static const ofmt_field_t agentprop_fields[] = {
	{ "LINK",	10,	PF_LINK,	prop_ofmt_cb },
	{ "PROPERTY",	22,	PF_PROPERTY,	prop_ofmt_cb },
	{ "VALUE",	20,	PF_VALUE,	prop_ofmt_cb },
	{ "SOURCE",	8,	PF_SOURCE,	prop_ofmt_cb },
	{ "DEFAULT",	20,	PF_DEFAULT,	prop_ofmt_cb },
	{ "POSSIBLE",	20,	PF_POSSIBLE,	prop_ofmt_cb },
	{ NULL,		0,	0,		NULL }
};

static const ofmt_field_t sysprop_fields[] = {
	{ "PROPERTY",	17,	PF_PROPERTY,	prop_ofmt_cb },
	{ "VALUE",	24,	PF_VALUE,	prop_ofmt_cb },
	{ "SOURCE",	8,	PF_SOURCE,	prop_ofmt_cb },
	{ "DEFAULT",	16,	PF_DEFAULT,	prop_ofmt_cb },
	{ "POSSIBLE",	20,	PF_POSSIBLE,	prop_ofmt_cb },
	{ NULL,		0,	0,		NULL }
};

/* The properties (of kind) to show: those named, or all of them */
static void
show_props(const lsmf_vals_t *names, uint_t kind,
    const lldp_propinfo_t ***pisp, uint_t *np)
{
	const lldp_propinfo_t	**pis;
	const lldp_propinfo_t	*pi;
	uint_t			n = 0;

	if (names->lv_n > 0) {
		pis = calloc(names->lv_n, sizeof (*pis));
		if (pis == NULL)
			err(EXIT_FAILURE, gettext("failed to allocate memory"));
		for (uint_t i = 0; i < names->lv_n; i++) {
			if ((pis[n] = prop_lookup(names->lv_v[i], kind)) ==
			    NULL) {
				exit(EXIT_USAGE);
			}
			n++;
		}
	} else {
		pis = NULL;
		for (uint_t i = 0; (pi = lldp_propinfo_iter(i)) != NULL; i++) {
			if ((pi->lpi_flags & kind) == 0)
				continue;
			pis = reallocarray(pis, n + 1, sizeof (*pis));
			if (pis == NULL) {
				err(EXIT_FAILURE, gettext("failed to allocate "
				    "memory"));
			}
			pis[n++] = pi;
		}
	}

	*pisp = pis;
	*np = n;
}

/* show-*prop's options */
static void
show_opts(const lldp_cmd_t *cmd, int argc, char **argv,
    lldp_ofmt_opts_t *opts, lsmf_vals_t *names)
{
	int c;

	optind = 1;
	while ((c = getopt(argc, argv, ":co:p:")) != -1) {
		switch (c) {
		case 'c':
			opts->loo_parsable = true;
			break;
		case 'o':
			opts->loo_fields = optarg;
			break;
		case 'p':
			props_list_add(names, optarg);
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}
}

static int
target_cmp(const void *a, const void *b)
{
	return (strcmp(((const target_t *)a)->t_pg,
	    ((const target_t *)b)->t_pg));
}

/*
 * With no operands, show-agentprop shows the defaults and every agent: the
 * physical links, and any link with its own property group (e.g. one that's
 * been removed).
 */
static void
all_targets(target_t **tsp, uint_t *np)
{
	target_t	*ts;
	char		**links, **pgs;
	uint_t		nlinks, npgs, n = 0;

	phys_links(&links, &nlinks);
	if (!lsmf_pgs(LSMF_RUNNING, &pgs, &npgs))
		smf_die(gettext("failed to read properties"));

	if ((ts = calloc(1 + nlinks + npgs, sizeof (target_t))) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));

	for (uint_t i = 0; i < nlinks + npgs; i++) {
		const char	*hw = (i < nlinks) ? links[i] : pgs[i - nlinks];
		bool		dup = false;
		size_t		len = strlen(hw);

		/* Agents' property groups are named for links (end in digit) */
		if (len == 0 || !isdigit((unsigned char)hw[len - 1]) ||
		    len >= sizeof (ts[0].t_pg)) {
			continue;
		}
		for (uint_t j = 0; j < n; j++) {
			if (strcmp(ts[j].t_pg, hw) == 0)
				dup = true;
		}
		if (dup)
			continue;

		(void) strlcpy(ts[n].t_pg, hw, sizeof (ts[n].t_pg));
		link_name(hw, ts[n].t_link, sizeof (ts[n].t_link));
		n++;
	}
	qsort(ts, n, sizeof (target_t), target_cmp);

	/* The defaults come first */
	(void) memmove(&ts[1], &ts[0], n * sizeof (target_t));
	(void) memset(&ts[0], '\0', sizeof (target_t));
	ts[0].t_default = true;
	(void) strlcpy(ts[0].t_pg, LLDP_PG_DEFAULT, sizeof (ts[0].t_pg));
	(void) strlcpy(ts[0].t_link, DEFAULT_TARGET, sizeof (ts[0].t_link));
	n++;

	for (uint_t i = 0; i < nlinks; i++)
		free(links[i]);
	free(links);
	lsmf_names_free(pgs, npgs);

	*tsp = ts;
	*np = n;
}

int
do_show_agentprop(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-agentprop");
	lldp_ofmt_opts_t	opts = { 0 };
	lsmf_vals_t		names = { 0 };
	const lldp_propinfo_t	**pis;
	ofmt_handle_t		ofmt;
	target_t		*ts;
	uint_t			npis, nts;

	show_opts(cmd, argc, argv, &opts, &names);
	show_props(&names, LLDP_PI_AGENT, &pis, &npis);
	ofmt = lldp_ofmt_open(&opts, agentprop_fields, 0);

	smf_open();

	if (optind == argc) {
		all_targets(&ts, &nts);
	} else {
		nts = argc - optind;
		if ((ts = calloc(nts, sizeof (target_t))) == NULL)
			err(EXIT_FAILURE, gettext("failed to allocate memory"));
		for (uint_t i = 0; i < nts; i++) {
			if (!target_get(argv[optind + i], &ts[i]))
				exit(EXIT_FAILURE);
		}
	}

	for (uint_t i = 0; i < nts; i++) {
		for (uint_t j = 0; j < npis; j++) {
			prow_t	r = { 0 };
			src_t	dsrc;

			if ((pis[j]->lpi_flags & LLDP_PI_LINK_ONLY) &&
			    ts[i].t_default) {
				continue;
			}

			r.pr_link = ts[i].t_link;
			r.pr_pi = pis[j];
			agent_value(LSMF_RUNNING, &ts[i], pis[j], false,
			    &r.pr_vals, &r.pr_src);

			/* The default is what it would be, if reset */
			if (ts[i].t_default) {
				builtin_vals(pis[j], &r.pr_def);
				dsrc = SRC_BUILTIN;
			} else {
				agent_value(LSMF_RUNNING, &ts[i], pis[j], true,
				    &r.pr_def, &dsrc);
			}
			r.pr_def_builtin = (dsrc == SRC_BUILTIN);

			ofmt_print(ofmt, &r);
			lsmf_vals_free(&r.pr_vals);
			lsmf_vals_free(&r.pr_def);
		}
	}

	ofmt_close(ofmt);
	free(ts);
	free(pis);
	lsmf_vals_free(&names);
	lsmf_close();
	return (EXIT_SUCCESS);
}

int
do_show_sysprop(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-sysprop");
	lldp_ofmt_opts_t	opts = { 0 };
	lsmf_vals_t		names = { 0 };
	const lldp_propinfo_t	**pis;
	ofmt_handle_t		ofmt;
	uint_t			npis;

	show_opts(cmd, argc, argv, &opts, &names);
	if (optind != argc) {
		warnx(gettext("unexpected argument '%s'"), argv[optind]);
		cmd_usage(cmd);
	}
	show_props(&names, LLDP_PI_SYSTEM, &pis, &npis);
	ofmt = lldp_ofmt_open(&opts, sysprop_fields, 0);

	smf_open();

	for (uint_t j = 0; j < npis; j++) {
		prow_t r = { 0 };

		r.pr_pi = pis[j];
		sys_value(LSMF_RUNNING, pis[j], &r.pr_vals, &r.pr_src);
		builtin_vals(pis[j], &r.pr_def);
		r.pr_def_builtin = true;
		ofmt_print(ofmt, &r);
		lsmf_vals_free(&r.pr_vals);
		lsmf_vals_free(&r.pr_def);
	}

	ofmt_close(ofmt);
	free(pis);
	lsmf_vals_free(&names);
	lsmf_close();
	return (EXIT_SUCCESS);
}
