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
 * lldp(8): display information from the LLDP daemon (lldpd).
 *
 *	lldp [subcommand [args]]
 *
 * With no subcommand, show-neighbors is run.
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <ofmt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ccompile.h>
#include <liblldp.h>

#define	EXIT_USAGE	2

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

typedef struct lldp_cmd {
	const char	*lc_name;
	int		(*lc_func)(int, char **);
	const char	*lc_usage;
} lldp_cmd_t;

static int do_help(int, char **);
static int do_show_neighbors(int, char **);
static int do_show_agent(int, char **);
static int do_stats(int, char **);

static const lldp_cmd_t lldp_cmds[] = {
	{ "help", do_help, "help" },
	{ "show-neighbors", do_show_neighbors,
	    "show-neighbors [[-p] -o field[,...]] [link]" },
	{ "show-agent", do_show_agent, "show-agent [link]" },
	{ "stats", do_stats, "stats [[-p] -o field[,...]] [link ...]" },
};

#define	NCMDS	(sizeof (lldp_cmds) / sizeof (lldp_cmds[0]))

/* Output options common to the subcommands that use libofmt */
typedef struct lldp_ofmt_opts {
	bool		loo_parsable;	/* -p */
	const char	*loo_fields;	/* -o; NULL for the default fields */
} lldp_ofmt_opts_t;

static void
usage(FILE *f)
{
	(void) fprintf(f, gettext("Usage: %s [subcommand [args]]\n\n"),
	    getprogname());
	(void) fprintf(f, gettext("Subcommands (default: %s):\n"),
	    "show-neighbors");
	for (size_t i = 0; i < NCMDS; i++)
		(void) fprintf(f, "\t%s\n", lldp_cmds[i].lc_usage);
}

static void __NORETURN
cmd_usage(const lldp_cmd_t *cmd)
{
	(void) fprintf(stderr, gettext("Usage: %s %s\n"), getprogname(),
	    cmd->lc_usage);
	exit(EXIT_USAGE);
}

static const lldp_cmd_t *
cmd_lookup(const char *name)
{
	for (size_t i = 0; i < NCMDS; i++) {
		if (strcmp(lldp_cmds[i].lc_name, name) == 0)
			return (&lldp_cmds[i]);
	}
	return (NULL);
}

/*
 * Parse the options of a subcommand. If opts is NULL, the subcommand takes
 * no options; otherwise it takes the ofmt options (-p, -o). Returns the
 * index in argv of the first operand.
 */
static int
cmd_opts(const lldp_cmd_t *cmd, int argc, char **argv, lldp_ofmt_opts_t *opts)
{
	const char *optstr = (opts == NULL) ? ":" : ":po:";
	int c;

	optind = 1;
	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'p':
			opts->loo_parsable = true;
			break;
		case 'o':
			opts->loo_fields = optarg;
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

	return (optind);
}

/*
 * For subcommands that take an optional link name. Returns the link name,
 * or NULL for all links.
 */
static const char *
cmd_link_arg(const lldp_cmd_t *cmd, int argc, char **argv,
    lldp_ofmt_opts_t *opts)
{
	int i = cmd_opts(cmd, argc, argv, opts);

	if (argc - i > 1)
		cmd_usage(cmd);

	return ((argc - i == 1) ? argv[i] : NULL);
}

/*
 * Report a failure from liblldp. If link is non-NULL, ENOENT means there's
 * no agent for it.
 */
static void
lldp_warn(int err, const char *link, const char *what)
{
	if (err == ENOENT && link != NULL)
		warnx(gettext("no LLDP agent for link %s"), link);
	else if (err == ECONNREFUSED)
		warnx(gettext("lldpd is not running"));
	else
		warnx(gettext("failed to retrieve %s: %s"), what,
		    strerror(err));
}

/*
 * ofmt_check() reports errors with these. The message is already formatted
 * (and may contain a user supplied field name), so it isn't used as a
 * format string.
 */
static void __NORETURN
ofmt_die(const char *msg, ...)
{
	warnx("%s", msg);
	exit(EXIT_FAILURE);
}

static void
ofmt_warn(const char *msg, ...)
{
	warnx("%s", msg);
}

/*
 * Create the ofmt handle for a subcommand's output. Exits on failure (any
 * failure, in parsable mode). In parsable mode, -o is required.
 */
static ofmt_handle_t
lldp_ofmt_open(const lldp_ofmt_opts_t *opts, const ofmt_field_t *fields,
    uint_t flags)
{
	ofmt_handle_t	ofmt;
	ofmt_status_t	st;

	if (opts->loo_parsable)
		flags |= OFMT_PARSABLE;

	st = ofmt_open(opts->loo_fields, fields, flags, 0, &ofmt);
	ofmt_check(st, opts->loo_parsable ? B_TRUE : B_FALSE, ofmt,
	    ofmt_die, ofmt_warn);
	return (ofmt);
}

static int
do_help(int argc __unused, char **argv __unused)
{
	usage(stdout);
	return (EXIT_SUCCESS);
}

/*
 * The fields of 'lldp show-neighbors'. Field names (like subcommand names)
 * are not translated.
 *
 * TODO: decode the PDUs (chassis id, port id, system name, ...). For now,
 * just list what was received.
 */
typedef enum nbr_field {
	NBR_LINK,
	NBR_TTL,
	NBR_PDU_LEN,
} nbr_field_t;

static boolean_t
nbr_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const lldp_neighbor_t *nb = arg->ofmt_cbarg;

	switch (arg->ofmt_id) {
	case NBR_LINK:
		(void) strlcpy(buf, nb->ln_link, buflen);
		break;
	case NBR_TTL:
		(void) snprintf(buf, buflen, "%u", nb->ln_ttl);
		break;
	case NBR_PDU_LEN:
		(void) snprintf(buf, buflen, "%zu", nb->ln_pdu_len);
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const ofmt_field_t nbr_fields[] = {
	{ "LINK",	17,	NBR_LINK,	nbr_ofmt_cb },
	{ "TTL",	7,	NBR_TTL,	nbr_ofmt_cb },
	{ "PDU-LEN",	8,	NBR_PDU_LEN,	nbr_ofmt_cb },
	{ NULL,		0,	0,		NULL }
};

static int
do_show_neighbors(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-neighbors");
	lldp_ofmt_opts_t	opts = { 0 };
	const char		*link = cmd_link_arg(cmd, argc, argv, &opts);
	ofmt_handle_t		ofmt;
	lldp_neighbor_t		*nbrs = NULL;
	uint_t			n = 0;
	int			ret;

	/* Check the options before talking to lldpd */
	ofmt = lldp_ofmt_open(&opts, nbr_fields, 0);

	ret = lldp_get_neighbors(link, &nbrs, &n);
	if (ret != 0) {
		lldp_warn(ret, link, gettext("neighbors"));
		ofmt_close(ofmt);
		return (EXIT_FAILURE);
	}

	for (uint_t i = 0; i < n; i++)
		ofmt_print(ofmt, &nbrs[i]);

	ofmt_close(ofmt);
	lldp_neighbors_free(nbrs, n);
	return (EXIT_SUCCESS);
}

static int
do_show_agent(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-agent");
	const char		*link __unused =
	    cmd_link_arg(cmd, argc, argv, NULL);

	/* TODO: needs an agent query in liblldp/lldpd */
	warnx(gettext("%s: not yet implemented"), "show-agent");
	return (EXIT_FAILURE);
}

/*
 * The fields of 'lldp stats'. Except for LINK, each field's id is the
 * offset of its counter in lldp_agent_stats_t.
 */
#define	STATS_LINK	UINT_MAX

static boolean_t
stats_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const lldp_stats_t *s = arg->ofmt_cbarg;
	uint64_t v;

	if (arg->ofmt_id == STATS_LINK) {
		(void) strlcpy(buf, s->ls_link, buflen);
		return (B_TRUE);
	}

	if (arg->ofmt_id > sizeof (s->ls_stats) - sizeof (v))
		return (B_FALSE);

	(void) memcpy(&v, (const char *)&s->ls_stats + arg->ofmt_id,
	    sizeof (v));
	(void) snprintf(buf, buflen, "%" PRIu64, v);
	return (B_TRUE);
}

#define	STATS_FIELD(name, width, field)	\
	{ name, width, offsetof(lldp_agent_stats_t, field), stats_ofmt_cb }

/*
 * With OFMT_RIGHTJUST, a column is its width plus a separating space. A
 * value that doesn't fit borrows space from the columns that follow.
 */
static const ofmt_field_t stats_fields[] = {
	{ "LINK", 10, STATS_LINK, stats_ofmt_cb },
	STATS_FIELD("RX",	9,	las_in_frames),
	STATS_FIELD("RXERR",	6,	las_in_errors),
	STATS_FIELD("RXDISC",	7,	las_discarded),
	STATS_FIELD("TLVDISC",	8,	las_discarded_tlvs),
	STATS_FIELD("TLVUNK",	7,	las_unknown_tlvs),
	STATS_FIELD("AGEOUT",	7,	las_ageouts),
	STATS_FIELD("REMDROP",	8,	las_rem_drops),
	STATS_FIELD("TX",	9,	las_out_frames),
	STATS_FIELD("TXLENERR",	9,	las_length_errs),
	{ NULL, 0, 0, NULL }
};

static int
do_stats(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("stats");
	lldp_ofmt_opts_t	opts = { 0 };
	int			i = cmd_opts(cmd, argc, argv, &opts);
	ofmt_handle_t		ofmt;
	lldp_stats_t		*s;
	uint_t			sn;
	int			status = EXIT_SUCCESS;
	int			ret;

	ofmt = lldp_ofmt_open(&opts, stats_fields, OFMT_RIGHTJUST);

	if (i == argc) {
		/* No links: every agent */
		ret = lldp_get_stats(NULL, &s, &sn);
		if (ret != 0) {
			lldp_warn(ret, NULL, gettext("statistics"));
			ofmt_close(ofmt);
			return (EXIT_FAILURE);
		}

		for (uint_t j = 0; j < sn; j++)
			ofmt_print(ofmt, &s[j]);
		lldp_stats_free(s, sn);
	}

	for (; i < argc; i++) {
		ret = lldp_get_stats(argv[i], &s, &sn);
		if (ret == ENOENT) {
			/* Show what we can, but note the failure */
			lldp_warn(ret, argv[i], NULL);
			status = EXIT_FAILURE;
			continue;
		}
		if (ret != 0) {
			lldp_warn(ret, argv[i], gettext("statistics"));
			ofmt_close(ofmt);
			return (EXIT_FAILURE);
		}

		for (uint_t j = 0; j < sn; j++)
			ofmt_print(ofmt, &s[j]);
		lldp_stats_free(s, sn);
	}

	ofmt_close(ofmt);
	return (status);
}

int
main(int argc, char **argv)
{
	static char		*default_argv[] = { "show-neighbors", NULL };
	const lldp_cmd_t	*cmd;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* No subcommand: show-neighbors */
	if (argc < 2) {
		argc = 1;
		argv = default_argv;
	} else {
		argc--;
		argv++;
	}

	cmd = cmd_lookup(argv[0]);
	if (cmd == NULL) {
		warnx(gettext("unknown subcommand '%s'"), argv[0]);
		usage(stderr);
		return (EXIT_USAGE);
	}

	/* Each subcommand sees its own name as argv[0] */
	return (cmd->lc_func(argc, argv));
}
