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
#include <libintl.h>
#include <locale.h>
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

static const lldp_cmd_t lldp_cmds[] = {
	{ "help", do_help, "help" },
	{ "show-neighbors", do_show_neighbors, "show-neighbors [link]" },
	{ "show-agent", do_show_agent, "show-agent [link]" },
};

#define	NCMDS	(sizeof (lldp_cmds) / sizeof (lldp_cmds[0]))

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
 * Common argument handling for subcommands that take no options and an
 * optional link name. Returns the link name, or NULL for all links.
 */
static const char *
cmd_link_arg(const lldp_cmd_t *cmd, int argc, char **argv)
{
	int c;

	optind = 1;
	while ((c = getopt(argc, argv, ":")) != -1) {
		switch (c) {
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		cmd_usage(cmd);

	return ((argc == 1) ? argv[0] : NULL);
}

static int
do_help(int argc __unused, char **argv __unused)
{
	usage(stdout);
	return (EXIT_SUCCESS);
}

static int
do_show_neighbors(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-neighbors");
	const char		*link = cmd_link_arg(cmd, argc, argv);
	lldp_neighbor_t		*nbrs = NULL;
	uint_t			n = 0;
	int			ret;

	ret = lldp_get_neighbors(link, &nbrs, &n);
	if (ret != 0) {
		if (ret == ENOENT && link != NULL)
			warnx(gettext("no LLDP agent for link %s"), link);
		else
			warnx(gettext("failed to retrieve neighbors: %s"),
			    strerror(ret));
		return (EXIT_FAILURE);
	}

	/*
	 * TODO: decode the PDUs (chassis id, port id, system name, ...).
	 * For now, just list what was received. Column names (like
	 * subcommand names) are not translated.
	 */
	(void) printf("%-16s %6s %8s\n", "LINK", "TTL", "PDU-LEN");
	for (uint_t i = 0; i < n; i++) {
		(void) printf("%-16s %6u %8zu\n", nbrs[i].ln_link,
		    nbrs[i].ln_ttl, nbrs[i].ln_pdu_len);
	}

	lldp_neighbors_free(nbrs, n);
	return (EXIT_SUCCESS);
}

static int
do_show_agent(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-agent");
	const char		*link __unused = cmd_link_arg(cmd, argc, argv);

	/* TODO: needs an agent query in liblldp/lldpd */
	warnx(gettext("%s: not yet implemented"), "show-agent");
	return (EXIT_FAILURE);
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
