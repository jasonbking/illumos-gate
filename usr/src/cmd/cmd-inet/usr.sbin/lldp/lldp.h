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

#ifndef _LLDP_H
#define	_LLDP_H

/*
 * Definitions shared by the lldp(8) subcommands.
 */

#include <stdbool.h>
#include <stddef.h>
#include <ofmt.h>
#include <sys/ccompile.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EXIT_USAGE	2

typedef struct lldp_cmd {
	const char	*lc_name;
	int		(*lc_func)(int, char **);
	const char	*lc_usage;
} lldp_cmd_t;

/* Output options common to the subcommands that use libofmt */
typedef struct lldp_ofmt_opts {
	bool		loo_parsable;	/* -p */
	const char	*loo_fields;	/* -o; NULL for the default fields */
} lldp_ofmt_opts_t;

const lldp_cmd_t *cmd_lookup(const char *);
void cmd_usage(const lldp_cmd_t *) __NORETURN;
void lldp_warn(int, const char *, const char *);
ofmt_handle_t lldp_ofmt_open(const lldp_ofmt_opts_t *, const ofmt_field_t *,
    uint_t);

/*
 * -v output: "label: value" lines, with the values aligned at VALUE_COL.
 * Top-level lines are indented by TOP_INDENT, those within a section (see
 * vsection()) by SUB_INDENT. A NULL label continues the previous line's
 * value.
 */
#define	VALUE_COL	27
#define	TOP_INDENT	4
#define	SUB_INDENT	8

void vline_init(void);
void vline(int, const char *, const char *);
void vsection(int, const char *);

void link_name(const char *, char *, size_t);

int do_show_neighbors(int, char **);
int do_show_agent(int, char **);
int do_show_system(int, char **);

#ifdef __cplusplus
}
#endif

#endif /* _LLDP_H */
