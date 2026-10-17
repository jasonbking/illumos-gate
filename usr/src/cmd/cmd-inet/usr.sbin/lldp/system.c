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
 * lldp show-system [-v | [-p] -o field[,...]]
 *
 * Shows what lldpd advertises for the system as a whole (on every link):
 * the Chassis ID (and where it came from), System Name, System Description,
 * and System Capabilities, along with a count of agents and neighbors.
 *
 *	(default)	"label: value" lines, as for show-agent -v (-v asks for
 *			this explicitly).
 *	-o		One line (via libofmt), with the given fields.
 */

#include <err.h>
#include <errno.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <liblldp.h>

#include "lldp.h"

/* Large enough for any string lldpd sends, escaped (4 bytes per byte) */
#define	SYS_STRBUF_LEN	(4 * 512 + 1)

/* Escape (as for strings from neighbors) a string from lldpd */
static void
sys_str(const char *s, char *buf, size_t buflen, uint_t flags)
{
	lldp_str_t ls = {
		.ls_data = (const uint8_t *)s,
		.ls_len = strlen(s),
	};

	(void) lldp_str_print(&ls, buf, buflen, flags);
}

typedef enum sys_field {
	SF_CHASSIS,
	SF_CHASSIS_TYPE,
	SF_CHASSIS_SRC,
	SF_CHASSIS_ID_TYPE,
	SF_SYSNAME,
	SF_SYSDESC,
	SF_SYSCAPS,
	SF_ENABLED_CAPS,
	SF_AGENTS,
	SF_ACTIVE,
	SF_NBRS,
	SF_CHANGED,
} sys_field_t;

static boolean_t
sys_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const lldp_system_info_t	*si = arg->ofmt_cbarg;
	char				t[LLDP_TYPESTR_LEN];

	buf[0] = '\0';

	switch (arg->ofmt_id) {
	case SF_CHASSIS:
		(void) lldp_chassis_str(&si->lsi_chassis, buf, buflen);
		break;
	case SF_CHASSIS_TYPE:
		(void) strlcpy(buf, lldp_chassis_typestr(
		    si->lsi_chassis.llc_type, t, sizeof (t)), buflen);
		break;
	case SF_CHASSIS_SRC:
		(void) strlcpy(buf, lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE,
		    si->lsi_chassis_src), buflen);
		break;
	case SF_CHASSIS_ID_TYPE:
		(void) strlcpy(buf, lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE,
		    si->lsi_chassis_type), buflen);
		break;
	case SF_SYSNAME:
		sys_str(si->lsi_sysname, buf, buflen, 0);
		break;
	case SF_SYSDESC:
		sys_str(si->lsi_sysdesc, buf, buflen, 0);
		break;
	case SF_SYSCAPS:
		(void) lldp_caps_str(si->lsi_syscap, buf, buflen);
		break;
	case SF_ENABLED_CAPS:
		(void) lldp_caps_str(si->lsi_encap, buf, buflen);
		break;
	case SF_AGENTS:
		(void) snprintf(buf, buflen, "%u", si->lsi_agents);
		break;
	case SF_ACTIVE:
		(void) snprintf(buf, buflen, "%u", si->lsi_active);
		break;
	case SF_NBRS:
		(void) snprintf(buf, buflen, "%u", si->lsi_neighbors);
		break;
	case SF_CHANGED:
		if (si->lsi_change_age != LLDP_NO_CHANGE) {
			(void) snprintf(buf, buflen, "%u",
			    si->lsi_change_age);
		}
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const ofmt_field_t sys_fields[] = {
	{ "CHASSIS",		38,	SF_CHASSIS,		sys_ofmt_cb },
	{ "CHASSIS-TYPE",	13,	SF_CHASSIS_TYPE,	sys_ofmt_cb },
	{ "CHASSIS-SRC",	12,	SF_CHASSIS_SRC,		sys_ofmt_cb },
	{ "CHASSIS-ID-TYPE",	16,	SF_CHASSIS_ID_TYPE,	sys_ofmt_cb },
	{ "SYSNAME",		24,	SF_SYSNAME,		sys_ofmt_cb },
	{ "SYSDESC",		32,	SF_SYSDESC,		sys_ofmt_cb },
	{ "SYSCAPS",		20,	SF_SYSCAPS,		sys_ofmt_cb },
	{ "ENABLED-CAPS",	20,	SF_ENABLED_CAPS,	sys_ofmt_cb },
	{ "AGENTS",		7,	SF_AGENTS,		sys_ofmt_cb },
	{ "ACTIVE",		7,	SF_ACTIVE,		sys_ofmt_cb },
	{ "NBRS",		6,	SF_NBRS,		sys_ofmt_cb },
	{ "CHANGED",		8,	SF_CHANGED,		sys_ofmt_cb },
	{ NULL,			0,	0,			NULL }
};

static void
sys_print(const lldp_system_info_t *si)
{
	char	buf[SYS_STRBUF_LEN], s[SYS_STRBUF_LEN], en[256];
	char	t[LLDP_TYPESTR_LEN];
	const char *src = lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE,
	    si->lsi_chassis_src);
	const char *want = lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE,
	    si->lsi_chassis_type);

	(void) lldp_chassis_str(&si->lsi_chassis, s, sizeof (s));
	(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
	    lldp_chassis_typedesc(si->lsi_chassis.llc_type, t, sizeof (t)));
	vline(0, gettext("Chassis ID"), buf);

	/*
	 * Where it came from, and if that isn't what chassis_id_type asked
	 * for, why: "uuid (auto)", or "hostid (topo is unavailable)".
	 */
	if (si->lsi_chassis_type == LLDP_CHASSIS_ID_SRC_AUTO) {
		(void) snprintf(buf, sizeof (buf), gettext("%s (auto)"), src);
	} else if (si->lsi_chassis_type != si->lsi_chassis_src) {
		(void) snprintf(buf, sizeof (buf),
		    gettext("%s (%s is unavailable)"), src, want);
	} else {
		(void) strlcpy(buf, src, sizeof (buf));
	}
	vline(0, gettext("Chassis ID source"), buf);

	sys_str(si->lsi_sysname, buf, sizeof (buf), 0);
	vline(0, gettext("System name"), buf);

	sys_str(si->lsi_sysdesc, buf, sizeof (buf), LLDP_STR_MULTILINE);
	vline(0, gettext("System description"), buf);

	(void) lldp_caps_str(si->lsi_syscap, s, sizeof (s));
	(void) lldp_caps_str(si->lsi_encap, en, sizeof (en));
	(void) snprintf(buf, sizeof (buf), gettext("%s (enabled: %s)"), s, en);
	vline(0, gettext("Capabilities"), buf);

	(void) snprintf(buf, sizeof (buf), gettext("%u (%u active)"),
	    si->lsi_agents, si->lsi_active);
	vline(0, gettext("Agents"), buf);

	(void) snprintf(buf, sizeof (buf), "%u", si->lsi_neighbors);
	vline(0, gettext("Neighbors"), buf);

	age_str(si->lsi_change_age, buf, sizeof (buf));
	vline(0, gettext("Last change"), buf);
}

int
do_show_system(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-system");
	lldp_ofmt_opts_t	opts = { 0 };
	lldp_system_info_t	si;
	ofmt_handle_t		ofmt = NULL;
	bool			verbose = false;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":po:v")) != -1) {
		switch (c) {
		case 'v':
			verbose = true;
			break;
		case 'p':
			opts.loo_parsable = true;
			break;
		case 'o':
			opts.loo_fields = optarg;
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

	if (verbose && (opts.loo_parsable || opts.loo_fields != NULL)) {
		warnx(gettext("-v can't be used with -p or -o"));
		cmd_usage(cmd);
	}

	if (argc - optind > 0) {
		warnx(gettext("unexpected argument '%s'"), argv[optind]);
		cmd_usage(cmd);
	}

	/* Check the options before talking to lldpd */
	if (opts.loo_parsable || opts.loo_fields != NULL)
		ofmt = lldp_ofmt_open(&opts, sys_fields, 0);
	else
		vline_init();

	if ((ret = lldp_get_system(&si)) != 0) {
		lldp_warn(ret, NULL, gettext("system information"));
		if (ofmt != NULL)
			ofmt_close(ofmt);
		return (EXIT_FAILURE);
	}

	if (ofmt != NULL) {
		ofmt_print(ofmt, &si);
		ofmt_close(ofmt);
	} else {
		sys_print(&si);
	}

	return (EXIT_SUCCESS);
}
