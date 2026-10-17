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
 * Output helpers shared by the lldp(8) subcommands.
 */

#include <libintl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/termios.h>
#include <libdladm.h>
#include <libdllink.h>
#include <liblldp.h>

#include "lldp.h"

/* For -v: the terminal width to wrap at (0 means don't wrap) */
static int wrap_width;

/*
 * The datalink name of an agent's link, given its hardware name (which is
 * what lldpd reports). If the link hasn't been renamed, they're the same.
 */
void
link_name(const char *hwname, char *buf, size_t buflen)
{
	static dladm_handle_t	dlh;
	static bool		tried;
	datalink_id_t		linkid;
	char			name[MAXLINKNAMELEN];

	(void) strlcpy(buf, hwname, buflen);

	if (!tried) {
		tried = true;
		if (dladm_open(&dlh) != DLADM_STATUS_OK)
			dlh = NULL;
	}
	if (dlh == NULL)
		return;

	if (dladm_dev2linkid(dlh, hwname, &linkid) == DLADM_STATUS_OK &&
	    dladm_datalink_id2info(dlh, linkid, NULL, NULL, NULL, name,
	    sizeof (name)) == DLADM_STATUS_OK) {
		(void) strlcpy(buf, name, buflen);
	}
}

/*
 * Wrap -v output to the terminal's width (if stdout is a terminal).
 */
void
vline_init(void)
{
	struct winsize ws;

	if (isatty(STDOUT_FILENO) &&
	    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
		wrap_width = ws.ws_col;
	}
}

/*
 * A line of -v output (of every subcommand that has one): a label and a
 * value, with the value aligned at VALUE_COL. Values may span lines (e.g. a
 * multi-line system description), and are wrapped (at spaces, where
 * possible) to the terminal's width.
 */
void
vline(int indent, const char *label, const char *value)
{
	const char	*p = value;
	int		col;

	if (label != NULL) {
		col = printf("%*s%s:", indent, "", label);
	} else {
		col = 0;
	}

	do {
		size_t len = strcspn(p, "\n");
		size_t avail = (wrap_width > VALUE_COL + 20) ?
		    (size_t)(wrap_width - VALUE_COL) : SIZE_MAX;

		/*
		 * Wrap long lines, at a space or after a comma (for lists)
		 * if there's one.
		 */
		while (len > avail) {
			size_t brk = avail;

			while (brk > avail / 2 && p[brk] != ' ' &&
			    p[brk - 1] != ',')
				brk--;
			if (p[brk] != ' ' && p[brk - 1] != ',')
				brk = avail;

			(void) printf("%*s%.*s\n", MAX(VALUE_COL - col, 1), "",
			    (int)brk, p);
			col = 0;
			p += brk;
			len -= brk;
			while (*p == ' ' && len > 0) {
				p++;
				len--;
			}
		}

		(void) printf("%*s%.*s\n", MAX(VALUE_COL - col, 1), "",
		    (int)len, p);
		col = 0;
		p += len;
	} while (*p++ == '\n' && *p != '\0');
}

void
vsection(int indent, const char *label)
{
	(void) printf("%*s%s:\n", indent, "", label);
}

/*
 * How long ago something happened, given its age in seconds: "never" (for
 * LLDP_NO_CHANGE), "45s ago", "3m12s ago", "2h05m ago", or "6d04h ago".
 */
void
age_str(uint32_t age, char *buf, size_t buflen)
{
	if (age == LLDP_NO_CHANGE) {
		(void) strlcpy(buf, gettext("never"), buflen);
	} else if (age < 60) {
		(void) snprintf(buf, buflen, gettext("%us ago"), age);
	} else if (age < 3600) {
		(void) snprintf(buf, buflen, gettext("%um%02us ago"),
		    age / 60, age % 60);
	} else if (age < 86400) {
		(void) snprintf(buf, buflen, gettext("%uh%02um ago"),
		    age / 3600, (age % 3600) / 60);
	} else {
		(void) snprintf(buf, buflen, gettext("%ud%02uh ago"),
		    age / 86400, (age % 86400) / 3600);
	}
}
