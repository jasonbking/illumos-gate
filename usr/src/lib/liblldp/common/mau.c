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
 * Copyright 2023 Jason King
 */

#include <synch.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ctype.h>	/* want C locale ISSPACE() */
#include "liblldp.h"

#define	LLDP_MAU_FILENAME	"/usr/share/lldpdata/mau.txt"

typedef struct lldp_mau {
	const char	*lm_name;
	const char	*lm_desc;
} lldp_mau_t;


static mutex_t		lldp_mau_lock = ERRORCHECKMUTEX;
static bool		lldp_mau_loaded;
static size_t		lldp_mau_num;
static size_t		lldp_mau_alloc;
static lldp_mau_t	*lldp_maus;

static void
skip_whitespace(char **pp)
{
	char *p = *pp;

	while (*p != '\0' && ISSPACE(*p))
		p++;

	*pp = p;
}

static char *
get_tok(char **linep)
{
	char *p = *linep;
	bool in_quote = false;

	skip_whitespace(&p);

	if (*p == '\0')
		return (NULL);

	
}

static void
parse_line(char *line)
{
	char *num = NULL;
	char *name = NULL;
	char *desc = NULL;

	if (!ISDIGIT(*line))
		return;

	/* Get the numeric value in 'num' */
	num = line;
	while (*line != '\0' && ISDIGIT(*line))
		line++;
	if (*line == '\0')
		return;
	*line++ = '\0';

	skip_whitespace(&line);

}

static void
load_maus(void)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t n;

	mutex_enter(&lldp_mau_lock);
	if (lldp_mau_loaded) {
		mutex_exit(&lldp_mau_lock);
		return;
	}

	f = fopen(LLDP_MAU_FILENAME, "rF");
	if (f == NULL)
		goto done;

	while ((n = getline(&line, &len, f)) > 0) {
		char *p = line;

		skip_whitespace(&p);

		/* Skip empty lines */
		if (*p == '\0')
			continue;

		/* Skip comment lines */
		if (*p == '#')
			continue;

		parse_line(p);
	}

	(void) fclose(f);

done:
	/*
	 * We only try to load the MAU data once, if that fails, we
	 * just won't return any data.
	 */
	lldp_mau_loaded = true;
	mutex_exit(&lldp_mau_lock);
}

const char *
lldp_mau_name(uint16_t id)
{
	load_maus();

	if (id > lldp_mau_num || lldp_maus[id].lm_name == NULL)
		return (NULL);

	return (lldp_maus[id].lm_name);
}

const char *
lldp_mau_desc(uint16_t id)
{
	load_maus();

	if (id > lldp_mau_num || lldp_maus[id].lm_desc == NULL)
		return (NULL);

	return (lldp_maus[id].lm_desc);
}
