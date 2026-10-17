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
 * Copyright 2024 Jason King
 */

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <libcustr.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <umem.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "exceptions.h"
#include "str.h"
#include "util.h"

/*
 * Read in the exceptions file. Each entry is of the form
 *    VERB REGEX
 *
 * where VERB is matched case-insensitively and REGEX is the remainder of
 * the line (after the whitespace following VERB). Regular expressions are
 * POSIX extended regular expressions.
 *
 * We compile the file into an array of regexes for each VERB that can
 * be tested in succession. The original perl script would instead join
 * every regex for a given verb into one (very) large regex using the |
 * operator. We elected to not carry over this behavior as then we can
 * compile each entry individually and report any errors on the line where
 * they occur.
 */

/*
 * What we append when expanding MACH(x) -- result is 'x(/amd64|/sparcv9)?'
 */
static const char *mach_exp = "(/amd64|/sparcv9)?";

exception_t *
get_exception(exceptions_t *exs, const char *verb)
{
	exception_t *e;

	if (exs == NULL)
		return (NULL);

	e = exs->es_exceptions;
	for (uint_t i = 0; i < exs->es_n; i++, e++) {
		if (strcasecmp(e->e_verb, verb) == 0)
			return (e);
	}
	return (NULL);
}

bool
is_exception(const char *path, const char *verb, exceptions_t *exs)
{
	exception_t	*e = get_exception(exs, verb);
	regex_t		*re;

	if (e == NULL)
		return (false);

	re = e->e_regexes;
	for (uint_t i = 0; i < e->e_n; i++, re++) {
		if (regexec(re, path, 0, NULL, 0) == 0)
			return (true);
	}

	return (false);
}

#define	EX_CHUNK 4
static char *
add_exception(exceptions_t *exs, const char *verb, const char *re)
{
	exception_t	*e = NULL;
	regex_t		*rep = NULL;
	int		ret;

	e = get_exception(exs, verb);
	if (e == NULL) {
		if (exs->es_n == exs->es_size) {
			size_t newsz = exs->es_n + EX_CHUNK;

			exs->es_exceptions = xcreallocarray(exs->es_exceptions,
			    exs->es_n, newsz, sizeof (exception_t));
			exs->es_size = newsz;
		}

		e = &exs->es_exceptions[exs->es_n++];
		e->e_verb = xstrdup(verb);
		e->e_patterns = xcalloc(EX_CHUNK, sizeof (char *));
		e->e_regexes = xcalloc(EX_CHUNK, sizeof (regex_t));
		e->e_n = 0;
		e->e_sz = EX_CHUNK;
	}

	if (e->e_n == e->e_sz) {
		size_t newsz = e->e_sz + EX_CHUNK;

		e->e_patterns = xcreallocarray(e->e_patterns, e->e_sz, newsz,
		    sizeof (char *));
		e->e_regexes = xcreallocarray(e->e_regexes, e->e_sz, newsz,
		    sizeof (regex_t));
		e->e_sz = newsz;
	}

	rep = &e->e_regexes[e->e_n];
	ret = regcomp(rep, re, REG_EXTENDED | REG_NOSUB);
	if (ret == 0) {
		/* Only count the entry once it has successfully compiled */
		e->e_patterns[e->e_n++] = xstrdup(re);
		return (NULL);
	}

	char *emsg = NULL;
	size_t emsg_len = regerror(ret, rep, NULL, 0) + 1;

	emsg = zalloc(emsg_len);
	(void) regerror(ret, rep, emsg, emsg_len);
	return (emsg);
}

/*
 * Create the regex string from the exception regex. This will expand the
 * first MACH(xxx) macro (as the perl version did).
 */
#define	MACH_STR "MACH("

static void
create_regex_str(const char *s, custr_t *cus)
{
	const char *mp, *mpend;

	custr_reset(cus);

	mp = strstr(s, MACH_STR);
	if (mp == NULL) {
		/* Simple case, just copy everything and return */
		fcustr_append(cus, s);
		return;
	}

	/*
	 * Find the closing parenthesis. The perl version required at least
	 * one character between the parenthesis, otherwise it treated the
	 * text as a literal. We do the same.
	 */
	mpend = strchr(mp + sizeof (MACH_STR) - 1, ')');
	if (mpend == NULL || mpend == mp + sizeof (MACH_STR) - 1) {
		fcustr_append(cus, s);
		return;
	}

	/* Copy up to the 'M' */
	while (s < mp)
		fcustr_appendc(cus, *s++);

	/* Copy the contents inside the () */
	s += sizeof (MACH_STR) - 1;
	while (s < mpend)
		fcustr_appendc(cus, *s++);

	/* Add (/amd64|/sparcv9) */
	fcustr_append(cus, mach_exp);

	/* Copy remainder of the string */
	s = mpend + 1;
	if (*s != '\0')
		fcustr_append(cus, s);
}

static bool
is_file(const char *path)
{
	struct stat sb;

	return (stat(path, &sb) == 0 && S_ISREG(sb.st_mode));
}

/*
 * Locate the exception file for the given tool, in the same order as the
 * perl implementation:
 *
 *  1. $CODEMGR_WS/exception_lists/<name> in an activated workspace
 *  2. <bindir>/../etc/exception_lists/<name>, relative to the installed
 *     onbld tool. execdir is the (absolute) directory containing this
 *     binary, which lives in bin/$(MACH), so this is
 *     <execdir>/../../etc/exception_lists/<name>.
 *
 * Returns NULL if no exception file was found, which is not an error.
 */
char *
find_exception_file(const char *execdir, const char *name)
{
	const char	*ws = getenv("CODEMGR_WS");
	char		*out = NULL;

	if (ws != NULL) {
		if (asprintf(&out, "%s/exception_lists/%s", ws, name) < 0)
			nomem_callback();

		if (is_file(out))
			return (out);

		free(out);
		out = NULL;
	}

	if (execdir == NULL)
		return (NULL);

	if (asprintf(&out, "%s/../../etc/exception_lists/%s", execdir,
	    name) < 0) {
		nomem_callback();
	}

	if (is_file(out))
		return (out);

	free(out);
	return (NULL);
}

/*
 * Split the line into the verb and the regex (the rest of the line).
 * Modifies line in place. Returns false if either is missing.
 */
static bool
split_entry(char *line, char **verbp, char **rep)
{
	char *p = line;

	while (isspace((unsigned char)*p))
		p++;
	if (*p == '\0')
		return (false);

	*verbp = p;
	while (*p != '\0' && !isspace((unsigned char)*p))
		p++;
	if (*p == '\0')
		return (false);
	*p++ = '\0';

	while (isspace((unsigned char)*p))
		p++;
	if (*p == '\0')
		return (false);

	*rep = p;
	return (true);
}

exceptions_t *
load_exceptions(FILE *f, const char *filename)
{
	exceptions_t	*exs = NULL;
	custr_t		*line = NULL;
	custr_t		*regex_str = NULL;
	char		*re_err = NULL;
	uint_t		linenum;

	exs = zalloc(sizeof (*exs));
	line = fcustr_alloc();
	regex_str = fcustr_alloc();

	linenum = 0;
	while (cgetline(f, line, &linenum)) {
		char *copy, *verb, *re;

		copy = xstrdup(custr_cstr(line));

		if (!split_entry(copy, &verb, &re)) {
			(void) fprintf(stderr, "%s: %s invalid exception entry "
			    "at line %u\n", getprogname(), filename, linenum);
			strfree(copy);
			exceptions_free(exs);
			exs = NULL;
			goto done;
		}

		create_regex_str(re, regex_str);
		re_err = add_exception(exs, verb, custr_cstr(regex_str));
		if (re_err != NULL) {
			(void) fprintf(stderr, "%s: %s failed to compile "
			    "regex '%s' at line %u: %s\n",
			    getprogname(), filename, re, linenum, re_err);
			strfree(re_err);
			strfree(copy);
			exceptions_free(exs);
			exs = NULL;
			goto done;
		}

		strfree(copy);
	}

	if (ferror(f)) {
		(void) fprintf(stderr, "%s: error reading %s\n", getprogname(),
		    filename);
		exceptions_free(exs);
		exs = NULL;
	}

done:
	custr_free(line);
	custr_free(regex_str);
	return (exs);
}

void
exceptions_free(exceptions_t *exs)
{
	if (exs == NULL)
		return;

	for (uint_t i = 0; i < exs->es_n; i++) {
		exception_t *e = &exs->es_exceptions[i];

		strfree(e->e_verb);

		for (uint_t j = 0; j < e->e_n; j++) {
			regfree(&e->e_regexes[j]);
			strfree(e->e_patterns[j]);
		}

		arrayfree(e->e_regexes, e->e_sz, sizeof (regex_t));
		arrayfree(e->e_patterns, e->e_sz, sizeof (char *));
	}
	arrayfree(exs->es_exceptions, exs->es_size, sizeof (exception_t));
	umem_free(exs, sizeof (*exs));
}
