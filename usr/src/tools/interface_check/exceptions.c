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

#include <fcntl.h>
#include <regex.h>
#include <libcustr.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
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
	exception_t *e = exs->es_exceptions;

	for (uint_t i = 0; i < exs->es_n; i++, e++) {
		if (strcmp(e->e_verb, verb) == 0)
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

	e->e_patterns[e->e_n] = xstrdup(re);
	rep = &e->e_regexes[e->e_n++];

	ret = regcomp(rep, re, REG_EXTENDED);
	if (ret == 0)
		return (NULL);

	char *emsg = NULL;
	size_t emsg_len = regerror(ret, rep, NULL, 0) + 1;

	emsg = zalloc(emsg_len);
	(void) regerror(ret, rep, emsg, emsg_len);
	return (emsg);
}

/*
 * Create the regex string from the exception regex. This will expand the
 * MACH(xxx) macro as appropriate.
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

	/* Find the closing parenthesis */
	mpend = strchr(mp + 1, ')');
	if (mpend == NULL) {
		/*
		 * The original perl script didn't error on this and treats
		 * it as a literal instead. We do the same.
		 */
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

char *
find_exception_file(int dirfd, const char *name)
{
	const char	*ws = getenv("CODEMGR_WS");
	char		*out = NULL;
	struct stat	sb = { 0 };

	if (ws != NULL) {
		if (asprintf(&out, "%s/exception_lists/%s", ws, name) < 0)
			return (NULL);

		if (fstatat(dirfd, out, &sb, 0) == 0 && S_ISREG(sb.st_mode))
			return (out);

		free(out);
		out = NULL;
	}

	if (asprintf(&out, "../etc/exception_lists/%s", name) < 0)
		return (NULL);

	if (fstatat(dirfd, out, &sb, 0) == 0 && S_ISREG(sb.st_mode))
		return (out);

	free(out);
	return (NULL);
}


exceptions_t *
load_exceptions(FILE *f, const char *filename)
{
	exceptions_t	*exs = NULL;
	custr_t		*line = NULL;
	custr_t		*regex_str = NULL;
	char		*re_err = NULL;
	uint_t		linenum;

	exs = zalloc(sizeof *exs);
	line = fcustr_alloc();
	regex_str = fcustr_alloc();

	linenum = 0;
	while (cgetline(f, line, &linenum)) {
		char *copy, *verb, *re;

		copy = xstrdup(custr_cstr(line));

		verb = strtok(copy, " \t\n");
		re = strtok(NULL, " \t\n");
		if (verb == NULL || re == NULL) {
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
			exceptions_free(exs);
			exs = NULL;
			goto done;
		}
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

		for (uint_t j = 0; j < e->e_n; j++)
			regfree(&e->e_regexes[j]);

		arrayfree(e->e_regexes, e->e_sz, sizeof (regex_t));
	}
	arrayfree(exs->es_exceptions, exs->es_size, sizeof (exception_t));
	umem_free(exs, sizeof (*exs));
}
