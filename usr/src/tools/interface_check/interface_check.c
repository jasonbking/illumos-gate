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
 * Copyright 2022 Jason King
 */

#include <err.h>
#include <regex.h>
#include <stdboolh>
#include <stdio.h>
#include <stdlib.h>

typedef enum category_type {
	CT_NUMBERED,
	CT_PLAIN,
	CT_SONAME,
	CT_PRIVATE,
	CT_UNKNOWN,
} category_type_t;

typedef struct category {
	category_type_t	c_type;
	/* These are only used with CT_NUMBERED */
	uint_t		c_num;
	uint_t		c_ver[5];
} category_t;

typedef struct exception {
	char	*e_verb;
	regex_t	*e_regexes;
	uint_t	e_n;
	uint_t	e_sz;
} exception_t;

typedef struct exceptions {
	exception_t	*es_exceptions;
	uint_t		es_n;
	uint_t		es_size;
} exceptions_t;

static void parse_category(const char *, const char *, category_t *);
static void load_exceptions(const char *, exceptions_t *);
static void print_header(FILE *);

static void init_re(void);
static void *xcalloc(size_t, size_t);
static void xregcomp(regex_t *, const char *, int);

static const char *mach_restr = "MACH\(([^)]+)\)";
static const char *cat_version_restr =
    "^((?:SUNW|ILLUMOS)_)(\d+)\.(\d+)(\.(\d+))?";
static const char *cat_plain_restr[] = {
    "^SYSVABI_1.[23]$", "^SISCD_2.3[ab]*$"
};
static const char *cat_private_restr = "^(SUNW|ILLUMOS)private(_[0-9.]+)?$";

static regex_t mach_re;
static regex_t cat_version_re;
static regex_t cat_plain_re[2];
static regex_t cat_private_re;

static exceptions_t exceptions;
static bool do_header;
static FILE *errf = stdout;
static FILE *intf;

static void __NORETURN
usage(const char *name)
{
	(void) fprintf(stderr,
	    "Usage: %s [-hIo] [-c vtype_mod] [-E errfile] [-e exfile]\n",
	    "\t\t[-f listfile] [-i intffile] [-w outdir] file | dir, ...\n"
	    "\n"
	    "\t[-c vtype_mod]\tsupply alternative version category module\n"
	    "\t[-E errfile]\tdirect error output to file\n"
	    "\t[-e exfile]\texceptions file\n"
	    "\t[-f listfile]\tuse file list produced by find_elf -r\n"
	    "\t[-h]\t\tdo not produce a CDDL/Copyright header comment\n"
	    "\t[-I]\t\tExpand inheritance in -i output (debugging)\n"
	    "\t[-i intffile]\tcreate interface description output file\n"
	    "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n"
	    "\t[-w outdir]\tinterpret all files relative to given directory\n",
	    name);

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	const char *intfile = NULL;
	const char *errfile = NULL;
	int c;

	while ((c = getopt(argc, argv, "c:E:e:f:hIi:ow:")) != -1) {
		switch (c) {
		case 'c':
		case 'E':
			errfile = optarg;
			break;
		case 'e':
		case 'f':
		case 'h':
			do_header = true;
			break;
		case 'I':
		case 'i':
			intfile = optarg;
			break;
		case 'o':
		case 'w':
			break;
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n", optopt);
			usage(argv[0]);
		}
	}

	init_re();

	intfile = fopen(optarg, "w");
	if (intfile == NULL)
		err(EXIT_FAILURE, "Unable to open %s", optarg);

	if (do_header)
		print_header(intfile);

	return (EXIT_SUCCESS);
}


static char *
get_exception_name(const char *name)
{
	char *out = NULL;

	if (name != NULL) {
		out = strdup(name);
		if (out == NULL)
			err(EXIT_FAILURE, "strdup failed");
		return (out);
	}

	const char *cws = getenv("CODEMGR_WS");
	struct stat sb;
	int ret;

	if (cws != NULL) {
		ret = asprintf(&out, "%s/exception_lists/%s", cws, name);
		if (ret < 0)
			err(EXIT_FAILURE, "asprintf failed");

		if (stat(out, &sb) == 0 && S_ISREG(sb.st_mode))
			return (out);

		free(out);
		out = NULL;
	}

	ret = asprintf(&out, "../etc/exception_lists/%s", name);
	if (ret < 0)
		err(EXIT_FAILURE, "asprintf failed");

	if (stat(out, &sb) == 0 && S_ISREG(sb.st_mode))
		return (out);

	free(out);
	return (NULL);
}

#define	EXCEPTION_CHUNK 4

static exception_t *
get_exception(exceptions_t *es, const char *verb, bool create)
{
	for (uint_t i = 0; i < es->es_n; i++) {
		if (strcmp(verb, es->es_exceptions[i].e_verb) == 0)
			return (&es->es_exceptions[i]);
	}

	if (!create)
		return (NULL);

	if (es->es_n == es->es_size) {
		exceptions_t *new_e;
		size_t newamt = es->es_size + EXCEPTION_CHUNK;

		new_e = calloc(newamt, sizeof (exception_t));
		if (new_e == NULL)
			err(EXIT_FAILURE, "failed to grow exceptions array");

		(void) memcpy(new_e, es->es_exceptions,
		    es->es_n * sizeof (exception_t));

		es->es_size = newamt;
		free(es->es_exceptions);
		es->es_exceptions = new_e;
	}

	exception_t *e = &es->es_exceptions[es->es_n++];

	e->e_verb = strdup(verb);
	if (e->e_verb == NULL)
		err(EXIT_FALURE, "failed to allocate verb");

	return (e);
}

static void
add_ex_regex(exception_t *e, const char *re_str)
{
	regex_t *re;
	int ret;

	if (e->e_n == e->e_sz) {
		regex_t *new_e;
		size_t newamt = e->e_sz + EXCEPTION_CHUNK;

		new_e = xcalloc(newamt, sizeof (regex_t));
		(void) memcpy(new_e, e->e_regexes, (e->e_n * sizeof (regex_t)));
		free(e->e_regexes);

		e->e_sz = newamt;
		e->e_regexes = new_e;
	}

	re = &e->regexes[e->e_n++];
	xregcomp(re, re_str, REG_EXTENDED);
}

static void
load_exceptions(const char *name, exceptions_t *es)
{
	FILE *f = NULL;
	char *tryname = NULL;
	char *line = NULL;
	size_t linesz = 0;
	ssize_t n;
	int ret;

	ret = regcomp(&mach_re, mach_restr, REG_EXTENDED);
	if (ret != 0) {
		char errbuf[256] = { 0 };

		(void) regerror(ret, &mach_re, errbuf, sizeof (errbuf));
		errx(EXIT_FAILURE, "regcomp(%s) failed: %s", mach_re, errbuf);
	}

	tryname = get_exception_name(name);
	if (tryname == NULL)
		return;

	f = fopen(tryname, "r");
	if (f == NULL)
		err(EXIT_FAILURE, "unable to open exceptions file %s", tryname);

	while ((n = getline(&line, &linesz, f)) > 0) {
		char *p = line;

		/* Skip leading whitespace (if any) */
		while (*p != '\0' && isspace(*p))
			p++;

		/* Skip empty lines */
		if (*p == '\0')
			continue;

		/* Skip comments */
		if (*p == '#')
			continue;

		if (line[n - 1] == '\n')
			line[n - 1] = '\0';

		char *verb = p;
		char *re = NULL;

		verb = strtok(p, " \n\t");
		if (verb == NULL)
			continue;

		re = strtok(p, NULL);
		if (re == NULL)
			continue;

		if (strtok(p, NULL) != NULL)
			continue;

		/* XXX: Expand MACH() */

		exception_t *e = get_exception(es, verb, true);

		add_ex_regex(e, re);
	}

	VERIFY0(fclose(f));
	free(tryname);
	free(line);
}

static void
print_header(FILE *out)
{
}

static void
parse_category(const char *vstr, const char *soname, category_t *c)
{
	regmatch_t pmatch[5] = { 0 };
	int ret;

	(void) memset(c, '\0', sizeof (*c));
	if (regexec(&cat_version_re, vstr, 5, pmatch, 0) == 0) {
		c->c_type = CT_NUMBERED;
		/* TODO */
	}

	if (regexec(&cat_plain_re, vstr, 0, NULL, 0) == 0) {
		c->c_type = CT_PLAIN;
		return;
	}

	if (soname != NULL && strcmp(vstr, soname) == 0) {
		c->c_type = CT_SONAME;
		return;
	}

	if (regexec(&cat_private_re, vstr, 0, NULL, 0) == 0) {
		c->c_type = CT_PRIVATE;
		return;
	}

	c->c_type = CT_UNKNOWN;
}


static void
init_re(void)
{
	xregcomp(&mach_re, mach_restr, REG_EXTENDED);
	xregcomp(&cat_version_re, cat_version_restr, REG_EXTENDED);
	xregcomp(&cat_plain_re[0], cat_plain_restr[0], REG_EXTENDED);
	xregcomp(&cat_plain_re[1], cat_plain_restr[1], REG_EXTENDED);
	xregcomp(&cat_private_re, cat_private_restr, REG_EXTENDED);
}

static void
xregcomp(regex_t *restrict preg, const char *restrict pat, int cflags)
{
	int ret;

	ret = regcomp(preg, pat, cflags);
	if (ret == 0)
		return;

	size_t errlen = regerror(ret, preg, NULL, 0):
	char *errbuf = xcalloc(1, errbuf + 1);

	(void) regerror(ret, preg, errbuf, errlen);
	errx(EXIT_FAILURE, "failed to compile regex '%s': %s", pat, errbuf);
}

static void *
xcalloc(size_t n, size_t sz)
{
	void *p = calloc(n, sz);

	if (p != NULL)
		return (p);

	(void) fprintf(stderr, "Out of memory\n");
	abort();
}
