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

#include <ctype.h>
#include <err.h>
#include <gelf.h>
#include <libcustr.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/debug.h>
#include <sys/linker_set.h>

typedef struct re_init {
	const char	*re_str;
	regex_t		*re_ptr;
} re_init_t;
SET_DECLARE(re_init_set, re_init_t);

#define	DECL_RE(_name, _str)			\
	static regex_t	re_##_name;		\
	static re_init_t re_init_##_name = {	\
		.re_str = _str,			\
		.re_ptr = &re_##_name,		\
	};					\
	DATA_SET(re_init_set, re_init_##_name)

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
	uint_t		c_ver[3];
} category_t;

typedef struct obj {
	char		*obj_relpath;
	char		**obj_aliases;
	size_t		obj_aliasalloc;
	int		obj_class;
	uint16_t	obj_type;
	bool		obj_hasverdef;
} obj_t;

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

typedef struct file {
	const char	*f_name;
	FILE		*f_f;
	uint_t		f_linenum;
	custr_t		*f_cus;
	char		*f_line;
} file_t;

static void parse_category(const char *, const char *, category_t *);
static void load_exceptions(const char *, exceptions_t *);
static void print_header(FILE *);

static int each_line(const char *, FILE *f,
    int (*)(char *, const bookmark_t *, void *), void *);
static void init_re(void);
static void *xcalloc(size_t, size_t);
static void *zalloc(size_t);
static void errout(const char *, ...);

/* BEGIN CSTYLED */
DECL_RE(mach, "MACH\(([^))]+)\)");
DECL_RE(cat_version, "^((?:SUNW|ILLUMOS)_)([:digit:]+)\.([:digit]+)(\.([:digit]+))?");
DECL_RE(cat_plain_1, "^SYSVAPI_1.[23]$");
DECL_RE(cat_plain_2, "^SISCD_2.3[ab]*$");
DECL_RE(cat_private, "^(SUNW_ILLUMOS)private(_[0-9.]+)?$");
/* END CSTYLED */

static exceptions_t exceptions;
static bool do_header;
static const char *errfname = "(stdout)";
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

static in
load_exceptions_cb(const char *line, const bookmark_t *bk, void *arg)
{
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
process_object(int dirfd, obj_t *obj)
{
	if (obj->obj_type != ET_DYN)
		return;
}

struct find_elf_arg {
	const char	*fea_filename;
	char		*fea_prefix;
	int		fea_dirfd;
	obj_t		*fea_obj;
	bool		fea_skip;
};

static int
load_find_elf(const char *name, int fd)
{
	file_t f = { 0 };
	char *line = NULL;
	char *word = NULL;
	int pfxfd = -1;
	obj_t obj = { 0 };
	bool skip = false;

	file_open(name, fd, &f);
	line = file_getline(&f);
	if (line == NULL)
		errx(EXIT_FAILURE, "%s: file is empty", name);

	word = strtok(line, " \t");
	if (strcmp(word, "PREFIX") != 0)
		f_fatal(&f, "PREFIX is not first");

	word = strtok(NULL, " \t");
	if (word == NULL)
		f_fatal(&f, "PREFIX line missing path");

	pfxfd = open(word, O_RDONLY|O_DIRECTORY);
	if (pfxfd < 0)
		err(EXIT_FAILURE, "%s", word);

	while ((line = file_getline(&f)) != NULL) {
		word = strtok(line, " \t");

		if (strcmp(word, "OBJECT") == 0) {
			char *bits, *type, *verdef, *path;

			/*
			 * Only interested in shareable objects. The -f
			 * option may give us more than just shareable
			 * objects as input.
			 */
			if (!skip || obj.obj_type != ET_DYN)
				process_obj(pfxfd, &obj);
			obj_reset(&obj);

			bits = strtok(NULL, " \t");
			type = strtok(NULL, " \t");
			verdef = strtok(NULL, " \t");
			path = strtok(NULL, " \t");

			if (bits == NULL || type == NULL || verdef == NULL ||
			    path == NULL) {
				f_warn(&f, "OBJECT line is misformed");
			}

			skip = false;
			if (!obj_init(&obj, bits, type, verdef, path)) {
				skip = true;
				f_warn(&f, "OBJECT line is misformed");
			}
			continue;
		}

		if (strcmp(word, "ALIAS") == 0) {
			char *objname, *alias;

			if (obj.obj_relpath == NULL) {
				f_warn(&f, "ALIAS line without OBJECT line");
				continue;
			}

			objname = strtok(NULL, " \t");
			alias = strtok(NULL, " \t");

			if (
		}

	}
	file_close(&f);
	VERIFY0(close(pfxdx));
}

static int
find_elf_cb(char *line, const bookmark_t *bk, void *arg)
{
	struct find_elf_arg *fea = arg;
	char *word;

	word = strtok(line, " \t");

	if (strcmp(word, "PREFIX") == 0) {
		if (fea->fea_prefix != NULL)
			in_fatal(bk, "duplicate 'PREFIX' keyword");

		word = strtok(NULL, " \t");
			in_fatal(bk, "missing argument to PREFIX");

		fea->fea_prefix = xstrdup(word);
		fea->fea_dirfd = open(fea->fea_prefix, O_RDONLY|O_DIRECTORY);
		if (fea->fea_dirfd < 0)
			err(EXIT_FAILURE, "%s", fea->fea_prefix);
		return (0);
	}

	if (strcmp(word, "OBJECT") == 0) {
		if (fea->fea_prefix == NULL)
			in_fatal(bk, "PREFIX line is not first");

		char *bits, *type, *verdef, *path;

		bits = strtok(NULL, " \t");
		type = strtok(NULL, " \t");
		verdef = strtok(NULL, " \t");
		path = strtok(NULL, " \t");

		if (bits == NULL || type == NULL || verdef == NULL ||
		    path == NULL) {
			in_fatal(bk, "misformed OBJECT line");
		}

		if (fea->fea_obj.obj_relpath != NULL) {
			if (!fea->fea_skip)
				process_obj(&fea->fea_obj);
			obj_reset(&fea->fea_obj);
			fea->fea_skip = false;
		}

		if (!obj_init(&fea->fea_obj, bits, type, verdef, path))
			fea->fea_skip = true;
		return (0);
	}

	if (strcmp(word, "ALIAS") == 0) {
		if (fea->fea_filename == NULL) {
			errx(EXIT_FAILURE, "%s:%zu: PREFIX line is not first",
			    fea->fea_filename, linenum);
		}

		if (fea->fea_obj == NULL) {
			errx(EXIT_FAILURE, "%s:%zu: ALIAS line preceeds OBJECT",
			    feq->fea_filename, linenum);
		}

		char *name = strtok(NULL, " \t");
		char *alias = strtok(NULL, " \t");

		if (name == NULL || alias == NULL) {
			errx(EXIT_FAILURE, "%s:%zu: invalid ALIAS line",
			    fea->fea_filename, linenum);
		}

		add_alias(fea->fea_obj, alias);
		return (0);
	}

	(void) fprintf(stderr, "%s:%zu unrecognized line\n", fea->fea_filename,
	    linenum);
	return (0);
}

static void
process_find_elf(FILE *f, const char *filename)
{
	struct find_elf_arg fea = {
		.fea_filename = filename,
	};

	(void) each_line(filename, f, find_elf_cb, &fea);

	if (fea->fea_obj.obj_path != NULL)
		process_obj(&fea->fea_obj);

	obj_reset(&fea->fea_obj);
	if (close(fea->fea_dirfd) < 0)
		err(EXIT_FAILURE, "%s", fea->fea_prefix);
	free(fea->fea_prefix);
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

static bool 
obj_init(obj_t *obj, char *cstr, char *tstr, char *vstr, char *pstr)
{
	obj->obj_relpath = strdup(pstr);
	if (obj->obj_relpath == NULL)
		err(EXIT_FAILURE, "failed to duplicate string");

	if (strcmp(cstr, "32") == 0) {
		obj->obj_class = ELFCLASS32;
	else if (strcmp(cstr, "64") == 0) {
		obj->obj_class = ELFCLASS64;
	} else {
		fprintf(stderr, "invalid class '%s' for %s\n", cstr, pstr);
		return (false);
	}

	if (strcmp(tstr, "REL") == 0) {
		obj->obj_type = ET_REL;
	} else if (strcmp(str, "DYN") == 0) {
		obj->obj_type = ET_DYN;
	} else if (strcmp(str, "EXEC") == 0) {
		obj->obj_type = ET_EXEC;
	} else {
		fprintf(stderr, "invalid type '%s' for %s\n", tstr, pstr);
		return (false);
	}

	if (strcmp(vstr, "VERDEF") == 0) {
		obj->obj_hasverdef = true;
	} else if (strcmp(vstr, "NOVERDEF") == 0) {
		obj->obj_hasverdef = false;
	} else {
		fprintf(stderr, "invalid version flag '%s' for %s\n", vstr,
		    pstr);
		return (false);
	}

	return (true);
}

static void
obj_reset(obj_t *obj)
{
	free(obj->obj_relpath);
	if (obj->obj_aliases != NULL) {
		for (uint_t i = 0; obj->obj_aliases[i] != NULL; i++)
			free(obj->obj_aliases[i]);
		free(obj->obj_aliases);
	}
	(void) memset(obj, '\0', sizeof (*obj));
}

static void
add_alias(obj_t *obj, const char *alias)
{
	uint_t n = 0;

	if (obj->obj_aliases == NULL) {
		obj->obj_aliases = xcalloc(4, sizeof (char *));
		obj->obj_aliasalloc = 4;
	} else {
		for (n = 0; obj->obj_aliases[n] != NULL; n++)
			;

		if (n + 2 >= obj->obj_aliasalloc) {
			size_t nalloc = obj->obj_aliasalloc + 4;
			char **temp = xcalloc(nalloc, sizeof (char *));

			(void) memcpy(temp, obj->obj_aliases,
			    n * sizeof (char *));

			free(obj->obj_aliases);
			obj->obj_aliases = temp;
			obj->obj_aliasalloc = nalloc;
		}
	}

	obj->obj_aliases[n] = strdup(alias);
	if (obj->obj_aliases[n] == NULL)
		err(EXIT_FAILURE, "failed to duplicate string");
}

static void
init_re(void)
{
	re_init_t **rei;
	int ret;

	SET_FOREACH(rei, re_init_set) {
		ret = regcomp(rei->re_ptr, rei->re_str, REG_EXTENDED);
		if (ret != 0) {
			char *errbuf;
			size_t errlen;

			errlen = regerror(ret, rei->re_ptr, NULL, 0);
			errbuf = xcalloc(1, errlen + 1);

			(void) regerror(ret, rei->re_ptr, errbuf, errlen);
			errx(EXIT_FAILURE, "failed to compile regex '%s': %s",
			    rei->re_str, errbuf);
		} 
	}
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

static void *
zalloc(size_t sz)
{
	return (xcalloc(1, sz));
}

static void
errout(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vfprintf(errf, fmt, ap);
	va_end(ap);

	if (n < 0)
		err(EXIT_FAILURE, "%s", errfname);
}

#define	LINE_CHUNK 128
static void
add_char(int c, size_t n, char **restrict buf, size_t *restrict lenp)
{
	if (n + 2 >= *lenp) {
		size_t templen = roundup(*lenp + LINE_CHUNK, LINE_CHUNK);
		char *temp = zalloc(templen);

		(void) memcpy(temp, *buf, n);
		free(*buf);
		*buf = temp;
		*lenp = templen;
	}
	*buf[n] = c;
	*buf[n + 1] = '\0';
}

static int
each_line(const char *filename, FILE *f, int (*cb)(char *, size_t, void *),
    void *arg)
{
	char *buf = NULL;
	size_t buflen = 0;
	size_t n = 0;
	size_t linenum = 0;
	int c, ret;

	while ((c = fgetc(f)) != -1) {
		if (c != '#' && c != '\n') {
			add_char(c, n++, &buf, &buflen);
			continue;
		}

		/* A continuation line */
		if (c == '\n' && n > 0 && buf[n - 1] == '\\') {
			add_char(c, n++, &buf, &buflen);
			linenum++;
			continue;
		}

		/*
		 * Either end of line or start of a comment.
		 * Since comments go to the end of the line, they
		 * effectively terminate a line -- we'll just skip
		 * over them.
		 */
		char *p = buf;

		/* Skip over leading whitespace */
		while (*p != '\0' && isspace(*p))
			p++;

		if (*p == '\0') {
			/* Blank line, reset and go to the next line */
			n = 0;
			buf[0] = '\0';
			continue;
		}

		ret = cb(p, ++linenum, arg);
		if (ret != 0) {
			free(buf);
			return (ret);
		}

		/*
		 * Line terminated by a comment, skip over the rest of the
		 * line
		 */
		if (c == '#') {
			while ((c = fgetc(f)) != -1 && c != '\n')
				;
		}
	}

	if (ferror(f))
		err(EXIT_FAILURE, "%s", filename);

	return (0);
}

static void
file_open(const char *name, int fd, file_t *fp)
{
	FILE *f;
	custr_t *cus;

	f = fdopen(fd, "r");
	if (f == NULL)
		err(EXIT_FAILURE, "%s", name);

	if (custr_alloc(&cus) != 0)
		err(EXIT_FAILURE, "custr_alloc failed");

	fp->f_name = name;
	fp->f_f = f;
	fp->f_cus = cus;
	fp->f_linenum = 0;
	fp->f_line = NULL;
}

static void
file_close(file_t *fp)
{
	VERIFY0(fclose(fp->f_f));
	custr_free(fp->f_cus);
	free(fp->f_line);
}

static char *
file_getline(file_t *fp)
{
	const char *p = NULL;
	int c, prevc;

	prevc = -1;
	while ((c = fgetc(fp->f_f)) != -1) {
		if (c == '\\') {
			prevc = c;
			continue;
		}

		if (c != '#' && c != '\n') {
			if (prevc == '\\' &&
			    custr_appendc(fp->f_cus, prevc) != 0) {
				err(EXIT_FAILURE, "custr_appendc failed");
			}
			if (custr_appendc(fp->f_cus, c) != 0) {
				err(EXIT_FAILURE, "custr_appendc failed");
			}
			prevc = c;
			continue;
		}

		/* A continuation line, just keep appending */
		if (c == '\n' && prevc == '\\') {
			fp->f_linenum++;
			prevc = c;
			continue;
		}

		ASSERT(c == '\n' || c == '#');

		p = custr_cstr(fp->f_cus);

		/* Skip leading whitespace */
		while (*p != '\0' && isspace(*p))
			p++;

		/* Empty line, reset and continue */
		if (*p == '\0') {
			custr_reset(fp->f_cus);
			prevc = c;
			continue;
		}

		break;
	}

	if (fp->f_line != NULL) {
		free(fp->f_line);
		fp->f_line = NULL;
	}

	if (c == -1 && custr_len(f->f_cus) == 0)
		return (NULL);

	fp->f_line = strdup(p);
	if (fp->f_line == NULL)
		err(EXIT_FAILURE, "strdup failed");

	custr_reset(fp->f_cus);
	return (fp->f_line);
}

static const char *
file_name(const file_t *fp)
{
	return (fp->f_name);
}

static uint_t
file_line(const file_t *fp)
{
	return (fp->f_linenum);
}

static void
in_fatal(const bookmark_t *bk, const char *fmt, ...)
{
	va_arg ap;

	va_start(ap, fmt);
	flockfile(stderr);
	(void) fprintf(stderr, "%s:%u: ", bk->bk_name, bk->bk_linenum);
	(void) vfprintf(stderr, fmt, ap);
	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fputc('\n', stderr);
	funlockfile(stderr);

	exit(EXIT_FAILURE);
}
