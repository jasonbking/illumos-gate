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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <gelf.h>
#include <umem.h>
#include <sys/debug.h>

#include "find_elf.h"
#include "str.h"
#include "util.h"

/* Load the find_elf data into memory */

static int
elf_obj_cmp(const void *a, const void *b)
{
	const elf_obj_t *l = a;
	const elf_obj_t *r = b;
	int ret = strcmp(l->eo_relpath, r->eo_relpath);

	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	return (0);
}

static void
elf_obj_free(elf_obj_t *obj)
{
	if (obj == NULL)
		return;

	strfree(obj->eo_relpath);
	for (size_t i = 0; i < obj->eo_nalias; i++)
		strfree(obj->eo_aliases[i]);
	arrayfree(obj->eo_aliases, obj->eo_aliases_sz, sizeof (char *));
	umem_free(obj, sizeof (*obj));
}

static elf_obj_t *
elf_obj_get(elf_objs_t *objs, const char *path, avl_index_t *where)
{
	elf_obj_t cmp = {
		.eo_relpath = (char *)path,
	};

	return (avl_find(&objs->eos_objs, &cmp, where));
}

#define	OBJ_ORDER_CHUNK	64

/*
 * Add an object. On failure, returns false with errno set: EEXIST for a
 * duplicate path, EINVAL for an unrecognized field (a message describing
 * which field has already been printed).
 */
static bool
elf_obj_add(elf_objs_t *objs, const char *cls_str, const char *et_str,
    const char *vd_str, const char *path)
{
	elf_obj_t *obj;
	avl_index_t where;

	if (elf_obj_get(objs, path, &where) != NULL) {
		errno = EEXIST;
		return (false);
	}

	obj = zalloc(sizeof (*obj));

	obj->eo_relpath = xstrdup(path);

	if (strcmp(cls_str, "32") == 0) {
		obj->eo_class = ELFCLASS32;
	} else if (strcmp(cls_str, "64") == 0) {
		obj->eo_class = ELFCLASS64;
	} else {
		(void) fprintf(stderr, "invalid class '%s' for %s\n", cls_str,
		    path);
		elf_obj_free(obj);
		errno = EINVAL;
		return (false);
	}

	if (strcmp(et_str, "REL") == 0) {
		obj->eo_type = ET_REL;
	} else if (strcmp(et_str, "DYN") == 0) {
		obj->eo_type = ET_DYN;
	} else if (strcmp(et_str, "EXEC") == 0) {
		obj->eo_type = ET_EXEC;
	} else {
		(void) fprintf(stderr, "invalid type '%s' for %s\n", et_str,
		    path);
		elf_obj_free(obj);
		errno = EINVAL;
		return (false);
	}

	if (strcmp(vd_str, "VERDEF") == 0) {
		obj->eo_has_verdef = true;
	} else if (strcmp(vd_str, "NOVERDEF") == 0) {
		obj->eo_has_verdef = false;
	} else {
		(void) fprintf(stderr, "invalid version flag '%s' for %s\n",
		    vd_str, path);
		elf_obj_free(obj);
		errno = EINVAL;
		return (false);
	}

	avl_insert(&objs->eos_objs, obj, where);

	/* Remember the order find_elf reported objects in */
	if (objs->eos_n == objs->eos_order_sz) {
		size_t newsz = objs->eos_order_sz + OBJ_ORDER_CHUNK;

		objs->eos_order = xcreallocarray(objs->eos_order,
		    objs->eos_order_sz, newsz, sizeof (elf_obj_t *));
		objs->eos_order_sz = newsz;
	}
	objs->eos_order[objs->eos_n++] = obj;

	return (true);
}

#define	OBJ_ALIAS_CHUNK	8

static bool
add_alias(elf_objs_t *objs, const char *name, const char *alias)
{
	elf_obj_t *obj;

	obj = elf_obj_get(objs, name, NULL);
	if (obj == NULL) {
		errno = ENOENT;
		return (false);
	}

	if (obj->eo_nalias == obj->eo_aliases_sz) {
		size_t newsz = obj->eo_aliases_sz + OBJ_ALIAS_CHUNK;

		obj->eo_aliases = xcreallocarray(obj->eo_aliases,
		    obj->eo_aliases_sz, newsz, sizeof (char *));
		obj->eo_aliases_sz = newsz;
	}

	obj->eo_aliases[obj->eo_nalias++] = xstrdup(alias);
	return (true);
}

/*
 * Return the next whitespace delimited field of *pp (NUL terminating it)
 * and advance *pp past it, or NULL if there are no more fields.
 */
static char *
next_field(char **pp)
{
	char *p = *pp;
	char *start;

	while (isspace((unsigned char)*p))
		p++;
	if (*p == '\0') {
		*pp = p;
		return (NULL);
	}

	start = p;
	while (*p != '\0' && !isspace((unsigned char)*p))
		p++;
	if (*p != '\0')
		*p++ = '\0';

	*pp = p;
	return (start);
}

/*
 * Return the remainder of *pp after any leading whitespace, or NULL if
 * nothing remains. This mirrors the perl version's use of split() with
 * a limit, so the last field may contain whitespace. Trailing whitespace
 * has already been removed by cgetline().
 */
static char *
rest_field(char **pp)
{
	char *p = *pp;

	while (isspace((unsigned char)*p))
		p++;
	*pp = p + strlen(p);

	return ((*p == '\0') ? NULL : p);
}

elf_objs_t *
read_find_elf(FILE *f, const char *filename)
{
	elf_objs_t	*objs;
	custr_t		*cus;
	uint_t		linenum;

	objs = zalloc(sizeof (*objs));

	avl_create(&objs->eos_objs, elf_obj_cmp, sizeof (elf_obj_t),
	    offsetof(elf_obj_t, eo_node));

	objs->eos_name = xstrdup(filename);

	cus = fcustr_alloc();

	linenum = 0;
	while (cgetline(f, cus, &linenum)) {
		char *line, *p, *word;

		line = xstrdup(custr_cstr(cus));
		p = line;

		word = next_field(&p);
		if (word == NULL) {
			strfree(line);
			continue;
		}

		/*
		 * The first entry must be PREFIX, which requires find_elf
		 * to have been run with -r.
		 */
		if (objs->eos_prefix == NULL) {
			char *prefix;

			if (strcmp(word, "PREFIX") != 0) {
				(void) fprintf(stderr, "%s: %s: PREFIX "
				    "expected on line %u\n", getprogname(),
				    filename, linenum);
				strfree(line);
				goto fail;
			}

			prefix = rest_field(&p);
			if (prefix == NULL) {
				(void) fprintf(stderr, "%s: %s: missing PREFIX "
				    "value at line %u\n", getprogname(),
				    filename, linenum);
				strfree(line);
				goto fail;
			}

			objs->eos_prefix = xstrdup(prefix);
			strfree(line);
			continue;
		}

		if (strcmp(word, "PREFIX") == 0) {
			(void) fprintf(stderr, "%s: %s: duplicate "
			    "PREFIX entry at line %u\n", getprogname(),
			    filename, linenum);
			strfree(line);
			goto fail;
		}

		if (strcmp(word, "OBJECT") == 0) {
			char *bits, *type, *verdef, *path;

			bits = next_field(&p);
			type = next_field(&p);
			verdef = next_field(&p);
			path = rest_field(&p);

			if (bits == NULL || type == NULL || verdef == NULL ||
			    path == NULL) {
				(void) fprintf(stderr, "%s: %s: malformed "
				    "OBJECT entry at line %u\n",
				    getprogname(), filename, linenum);
				strfree(line);
				goto fail;
			}

			if (!elf_obj_add(objs, bits, type, verdef, path)) {
				(void) fprintf(stderr, "%s: %s: failed to add "
				    "entry on line %u: %s\n", getprogname(),
				    filename, linenum, strerror(errno));
				strfree(line);
				goto fail;
			}
			strfree(line);
			continue;
		}

		if (strcmp(word, "ALIAS") == 0) {
			char *path = next_field(&p);
			char *alias = rest_field(&p);

			if (path == NULL || alias == NULL) {
				(void) fprintf(stderr, "%s: %s: invalid ALIAS "
				    "entry on line %u\n", getprogname(),
				    filename, linenum);
				strfree(line);
				goto fail;
			}

			if (!add_alias(objs, path, alias)) {
				(void) fprintf(stderr, "%s: %s: failed to add "
				    "ALIAS on line %u: %s\n",
				    getprogname(), filename, linenum,
				    strerror(errno));
				strfree(line);
				goto fail;
			}
			strfree(line);
			continue;
		}

		(void) fprintf(stderr, "%s: WARNING: %s: unrecognized "
		    "entry '%s' on line %u\n", getprogname(), filename, word,
		    linenum);

		strfree(line);
	}

	if (ferror(f)) {
		(void) fprintf(stderr, "%s: error reading %s\n", getprogname(),
		    filename);
		goto fail;
	}

	if (objs->eos_prefix == NULL) {
		(void) fprintf(stderr, "%s: %s: no PREFIX entry (was find_elf "
		    "run with -r?)\n", getprogname(), filename);
		goto fail;
	}

	custr_free(cus);
	return (objs);

fail:
	custr_free(cus);
	elf_objs_free(objs);
	return (NULL);
}

void
elf_objs_free(elf_objs_t *objs)
{
	elf_obj_t	*obj;
	void		*c = NULL;

	if (objs == NULL)
		return;

	strfree(objs->eos_name);
	strfree(objs->eos_prefix);

	while ((obj = avl_destroy_nodes(&objs->eos_objs, &c)) != NULL) {
		elf_obj_free(obj);
	}
	avl_destroy(&objs->eos_objs);

	arrayfree(objs->eos_order, objs->eos_order_sz, sizeof (elf_obj_t *));
	umem_free(objs, sizeof (*objs));
}

const char *
elf_type_str(int t)
{
	switch (t) {
	case ET_REL:
		return ("ET_REL");
	case ET_DYN:
		return ("ET_DYN");
	case ET_EXEC:
		return ("ET_EXEC");
	default:
		return ("UNKNOWN");
	}
}

const char *
elf_class_str(int cls)
{
	switch (cls) {
	case ELFCLASS32:
		return ("ELFCLASS32");
	case ELFCLASS64:
		return ("ELFCLASS64");
	default:
		return ("UNKNOWN");
	}
}
