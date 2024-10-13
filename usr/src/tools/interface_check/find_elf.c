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

	return (strcmp(l->eo_relpath, r->eo_relpath));
}

static void
elf_obj_free(elf_obj_t *obj)
{
	if (obj == NULL)
		return;

	strfree(obj->eo_relpath);
	if (obj->eo_aliases_sz > 0) {
		for (uint_t i = 0; obj->eo_aliases[i] != NULL; i++) {
			strfree(obj->eo_aliases[i]);
		}
		arrayfree(obj->eo_aliases, obj->eo_aliases_sz, sizeof (char *));
	}
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

static bool
elf_obj_add(elf_objs_t *objs, const char *cls_str, const char *et_str,
    const char *vd_str, const char *path)
{
	elf_obj_t *obj;
	avl_index_t where;

	if (elf_obj_get(objs, path, &where) != NULL) {
		errno = EEXIST;
		return (NULL);
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
		return (false);
	}

	avl_insert(&objs->eos_objs, obj, where);
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

	if (obj->eo_aliases == NULL) {
		VERIFY0(obj->eo_aliases_sz);
		obj->eo_aliases = xcalloc(OBJ_ALIAS_CHUNK, sizeof (char *));
		obj->eo_aliases_sz = OBJ_ALIAS_CHUNK;
	}

	if (obj->eo_nalias + 2 >= obj->eo_aliases_sz) {
		size_t newsz;

		newsz = obj->eo_aliases_sz + OBJ_ALIAS_CHUNK;
		obj->eo_aliases = xcreallocarray(obj->eo_aliases,
		    obj->eo_aliases_sz, newsz, sizeof (char *));

		obj->eo_aliases_sz = newsz;
	}

	obj->eo_aliases[obj->eo_nalias] = xstrdup(alias);
	obj->eo_nalias++;

	/*
	 * We should always be NULL terminated by virtue of calloc+reallocarray,
	 * but out of an abundance of caution, we'll explicitly terminate the
	 * list.
	 */
	obj->eo_aliases[obj->eo_nalias] = NULL;

	return (true);
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
		char *line, *word;

		line = xstrdup(custr_cstr(cus));

		word = strtok(line, " \t\n");
		if (word == NULL) {
			strfree(line);
			continue;
		}

		if (strcmp(word, "PREFIX") == 0) {
			word = strtok(NULL, " \t\n");
			if (word == NULL) {
				(void) fprintf(stderr, "%s: %s missing PREFIX "
				    "value at line %u\n", getprogname(),
				     filename, linenum);
				strfree(line);
				goto fail;
			}

			if (objs->eos_prefix != NULL) {
				(void) fprintf(stderr, "%s: %s duplicate "
				    "PREFIX entry at line %u\n", getprogname(),
				    filename, linenum);
				strfree(line);
				goto fail;
			}

			objs->eos_prefix = xstrdup(word);
			strfree(line);
			continue;
		}

		if (strcmp(word, "OBJECT") == 0) {
			char *bits, *type, *verdef, *path;

			if (objs->eos_prefix == NULL) {
				(void) fprintf(stderr, "%s: %s PREFIX line is"
				    "not first entry\n", getprogname(),
				    filename);
				strfree(line);
				goto fail;
			}

			bits = strtok(NULL, " \t\n");
			type = strtok(NULL, " \t\n");
			verdef = strtok(NULL, " \t\n");
			path = strtok(NULL, " \t\n");

			if (bits == NULL || type == NULL || verdef == NULL ||
			    path == NULL) {
				(void) fprintf(stderr, "%s: %s: misformed "
				    "OBJECT entry at line %u\n",
				    getprogname(), filename, linenum);
				strfree(line);
				goto fail;
			}

			if (!elf_obj_add(objs, bits, type, verdef, path)) {
				(void) fprintf(stderr, "%s: %s failed to add "
				    "entry on line %u: %s\n", getprogname(),
				    filename, linenum, strerror(errno));
				strfree(line);
				goto fail;
			}
			strfree(line);
			continue;
		}

		if (strcmp(word, "ALIAS") == 0) {
			char *path = strtok(NULL, " \t\n");
			char *alias = strtok(NULL, " \t\n");

			if (path == NULL || alias == NULL) {
				(void) fprintf(stderr, "%s: %s invalid ALIAS "
				    "entry on line %u\n", getprogname(),
				    filename, linenum);
				strfree(line);
				goto fail;
			}

			if (!add_alias(objs, path, alias)) {
				(void) fprintf(stderr, "%s: %s failed to add "
				    "ALIAS on line %u: %s\n",
				    getprogname(), filename, linenum,
				    strerror(errno));
				strfree(line);
				goto fail;
			}
			strfree(line);
			continue;
		}

		if (strlen(line) > 0) {
			(void) fprintf(stderr, "%s: WARNING: unrecognized "
			    "entry '%s' on line %u\n", getprogname(), word,
			    linenum);
		}

		strfree(line);
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
