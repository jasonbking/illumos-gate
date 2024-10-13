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

#ifndef _IFCHK_FIND_ELF_H
#define	_IFCHK_FIND_ELF_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/avl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct elf_objs {
	char		*eos_name;
	char		*eos_prefix;
	avl_tree_t	eos_objs;
} elf_objs_t;

typedef struct elf_obj {
	avl_node_t	eo_node;
	char		*eo_relpath;
	char		**eo_aliases;
	size_t		eo_nalias;
	size_t		eo_aliases_sz;
	int		eo_class;
	uint16_t	eo_type;
	bool		eo_has_verdef;
} elf_obj_t;

elf_objs_t *read_find_elf(FILE *, const char *);
void elf_objs_free(elf_objs_t *);

const char *elf_type_str(int);
const char *elf_class_str(int);

#ifdef __cplusplus
}
#endif

#endif /* _IFCHK_FIND_ELF_H */
