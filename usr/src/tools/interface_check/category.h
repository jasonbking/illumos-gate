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

#ifndef _CATEGORY_H
#define	_CATEGORY_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum category_type {
	CT_UNKNOWN,
	CT_NUMBERED,
	CT_PLAIN,
	CT_SONAME,
	CT_PRIVATE,
} category_type_t;

typedef struct category {
	category_type_t	c_type;

	/* These are only used with CT_NUMBERED */
	uint_t		c_num;
	uint_t		c_ver[3];
} category_t;

void category_init(void);
void parse_category(const char *, const char *, category_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CATEGORY_H */
