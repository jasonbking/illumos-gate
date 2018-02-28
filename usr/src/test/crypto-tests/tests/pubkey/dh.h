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
 * Copyright 2018, Joyent, Inc.
 */

#ifndef _DH_H
#define	_DH_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dh_test {
	const char	*testname;

	uint8_t		*prime;
	uint8_t		*generator;

	uint8_t		*a_priv;
	uint8_t		*a_pub;
	uint8_t		*b_priv;
	uint8_t		*b_pub;
	uint8_t		*secret;

	size_t		primelen;
	size_t		genlen;
	size_t		privlen;
	size_t		publen;		/* Also secret len */
} dh_test_t;

extern dh_test_t dh_tests[];
extern const size_t dh_ntests;

#ifdef __cplusplus
}
#endif

#endif /* _DH_H */
