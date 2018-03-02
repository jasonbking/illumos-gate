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

#ifndef _ECC_H
#define	_ECC_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecc_test {
	const char	*testname;

	uint8_t		*oid;

	uint8_t		*a_priv;
	uint8_t		*a_pub_x;
	uint8_t		*a_pub_y;

	uint8_t		*b_priv;
	uint8_t		*b_pub_x;
	uint8_t		*b_pub_y;

			/* ECDH only uses the x coordinate */
	uint8_t		*secret_x;

	size_t		oidlen;
	size_t		len;
} ecc_test_t;

extern ecc_test_t ecc_tests[];
extern const size_t ecc_ntests;

#ifdef __cplusplus
}
#endif

#endif /* _DH_H */
