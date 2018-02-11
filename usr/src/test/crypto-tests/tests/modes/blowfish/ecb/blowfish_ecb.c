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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>

#ifdef PKCS11
#include <security/cryptoki.h>
#include <sys/debug.h>
#include <blowfish/blowfish_impl.h>
#endif

#include "cryptotest.h"
#include "blowfish_ecb.h"

#ifdef PKCS11

/*
 * PKCS#11 currently does not define CKM_BLOWFISH_ECB, however we
 * can emulate it by using CKM_BLOWFISH_CBC with a 0 IV and only
 * encrypting a single block.
 */

#ifdef SUN_CKM_BLOWFISH_ECB
#undef SUN_CKM_BLOWFISH_ECB
#define	SUN_CKM_BLOWFISH_ECB "CKM_BLOWFISH_CBC"
#endif

static uint8_t IV[8] = { 0 };

static size_t
ecb_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen, test_fg_t *funcs)
{
	size_t i, total = 0;
	size_t n = cmplen / BLOWFISH_BLOCK_LEN;

	VERIFY0(cmplen % BLOWFISH_BLOCK_LEN);

	args->param = IV;
	args->plen = sizeof (IV);

	for (i = 0; i < n; i++) {
		total += run_test(args, &cmp[i * BLOWFISH_BLOCK_LEN],
		    BLOWFISH_BLOCK_LEN, funcs);
	}

	return (total);
}
#else
static size_t
ecb_test(cryptotest_t *args, uint8_t *cmp, size_t cmplen, test_fg_t *funcs)
{
	return (run_test(args, cmp, cmplen, funcs));
}
#endif

int
main(void)
{
	int errs = 0;
	int i;
#ifdef PKCS11
	int k;
#endif
	uint8_t N[1024];
	cryptotest_t args;

	args.out = N;
	args.param = NULL;

	args.outlen = sizeof (N);
	args.plen = 0;

	args.mechname = SUN_CKM_BLOWFISH_ECB;
	args.updatelen = 1;

	for (i = 0; i < sizeof (RES) / sizeof (RES[0]); i++) {
		args.in = DATA[i];
		args.inlen = DATALEN[i];
		args.key = KEY[i];
		args.keylen = KEYLEN[i];
		errs += ecb_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	for (i = 0; i < sizeof (RES) / sizeof (RES[0]); i++) {
		args.key = KEY[i];
		args.in = RES[i];
		args.keylen = KEYLEN[i];
		args.inlen = RESLEN[i];
		errs += ecb_test(&args, DATA[i], DATALEN[i], DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}
	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
