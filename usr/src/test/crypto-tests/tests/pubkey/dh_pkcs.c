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

#include <cryptoutil.h>
#include <err.h>
#include <security/cryptoki.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "dh.h"

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#endif

extern const char *__progname;

static void
key_to_obj(CK_SESSION_HANDLE h, const uint8_t *prime, size_t primelen,
    const uint8_t *base, size_t baselen,
    const uint8_t *raw, size_t rawlen, CK_OBJECT_HANDLE_PTR obj)
{
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_DH;
	CK_BBOOL trueval = CK_TRUE;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof (key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		{ CKA_PRIME, (void *)prime, primelen },
		{ CKA_BASE, (void *)base, baselen },
		{ CKA_VALUE, (void *)raw, rawlen },
		{ CKA_DERIVE, &trueval, sizeof (trueval) },
	};
	CK_RV rv = C_CreateObject(h, template, ARRAY_SIZE(template), obj);

	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "\nC_CreateObject failed: %s (%lu)\n",
		    pkcs11_strerror(rv), rv);
	}
}

static void
obj_to_key(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE obj, uint8_t **raw,
    size_t *len)
{
	CK_RV rv = pkcs11_ObjectToKey(h, obj, (void **)raw, len, B_TRUE);

	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "\npkcs11_ObjectToKey failed: %s (%lu)\n",
		    pkcs11_strerror(rv), rv);
	}
}

static void
derive(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE priv, uint8_t *pub, size_t publen,
    CK_OBJECT_HANDLE_PTR hp)
{
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_BBOOL trueval = CK_TRUE;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof (key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		{ CKA_ENCRYPT, &trueval, sizeof (trueval) },
		{ CKA_DECRYPT, &trueval, sizeof (trueval) }
	};
	CK_MECHANISM mech = {
		.mechanism = CKM_DH_PKCS_DERIVE,
		.pParameter = pub,
		.ulParameterLen = publen
	};
	CK_RV rv;

	rv = C_DeriveKey(h, &mech, priv, template, ARRAY_SIZE(template), hp);
	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "\nC_DeriveKey failed: %s (%lu)",
		     pkcs11_strerror(rv), rv);
	}
}

static void
destroy(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;

	rv = C_DestroyObject(h, obj);
	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "C_DestroyObject failed: %s (%lu)",
		    pkcs11_strerror(rv), rv);
	}
}

static size_t
check(const char *desc, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE priv,
    uint8_t *pub, uint8_t *cmp, size_t len)
{
	uint8_t *secret = NULL;
	size_t sec_len = 0;
	size_t nerrs = 0;
	CK_OBJECT_HANDLE sec_obj;

	(void) fprintf(stderr, "%20s: ", desc);
	derive(h, priv, pub, len, &sec_obj);
	obj_to_key(h, sec_obj, &secret, &sec_len);
	nerrs = bufcmp(8, "Z", cmp, len, secret, sec_len);
	free(secret);
	return (nerrs);
}

int
main(void)
{
	size_t i, nerrs = 0;

	CK_SESSION_HANDLE h;
	CK_OBJECT_HANDLE a_priv, b_priv;
	CK_RV rv;

	cryptodebug_init(__progname);

	init_term();

	rv = SUNW_C_GetMechSession(CKM_DH_PKCS_DERIVE, &h);
	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "SUNW_C_GetMechSession failed: %s (%lu)",
		    pkcs11_strerror(rv), rv);
	}

	divider();

	for (i = 0; i < dh_ntests; i++) {
		dh_test_t *t = &dh_tests[i];

		(void) fprintf(stderr, "Test: %s\n\n", t->testname);

		key_to_obj(h, t->prime, t->primelen, t->generator, t->genlen,
		    t->a_priv, t->privlen, &a_priv);
		key_to_obj(h, t->prime, t->primelen, t->generator, t->genlen,
		    t->b_priv, t->privlen, &b_priv);

		check("Priv A + Pub B", h, a_priv, t->b_pub, t->secret,
		    t->publen);

		check("Priv B + Pub A", h, b_priv, t->a_pub, t->secret,
		    t->publen);

		destroy(h, a_priv);
		destroy(h, b_priv);

		divider();
	}

	rv = C_CloseSession(h);
	if (rv != CKR_OK) {
		errx(EXIT_FAILURE, "C_CloseSession failed: %s (%lu)",
		    pkcs11_strerror(rv), rv);
	}

	if (nerrs > 0)
		(void) fprintf(stderr, "%zu tests failed\n", nerrs);

	return (nerrs);
}
