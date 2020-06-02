/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2017 Jason King.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <aes_impl.h>
#include <cryptoutil.h>
#include "softSession.h"
#include "softObject.h"
#include "softCrypt.h"
#include "softOps.h"

/*
 * Check that the mechanism parameter is present and the correct size if
 * required and allocate an AES context.
 */
static CK_RV
soft_aes_check_mech_param(CK_MECHANISM_PTR mech, aes_ctx_t **ctxp)
{
	void *(*allocf)(int) = NULL;
	size_t param_len = 0;
	boolean_t param_req = B_TRUE;

	switch (mech->mechanism) {
	case CKM_AES_ECB:
		param_req = B_FALSE;
		allocf = ecb_alloc_ctx;
		break;
	case CKM_AES_CMAC:
		param_req = B_FALSE;
		allocf = cmac_alloc_ctx;
		break;
	case CKM_AES_CMAC_GENERAL:
		param_len = sizeof (CK_MAC_GENERAL_PARAMS);
		allocf = cmac_alloc_ctx;
		break;
	case CKM_AES_CBC:
		param_len = AES_BLOCK_LEN;
		allocf = cbc_alloc_ctx;
		break;
	case CKM_AES_CBC_PAD:
		param_len = AES_BLOCK_LEN;
		allocf = cbc_pad_alloc_ctx;
		break;
	case CKM_AES_CTR:
		param_len = sizeof (CK_AES_CTR_PARAMS);
		allocf = ctr_alloc_ctx;
		break;
	case CKM_AES_CCM:
		param_len = sizeof (CK_CCM_PARAMS);
		allocf = ccm_alloc_ctx;
		break;
	case CKM_AES_GCM:
		param_len = sizeof (CK_GCM_PARAMS);
		allocf = gcm_alloc_ctx;
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	if (param_req && (mech->pParameter == NULL ||
	    mech->ulParameterLen != param_len)) {
		return (CKR_MECHANISM_PARAM_INVALID);
	}

	*ctxp = allocf(0);
	if (*ctxp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	return (CKR_OK);
}

/*
 * Create an AES key schedule for the given AES context from the given key.
 * If the key is not sensitive, cache a copy of the key schedule in the
 * key object and/or use the cached copy of the key schedule.
 *
 * Must be called before the init function for a given mode is called.
 */
static CK_RV
soft_aes_init_key(aes_ctx_t *aes_ctx, soft_object_t *key_p)
{
	void *ks = NULL;
	size_t size = 0;
	CK_RV rv = CKR_OK;

	(void) pthread_mutex_lock(&key_p->object_mutex);

	/*
	 * AES keys should be either 128, 192, or 256 bits long.
	 * soft_object_t stores the key size in bytes, so we check those sizes
	 * in bytes.
	 *
	 * While soft_build_secret_key_object() does these same validations for
	 * keys created by the user, it may be possible that a key loaded from
	 * disk could be invalid or corrupt.  We err on the side of caution
	 * and check again that it's the correct size before performing any
	 * AES operations.
	 */
	switch (OBJ_SEC_VALUE_LEN(key_p)) {
	case AES_MIN_KEY_BYTES:
	case AES_MAX_KEY_BYTES:
	case AES_192_KEY_BYTES:
		break;
	default:
		rv = CKR_KEY_SIZE_RANGE;
		goto done;
	}

	ks = aes_alloc_keysched(&size, 0);
	if (ks == NULL) {
		rv = CKR_HOST_MEMORY;
		goto done;
	}

	/* If this is a sensitive key, always expand the key schedule */
	if (key_p->bool_attr_mask & SENSITIVE_BOOL_ON) {
		/* aes_init_keysched() requires key length in bits.  */
#ifdef	__sparcv9
		/* LINTED */
		aes_init_keysched(OBJ_SEC_VALUE(key_p), (uint_t)
		    (OBJ_SEC_VALUE_LEN(key_p) * NBBY), ks);
#else	/* !__sparcv9 */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * NBBY), ks);
#endif	/* __sparcv9 */

		goto done;
	}

	/* If a non-sensitive key and doesn't have a key schedule, create it */
	if (OBJ_KEY_SCHED(key_p) == NULL) {
		void *obj_ks = NULL;

		obj_ks = aes_alloc_keysched(&size, 0);
		if (obj_ks == NULL) {
			rv = CKR_HOST_MEMORY;
			goto done;
		}

#ifdef	__sparcv9
		/* LINTED */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (uint_t)(OBJ_SEC_VALUE_LEN(key_p) * 8), obj_ks);
#else	/* !__sparcv9 */
		aes_init_keysched(OBJ_SEC_VALUE(key_p),
		    (OBJ_SEC_VALUE_LEN(key_p) * 8), obj_ks);
#endif	/* __sparcv9 */

		OBJ_KEY_SCHED_LEN(key_p) = size;
		OBJ_KEY_SCHED(key_p) = obj_ks;
	}

	(void) memcpy(ks, OBJ_KEY_SCHED(key_p), OBJ_KEY_SCHED_LEN(key_p));

done:
	(void) pthread_mutex_unlock(&key_p->object_mutex);

	if (rv == CKR_OK) {
		aes_ctx->ac_keysched = ks;
		aes_ctx->ac_keysched_len = size;
	} else {
		freezero(ks, size);
	}

	return (rv);
}

/*
 * Initialize the AES context for the given mode, including allocating and
 * expanding the key schedule if required.
 */
static CK_RV
soft_aes_init_ctx(aes_ctx_t *aes_ctx, CK_MECHANISM_PTR mech_p,
    boolean_t encrypt)
{
	int rc = CRYPTO_SUCCESS;

	switch (mech_p->mechanism) {
	case CKM_AES_ECB:
		aes_ctx->ac_flags |= ECB_MODE;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_init_ctx((cbc_ctx_t *)aes_ctx, AES_BLOCK_LEN);
		break;
	case CKM_AES_CBC:
		rc = cbc_init_ctx((cbc_ctx_t *)aes_ctx, mech_p->pParameter,
		    mech_p->ulParameterLen, AES_BLOCK_LEN, aes_copy_block64);
		break;
	case CKM_AES_CBC_PAD:
		rc = cbc_pad_init_ctx((cbc_ctx_t *)aes_ctx, mech_p->pParameter,
		    mech_p->ulParameterLen, AES_BLOCK_LEN, aes_copy_block64,
		    encrypt);
		break;
	case CKM_AES_CTR:
	{
		/*
		 * soft_aes_check_param() verifies this is !NULL and is the
		 * correct size.
		 */
		CK_AES_CTR_PARAMS *pp = (CK_AES_CTR_PARAMS *)mech_p->pParameter;

		rc = ctr_init_ctx((ctr_ctx_t *)aes_ctx, pp->ulCounterBits,
		    pp->cb, aes_encrypt_block, aes_copy_block);
		break;
	}
	case CKM_AES_CCM: {
		CK_CCM_PARAMS *pp = (CK_CCM_PARAMS *)mech_p->pParameter;

		/*
		 * The illumos ccm mode implementation predates the PKCS#11
		 * version that specifies CK_CCM_PARAMS.  As a result, the order
		 * and names of the struct members are different, so we must
		 * translate.  ccm_init_ctx() does not store a ref ccm_params,
		 * so it is safe to allocate on the stack.
		 */
		CK_AES_CCM_PARAMS ccm_params = {
			.ulMACSize = pp->ulMACLen,
			.ulNonceSize = pp->ulNonceLen,
			.ulAuthDataSize = pp->ulAADLen,
			.ulDataSize = pp->ulDataLen,
			.nonce = pp->pNonce,
			.authData = pp->pAAD
		};

		rc = ccm_init_ctx((ccm_ctx_t *)aes_ctx, (char *)&ccm_params, 0,
		    encrypt, AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	}
	case CKM_AES_GCM:
		/*
		 * Similar to the ccm mode implementation, the gcm mode also
		 * predates PKCS#11 2.40, however in this instance
		 * CK_AES_GCM_PARAMS and CK_GCM_PARAMS are identical except
		 * for the member names, so we can just pass it along.
		 */
		rc = gcm_init_ctx((gcm_ctx_t *)aes_ctx, mech_p->pParameter,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	}

	return (crypto2pkcs11_error_number(rc));
}

/*
 * Allocate context for the active encryption or decryption operation, and
 * generate AES key schedule to speed up the operation.
 */
CK_RV
soft_aes_crypt_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p,
    boolean_t encrypt)
{
	aes_ctx_t *aes_ctx = NULL;
	CK_RV rv = CKR_OK;

	if (key_p->key_type != CKK_AES)
		return (CKR_KEY_TYPE_INCONSISTENT);

	/* C_{Encrypt,Decrypt}Init() validate pMechanism != NULL */
	rv = soft_aes_check_mech_param(pMechanism, &aes_ctx);
	if (rv != CKR_OK) {
		goto done;
	}

	rv = soft_aes_init_key(aes_ctx, key_p);
	if (rv != CKR_OK) {
		goto done;
	}

	rv = soft_aes_init_ctx(aes_ctx, pMechanism, encrypt);
	if (rv != CKR_OK) {
		goto done;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	if (encrypt) {
		/* Called by C_EncryptInit. */
		session_p->encrypt.context = aes_ctx;
		session_p->encrypt.mech.mechanism = pMechanism->mechanism;
	} else {
		/* Called by C_DecryptInit. */
		session_p->decrypt.context = aes_ctx;
		session_p->decrypt.mech.mechanism = pMechanism->mechanism;
	}
	(void) pthread_mutex_unlock(&session_p->session_mutex);

done:
	if (rv != CKR_OK) {
		soft_aes_free_ctx(aes_ctx);
	}

	return (rv);
}


CK_RV
soft_aes_encrypt(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	size_t length_needed;
	size_t remainder;
	int rc = CRYPTO_SUCCESS;
	CK_RV rv = CKR_OK;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulEncryptedDataLen,
		.cd_raw.iov_base = (char *)pEncryptedData,
		.cd_raw.iov_len = *pulEncryptedDataLen
	};

	/*
	 * A bit unusual, but it's permissible for ccm and gcm modes to not
	 * encrypt any data.  This ends up being equivalent to CKM_AES_CMAC
	 * or CKM_AES_GMAC of the additional authenticated data (AAD).
	 */
	if ((pData == NULL || ulDataLen == 0) &&
	    !(aes_ctx->ac_flags & (CCM_MODE|GCM_MODE|CMAC_MODE))) {
		return (CKR_ARGUMENTS_BAD);
	}

	remainder = ulDataLen % AES_BLOCK_LEN;

	/*
	 * CTR, CCM, CMAC, and GCM modes do not require the plaintext
	 * to be a multiple of the AES block size. CKM_AES_CBC_PAD as the
	 * name suggests pads it's output, so it can also accept any
	 * size plaintext.
	 */
	switch (mech) {
	case CKM_AES_CBC_PAD:
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CTR:
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		break;
	default:
		if (remainder != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	switch (mech) {
	case CKM_AES_CCM:
		length_needed = ulDataLen + aes_ctx->ac_mac_len;
		break;
	case CKM_AES_GCM:
		length_needed = ulDataLen + aes_ctx->ac_tag_len;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		length_needed = AES_BLOCK_LEN;
		break;
	case CKM_AES_CBC_PAD:
		/* CKM_AES_CBC_PAD always adds 1..AES_BLOCK_LEN of padding */
		length_needed = ulDataLen + AES_BLOCK_LEN - remainder;
		break;
	default:
		length_needed = ulDataLen;
		break;
	}

	if (pEncryptedData == NULL) {
		/*
		 * The application can ask for the size of the output buffer
		 * with a NULL output buffer (pEncryptedData).
		 * C_Encrypt() guarantees pulEncryptedDataLen != NULL.
		 */
		*pulEncryptedDataLen = length_needed;
		return (CKR_OK);
	}

	if (*pulEncryptedDataLen < length_needed) {
		*pulEncryptedDataLen = length_needed;
		return (CKR_BUFFER_TOO_SMALL);
	}

	if (ulDataLen > 0) {
		rv = soft_aes_encrypt_update(session_p, pData, ulDataLen,
		    pEncryptedData, pulEncryptedDataLen);

		if (rv != CKR_OK) {
			rv = CKR_FUNCTION_FAILED;
			goto cleanup;
		}

		/*
		 * Some modes (e.g. CCM and GCM) will append data such as a MAC
		 * to the ciphertext after the plaintext has been encrypted.
		 * Update out to reflect the amount of data in pEncryptedData
		 * after encryption.
		 */
		out.cd_offset = *pulEncryptedDataLen;
	}

	switch (mech) {
	case CKM_AES_CBC_PAD:
		rc = cbc_pad_encrypt_final((cbc_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		break;
	case CKM_AES_CCM:
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		break;
	case CKM_AES_GCM:
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &out, AES_BLOCK_LEN,
		    aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
		aes_ctx->ac_remainder_len = 0;
		break;
	case CKM_AES_CTR:
		/*
		 * As CKM_AES_CTR is a stream cipher, ctr_mode_final is always
		 * invoked in the xx_update() functions, so we do not need to
		 * call it again here.
		 */
		break;
	case CKM_AES_ECB:
	case CKM_AES_CBC:
		/*
		 * These mechanisms do not have nor require a xx_final function.
		 */
		break;
	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

cleanup:
	switch (rv) {
	case CKR_OK:
		*pulEncryptedDataLen = out.cd_offset;
		break;
	case CKR_BUFFER_TOO_SMALL:
		/* *pulEncryptedDataLen was set earlier */
		break;
	default:
		/* something else failed */
		*pulEncryptedDataLen = 0;
		break;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_aes_free_ctx(aes_ctx);
	session_p->encrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

CK_RV
soft_aes_decrypt(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	size_t length_needed;
	size_t remainder;
	int rc = CRYPTO_SUCCESS;
	CK_RV rv = CKR_OK;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulDataLen,
		.cd_raw.iov_base = (char *)pData,
		.cd_raw.iov_len = *pulDataLen
	};

	/*
	 * A bit unusual, but it's permissible for ccm and gcm modes to not
	 * decrypt any data.  This ends up being equivalent to CKM_AES_CMAC
	 * or CKM_AES_GMAC of the additional authenticated data (AAD).
	 */
	if ((pEncryptedData == NULL || ulEncryptedDataLen == 0) &&
	    !(aes_ctx->ac_flags & (CCM_MODE|GCM_MODE))) {
		return (CKR_ARGUMENTS_BAD);
	}

	remainder = ulEncryptedDataLen % AES_BLOCK_LEN;

	/*
	 * CTR, CCM, CMAC, and GCM modes do not require the ciphertext
	 * to be a multiple of the AES block size.  Note that while
	 * CKM_AES_CBC_PAD accepts an arbitrary sized plaintext, the
	 * ciphertext is always a multiple of the AES block size
	 */
	switch (mech) {
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
	case CKM_AES_CTR:
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		break;
	default:
		if (remainder != 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto cleanup;
		}
	}

	switch (aes_ctx->ac_flags & (CBC_PAD_MODE|CCM_MODE|GCM_MODE)) {
	case CCM_MODE:
		length_needed = aes_ctx->ac_processed_data_len;
		break;
	case GCM_MODE:
		length_needed = ulEncryptedDataLen - aes_ctx->ac_tag_len;
		break;
	case CBC_PAD_MODE:
		/*
		 * PKCS#11 allows a caller to query the amount of space
		 * required to hold the output plaintext by passing in
		 * pData == NULL. In this instance, PKCS#11 allows a
		 * provider to return a 'somewhat' larger than necessary
		 * value (PKCS#11 Base Specification, Sec. 5.2).
		 *
		 * Since we always add padding, when queried in this manner,
		 * we can merely use the size of the input ciphertext since
		 * the output will always be smaller (technically between 1..
		 * AES_BLOCK_LEN bytes smaller) -- that is, we fall through
		 * to the default case.
		 *
		 * When we aren't being queried for the output size
		 * (pData != NULL), we must decrypt the final block of
		 * input ciphertext to determine the amount of padding. This
		 * is because when not being queried for the output size,
		 * if the output buffer is too small, we must return
		 * CKR_BUFFER_TOO_SMALL and set *pulDataLen to the exact
		 * amount of space required.
		 *
		 * The cbc_pad_decrypted_len() does this and returns the
		 * size of the decrypted plaintext (after stripping padding).
		 */
		if (pData != NULL) {
			cbc_ctx_t *ctx = (cbc_ctx_t *)aes_ctx;
			crypto_data_t data = {
				.cd_format = CRYPTO_DATA_RAW,
				.cd_offset = 0,
				.cd_length = ulEncryptedDataLen,
				.cd_raw.iov_base = (char *)pEncryptedData,
				.cd_raw.iov_len = ulEncryptedDataLen
			};

			rc = cbc_pad_decrypted_len(ctx, &data, AES_BLOCK_LEN,
			    &length_needed, aes_decrypt_block, aes_xor_block);

			if (rc != CRYPTO_SUCCESS)
				return (crypto2pkcs11_error_number(rc));

			break;
		}
		/*FALLTHRU*/
	default:
		length_needed = ulEncryptedDataLen;
	}

	if (pData == NULL) {
		/*
		 * The application can ask for the size of the output buffer
		 * with a NULL output buffer (pData).
		 * C_Decrypt() guarantees pulDataLen != NULL.
		 */
		*pulDataLen = length_needed;
		return (CKR_OK);
	}

	if (*pulDataLen < length_needed) {
		*pulDataLen = length_needed;
		return (CKR_BUFFER_TOO_SMALL);
	}

	if (ulEncryptedDataLen > 0) {
		rv = soft_aes_decrypt_update(session_p, pEncryptedData,
		    ulEncryptedDataLen, pData, pulDataLen);
	}

	if (rv != CKR_OK) {
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	/*
	 * Some modes (e.g. CCM and GCM) will output additional data
	 * after the plaintext (such as the MAC).  Update out to
	 * reflect the amount of data in pData for the _final() functions.
	 */
	out.cd_offset = *pulDataLen;

	/*
	 * As CKM_AES_CTR is a stream cipher, ctr_mode_final is always
	 * invoked in the _update() functions, so we do not need to call it
	 * here.
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		ASSERT3U(aes_ctx->ac_processed_data_len, ==,
		    aes_ctx->ac_data_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
	} else if (aes_ctx->ac_flags & GCM_MODE) {
		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
	} else if (aes_ctx->ac_flags & CBC_PAD_MODE) {
		rc = cbc_pad_decrypt_final((cbc_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_decrypt_block, aes_xor_block);
		rv = crypto2pkcs11_error_number(rc);
	}

cleanup:
	if (rv == CKR_OK) {
		*pulDataLen = out.cd_offset;
	} else {
		*pulDataLen = 0;
	}

	(void) pthread_mutex_lock(&session_p->session_mutex);
	soft_aes_free_ctx(aes_ctx);
	session_p->decrypt.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

CK_RV
soft_aes_encrypt_update(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulEncryptedDataLen,
		.cd_raw.iov_base = (char *)pEncryptedData,
		.cd_raw.iov_len = *pulEncryptedDataLen
	};
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t out_len;
	int rc;

	/*
	 * If pData is NULL, we should have zero bytes to process, and
	 * the aes_encrypt_contiguous_blocks() call will be an effective no-op.
	 */
	IMPLY(pData == NULL, ulDataLen == 0);

	/* Check size of the output buffer */
	switch (mech) {
	case CKM_AES_CMAC:
		/*
		 * The underlying CMAC implementation handles the storing of
		 * extra bytes and does not output any data until *_final,
		 * so do not bother looking at the size of the output
		 * buffer at this time.
		 */
		out_len = 0;
		break;
	case CKM_AES_CTR:
		/*
		 * CTR mode is a stream cipher, so we always output exactly as
		 * much ciphertext as input plaintext
		 */
		out_len = ulDataLen;
		break;
	default:
		out_len = aes_ctx->ac_remainder_len + ulDataLen;

		/*
		 * The number of complete blocks we can encrypt right now.
		 * The underlying implementation will buffer any remaining data
		 * until the next *_update call.
		 */
		out_len &= ~(AES_BLOCK_LEN - 1);
		break;
	}

	if (pEncryptedData == NULL) {
		*pulEncryptedDataLen = out_len;
		return (CKR_OK);
	}

	if (*pulEncryptedDataLen < out_len) {
		*pulEncryptedDataLen = out_len;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = aes_encrypt_contiguous_blocks(aes_ctx, (char *)pData, ulDataLen,
	    &out);

	/*
	 * Since out.cd_offset is set to 0 initially and the underlying
	 * implementation increments out.cd_offset by the amount of output
	 * written, so we can just use the value as the amount written.
	 */
	*pulEncryptedDataLen = out.cd_offset;

	if (rc != CRYPTO_SUCCESS) {
		return (CKR_FUNCTION_FAILED);
	}

	rv = crypto2pkcs11_error_number(rc);

	return (rv);
}

CK_RV
soft_aes_decrypt_update(soft_session_t *session_p, CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	uint8_t *buffer_block = NULL;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulDataLen,
		.cd_raw.iov_base = (char *)pData,
		.cd_raw.iov_len = *pulDataLen
	};
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t in_len = ulEncryptedDataLen;
	size_t out_len;
	int rc = CRYPTO_SUCCESS;

	switch (mech) {
	case CKM_AES_CCM:
	case CKM_AES_GCM:
		out_len = 0;
		break;
	case CKM_AES_CBC_PAD:
		VERIFY3U(aes_ctx->ac_remainder_len, <=, AES_BLOCK_LEN);
		if (in_len >= SIZE_MAX - AES_BLOCK_LEN)
			return (CKR_ENCRYPTED_DATA_LEN_RANGE);

		out_len = aes_ctx->ac_remainder_len + in_len;

		/* check for overflow */
		if (out_len < in_len)
			return (CKR_ENCRYPTED_DATA_LEN_RANGE);

		/*
		 * Since CBC_PAD modes have to process the final block of
		 * (to remove the padding), and since we do not know which
		 * block is the final block until C_DecryptFinal() is called,
		 * decryption of a given block is delayed until it is known
		 * that at least one block follows it. This ensures that
		 * when C_DecryptFinal() is called, we have the final block
		 * of input ciphertext buffered in aes_ctx (which is then
		 * processed in the C_DecryptFinal() call).
		 *
		 * From all of this, it means when we have _exactly_
		 * n * AES_BLOCK_LEN bytes of output available to process,
		 * we output (n - 1) * AES_BLOCK_LEN bytes of output plaintext.
		 *
		 * When we don't have an exact multiple of AES_BLOCK_LEN, we
		 * output as may full blocks of output plaintext as we have.
		 */
		if (out_len % AES_BLOCK_LEN == 0) {
			out_len &= ~(AES_BLOCK_LEN - 1);
			out_len--;
		} else {
			out_len &= ~(AES_BLOCK_LEN - 1);
		}
		break;
	case CKM_AES_CTR:
		/*
		 * CKM_AES_CTR is a stream cipher, so we always output
		 * exactly as much output plaintext as input ciphertext
		 */
		out_len = in_len;
		break;
	default:
		out_len = aes_ctx->ac_remainder_len + in_len;
		out_len &= ~(AES_BLOCK_LEN - 1);
		break;
	}

	/*
	 * C_DecryptUpdate() verifies that pulDataLen is not NULL prior
	 * to calling soft_decrypt_common() (which calls us).
	 */

	if (pData == NULL) {
		/*
		 * If the output buffer (pData) is NULL, that means the
		 * caller is inquiring about the size buffer needed to
		 * complete the C_DecryptUpdate() request.  While we are
		 * permitted to set *pulDataLen to an estimated value that can
		 * be 'slightly' larger than the actual value required,
		 * since we know the exact size we need, we stick with the
		 * exact size.
		 */
		*pulDataLen = out_len;
		return (CKR_OK);
	}

	if (*pulDataLen < out_len) {
		/*
		 * Not an inquiry, but the output buffer isn't large enough.
		 * PKCS#11 requires that this scenario not fail fatally (as
		 * well as return a different error value). This situation
		 * also requires us to set *pulDataLen to the _exact_ size
		 * required.
		 */
		*pulDataLen = out_len;
		return (CKR_BUFFER_TOO_SMALL);
	}

	rc = aes_decrypt_contiguous_blocks(aes_ctx, (char *)pEncryptedData,
	    in_len, &out);

	if (rc != CRYPTO_SUCCESS) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	*pulDataLen = out.cd_offset;
done:
	return (rv);
}

CK_RV
soft_aes_encrypt_final(soft_session_t *session_p,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	aes_ctx_t *aes_ctx = session_p->encrypt.context;
	crypto_data_t data = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulLastEncryptedPartLen,
		.cd_raw.iov_base = (char *)pLastEncryptedPart,
		.cd_raw.iov_len = *pulLastEncryptedPartLen
	};
	CK_MECHANISM_TYPE mech = session_p->encrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	size_t out_len;
	int rc = CRYPTO_SUCCESS;

	switch (mech) {
	case CKM_AES_CBC_PAD:
		/*
		 * We always add 1..AES_BLOCK_LEN of padding to the input
		 * plaintext to round up to a multiple of AES_BLOCK_LEN.
		 * During encryption, we never output a partially encrypted
		 * block (that is the amount encrypted by each call of
		 * C_EncryptUpdate() is always either 0 or n * AES_BLOCK_LEN).
		 * As a result, at the end of the encryption operation, we
		 * output AES_BLOCK_LEN bytes of data -- this could be a full
		 * block of padding, or a combination of data + padding.
		 */
		out_len = AES_BLOCK_LEN;
		break;
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never buffer any
		 * input, so we always have 0 remaining bytes of output.
		 */
		out_len = 0;
		break;
	case CKM_AES_CCM:
		out_len = aes_ctx->ac_remainder_len +
		    aes_ctx->acu.acu_ccm.ccm_mac_len;
		break;
	case CKM_AES_GCM:
		out_len = aes_ctx->ac_remainder_len +
		    aes_ctx->acu.acu_gcm.gcm_tag_len;
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		out_len = AES_BLOCK_LEN;
		break;
	default:
		/*
		 * Everything other AES mechansism requires full blocks of
		 * input.  If the input was not an exact multiple of
		 * AES_BLOCK_LEN, it is a fatal error.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto done;
		}
		out_len = 0;
	}

	if (*pulLastEncryptedPartLen < out_len || pLastEncryptedPart == NULL) {
		*pulLastEncryptedPartLen = out_len;
		return ((pLastEncryptedPart == NULL) ?
		    CKR_OK : CKR_BUFFER_TOO_SMALL);
	}

	switch (mech) {
	case CKM_AES_CBC_PAD:
		rc = cbc_pad_encrypt_final((cbc_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never
		 * buffer any data, and thus have no remaining data
		 * to output at the end
		 */
		break;
	case CKM_AES_CCM:
		rc = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	case CKM_AES_GCM:
		rc = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, &data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case CKM_AES_CMAC:
	case CKM_AES_CMAC_GENERAL:
		rc = cmac_mode_final((cbc_ctx_t *)aes_ctx, &data, AES_BLOCK_LEN,
		    aes_encrypt_block, aes_xor_block);
		break;
	default:
		break;
	}
	rv = crypto2pkcs11_error_number(rc);

done:
	if (rv == CKR_OK) {
		*pulLastEncryptedPartLen = data.cd_offset;
	}

	soft_aes_free_ctx(aes_ctx);
	session_p->encrypt.context = NULL;
	return (rv);
}

CK_RV
soft_aes_decrypt_final(soft_session_t *session_p, CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen)
{
	aes_ctx_t *aes_ctx = session_p->decrypt.context;
	CK_MECHANISM_TYPE mech = session_p->decrypt.mech.mechanism;
	CK_RV rv = CKR_OK;
	int rc = CRYPTO_SUCCESS;
	size_t out_len;
	crypto_data_t out = {
		.cd_format = CRYPTO_DATA_RAW,
		.cd_offset = 0,
		.cd_length = *pulLastPartLen,
		.cd_raw.iov_base = (char *)pLastPart,
		.cd_raw.iov_len = *pulLastPartLen
	};

	switch (mech) {
	case CKM_AES_CBC_PAD:
		/*
		 * PKCS#11 allows a caller to discover the size of the
		 * required output buffer by calling
		 * C_DecryptFinal(hSession, NULL, &len) which will return
		 * CKR_OK and set len to the size required (or a value
		 * 'slightly' larger). In this instance we can use
		 * AES_BLOCK_LEN since the exact amount required will be
		 * [0..AES_BLOCK_LEN - 1] bytes.
		 *
		 * However, when C_DecryptFinal() is called with a non-NULL
		 * output buffer, and the output buffer size is too small,
		 * we _must_ return the exact size of the output buffer
		 * required (and cannot use the same estimate when the
		 * output buffer is NULL).
		 *
		 * In this instance, we optimistically just do the
		 * final call. If the buffer is too small,
		 * cbc_pad_decrypt_final() will set out.cd_length to
		 * the required size and return CRYPTO_DATA_LEN_RANGE and
		 * the caller can retry. It does mean there's a chance we
		 * must decrypt the final block multiple times, but it's
		 * a single block, and most callers will likely just pass
		 * a buffer at least AES_BLOCK_LEN bytes, so this seems
		 * unlikely to be a problem in practice.
		 */
		if (pLastPart == NULL) {
			*pulLastPartLen = AES_BLOCK_LEN;
			return (CKR_OK);
		}

		rc = cbc_pad_decrypt_final((cbc_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_decrypt_block, aes_xor_block);

		if (rc == CRYPTO_DATA_LEN_RANGE) {
			*pulLastPartLen = out.cd_length;
			/*
			 * Return and don't terminate the active decrypt op.
			 * This allows the caller to retry with a sufficiently
			 * large buffer.
			 */
			return (CKR_BUFFER_TOO_SMALL);
		}

		/* For all other results, we finish up and terminate the op */
		rv = crypto2pkcs11_error_number(rc);
		goto done;
	case CKM_AES_CTR:
		/*
		 * Since CKM_AES_CTR is a stream cipher, we never have
		 * any remaining bytes to output.
		 */
		out_len = 0;
		break;
	case CKM_AES_CCM:
		out_len = aes_ctx->ac_data_len;
		break;
	case CKM_AES_GCM:
		out_len = aes_ctx->acu.acu_gcm.gcm_processed_data_len -
		    aes_ctx->acu.acu_gcm.gcm_tag_len;
		break;
	default:
		/*
		 * The remaining mechanims require an exact multiple of
		 * AES_BLOCK_LEN of ciphertext.  Any other value is an error.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			rv = CKR_DATA_LEN_RANGE;
			goto done;
		}
		out_len = 0;
		break;
	}

	if (*pulLastPartLen < out_len || pLastPart == NULL) {
		*pulLastPartLen = out_len;
		return ((pLastPart == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL);
	}

	switch (mech) {
	case CKM_AES_CCM:
		ASSERT3U(aes_ctx->ac_processed_data_len, ==, out_len);
		ASSERT3U(aes_ctx->ac_processed_mac_len, ==,
		    aes_ctx->ac_mac_len);

		rc = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case CKM_AES_GCM:
		rc = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, &out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		break;
	default:
		break;
	}

	VERIFY3U(out.cd_offset, ==, out_len);
	rv = crypto2pkcs11_error_number(rc);

done:
	if (rv == CKR_OK) {
		*pulLastPartLen = out.cd_offset;
	}

	soft_aes_free_ctx(aes_ctx);
	session_p->decrypt.context = NULL;

	return (rv);
}

/*
 * Allocate and initialize AES contexts for sign and verify operations
 * (including the underlying encryption context needed to sign or verify) --
 * called by C_SignInit() and C_VerifyInit() to perform the CKM_AES_* MAC
 * mechanisms. For general-length AES MAC, also validate the MAC length.
 */
CK_RV
soft_aes_sign_verify_init_common(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *key_p, boolean_t sign_op)
{
	soft_aes_sign_ctx_t	*ctx = NULL;
	/* For AES CMAC (the only AES MAC currently), iv is always 0 */
	CK_BYTE		iv[AES_BLOCK_LEN] = { 0 };
	CK_MECHANISM	encrypt_mech = {
		.mechanism = CKM_AES_CMAC,
		.pParameter = iv,
		.ulParameterLen = sizeof (iv)
	};
	CK_RV		rv;
	size_t		mac_len = AES_BLOCK_LEN;

	if (key_p->key_type != CKK_AES)
		return (CKR_KEY_TYPE_INCONSISTENT);

	/* C_{Sign,Verify}Init() validate pMechanism != NULL */
	if (pMechanism->mechanism == CKM_AES_CMAC_GENERAL) {
		if (pMechanism->pParameter == NULL) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}

		mac_len = *(CK_MAC_GENERAL_PARAMS *)pMechanism->pParameter;

		if (mac_len > AES_BLOCK_LEN) {
			return (CKR_MECHANISM_PARAM_INVALID);
		}
	}

	ctx = calloc(1, sizeof (*ctx));
	if (ctx == NULL) {
		return (CKR_HOST_MEMORY);
	}

	rv = soft_aes_check_mech_param(pMechanism, &ctx->aes_ctx);
	if (rv != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		goto done;
	}

	if ((rv = soft_encrypt_init_internal(session_p, &encrypt_mech,
	    key_p)) != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		goto done;
	}

	ctx->mac_len = mac_len;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (sign_op) {
		session_p->sign.context = ctx;
		session_p->sign.mech.mechanism = pMechanism->mechanism;
	} else {
		session_p->verify.context = ctx;
		session_p->verify.mech.mechanism = pMechanism->mechanism;
	}

	(void) pthread_mutex_unlock(&session_p->session_mutex);

done:
	if (rv != CKR_OK) {
		soft_aes_free_ctx(ctx->aes_ctx);
		free(ctx);
	}

	return (rv);
}

CK_RV
soft_aes_sign_verify_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSigned, CK_ULONG_PTR pulSignedLen,
    boolean_t sign_op, boolean_t Final)
{
	soft_aes_sign_ctx_t	*soft_aes_ctx_sign_verify;
	CK_RV			rv;
	CK_BYTE			*pEncrypted = NULL;
	CK_ULONG		ulEncryptedLen = AES_BLOCK_LEN;
	CK_BYTE			last_block[AES_BLOCK_LEN];

	if (sign_op) {
		soft_aes_ctx_sign_verify =
		    (soft_aes_sign_ctx_t *)session_p->sign.context;

		if (soft_aes_ctx_sign_verify->mac_len == 0) {
			*pulSignedLen = 0;
			goto clean_exit;
		}

		/* Application asks for the length of the output buffer. */
		if (pSigned == NULL) {
			*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;
			return (CKR_OK);
		}

		/* Is the application-supplied buffer large enough? */
		if (*pulSignedLen < soft_aes_ctx_sign_verify->mac_len) {
			*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;
			return (CKR_BUFFER_TOO_SMALL);
		}
	} else {
		soft_aes_ctx_sign_verify =
		    (soft_aes_sign_ctx_t *)session_p->verify.context;
	}

	if (Final) {
		rv = soft_encrypt_final(session_p, last_block,
		    &ulEncryptedLen);
	} else {
		rv = soft_encrypt(session_p, pData, ulDataLen,
		    last_block, &ulEncryptedLen);
	}

	if (rv == CKR_OK) {
		*pulSignedLen = soft_aes_ctx_sign_verify->mac_len;

		/* the leftmost mac_len bytes of last_block is our MAC */
		(void) memcpy(pSigned, last_block, *pulSignedLen);
	}

clean_exit:

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* soft_encrypt_common() has freed the encrypt context */
	if (sign_op) {
		free(session_p->sign.context);
		session_p->sign.context = NULL;
	} else {
		free(session_p->verify.context);
		session_p->verify.context = NULL;
	}
	session_p->encrypt.flags = 0;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	if (pEncrypted) {
		free(pEncrypted);
	}

	return (rv);
}

/*
 * Called by soft_sign_update()
 */
CK_RV
soft_aes_mac_sign_verify_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{
	CK_BYTE		buf[AES_BLOCK_LEN];
	CK_ULONG	ulEncryptedLen = AES_BLOCK_LEN;
	CK_RV		rv;

	rv = soft_encrypt_update(session_p, pPart, ulPartLen,
	    buf, &ulEncryptedLen);
	explicit_bzero(buf, sizeof (buf));

	return (rv);
}

void
soft_aes_free_ctx(aes_ctx_t *ctx)
{
	size_t len = 0;

	if (ctx == NULL)
		return;

	if (ctx->ac_flags & ECB_MODE) {
		len = sizeof (ecb_ctx_t);
	} else if (ctx->ac_flags & (CBC_MODE|CMAC_MODE)) {
		len = sizeof (cbc_ctx_t);
	} else if (ctx->ac_flags & CTR_MODE) {
		len = sizeof (ctr_ctx_t);
	} else if (ctx->ac_flags & CCM_MODE) {
		len = sizeof (ccm_ctx_t);
	} else if (ctx->ac_flags & GCM_MODE) {
		len = sizeof (gcm_ctx_t);
	}

	freezero(ctx->ac_keysched, ctx->ac_keysched_len);
	freezero(ctx, len);
}
