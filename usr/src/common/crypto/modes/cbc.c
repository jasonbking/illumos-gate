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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _KERNEL
#include <strings.h>
#include <limits.h>
#include <assert.h>
#include <security/cryptoki.h>
#else
#include <sys/cmn_err.h>
#endif

#include <sys/debug.h>
#include <sys/types.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <aes/aes_impl.h>

/* These are the CMAC Rb constants from NIST SP 800-38B */
#define	CONST_RB_128	0x87
#define	CONST_RB_64	0x1B

#ifdef _KERNEL
#define	ZERO(_ptr, _len) bzero(_ptr, _len)
#else
#define	ZERO(_ptr, _len) explicit_bzero(_ptr, _len)
#endif

/*
 * Algorithm independent CBC functions.
 */
int
cbc_encrypt_contiguous_blocks(cbc_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	void *iov_or_mp;
	offset_t offset;

	if (length + ctx->cbc_remainder_len <= ctx->max_remain) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->cbc_remainder + ctx->cbc_remainder_len,
		    length);
		ctx->cbc_remainder_len += length;
		ctx->cbc_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	lastp = (uint8_t *)ctx->cbc_iv;
	if (out != NULL)
		crypto_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->cbc_remainder_len > 0) {
			need = block_size - ctx->cbc_remainder_len;

			if (need > remainder)
				return (CRYPTO_DATA_LEN_RANGE);

			bcopy(datap, &((uint8_t *)ctx->cbc_remainder)
			    [ctx->cbc_remainder_len], need);

			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			blockp = datap;
		}

		if (out == NULL) {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block.
			 */
			xor_block(lastp, blockp);
			encrypt(ctx->cbc_keysched, blockp, blockp);

			ctx->cbc_lastp = blockp;
			lastp = blockp;

			if ((ctx->cbc_flags & CMAC_MODE) == 0 &&
			    ctx->cbc_remainder_len > 0) {
				bcopy(blockp, ctx->cbc_copy_to,
				    ctx->cbc_remainder_len);
				bcopy(blockp + ctx->cbc_remainder_len, datap,
				    need);
			}
		} else {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block.
			 */
			xor_block(blockp, lastp);
			encrypt(ctx->cbc_keysched, lastp, lastp);

			/*
			 * CMAC doesn't output until encrypt_final
			 */
			if ((ctx->cbc_flags & CMAC_MODE) == 0) {
				uint8_t *out_data_1;
				uint8_t *out_data_2;
				size_t out_data_1_len;

				crypto_get_ptrs(out, &iov_or_mp, &offset,
				    &out_data_1, &out_data_1_len,
				    &out_data_2, block_size);

				/* copy block to where it belongs */
				if (out_data_1_len == block_size) {
					copy_block(lastp, out_data_1);
				} else {
					bcopy(lastp, out_data_1,
					    out_data_1_len);
					if (out_data_2 != NULL) {
						bcopy(lastp + out_data_1_len,
						    out_data_2,
						    block_size -
						    out_data_1_len);
					}
				}
				/* update offset */
				out->cd_offset += block_size;
			}
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->cbc_remainder_len != 0) {
			datap += need;
			ctx->cbc_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder <= ctx->max_remain) {
			bcopy(datap, ctx->cbc_remainder, remainder);
			ctx->cbc_remainder_len = remainder;
			ctx->cbc_copy_to = datap;
			goto out;
		}
		ctx->cbc_copy_to = NULL;

	} while (remainder > 0);

out:
	/*
	 * Save the last encrypted block in the context.
	 */
	if (ctx->cbc_lastp != NULL) {
		copy_block((uint8_t *)ctx->cbc_lastp, (uint8_t *)ctx->cbc_iv);
		ctx->cbc_lastp = (uint8_t *)ctx->cbc_iv;
	}

	return (CRYPTO_SUCCESS);
}

#define	OTHER(a, ctx) \
	(((a) == (ctx)->cbc_lastblock) ? (ctx)->cbc_iv : (ctx)->cbc_lastblock)

/* ARGSUSED */
int
cbc_decrypt_contiguous_blocks(cbc_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	void *iov_or_mp;
	offset_t offset;

	if (length + ctx->cbc_remainder_len <= ctx->max_remain) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->cbc_remainder + ctx->cbc_remainder_len,
		    length);
		ctx->cbc_remainder_len += length;
		ctx->cbc_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	lastp = ctx->cbc_lastp;
	if (out != NULL)
		crypto_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->cbc_remainder_len > 0) {
			need = block_size - ctx->cbc_remainder_len;

			if (need > remainder)
				return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

			bcopy(datap, &((uint8_t *)ctx->cbc_remainder)
			    [ctx->cbc_remainder_len], need);

			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			blockp = datap;
		}

		copy_block(blockp, (uint8_t *)OTHER((uint64_t *)lastp, ctx));

		if (out != NULL) {
			decrypt(ctx->cbc_keysched, blockp,
			    (uint8_t *)ctx->cbc_remainder);
			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			decrypt(ctx->cbc_keysched, blockp, blockp);
		}

		/*
		 * XOR the previous cipher block or IV with the
		 * currently decrypted block.
		 */
		xor_block(lastp, blockp);

		/* LINTED: pointer alignment */
		lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);

		if (out != NULL) {
			uint8_t *out_data_1, *out_data_2;
			size_t out_data_1_len;

			crypto_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2, block_size);

			bcopy(blockp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(blockp + out_data_1_len, out_data_2,
				    block_size - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += block_size;

		} else if (ctx->cbc_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->cbc_copy_to, ctx->cbc_remainder_len);
			bcopy(blockp + ctx->cbc_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->cbc_remainder_len != 0) {
			datap += need;
			ctx->cbc_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder <= ctx->max_remain) {
			bcopy(datap, ctx->cbc_remainder, remainder);
			ctx->cbc_remainder_len = remainder;
			ctx->cbc_lastp = lastp;
			ctx->cbc_copy_to = datap;
			return (CRYPTO_SUCCESS);
		}
		ctx->cbc_copy_to = NULL;

	} while (remainder > 0);

	ctx->cbc_lastp = lastp;
	return (CRYPTO_SUCCESS);
}

static int
cbc_init_ctx_common(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *), uint32_t mode)
{
	/*
	 * Copy IV into context.
	 *
	 * If cm_param == NULL then the IV comes from the
	 * cd_miscdata field in the crypto_data structure.
	 */
	if (param != NULL) {
		ASSERT3U(param_len, ==, block_size);
		copy_block((uchar_t *)param, cbc_ctx->cbc_iv);
	}

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_flags |= mode;
	cbc_ctx->max_remain = block_size - 1;

	return (CRYPTO_SUCCESS);
}

int
cbc_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *))
{
	return (cbc_init_ctx_common(cbc_ctx, param, param_len, block_size,
	    copy_block, CBC_MODE));
}

int
cbc_pad_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *),
    boolean_t encrypt)
{
	int ret = cbc_init_ctx_common(cbc_ctx, param, param_len, block_size,
	    copy_block, CBC_PAD_MODE);

	/*
	 * When decrypting in CBC_PAD mode, the final block of input
	 * ciphertext requires extra processing to strip the padding. During
	 * decryption, we do not know which block will be the final block
	 * until cbc_pad_decrypt_final() is called. However we do know that
	 * the total input ciphertext size _must_ be a multiple of the
	 * block_size (otherwise a decryption error is returned).
	 *
	 * Typically, we buffer up to `block_size - 1` bytes of input and
	 * once at least 1 full block of input is available, we process as
	 * many full blocks as we can, then buffer any remaining input to
	 * be processed in a subsequent xx_update call. For CBC_PAD decryption,
	 * we must always buffer `block_size` bytes of input. When
	 * cbc_pad_decrypt_final() is called, we know the final block of
	 * input is in cbc_ctx->cbc_remainder (or there was an error in the
	 * input ciphertext if cbc_ctx->cbc_remainder_len < block_size)
	 * and we can process the padding accordingly.
	 *
	 * For CBC_PAD encryption, since we always pad out the input
	 * plaintext to a multiple of block_size (up to adding a full block
	 * of nothing but padding bytes if the input was already an exact
	 * multiple of block_size), we do not need to buffer a full block
	 * and can use the default `block_size - 1` value for max_remain.
	 */
	if (ret == CRYPTO_SUCCESS && !encrypt)
		cbc_ctx->max_remain = block_size;

	return (ret);
}

/* ARGSUSED */
static void *
cbc_cmac_alloc_ctx(int kmflag, uint32_t mode)
{
	cbc_ctx_t *cbc_ctx;
	uint32_t modeval = mode & (CBC_MODE|CMAC_MODE|CBC_PAD_MODE);

	/* Only one of the three modes can be set */
	VERIFY(modeval == CBC_MODE || modeval == CMAC_MODE ||
	    modeval == CBC_PAD_MODE);

#ifdef _KERNEL
	if ((cbc_ctx = kmem_zalloc(sizeof (cbc_ctx_t), kmflag)) == NULL)
#else
	if ((cbc_ctx = calloc(1, sizeof (cbc_ctx_t))) == NULL)
#endif
		return (NULL);

	cbc_ctx->cbc_flags = mode;
	return (cbc_ctx);
}

void *
cbc_alloc_ctx(int kmflag)
{
	return (cbc_cmac_alloc_ctx(kmflag, CBC_MODE));
}

void *
cbc_pad_alloc_ctx(int kmflag)
{
	return (cbc_cmac_alloc_ctx(kmflag, CBC_PAD_MODE));
}

/*
 * Algorithms for supporting AES-CMAC
 * NOTE: CMAC is generally just a wrapper for CBC
 */

void *
cmac_alloc_ctx(int kmflag)
{
	return (cbc_cmac_alloc_ctx(kmflag, CMAC_MODE));
}


/*
 * Typically max_remain is set to block_size - 1, since we usually
 * will process the data once we have a full block.  However with CMAC,
 * we must preprocess the final block of data.  Since we cannot know
 * when we've received the final block of data until the _final() method
 * is called, we must not process the last block of data until we know
 * it is the last block, or we receive a new block of data.  As such,
 * max_remain for CMAC is block_size.
 */
int
cmac_init_ctx(cbc_ctx_t *cbc_ctx, size_t block_size)
{
	/*
	 * CMAC is only approved for block sizes 64 and 128 bits /
	 * 8 and 16 bytes.
	 */

	if (block_size != 16 && block_size != 8)
		return (CRYPTO_INVALID_CONTEXT);

	/*
	 * For CMAC, cbc_iv is always 0.
	 */

	cbc_ctx->cbc_iv[0] = 0;
	cbc_ctx->cbc_iv[1] = 0;

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_flags |= CMAC_MODE;
	cbc_ctx->max_remain = block_size;

	return (CRYPTO_SUCCESS);
}

/*
 * Left shifts blocks by one and returns the leftmost bit
 */
static uint8_t
cmac_left_shift_block_by1(uint8_t *block, size_t block_size)
{
	uint8_t carry = 0, old;
	size_t i;
	for (i = block_size; i > 0; i--) {
		old = carry;
		carry = (block[i - 1] & 0x80) ? 1 : 0;
		block[i - 1] = (block[i - 1] << 1) | old;
	}
	return (carry);
}

int
cbc_pad_encrypt_final(cbc_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *datap = (uint8_t *)ctx->cbc_remainder;
	void *iov_or_mp;
	offset_t offset;
	size_t pad_amt = block_size - ctx->cbc_remainder_len;
	size_t remaining;

	/*
	 * For CBC_PAD, we always emit a final full block. If the
	 * input plaintext was an exact multiple of the block size,
	 * this will be a full block of padding, otherwise we pad
	 * out the remaining bytes to a full block.
	 */
	VERIFY3U(pad_amt, >, 0);

	if (out->cd_length < block_size)
		return (CRYPTO_DATA_LEN_RANGE);

	/*
	 * Since any trailing bytes are already in cbc_remainder, we
	 * just pad it out and encrypt that.
	 */
	(void) memset(datap + ctx->cbc_remainder_len, pad_amt & 0xff, pad_amt);

	xor_block(ctx->cbc_lastp, datap);
	encrypt(ctx->cbc_keysched, datap, datap);

	/* Write out the results */
	remaining = block_size;
	crypto_init_ptrs(out, &iov_or_mp, &offset);

	while (remaining > 0) {
		uint8_t *outbuf = NULL, *outbuf_more = NULL;
		size_t outbuflen;

		crypto_get_ptrs(out, &iov_or_mp, &offset, &outbuf,
		    &outbuflen, &outbuf_more, block_size);

		bcopy(datap, outbuf, outbuflen);

		remaining -= outbuflen;
		datap += outbuflen;

		offset = 0;
	}

	out->cd_offset = block_size;
	return (CRYPTO_SUCCESS);
}

/*
 * Decrypts the final block of input ciphertext (datap) and the 2nd to last
 * block of input ciphertext (prevp) and writes the block out to outp.
 * After decryption, it validates the PKCS#7 padding in the block.
 */
static int
cbc_pad_decrypt_final_common(cbc_ctx_t *ctx, size_t block_size,
    const uint8_t *datap, uint8_t *prevp, uint8_t *outp,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	const uint8_t masks[2] = { 0xff, 0x00 };
	size_t data_len, i;
	uint8_t pad_val, pad_cmp, pad_extra_bits;

	ASSERT(ISP2(block_size));

	decrypt(ctx->cbc_keysched, datap, outp);
	xor_block(prevp, outp);

	/*
	 * At this point we have the final block of plaintext in outp.
	 * It should contain 1..block_size bytes of padding at the end.
	 * The padding should be an 8-bit value indicating the amount of
	 * padding that was added. We must validate the pad amount is
	 * in range, and that the padding bytes all contain the correct
	 * pad value. Effectively, we want to do:
	 *
	 * pad_len = outp[block_len - 1];
	 * if (pad_len > block_size || pad_len == 0)
	 *		return (CRYPTO_ENCRYPTED_DATA_INVALID);
	 *
	 * for (i = block_size - pad_len; i < block_size; i++) {
	 *	if (outp[i] != pad_len)
	 *		return (CRYPTO_ENCRYPTED_DATA_INVALID);
	 * }
	 *
	 * However we also want to do this in as close to constant time as
	 * we can to avoid padding oracles or other timing based attacks.
	 * Doing so requires a less obvious approach:
	 *
	 * First get the pad value.
	 */
	pad_val = outp[block_size - 1];

	/*
	 * The pad value should be in the range [1..block_size]. Since we
	 * require block_size to be a power of two, we can subtract one to
	 * get a range [0..block_size - 1]. A valid pad value will then only
	 * have bits below log2(block_size) set, and any
	 * bits >= log2(block_size) should be zero. Visually, if block_size
	 * is 16, then an 8-bit value 'xxxxyyyy', all the 'x' bits should be 0
	 * and the value can be contained by masking off the 'yyyy' bits.
	 *
	 * We save off the upper bits of pad_val into pad_extra_bits. If the
	 * original pad amount was out of range, this will then != 0. If the
	 * original pad_value was in range, pad_extra_bits will == 0. This
	 * is true both for values > block_size, as well as 0 -- in the
	 * pad_len == 0 case, since pad_len is unsigned, it will underflow
	 * (which is defined to rollover to UINT8_MAX), and we again have
	 * extra bits set which we can mask off.
	 *
	 * Once we have saved any high bits off, we add one back to pad_val
	 * to undo the subtraction and bring the range of values back into
	 * [1..block_size].
	 */
	pad_val--;
	pad_extra_bits = pad_val & ~(block_size - 1);
	pad_val &= (block_size - 1);
	pad_val++;

	/*
	 * Since we've forced pad_val into the range [1..block_size],
	 * the data_len calculation cannot underflow and will produce a value
	 * [0..block_len - 1].
	 */
	data_len = block_size - pad_val;

	/* Validate the padding. */
	pad_cmp = 0x00;
	for (i = 0; i < block_size; i++) {
		/*
		 * Select a mask based on the type of byte. For data bytes
		 * (i < data_len), the mask will be 0x00, for padding bytes,
		 * the mask will be 0xFF
		 */
		uint8_t mask = masks[!!(i < data_len)];

		/*
		 * Compare the output byte with the pad value using a bitwise
		 * XOR. For bytes that equal the pad_val, this results in
		 * a value of 0, for bytes that do not match, it results
		 * in some non-zero value. We then bitwise-AND the result
		 * with the mask selected above.
		 *
		 * For data bytes, the mask value forces val to == 0 (since we
		 * bitwise-AND with 0x00). For padding bytes, the mask value
		 * (0xFF) will preserve the result of the bitwise-XOR with
		 * pad_val and val will == 0 for a correct padding byte and
		 * non-zero for bad padding value.
		 */
		uint8_t val = (outp[i] ^ pad_val) & mask;

		/*
		 * Bitwise-OR with all the previous values. This will cause
		 * pad_cmp to != 0 if there are any non-matching pad bytes.
		 */
		pad_cmp |= val;
	}

	/*
	 * Finally, we bitwise-OR the high bits from the original pad value.
	 * If the original pad value was in [1..block_size],
	 * pad_extra_bits == 0, and this has no net effect. However if the
	 * original value was not in range, this will cause pad_cmp to != 0
	 * even if somehow an out of range value manages to pass the
	 * padding value check.
	 */
	pad_cmp |= pad_extra_bits;

	if (pad_cmp != 0)
		return (CRYPTO_ENCRYPTED_DATA_INVALID);

	return (CRYPTO_SUCCESS);
}

int
cbc_pad_decrypt_final(cbc_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint64_t block[2] = { 0 };
	const uint8_t *datap = (const uint8_t *)ctx->cbc_remainder;
	uint8_t *lastp = ctx->cbc_lastp;
	uint8_t *outp = (uint8_t *)block;
	size_t outlen;
	int rv;

	if (ctx->cbc_remainder_len != block_size) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	rv = cbc_pad_decrypt_final_common(ctx, block_size, datap, lastp, outp,
	    decrypt, xor_block);
	if (rv != CRYPTO_SUCCESS) {
		ZERO(block, sizeof (block));
		return (rv);
	}

	outlen = block_size - (outp[block_size - 1] & 0xff);
	if (out->cd_length < outlen) {
		out->cd_length = outlen;
		ZERO(block, sizeof (block));
		return (CRYPTO_DATA_LEN_RANGE);
	}

	rv = crypto_put_output_data(outp, out, outlen);
	out->cd_offset += outlen;

	ZERO(block, sizeof (block));
	return (rv);
}

#ifndef _KERNEL
/*
 * This is a helper function for pkcs11_softtoken. There are situations where
 * we need to know the exact size of the output plaintext prior to decrypting
 * all of the input ciphertext. This decrypts the final block of input
 * ciphertext (it also requires the second to last block of input ciphertext
 * to do this), validates the padding, then sets *lenp to the exact size of
 * the output plaintext.
 *
 * It returns CRYPTO_SUCCESS on success, or an error on failure (e.g. padding
 * validation failed).
 */
int
cbc_pad_decrypted_len(cbc_ctx_t *ctx, crypto_data_t *data,
    size_t block_size, size_t *lenp,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint64_t block[2];
	uint8_t *datap, *prevp, *outp;
	int rv;

	/* Input ciphertext must be an exact multiple of the block size */
	if (data->cd_length % block_size != 0 || data->cd_length == 0)
		return (CRYPTO_DATA_LEN_RANGE);

	/* Since this is userland, we should only have RAW crypto_data_ts */
	VERIFY3S(data->cd_format, ==, CRYPTO_DATA_RAW);

	/*
	 * Make datap point to the final block of input ciphertext and prevp
	 * to the second to last block of input ciphertext.
	 */
	if (data->cd_length == block_size) {
		/*
		 * If we only have a single block of input, the 'previous'
		 * block is the IV, just like with normal decryption and
		 * the last block is also the first block.
		 */
		datap = (uint8_t *)data->cd_raw.iov_base;
		prevp = (uint8_t *)ctx->cbc_iv;
	} else {
		/*
		 * If we get here, we know that cd_length is > block_size and
		 * is an exact multiple of block_size. Therefore, the amount
		 * we advance prevpp is guaranteed to never underflow.
		 */
		prevp = (uint8_t *)data->cd_raw.iov_base + data->cd_length -
		    2 * block_size;
		datap = prevp + block_size;
	}
	outp = (uint8_t *)block;

	rv = cbc_pad_decrypt_final_common(ctx, block_size, datap, prevp, outp,
	    decrypt, xor_block);

	if (rv == CRYPTO_SUCCESS) {
		size_t pad_len = outp[block_size - 1] & 0xff;

		ASSERT3U(pad_len, >, 0);
		ASSERT3U(pad_len, <=, block_size);
		ASSERT3U(pad_len, <=, data->cd_length);

		*lenp = block_size - pad_len;
	}

	ZERO(block, sizeof (block));
	return (rv);
}
#endif

/*
 * Generate subkeys to preprocess the last block according to RFC 4493.
 * Store the final block_size MAC generated in 'out'.
 */
int
cmac_mode_final(cbc_ctx_t *cbc_ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t buf[AES_BLOCK_LEN] = {0};
	uint8_t *M_last = (uint8_t *)cbc_ctx->cbc_remainder;
	size_t length = cbc_ctx->cbc_remainder_len;
	uint8_t const_rb;

	if (length > block_size)
		return (CRYPTO_INVALID_CONTEXT);

	if (out->cd_length < block_size)
		return (CRYPTO_DATA_LEN_RANGE);

	if (block_size == 16)
		const_rb = CONST_RB_128;
	else if (block_size == 8)
		const_rb = CONST_RB_64;
	else
		return (CRYPTO_INVALID_CONTEXT);

	/* k_0 = E_k(0) */
	encrypt_block(cbc_ctx->cbc_keysched, buf, buf);

	if (cmac_left_shift_block_by1(buf, block_size))
		buf[block_size - 1] ^= const_rb;

	if (length == block_size) {
		/* Last block complete, so m_n = k_1 + m_n' */
		xor_block(buf, M_last);
		xor_block(cbc_ctx->cbc_lastp, M_last);
		encrypt_block(cbc_ctx->cbc_keysched, M_last, M_last);
	} else {
		/* Last block incomplete, so m_n = k_2 + (m_n' | 100...0_bin) */
		if (cmac_left_shift_block_by1(buf, block_size))
			buf[block_size - 1] ^= const_rb;

		M_last[length] = 0x80;
		bzero(M_last + length + 1, block_size - length - 1);
		xor_block(buf, M_last);
		xor_block(cbc_ctx->cbc_lastp, M_last);
		encrypt_block(cbc_ctx->cbc_keysched, M_last, M_last);
	}

	/*
	 * zero out the sub-key.
	 */
	ZERO(buf, sizeof (buf));
	return (crypto_put_output_data(M_last, out, block_size));
}
