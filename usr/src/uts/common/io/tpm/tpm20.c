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
 * Copyright 2022 Jason King
 */

#include <sys/debug.h>
#include <sys/crypto/common.h>
#include "tpm_ddi.h"
#include "tpm20.h"

bool
tpm20_init(tpm_t *tpm)
{
	/* Until TAB support is implemented, only support a single client */
	tpm->tpm_client_max = 1;

	/*
	 * TPM2.0 defines explicit timeouts (unlike TPM1.2 where there are
	 * default timeouts, but the TPM can advertise its own timeout
	 * values if desired).
	 *
	 * Timeouts are in milliseconds.
	 */
	tpm->tpm_timeout_a = drv_usectohz(TPM20_TIMEOUT_A * 1000);
	tpm->tpm_timeout_b = drv_usectohz(TPM20_TIMEOUT_B * 1000);
	tpm->tpm_timeout_c = drv_usectohz(TPM20_TIMEOUT_C * 1000);
	tpm->tpm_timeout_d = drv_usectohz(TPM20_TIMEOUT_D * 1000);

	tpm->tpm_timeout_poll = drv_usectohz(TPM_POLLING_TIMEOUT * 1000);
	return (true);
}

clock_t
tpm20_get_timeout(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	switch (cmd) {
	case TPM_CC_Startup:
		return (tpm->tpm_timeout_a);
	case TPM_CC_SelfTest:
		return (tpm->tpm_timeout_a);
	case TPM_CC_GetRandom:
		return (tpm->tpm_timeout_b);
	case TPM_CC_HashSequenceStart:
		return (tpm->tpm_timeout_a);
	case TPM_CC_SequenceUpdate:
		return (tpm->tpm_timeout_a);
	case TPM_CC_SequenceComplete:
		return (tpm->tpm_timeout_a);
	case TPM_CC_EventSequenceComplete:
		return (tpm->tpm_timeout_a);
	case TPM_CC_VerifySignature:
		return (tpm->tpm_timeout_b);
	case TPM_CC_PCR_Extend:
		return (tpm->tpm_timeout_a);
	case TPM_CC_HierarchyControl:
		return (tpm->tpm_timeout_b);
	case TPM_CC_HierarchyChangeAuth:
		return (tpm->tpm_timeout_b);
	case TPM_CC_GetCapability:
		return (tpm->tpm_timeout_a);
	case TPM_CC_NV_Read:
		return (tpm->tpm_timeout_b);
	case TPM_CC_Create:
	case TPM_CC_CreatePrimary:
	case TPM_CC_CreateLoaded:
		/*
		 * TCG PC Client Decide Driver Design Principles for TPM 2.0
		 * Section 10 says these three should use an 180s timeout.
		 */
		return (drv_usectohz(180 * MICROSEC));
	default:
		/*
		 * Similiarly, it also says commands not explicitly
		 * mentioned to [PTP] should use a 90s timeout.
		 */
		return (drv_usectohz(90 * MICROSEC));
	}
}

clock_t
tpm20_get_duration(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	switch (cmd) {
	case TPM_CC_Startup:
		return (tpm->tpm_duration[TPM_SHORT]);

	case TPM_CC_SelfTest:
		/* XXX: look at fullTest (yes = long, no = short); */
 		break;

	case TPM_CC_GetRandom:
		return (tpm->tpm_duration[TPM_MEDIUM]);

	case TPM_CC_HashSequenceStart:
	case TPM_CC_SequenceUpdate:
	case TPM_CC_SequenceComplete:
	case TPM_CC_EventSequenceComplete:
		return (tpm->tpm_duration[TPM_SHORT]);

	case TPM_CC_VerifySignature:
		return (tpm->tpm_duration[TPM_MEDIUM]);

	case TPM_CC_PCR_Extend:
		return (tpm->tpm_duration[TPM_SHORT]);

	case TPM_CC_HierarchyControl:
	case TPM_CC_HierarchyChangeAuth:
		return (tpm->tpm_duration[TPM_MEDIUM]);

	case TPM_CC_GetCapability:
		return (tpm->tpm_duration[TPM_SHORT]);

	case TPM_CC_NV_Read:
		return (tpm->tpm_duration[TPM_MEDIUM]);

	default:
		return (0);
	}

	return (0);
}

#define	RNDHDR_SIZE	(TPM_HEADER_SIZE + sizeof (uint16_t))

int
tpm20_generate_random(tpm_t *tpm, uchar_t *buf, size_t len)
{
	if (len > UINT16_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	uint8_t cmd[RNDHDR_SIZE] = { 0 };
	iovec_t	iov[2] = {
		[0] = {
			.iov_base = (char *)cmd,
			.iov_len = sizeof (cmd),
		},
		[1] = {
			.iov_base = (char *)buf,
			.iov_len = len,
		},
	};
	uio_t in = {
		.uio_iov = iov,
		.uio_iovcnt = 1,
		.uio_segflg = UIO_SYSSPACE,
		.uio_resid = RNDHDR_SIZE,
	};
	uio_t out = {
		.uio_iov = iov,
		.uio_iovcnt = 2,
		.uio_segflg = UIO_SYSSPACE,
		.uio_resid = RNDHDR_SIZE + len,
	};
	int ret;
	uint32_t tpmret;

	BE_OUT16(cmd + TPM_TAG_OFFSET,		TPM_ST_NO_SESSIONS);
	BE_OUT32(cmd + TPM_PARAMSIZE_OFFSET,	RNDHDR_SIZE);
	BE_OUT32(cmd + TPM_COMMAND_CODE_OFFSET,	TPM_CC_GetRandom);
	BE_OUT16(cmd + TPM_HEADER_SIZE,		(uint16_t)len);

	ret = tpm_exec_internal(tpm, 0, &in, &out);
	if (ret != 0) {
		/* XXX: Can we map to better errors here?
		 * Maybe CRYPTO_BUSY for timeouts?
		 */
		return (CRYPTO_FAILED);
	}

	tpmret = tpm_getbuf32(cmd, TPM_RETURN_OFFSET);
	if (tpmret != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetRandom failed with %u\n", tpmret);
		/* TODO: Maybe map TPM rc codes to CRYPTO_xxx values */
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

#define	TPM_STIR_MAX 128

int
tpm20_seed_random(tpm_t *tpm, uchar_t *buf, size_t len)
{
	/* XXX: Should we maybe just truncate instead? */
	if (len > TPM_STIR_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	uint32_t plen = len + TPM_HEADER_SIZE;
	uint8_t cmd[] = {
		/* Header */
		0x80, 0x01,		/* TPM_ST_NO_SESSIONS */
		(uint8_t)((plen >> 24) & 0xff),	/* Param size */
		(uint8_t)((plen >> 16) & 0xff),
		(uint8_t)((plen >> 8) & 0xff),
		(uint8_t)(plen & 0xff),
		0x00, 0x00, 0x01, 0x46,	/* TPM_CC_StirRandom */

		/* Parameters */

		/*
		 * The data is sent as a TPM2B_SENSITIVE_DATA type which
		 * includes a 16-bit length followed by the value.
		 *
		 * No parameters are returned in the response.
		 */
		(uint8_t)((len >> 8) & 0xff),
		(uint8_t)(len & 0xff),
	};
	iovec_t iov[2] = {
		[0] = {
			.iov_base = (char *)cmd,
			.iov_len = sizeof (cmd),
		},
		[1] = {
			.iov_base = (char *)buf,
			.iov_len = len,
		}
	};
	uio_t in = {
		.uio_iov = iov,
		.uio_iovcnt = 2,
		.uio_segflg = UIO_SYSSPACE,
		.uio_resid = plen,
	};
	/* The TPM just returns a header w/ no data */
	uio_t out = {
		.uio_iov = iov,
		.uio_iovcnt = 1,
		.uio_segflg = UIO_SYSSPACE,
		.uio_resid = TPM_HEADER_SIZE,
	};
	int	ret;
	uint32_t tpmret;

	ret = tpm_exec_internal(tpm, 0, &in, &out);
	if (ret != 0) {
		/* XXX: Map to better errors? */
		return (CRYPTO_FAILED);
	}

	tpmret = tpm_getbuf32(cmd, TPM_RETURN_OFFSET);
	if (tpmret != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_CONT,
		    "!TPM_CC_StirRandom failed with %u\n", tpmret);
		/* TODO: Maybe map TPM return codes to CRYPTO_xxx values */
		return (CRYPTO_FAILED);
	}

done:
	return (ret);
}
