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
 * Copyright 2023 Jason King
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

tpm_duration_t
tpm20_get_duration_type(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	switch (cmd) {
	case TPM_CC_Startup:
		return (TPM_SHORT);

	case TPM_CC_SelfTest:
		/* XXX: look at fullTest (yes = long, no = short); */
		return (TPM_LONG);

	case TPM_CC_GetRandom:
		return (TPM_MEDIUM);

	case TPM_CC_HashSequenceStart:
	case TPM_CC_SequenceUpdate:
	case TPM_CC_SequenceComplete:
	case TPM_CC_EventSequenceComplete:
		return (TPM_SHORT);

	case TPM_CC_VerifySignature:
		return (TPM_MEDIUM);

	case TPM_CC_PCR_Extend:
		return (TPM_SHORT);

	case TPM_CC_HierarchyControl:
	case TPM_CC_HierarchyChangeAuth:
		return (TPM_MEDIUM);

	case TPM_CC_GetCapability:
		return (TPM_SHORT);

	case TPM_CC_NV_Read:
		return (TPM_MEDIUM);

	default:
		return (TPM_MEDIUM);
	}

	return (TPM_MEDIUM);
}

#define	RNDHDR_SIZE	(TPM_HEADER_SIZE + sizeof (uint16_t))

int
tpm20_generate_random(tpm_t *tpm, uchar_t *buf, size_t len)
{
	tpm_client_t *c = tpm->tpm_internal_client;
	uint8_t *cmd = c->tpmc_buf;
	int ret;
	uint32_t tpmret;

	if (len > UINT16_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	mutex_enter(&c->tpmc_lock);
	tpm_int_newcmd(c, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);
	tpm_int_put16(c, len);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		/* XXX: Can we map to better errors here?
		 * Maybe CRYPTO_BUSY for timeouts?
		 */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	tpmret = tpm_getbuf32(cmd, TPM_RETURN_OFFSET);
	if (tpmret != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetRandom failed with %u\n", tpmret);
		/* TODO: Maybe map TPM rc codes to CRYPTO_xxx values */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	/*
	 * The response includes the fixed sized TPM header, followed by
	 * a 16-bit length, followed by the random data.
	 *
	 * Verify we have at least len bytes of random data.
	 */
	if (tpm_getbuf16(cmd, TPM_HEADER_SIZE) < len) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}
	cmd += TPM_HEADER_SIZE + sizeof (uint16_t);

	bcopy(cmd, buf, len);

	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	return (CRYPTO_SUCCESS);
}

#define	TPM_STIR_MAX 128

int
tpm20_seed_random(tpm_t *tpm, uchar_t *buf, size_t len)
{
	tpm_client_t	*c = tpm->tpm_internal_client;
	uint8_t		*cmd = c->tpmc_buf;
	int		ret;
	uint32_t	tpmret;

	/* XXX: Should we maybe just truncate instead? */
	if (len > TPM_STIR_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	mutex_enter(&c->tpmc_lock);
	tpm_int_newcmd(c, TPM_ST_NO_SESSIONS, TPM_CC_StirRandom);
	tpm_int_put16(c, (uint16_t)len);
	tpm_int_copy(c, buf, len);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		/* XXX: Map to better errors? */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	tpmret = tpm_getbuf32(cmd, TPM_RETURN_OFFSET);
	if (tpmret != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_CONT,
		    "!TPM_CC_StirRandom failed with %u\n", tpmret);
		/* TODO: Maybe map TPM return codes to CRYPTO_xxx values */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	return (ret);
}
