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
 * Copyright 2025 RackTop Systems, Inc.
 */

#include <sys/debug.h>
#include <sys/crypto/common.h>
#include <sys/types.h>

#include "tpm_ddi.h"
#include "tpm20.h"

/*
 * The wrappers around the TPM2.0 commands (TPM2_CC_GenerateRandom, etc)
 * are designed such that they can be utilized both during startup (no
 * client) as well as by an 'internal' (in-kernel) client. When called
 * by an internal client, commands utilize the TAB just like any other
 * client. During startup however, the TAB isn't initialized, and we
 * don't want to utilize it since we need to speak directly to the TPM
 * in order to do things like initialize the TAB.
 */

/*
 * From PTP 6.5.1.3 Table 17, note that it doesn't explicitly
 * label them, but there are three defined durations, so they're interpreted
 * as short, medium, and long.
 */
#define	TPM20_DURATION_SHORT	20
#define	TPM20_DURATION_MEDIUM	750
#define	TPM20_DURATION_LONG	1000

/*
 * PTP 6.5.1.4, Table 18 (all in milliseconds)
 * Unlike TPM1.2, these are fixed values.
 */
#define	TPM20_TIMEOUT_A	750
#define	TPM20_TIMEOUT_B	2000
#define	TPM20_TIMEOUT_C	200
#define	TPM20_TIMEOUT_D	30

#define	TPM20_TIMEOUT_CANCEL	TPM20_TIMEOUT_B

static bool tpm20_get_prop_cb(uint32_t, uint32_t, bool, void *);

static inline tpm_cmd_t *
tpm20_get_cmd(tpm_t *tpm, tpm_client_t *c)
{
	return ((c != NULL) ? &c->tpmc_cmd : &tpm->tpm_cmd);
}

static uint8_t
tpm20_get_locality(tpm_client_t *c)
{
	/* We assume locality 0 if there isn't a client */
	return ((c != NULL) ? c->tpmc_locality : 0);
}

bool
tpm20_init(tpm_t *tpm)
{
	TPM2_RC ret;

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

	/*
	 * Get all of the fixed properties. We'll ignore the ones we
	 * don't care about. It's simpler than requesting each property
	 * one at a time.
	 */
	(void) tpm20_get_properties(tpm, NULL, TPM2_PT_FIXED, 256,
	    tpm20_get_prop_cb, tpm);

	tpm->tpm20_cca = kmem_zalloc(tpm->tpm20_num_cc * sizeof (uint32_t),
	    KM_SLEEP);

	if (tpm->tpm20_cca == 0) {
		/*
		 * We should have attributes for at least the commands in
		 * the spec.
		 */
		return (false);
	}

	ret = tpm20_get_cmd_attr(tpm, NULL, tpm->tpm20_num_cc, tpm->tpm20_cca);
	if (ret != 0) {
		kmem_free(tpm->tpm20_cca, tpm->tpm20_num_cc * sizeof (uint32_t));
		tpm->tpm20_cca = NULL;
	}

	return ((ret == 0) ? true : false);
}

static bool
tpm20_get_prop_cb(uint32_t tag, uint32_t val, bool more, void *arg)
{
	tpm_t *tpm = arg;

	switch (tag) {
	case TPM2_PT_MAX_OBJECT_CONTEXT:
		tpm->tpm_object_size = val;
		break;
	case TPM2_PT_MAX_SESSION_CONTEXT:
		tpm->tpm_session_size = val;
		break;
	case TPM2_PT_TOTAL_COMMANDS:
		tpm->tpm20_num_cc = val;
		break;
	case TPM2_PT_HR_TRANSIENT_MIN:
		/*
		 * For now, we'll use the TPM's physical value for the maximum
		 * number of transient objects that can be loaded.
		 *
		 * Any application that cares when the value is greater
		 * than the platform minimum has to inquire about this
		 * property, so we can always increase this in the future
		 * without breaking clients. The only requirement (beyond
		 * supporting the platform minimum) is that this value
		 * cannot change for the duration of a clients connection
		 * (e.g. while the device is open).
		 */
		tpm->tpm20_object_max = val;
		break;
	default:
		/* Ignore other properties */
		break;
	}

	return (true);
}

clock_t
tpm20_get_timeout(tpm_t *tpm, const tpm_cmd_t *cmd)
{
	uint32_t cc = tpm_cc(cmd);

	switch (cc) {
	case TPM2_CC_Startup:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_SelfTest:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_GetRandom:
		return (tpm->tpm_timeout_b);
	case TPM2_CC_HashSequenceStart:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_SequenceUpdate:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_SequenceComplete:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_EventSequenceComplete:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_VerifySignature:
		return (tpm->tpm_timeout_b);
	case TPM2_CC_PCR_Extend:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_HierarchyControl:
		return (tpm->tpm_timeout_b);
	case TPM2_CC_HierarchyChangeAuth:
		return (tpm->tpm_timeout_b);
	case TPM2_CC_GetCapability:
		return (tpm->tpm_timeout_a);
	case TPM2_CC_NV_Read:
		return (tpm->tpm_timeout_b);
	case TPM2_CC_Create:
	case TPM2_CC_CreatePrimary:
	case TPM2_CC_CreateLoaded:
		/*
		 * TCG PC Client Device Driver Design Principles for TPM 2.0
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
tpm20_get_duration_type(tpm_t *tpm, const tpm_cmd_t *cmd)
{
	uint32_t cc = tpm_cc(cmd);

	switch (cc) {
	case TPM2_CC_Startup:
		return (TPM_SHORT);

	case TPM2_CC_SelfTest:
		/*
		 * Immediately after the buffer is the fullTest parameter.
		 * If true, a full test is done which uses the long timeout.
		 * Otherwise a short duration is used.
		 */
		if (cmd->tcmd_buf[TPM_HEADER_SIZE] != 0)
			return (TPM_LONG);
		return (TPM_SHORT);

	case TPM2_CC_GetRandom:
		return (TPM_MEDIUM);

	case TPM2_CC_HashSequenceStart:
	case TPM2_CC_SequenceUpdate:
	case TPM2_CC_SequenceComplete:
	case TPM2_CC_EventSequenceComplete:
		return (TPM_SHORT);

	case TPM2_CC_VerifySignature:
		return (TPM_MEDIUM);

	case TPM2_CC_PCR_Extend:
		return (TPM_SHORT);

	case TPM2_CC_HierarchyControl:
	case TPM2_CC_HierarchyChangeAuth:
		return (TPM_MEDIUM);

	case TPM2_CC_GetCapability:
		return (TPM_SHORT);

	case TPM2_CC_NV_Read:
		return (TPM_MEDIUM);

	default:
		return (TPM_MEDIUM);
	}

	return (TPM_MEDIUM);
}


TPM2_RC
tpm20_get_properties(tpm_t *tpm, tpm_client_t *c, uint32_t start,
    uint32_t count, bool (*cb)(uint32_t, uint32_t, bool, void *), void *arg)
{
	tpm_cmd_t *cmd;
	uint8_t *buf;
	uint8_t *end;
	int ret;
	TPM2_RC trc;
	uint32_t i, n, tag, val;
	bool more;

	IMPLY(c != NULL, MUTEX_HELD(&c->tpmc_lock));

	cmd = tpm20_get_cmd(tpm, c);

	tpm_cmd_init(cmd, tpm20_get_locality(c), TPM2_CC_GetCapability,
	    TPM2_ST_NO_SESSIONS);
	tpm_cmd_put32(cmd, TPM2_CAP_TPM_PROPERTIES);
	tpm_cmd_put32(cmd, start);
	tpm_cmd_put32(cmd, count);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		return (ret);
	}

	trc = tpm_cmd_rc(cmd);
	if (trc != TPM2_RC_SUCCESS) {
		(void) cb(0, 0, false, arg);

		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM2_CC_GetCapability(TPM2_CAP_TPM_PROPERTIES) failed "
		    "with %u", trc);
		return (EIO);
	}

	buf = cmd->tcmd_buf;
	end = buf + tpm_cmdlen(cmd);

	buf += TPM_HEADER_SIZE;

	more = (*buf++ != 0) ? true : false;

	/* capability -- should be what we asked for */
	val = BE_IN32(buf);
	if (val != TPM2_CAP_TPM_PROPERTIES) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM2_CC_GetCapability(TPM2_CAP_TPM_PROPERTIES) "
		    "returned wrong capability 0x%x", val);
		return (EIO);
	}
	buf += sizeof (uint32_t);

	/* Tagged property count */
	n = BE_IN32(buf);
	if (n == 0) {
		/* Property doesn't exist */
		return (ENOENT);
	}
	buf += sizeof (uint32_t);

	for (i = 0; i < n && buf < end; i++) {
		bool last = (i + 1 == n) ? true : false;

		tag = BE_IN32(buf);
		buf += sizeof (uint32_t);

		val = BE_IN32(buf);
		buf += sizeof (uint32_t);

		if (!cb(tag, val, more && last, arg))
			break;
	}

	return (0);
}

TPM2_RC
tpm20_generate_random(tpm_t *tpm, tpm_client_t *c, void *buf, size_t len)
{
	tpm_cmd_t	*cmd;
	int		ret;
	TPM2_RC		trc;

	if (len > UINT16_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	cmd = tpm20_get_cmd(tpm, c);

	tpm_cmd_init(cmd, tpm20_get_locality(c), TPM2_CC_GetRandom,
	    TPM2_ST_NO_SESSIONS);
	tpm_cmd_put16(cmd, len);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		/* XXX: Can we map to better errors here?
		 * Maybe CRYPTO_BUSY for timeouts?
		 */
		return (CRYPTO_FAILED);
	}

	trc = tpm_cmd_rc(cmd);
	if (trc != TPM2_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM2_CC_GetRandom failed with 0x%x", trc);
		/* TODO: Maybe map TPM rc codes to CRYPTO_xxx values */
		return (CRYPTO_FAILED);
	}

	/*
	 * The response includes the fixed sized TPM header, followed by
	 * a 16-bit length, followed by the random data.
	 *
	 * Verify we have at least len bytes of random data.
	 */
	if (tpm_getbuf16(cmd, TPM_HEADER_SIZE) < len) {
		return (CRYPTO_FAILED);
	}

	/* Copy out the random data */
	tpm_cmd_getbuf(cmd, TPM_HEADER_SIZE + sizeof (uint16_t), len, buf);

	return (CRYPTO_SUCCESS);
}

#define	TPM_STIR_MAX 128

TPM2_RC
tpm20_seed_random(tpm_t *tpm, tpm_client_t *c, void *buf, size_t len)
{
	tpm_cmd_t	*cmd = &c->tpmc_cmd;
	int		ret;
	TPM2_RC		trc;

	/* XXX: Should we maybe just truncate instead? */
	if (len > TPM_STIR_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	cmd = tpm20_get_cmd(tpm, c);

	tpm_cmd_init(cmd, tpm20_get_locality(c), TPM2_CC_StirRandom,
	    TPM2_ST_NO_SESSIONS);
	/*
	 * Note we've checked the value of 'len' at the start of
	 * tpm2_seed_random().
	 */
	tpm_cmd_put16(cmd, len);
	tpm_cmd_copy(cmd, buf, len);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		/* XXX: Map to better errors? */
		return (CRYPTO_FAILED);
	}

	trc = tpm_cmd_rc(cmd);
	if (trc != TPM2_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_CONT,
		    "!TPM2_CC_StirRandom failed with 0x%x", trc);
		/* TODO: Maybe map TPM return codes to CRYPTO_xxx values */
		return (CRYPTO_FAILED);
	}

	return (ret);
}

uint32_t
tpm20_get_ccattr(tpm_t *tpm, TPM2_CC cc)
{
	uint32_t *attrs = tpm->tpm20_cca;

	for (uint32_t i = 0; i < tpm->tpm20_num_cc; i++) {
		if (TPM2_CCA_IDX(attrs[i]) == cc) {
			return (attrs[i]);
		}
	}

	return (0);
}

TPM2_RC
tpm20_get_cmd_attr(tpm_t *tpm, tpm_client_t *c, uint32_t num_cc, uint32_t *buf)
{
	tpm_cmd_t	*cmd = &c->tpmc_cmd;
	TPM2_RC		rc;
	int		ret;
	uint32_t	offset;
	uint32_t	val;

	if (tpm->tpm20_num_cc == 0) {
		return (0);
	}

	cmd = tpm20_get_cmd(tpm, c);

	tpm_cmd_init(cmd, tpm20_get_locality(c), TPM2_CC_GetCapability,
	    TPM2_ST_NO_SESSIONS);
	tpm_cmd_put32(cmd, TPM2_CAP_COMMANDS);
	tpm_cmd_put32(cmd, TPM2_CAP_FIRST);
	tpm_cmd_put32(cmd, num_cc);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		return (ret);
	}

	rc = tpm_cmd_rc(cmd);
	if (rc != TPM2_RC_SUCCESS) {
		/* XXX */
		return (rc);
	}

	/* We ignore the first byte of the response */
	offset = TPM_HEADER_SIZE + 1;
	val = tpm_getbuf32(cmd, offset);

	if (val != TPM2_CAP_COMMANDS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM2_CC_GetCapability(TPM2_CAP_COMMANDS, TPM2_CAP_FIRST) "
		    "returned wrong capability %u\n", val);
		return (EIO);
	}
	offset += sizeof (uint32_t);

	val = tpm_getbuf32(cmd, offset);
	if (val != num_cc) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM2_CC_GetCapability(TPM2_CAP_COMMANDS, TPM2_CAP_FIRST) "
		    "returned %u commands, expecting %u\n", val, num_cc);
		return (EIO);
	}
	offset += sizeof (uint32_t);

	for (uint32_t i = 0; i < num_cc; i++) {
		buf[i] = tpm_getbuf32(cmd, offset);
		offset += sizeof (uint32_t);
	}

	return (0);
}
