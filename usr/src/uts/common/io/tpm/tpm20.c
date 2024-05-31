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
#include <sys/types.h>

#include "tpm_ddi.h"
#include "tpm20.h"

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

static void tpm20_get_cmd_attr(tpm_t *);
static bool tpm20_get_prop_cb(TPM_RC, bool, uint32_t, uint32_t, void *);

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

	/*
	 * Get all of the fixed properties. We'll ignore the ones we
	 * don't care about, and this avoid broken TPM implementations
	 * like NitroTPM that return garbage when requesting fewer than
	 * 9 properties for some bizarre reason.
	 */
	(void) tpm20_get_properties(tpm, PT_FIXED, 256,
	    tpm20_get_prop_cb, tpm);

	tpm20_get_cmd_attr(tpm);
	return (true);
}

static bool
tpm20_get_prop_cb(uint32_t rc, bool more, uint32_t tag, uint32_t val, void *arg)
{
	tpm_t *tpm = arg;

	switch (tag) {
	case TPM_PT_MAX_OBJECT_CONTEXT:
		tpm->tpm_object_size = val;
		break;
	case TPM_PT_MAX_SESSION_CONTEXT:
		tpm->tpm_session_size = val;
		break;
	case TPM_PT_TOTAL_COMMANDS:
		tpm->tpm20_num_cc = val;
		break;
	case TPM_PT_HR_TRANSIENT_MIN:
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
tpm20_get_duration_type(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	switch (cmd) {
	case TPM_CC_Startup:
		return (TPM_SHORT);

	case TPM_CC_SelfTest:
		/*
		 * Immediately after the buffer is the fullTest parameter.
		 * If true, a full test is done which uses the long timeout.
		 * Otherwise a short duration is used.
		 */
		if (buf[TPM_HEADER_SIZE] != 0)
			return (TPM_LONG);
		return (TPM_SHORT);

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


int
tpm20_get_properties(tpm_t *tpm, uint32_t start, uint32_t count,
    bool (*cb)(TPM_RC, bool, uint32_t, uint32_t, void *), void *arg)
{
	tpm_client_t *c = tpm->tpm_internal_client;
	uint8_t *buf = c->tpmc_buf;
	uint8_t *end;
	int ret;
	TPM_RC trc;
	uint32_t i, n, tag, val;
	bool more;

	tpm_int_newcmd(c, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);
	tpm_int_put32(c, TPM_CAP_TPM_PROPERTIES);
	tpm_int_put32(c, start);
	tpm_int_put32(c, count);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (ret);
	}

	trc = tpm_int_rc(c);
	if (trc != TPM_RC_SUCCESS) {
		(void) cb(trc, false, 0, 0, arg);

		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetCapability(TPM_CAP_TPM_PROPERTIES) failed "
		    "with %u", trc);
		return (EIO);
	}

	end = buf + tpm_cmdlen(buf);

	buf += TPM_HEADER_SIZE;

	more = (*buf++ != 0) ? true : false;

	/* capability -- should be what we asked for */
	val = BE_IN32(buf);
	if (val != TPM_CAP_TPM_PROPERTIES) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetCapability(TPM_CAP_TPM_PROPERTIES) "
		    "returned wrong capability 0x%x", val);
		return (EIO);
	}
	buf += sizeof (uint32_t);

	/* Tagged property count */
	n = BE_IN32(buf);
	if (n == 0) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

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

		if (!cb(trc, more && last, tag, val, arg))
			break;
	}

	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	return (0);
}

int
tpm20_generate_random(tpm_t *tpm, uchar_t *buf, size_t len)
{
	tpm_client_t *c = tpm->tpm_internal_client;
	uint8_t *cmd = c->tpmc_buf;
	int ret;
	TPM_RC trc;

	if (len > UINT16_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

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

	trc = tpm_int_rc(c);
	if (trc != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetRandom failed with 0x%x", trc);
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
	int		ret;
	TPM_RC		trc;

	/* XXX: Should we maybe just truncate instead? */
	if (len > TPM_STIR_MAX) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	tpm_int_newcmd(c, TPM_ST_NO_SESSIONS, TPM_CC_StirRandom);
	tpm_int_put16(c, (uint16_t)len);
	tpm_int_copy(c, buf, len);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		/* XXX: Map to better errors? */
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	trc = tpm_int_rc(c);
	if (trc != TPM_RC_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_CONT,
		    "!TPM_CC_StirRandom failed with 0x%x", trc);
		/* TODO: Maybe map TPM return codes to CRYPTO_xxx values */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (CRYPTO_FAILED);
	}

	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	return (ret);
}

uint32_t
tpm20_get_ccattr(tpm_t *tpm, TPM_CC cc)
{
	uint32_t *attrs = tpm->tpm20_cca;

	for (uint32_t i = 0; i < tpm->tpm20_num_cc; i++) {
		if (TPM_CCA_IDX(attrs[i]) == cc) {
			return (attrs[i]);
		}
	}

	return (0);
}

static void
tpm20_get_cmd_attr(tpm_t *tpm)
{
	tpm_client_t	*c = tpm->tpm_internal_client;
	uint8_t		*buf = c->tpmc_buf;
	TPM_RC		rc;
	int		ret;
	uint32_t	val;

	if (tpm->tpm20_num_cc == 0) {
		return;
	}

	tpm_int_newcmd(c, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);
	tpm_int_put32(c, TPM_CAP_COMMANDS);
	tpm_int_put32(c, TPM_CAP_FIRST);
	tpm_int_put32(c, tpm->tpm20_num_cc);

	ret = tpm_exec_internal(tpm, c);
	if (ret != 0) {
		mutex_exit(&c->tpmc_lock);
		return;
	}

	rc = tpm_int_rc(c);
	if (rc != TPM_RC_SUCCESS) {
		/* XXX */
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

		return;
	}

	tpm->tpm20_cca = kmem_zalloc(tpm->tpm20_num_cc * sizeof (uint32_t),
	    KM_SLEEP);

	buf += TPM_HEADER_SIZE;
	buf += 1; /* TPMI_YES_NO */

	val = BE_IN32(buf);
	if (val != TPM_CAP_COMMANDS) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetCapability(TPM_CAP_COMMANDS, TPM_CAP_FIRST) "
		    "returned wrong capability %u\n", val);
		return;
	}
	buf += sizeof (uint32_t);

	val = BE_IN32(buf);
	if (val != tpm->tpm20_num_cc) {
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);

		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM_CC_GetCapability(TPM_CAP_COMMANDS, TPM_CAP_FIRST) "
		    "returned %u commands, expecting %u\n", val,
		    tpm->tpm20_num_cc);
		return;
	}
	buf += sizeof (uint32_t);

	for (uint32_t i = 0; i < tpm->tpm20_num_cc; i++) {
		tpm->tpm20_cca[i] = BE_IN32(buf);
		buf += sizeof (uint32_t);
	}

	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
}
