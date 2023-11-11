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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 Jason King
 */

#include "tpm_ddi.h"
#include "tpm_tis.h"
#include "tpm20.h"

static void tis_release_locality(tpm_t *, uint8_t, bool);

static uint8_t
tpm_tis_get_status(tpm_t *tpm)
{
	return (tpm_get8(tpm, TPM_STS));
}

static void
tpm_tis_set_ready(tpm_t *tpm)
{
	tpm_put8(tpm, TPM_STS, TPM_STS_CMD_READY);
}

static int
tpm_tis_wait_for_stat(tpm_t *tpm, uint8_t mask, clock_t timeout,
    bool intr)
{
	return (tpm_wait_u32(tpm, TPM_STS, mask, mask, timeout, intr));
}

/*
 * Whenever the driver wants to write to the DATA_IO register, it needs
 * to figure out the burstcount.  This is the amount of bytes it can write
 * before having to wait for the long LPC bus cycle
 *
 * Returns: 0 if error, burst count if success
 */
static uint16_t
tpm_tis_get_burstcount(tpm_t *tpm)
{
	clock_t stop;
	uint16_t burstcnt;

	ASSERT(tpm != NULL);

	/*
	 * Spec says timeout should be TIMEOUT_D
	 * burst count is TPM_STS bits 8..23
	 */
	stop = ddi_get_lbolt() + tpm->tpm_timeout_d;
	do {
		uint32_t sts = tpm_get32(tpm, TPM_STS);

		burstcnt = TPM_STS_BURSTCOUNT(sts);
		if (burstcnt > 0)
			return (burstcnt);

		/* XXX: use intr_cv to allow cancellation? */
		delay(tpm->tpm_timeout_poll);
	} while (ddi_get_lbolt() < stop);

	return (0);
}

static bool
tis_fifo_make_ready(tpm_t *tpm)
{
	int ret;
	uint8_t status;
	bool use_intr = tpm->tpm_u.tpmu_tis.ttis_has_cmd_ready_int;

	status = tpm_tis_get_status(tpm);

	/* If already ready, we're done */
	if ((status & TPM_STS_CMD_READY) != 0)
		return (true);

	/*
	 * Otherwise, request the TPM to transition to the ready state, and
	 * wait until it is.
	 */
	tpm_tis_set_ready(tpm);
	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_CMD_READY, tpm->tpm_timeout_b,
	    use_intr);
	if (ret != 0) {
		/* XXX: ereport? */
		dev_err(tpm->tpm_dip, CE_WARN, "%s: failed to put TPM into "
		    "ready state", __func__);
		return (false);
	}

	return (true);
}

static int
tis_send_data(tpm_t *tpm, uint8_t *buf, size_t amt)
{
	clock_t to;
	size_t count = 0;
	int ret;
	uint32_t ordinal;
	uint16_t burstcnt;
	uint8_t status;
	bool use_intr = tpm->tpm_u.tpmu_tis.ttis_has_sts_valid_int;

	VERIFY3U(amt, >, 0);

	if (!tis_fifo_make_ready(tpm))
		return (SET_ERROR(ETIME));

	/*
	 * Now we are ready to send command
	 * TPM's burstcount dictates how many bytes we can write at a time
	 * Burstcount is dynamic if INTF_CAPABILITY for static burstcount is
	 * not set.
	 */
	while (count < amt - 1) {
		burstcnt = tpm_tis_get_burstcount(tpm);
		if (burstcnt == 0) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "%s: timed out getting burst count", __func__);
			ret = SET_ERROR(EIO);
			goto fail;
		}

		for (; burstcnt > 0 && count < amt - 1; burstcnt--) {
			tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
			count++;
		}
		/* Wait for TPM to indicate that it is ready for more data */
		ret = tpm_tis_wait_for_stat(tpm,
		    (TPM_STS_VALID | TPM_STS_DATA_EXPECT), tpm->tpm_timeout_c,
		    false);
		if (ret != 0) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "%s: timeout waiting to enter STS_VALID state "
			    "while writing command", __func__);
			goto fail;
		}
	}
	/* We can't exit the loop above unless we wrote amt-1 bytes */

	/* Write last byte */
	tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
	count++;

	/* Wait for the TPM to enter Valid State */
	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_VALID, tpm->tpm_timeout_c,
	    use_intr);
	if (ret != 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "%s: timeout waiting to enter STS_VALID state", __func__);
		goto fail;
	}

	status = tpm_tis_get_status(tpm);

	/*
	 * The TPM should NOT be expecing more data at this point. This
	 * could be user error, so we only display in verbose mode, otherwise
	 * we just return the error.
	 */
	if ((status & TPM_STS_DATA_EXPECT) != 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "!%s: TPM still expecting data after writing last byte",
		    __func__);
		ret = SET_ERROR(EIO);
		goto fail;
	}

	/*
	 * Final step: Writing TPM_STS_GO to TPM_STS
	 * register will actually send the command.
	 */
	tpm_put8(tpm, TPM_STS, TPM_STS_GO);

	/* Ordinal/Command_code is located in buf[6..9] */
	ordinal = tpm_cmd(buf);
	to = tpm_get_ordinal_duration(tpm, ordinal);

	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    to, true);
	if (ret != 0) {
#ifdef DEBUG
		status = tpm_tis_get_status(tpm);
		if (!(status & TPM_STS_DATA_AVAIL) ||
		    !(status & TPM_STS_VALID)) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "!%s: TPM not ready or valid "
			    "(ordinal = %d timeout = %ld status = 0x%0x)",
			    __func__, ordinal, to, status);
		} else {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "!%s: tpm_tis_wait_for_stat "
			    "(DATA_AVAIL | VALID) failed status = 0x%0X",
			    __func__, status);
		}
#endif
		goto fail;
	}
	return (0);

fail:
	tpm_tis_set_ready(tpm);
	tis_release_locality(tpm, tpm->tpm_locality, false);
	return (ret);
}

static int
receive_data(tpm_t *tpm, uint8_t *buf, size_t amt)
{
	int size = 0;
	bool retried = false;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

retry:
	while (size < amt) {
		int ret;

		ret = tpm_tis_wait_for_stat(tpm,
		    TPM_STS_DATA_AVAIL|TPM_STS_VALID, tpm->tpm_timeout_c,
		    false);
		if (ret != 0) {
			break;
		}

		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		burstcnt = tpm_tis_get_burstcount(tpm);
		for (; burstcnt > 0 && size < amt; burstcnt--) {
			buf[size++] = tpm_get8(tpm, TPM_DATA_FIFO);
		}
	}
	stsbits = tpm_tis_get_status(tpm);

	/* check to see if we need to retry (just once) */
	if (size < amt && !(stsbits & TPM_STS_DATA_AVAIL) && !retried) {
		/* issue responseRetry (TIS 1.2 pg 54) */
		tpm_put8(tpm, TPM_STS, TPM_STS_RESPONSE_RETRY);

		/* update the retry counter so we only retry once */
		retried = true;

		/* reset the size to 0 and reread the entire response */
		size = 0;
		goto retry;
	}

	if (size != amt) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!short read: expected %lu, read %u", amt, size);
		/* XXX: Better error value? */
		return (ENODATA);
	}

	return (0);
}

/* Receive the data from the TPM */
static int
tis_recv_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz, clock_t to)
{
	int ret;
	int size = 0;
	uint32_t expected, status;
	uint32_t cmdresult;

	/*
	 * We should always have a buffer large enough for the smallest
	 * result.
	 */
	VERIFY3U(bufsiz, >=, TPM_HEADER_SIZE);

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	ret = receive_data(tpm, buf, TPM_HEADER_SIZE);
	if (ret != 0) {
		goto OUT;
	}

	/* If we succeeded, we have TPM_HEADER_SIZE bytes in buf */
	cmdresult = tpm_getbuf32(buf, TPM_RETURN_OFFSET);

	/* Get 'paramsize'(4 bytes)--it includes tag and paramsize */
	expected = tpm_getbuf32(buf, TPM_PARAMSIZE_OFFSET);
	if (expected > bufsiz) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "!command returned more data than expected: "
		    "amount returned = %u max = %lu command result = %d",
		    expected, bufsiz, cmdresult);

		goto OUT;
	}

	/* Read in the rest of the data from the TPM */
	ret = receive_data(tpm, buf + TPM_HEADER_SIZE,
	    expected - TPM_HEADER_SIZE);
	if (ret != 0) {
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_VALID, tpm->tpm_timeout_c,
	    false);

	status = tpm_tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "!failed to set valid status after I/O; status = 0x%08X",
		    status);
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "!reported more data after reading result "
		    "(TPM_STS_DATA_AVAIL still set: 0x%08X", status);
		goto OUT;
	}

	/*
	 * Release the control of the TPM after we are done with it
	 * it...so others can also get a chance to send data
	 */
	tis_release_locality(tpm, tpm->tpm_locality, 0);

OUT:
	tpm_tis_set_ready(tpm);
	tis_release_locality(tpm, tpm->tpm_locality, 0);
	return (ret);
}

/*
 * Checks whether the given locality is active
 * Use TPM_ACCESS register and the masks TPM_ACCESS_VALID,TPM_ACTIVE_LOCALITY
 */
static bool
tis_locality_active(tpm_t *tpm, uint8_t locality)
{
	uint8_t access_bits;
	uint8_t current_locality;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	/* Just check to see if the requested locality works */
	current_locality = tpm->tpm_locality;
	tpm->tpm_locality = locality;
	access_bits = tpm_get8(tpm, TPM_ACCESS);
	tpm->tpm_locality = current_locality;

	access_bits &= (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID);

	if (access_bits == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
		return (true);
	} else {
		return (false);
	}
}

static bool
tis_request_locality(tpm_t *tpm, uint8_t locality)
{
	int ret;
	uint8_t old_locality = tpm->tpm_locality;
	uint8_t mask;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	if (tis_locality_active(tpm, locality)) {
		tpm->tpm_locality = locality;
		return (true);
	}

	mask = TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY;

	/*
	 * Unlike CRB, where the TPM_LOC_STATE_x register can be read from
	 * any locality to determine the active locality, for TIS/FIFO we
	 * must read the TPM_ACCESS in register for a given locality to
	 * determine if it is the active locality.
	 */
	tpm->tpm_locality = locality;
	tpm_put8(tpm, TPM_ACCESS, TPM_ACCESS_REQUEST_USE);

	ret = tpm_wait_u8(tpm, TPM_ACCESS, mask, mask, tpm->tpm_timeout_a,
	    true);
	if (ret != 0) {
		/* Restore what we think the current locality is */
		tpm->tpm_locality = old_locality;
	}

	return ((ret == 0) ? true : false);
}

static void
tis_release_locality(tpm_t *tpm, uint8_t locality, bool force)
{
	uint8_t orig_loc = tpm->tpm_locality;

	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	tpm->tpm_locality = locality;
	if (force ||
	    (tpm_get8(tpm, TPM_ACCESS) &
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) ==
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) {
		/*
		 * Writing 1 to active locality bit in TPM_ACCESS
		 * register reliquishes the control of the locality
		 */
		tpm_put8(tpm, TPM_ACCESS, TPM_ACCESS_ACTIVE_LOCALITY);
	}
	tpm->tpm_locality = orig_loc;
}

uint_t
tpm_tis_intr(caddr_t arg0, caddr_t arg1 __unused)
{
	const uint32_t mask = TPM_TIS_INT_CMD_READY |
	    TPM_TIS_INT_LOCALITY_CHANGED | TPM_TIS_INT_STATUS_VALID |
	    TPM_TIS_INT_DATA_AVAIL;

	tpm_t *tpm = (tpm_t *)arg0;
	uint32_t status;

	status = tpm_get32(tpm, TPM_INT_STATUS);
	if ((status & mask) == 0) {
		/* Not us */
		return (DDI_INTR_UNCLAIMED);
	}

	/* Ack the interrupt */
	tpm_put32(tpm, TPM_INT_STATUS, status);

	/*
	 * For now at least, it's enough to signal the waiting command to
	 * recheck their appropriate register.
	 */
	cv_signal(&tpm->tpm_intr_cv);

	return (DDI_INTR_CLAIMED);
}

bool
tpm_tis_init(tpm_t *tpm)
{
	tpm_tis_t *tis = &tpm->tpm_u.tpmu_tis;
	uint32_t cap;
	uint32_t devid;
	uint8_t revid;

	VERIFY(tpm->tpm_iftype == TPM_IF_TIS || tpm->tpm_iftype == TPM_IF_FIFO);

	cap = tpm_get32(tpm, TPM_INTF_CAP);

	switch (tpm->tpm_iftype) {
	case TPM_IF_TIS:
		switch (TIS_INTF_VER_VAL(cap)) {
		case TIS_INTF_VER_VAL_1_21:
		case TIS_INTF_VER_VAL_1_3:
			tpm->tpm_family = TPM_FAMILY_1_2;
			break;
		case TIS_INTF_VER_VAL_1_3_TPM:
			tpm->tpm_family = TPM_FAMILY_2_0;
			break;
		default:
			dev_err(tpm->tpm_dip, CE_NOTE,
			    "!%s: unknown TPM interface version 0x%x", __func__,
			    TIS_INTF_VER_VAL(cap));
			return (false);
		}
		break;
	case TPM_IF_FIFO:
		VERIFY3S(tpm->tpm_family, ==, TPM_FAMILY_2_0);
		break;
	default:
		/*
		 * We should only be called if the TPM is using the TIS
		 * or FIFO interface.
		 */
		dev_err(tpm->tpm_dip, CE_PANIC, "%s: invalid interface type %d",
		    __func__, tpm->tpm_iftype);
		break;
	}

	devid = tpm_get32(tpm, TPM_DID_VID);
	revid = tpm_get8(tpm, TPM_RID);

	tpm->tpm_did = devid >> 16;
	tpm->tpm_vid = devid & 0xffff;
	tpm->tpm_rid = revid;

	tis->ttis_state = TPMT_ST_IDLE;
	tis->ttis_xfer_size = TIS_INTF_XFER_VAL(cap);

	/* Both of these are mandated by the spec */
	if ((cap & TPM_INTF_CAP_DATA_AVAIL) == 0) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM does not support mandatory data available interrupt");
		return (false);
	}
	if ((cap & TPM_INTF_CAP_LOC_CHANGED) == 0) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM does not support mandatory locality changed "
		    "interrupt");
		return (false);
	}

	/* These are optional */
	if ((cap & TPM_INTF_CAP_STS_VALID) != 0) {
		tis->ttis_has_sts_valid_int = true;
	}
	if ((cap & TPM_INTF_CAP_CMD_READY) != 0) {
		tis->ttis_has_cmd_ready_int = true;
	}

	switch (tpm->tpm_family) {
	case TPM_FAMILY_1_2:
		return (tpm12_init(tpm));
	case TPM_FAMILY_2_0:
		return (tpm20_init(tpm));
	}
	return (false);
}

int
tis_exec_cmd(tpm_t *tpm, uint8_t loc, uint8_t *buf, size_t buflen)
{
	clock_t to;
	uint32_t cmd, cmdlen;
	int ret;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY(tpm->tpm_iftype == TPM_IF_TIS || tpm->tpm_iftype == TPM_IF_FIFO);
	VERIFY3U(buflen, >=, TPM_HEADER_SIZE);

	cmdlen = tpm_cmdlen(buf);
	VERIFY3U(cmdlen, >=, TPM_HEADER_SIZE);
	VERIFY3U(cmdlen, <=, buflen);

	if (!tis_request_locality(tpm, loc)) {
		return (ETIME);
	}

	ret = tis_send_data(tpm, buf, cmdlen);
	if (ret != 0) {
		goto done;
	}

	cmd = tpm_cmd(buf);
	to = tpm_get_ordinal_duration(tpm, cmd);
	ret = tis_recv_data(tpm, buf, buflen, to);

done:
	/*
	 * Release the locality after completion to allow a lower value
	 * locality to use the TPM.
	 */
	tis_release_locality(tpm, loc, false);
	return (ret);
}

int
tpm_tis_cancel_cmd(tpm_client_t *c)
{
	return (0);
}

void
tpm_tis_intr_mgmt(tpm_t *tpm, bool enable)
{
	tpm_tis_t *tis = &tpm->tpm_u.tpmu_tis;
	uint32_t mask = 0;

	VERIFY(tpm->tpm_use_interrupts);

	if (enable) {
		/* Enable global interrupts */
		mask |= TPM_INT_GLOBAL_EN;

		/*
		 * Enable locality change and data available. These are
		 * always supported.
		 */
		mask |= TPM_INT_LOCAL_CHANGE_INT_EN;
		mask |= TPM_INT_STS_DATA_AVAIL_EN;

		if (tis->ttis_has_sts_valid_int) {
			mask |= TPM_INT_STS_VALID_EN;
		}
		if (tis->ttis_has_cmd_ready_int) {
			mask |= TPM_INT_STS_DATA_AVAIL_EN;
		}
	}

	tpm_put32(tpm, TPM_INT_ENABLE, mask);
}
