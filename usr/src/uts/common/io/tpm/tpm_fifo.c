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

static bool
tis_burst_nonzero(tpm_t *tpm)
{
	uint32_t sts = tpm_get32(tpm, TPM_STS);

	return (TPM_STS_BURSTCOUNT(sts) > 0 ? true : false);
}

/*
 * Whenever the driver wants to write to the DATA_IO register, it needs
 * to figure out the burstcount.  This is the amount of bytes it can write
 * before having to wait for the long LPC bus cycle
 *
 * Returns: 0 if error, burst count if success
 */
static int
tpm_tis_get_burstcount(tpm_t *tpm, uint16_t *burstp)
{
	int ret;
	uint16_t burstcnt;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));

	ret = tpm_wait(tpm, tis_burst_nonzero, tpm->tpm_timeout_d);
	if (ret != 0) {
		return (ret);
	}

	*burstp = TPM_STS_BURSTCOUNT(tpm_get32(tpm, TPM_STS));
	return (0);
}

static bool
tis_is_ready(tpm_t *tpm)
{
	uint8_t sts = tpm_tis_get_status(tpm);

	return ((sts & TPM_STS_CMD_READY) != 0 ? true : false);
}

static int
tis_fifo_make_ready(tpm_t *tpm, clock_t to)
{
	int ret;
	uint8_t status;
	bool use_intr = tpm->tpm_u.tpmu_tis.ttis_has_cmd_ready_int;

	status = tpm_tis_get_status(tpm);

	/* If already ready, we're done */
	if ((status & TPM_STS_CMD_READY) != 0)
		return (0);

	/*
	 * Otherwise, request the TPM to transition to the ready state, and
	 * wait until it is.
	 */
	tpm_tis_set_ready(tpm);
	ret = tpm_wait(tpm, tis_is_ready, to);
	if (ret != 0) {
		/* XXX: ereport? */
		dev_err(tpm->tpm_dip, CE_WARN, "%s: failed to put TPM into "
		    "ready state", __func__);
		return (ret);
	}

	return (0);
}

static bool
tis_status_valid(tpm_t *tpm)
{
	uint8_t sts = tpm_tis_get_status(tpm);

	return ((sts & TPM_STS_VALID) != 0 ? true : false);
}

static int
tis_expecting_data(tpm_t *tpm, bool *expp)
{
	int ret;
	uint8_t sts;

	/*
	 * Wait for stsValid to be set before checking the Expect
	 * bit.
	 */
	ret = tpm_wait(tpm, tis_status_valid, tpm->tpm_timeout_c);
	if (ret != 0) {
		return (ret);
	}

	sts = tpm_tis_get_status(tpm);
	if ((sts & TPM_STS_VALID) == 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "status went from valid to non-valid");
		return (SET_ERROR(EIO));
	}

	*expp = (sts & TPM_STS_DATA_EXPECT) != 0 ? true : false;
	return (0);
}
	
static int
tis_send_data(tpm_t *tpm, uint8_t *buf, size_t amt)
{
	size_t count = 0;
	int ret;
	uint16_t burstcnt;
	bool expecting;

	VERIFY3U(amt, >, 0);

	/* Make sure the TPM is in the ready state */
	ret = tis_fifo_make_ready(tpm, tpm->tpm_timeout_b);
	if (ret != 0) {
		return (ret);
	}

	/*
	 * Send the command. The TPM's burst count determines how many
	 * how many bytes to write at one time. Once we write burstcount
	 * bytes, we must wait for the TPM to report a burstcount > 0
	 * before writing more bytes.
	 */
	while (count < amt) {
		ret = tpm_tis_get_burstcount(tpm, &burstcnt);
		switch (ret) {
		case 0:
			VERIFY3U(burstcnt, >, 0);
			break;
		case ETIME:
			dev_err(tpm->tpm_dip, CE_WARN,
			    "%s: timed out getting burst count", __func__);
			/*FALLTHRU*/
		case ECANCELED:
			return (ret);
		default:
			dev_err(tpm->tpm_dip, CE_PANIC,
			    "unexpected return value from "
			    "tpm_tis_get_burstcount: %d", ret);
		}

		if (count > 0) {
			/*
			 * Once the first byte is written to the TPM,
			 * Expect is set, and remains set until the
			 * last byte of the command has been written.
			 *
			 * Make sure if there is more data to write, that
			 * the TPM is expecting more data. We only check
			 * every burstcnt bytes as this is just a sanity
			 * check. Any data written after what the TPM
			 * believes is the last bytes of the command
			 * are ignored. If there is a disagreement between
			 * us and the TPM, we error out and abort the
			 * current command.
			 */
			ret = tis_expecting_data(tpm, &expecting);
			if (ret != 0) {
				return (ret);
			}

			if (!expecting) {
				dev_err(tpm->tpm_dip, CE_NOTE,
				    "TPM not expecting data before entire "
				    "command has been sent.");
				return (SET_ERROR(EIO));
			}
		}

		while (burstcnt > 0 && count < amt) {
			tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
			count++;
			burstcnt--;
		}
	}

	/*
	 * Verify that the TPM agrees that it's received the entire
	 * command.
	 */
	ret = tis_expecting_data(tpm, &expecting);
	if (ret != 0) {
		return (ret);
	}
	if (expecting) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "!%s: TPM still expecting data after writing last byte",
		    __func__);
		return (SET_ERROR(EIO));
	}

	/*
	 * Final step: Writing TPM_STS_GO to TPM_STS register to start
	 * execution of the command.
	 */
	tpm_put8(tpm, TPM_STS, TPM_STS_GO);

	return (0);
}

static bool
tis_data_avail(tpm_t *tpm)
{
	uint8_t status = tpm_tis_get_status(tpm);

	/*
	 * We shouldn't check the dataAvail bit unless the stsValid bit
	 * is set.
	 */
	if ((status & TPM_STS_VALID) == 0) {
		return (false);
	}

	return ((status & TPM_STS_DATA_AVAIL) ? true : false);
}

static int
tis_recv_chunk(tpm_t *tpm, uint8_t *buf, size_t amt)
{
	int size = 0;
	bool retried = false;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

retry:
	while (size < amt) {
		int ret;

		ret = tpm_wait(tpm, tis_data_avail, tpm->tpm_timeout_c);
		switch (ret) {
		case 0:
			break;
		case ECANCELED:
			return (ret);
		case ETIME:
			goto check_retry;
		default:
			dev_err(tpm->tpm_dip, CE_PANIC, "unexpected return "
			    "value from tpm_tis_wait_for_stat: %d", ret);
		}

		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		ret = tpm_tis_get_burstcount(tpm, &burstcnt);
		switch (ret) {
		case 0:
			break;
		case ECANCELED:
			return (ret);
		case ETIME:
			goto check_retry;
		default:
			dev_err(tpm->tpm_dip, CE_PANIC, "unexpected return "
			    "value from tpm_tis_get_burstcount: %d", ret);
		}

		for (; burstcnt > 0 && size < amt; burstcnt--) {
			buf[size++] = tpm_get8(tpm, TPM_DATA_FIFO);
		}
	}

check_retry:
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
		return (SET_ERROR(ENODATA));
	}

	return (0);
}

static bool
tis_status_is_valid(tpm_t *tpm)
{
	uint8_t sts = tpm_tis_get_status(tpm);

	return ((sts & TPM_STS_VALID) != 0 ? true : false);
}

static int
tis_recv_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	uint32_t expected, status;
	uint32_t cmdresult;

	/*
	 * We should always have a buffer large enough for the smallest
	 * result.
	 */
	VERIFY3U(bufsiz, >=, TPM_HEADER_SIZE);

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	ret = tis_recv_chunk(tpm, buf, TPM_HEADER_SIZE);
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
	ret = tis_recv_chunk(tpm, buf + TPM_HEADER_SIZE,
	    expected - TPM_HEADER_SIZE);
	if (ret != 0) {
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_wait(tpm, tis_status_is_valid, tpm->tpm_timeout_c);

	status = tpm_tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!failed to set valid status after I/O; status = 0x%08X",
		    status);
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!reported more data after reading result "
		    "(TPM_STS_DATA_AVAIL still set: 0x%08X", status);
	}

OUT:
	/*
	 * Release the control of the TPM after we are done with it
	 * it...so others can also get a chance to send data
	 */
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

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	/* Just check to see if the requested locality works */
	access_bits = tpm_get8_loc(tpm, locality, TPM_ACCESS);

	access_bits &= (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID);

	if (access_bits == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
		return (true);
	} else {
		return (false);
	}
}

static bool
tis_is_locality_active(tpm_t *tpm)
{
	return (tis_locality_active(tpm, tpm->tpm_locality));
}

static int
tis_request_locality(tpm_t *tpm, uint8_t locality)
{
	int ret;
	uint8_t old_locality = tpm->tpm_locality;
	uint8_t mask;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	if (tis_locality_active(tpm, locality)) {
		tpm->tpm_locality = locality;
		return (0);
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

	ret = tpm_wait(tpm, tis_is_locality_active, tpm->tpm_timeout_a);
	switch (ret) {
	case 0:
		break;
	case ETIME:
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "timed out requesting locality %hhu", locality);
		/*FALLTHRU*/
	case ECANCELED:
		tis_release_locality(tpm, locality, true);
		tpm->tpm_locality = old_locality;
		return (ret);
	default:
		dev_err(tpm->tpm_dip, CE_PANIC,
		    "unexpected value from tpm_wait_u8: %d", ret);
	}

	return (0);
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
	cv_signal(&tpm->tpm_thr_cv);

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

	// ttis_burst_count / ttis_burst_static
	
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
	uint32_t cmdlen;
	int ret, ret2;
	clock_t to;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY(tpm->tpm_iftype == TPM_IF_TIS || tpm->tpm_iftype == TPM_IF_FIFO);
	VERIFY3U(buflen, >=, TPM_HEADER_SIZE);

	cmdlen = tpm_cmdlen(buf);
	VERIFY3U(cmdlen, >=, TPM_HEADER_SIZE);
	VERIFY3U(cmdlen, <=, buflen);

	ret = tis_request_locality(tpm, loc);
	if (ret != 0) {
		return (ret);
	}

	ret = tis_send_data(tpm, buf, cmdlen);
	if (ret != 0) {
		goto done;
	}

	ret = tpm_wait_cmd(tpm, buf, tis_data_avail);
	if (ret != 0) {
		goto done;
	}

	ret = tis_recv_data(tpm, buf, buflen);

done:
	/*
	 * If we were cancelled, we defer putting the TPM into the ready
	 * state (which will stop any current execution) and release the
	 * locality until after we've released the client so it's not
	 * blocking while waiting for the TPM to cancel the operation.
	 */
	if (ret != ECANCELED) {
		tpm_tis_set_ready(tpm);

		/*
		 * Release the locality after completion to allow a lower value
		 * locality to use the TPM.
		 */
		tis_release_locality(tpm, loc, false);
	}

	return (ret);
}

void
tis_cancel_cmd(tpm_t *tpm, tpm_duration_t dur)
{
	clock_t to;

	switch (dur) {
	case TPM_SHORT:
	case TPM_MEDIUM:
		to = tpm->tpm_timeout_a;
		break;
	default:
		to = tpm->tpm_timeout_b;
		break;
	}

	(void) tis_fifo_make_ready(tpm, to);
	tis_release_locality(tpm, tpm->tpm_locality, false);
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
