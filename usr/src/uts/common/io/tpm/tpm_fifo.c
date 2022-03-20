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
 * Copyright 2022 Jason King
 */

#include "tpm_tis.h"

static uint8_t
tpm_tis_get_status(tpm_state_t *tpm)
{
	return (tpm_get8(tpm, TPM_STS));
}

static void
tpm_tis_set_ready(tpm_state_t *tpm)
{
	tpm_put8(tpm, TPM_STS, TPM_STS_CMD_READY);
}

static int
tpm_tis_wait_for_stat(tpm_state_t *tpm, uint8_t mask, clock_t timeout)
{
	int ret;

	clock_t absolute_timeout = ddi_get_lbolt() + timeout;

	/* Using polling */
	while ((tpm_tis_get_status(tpm) & mask) != mask) {
		if (ddi_get_lbolt() >= absolute_timeout) {
			/* Timeout reached */
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: using "
			    "polling - reached timeout (%ld usecs)",
			    __func__, drv_hztousec(timeout));
#endif
			return (DDI_FAILURE);
		}
		delay(tpm->timeout_poll);
	}
	return (DDI_SUCCESS);
}

/*
 * Whenever the driver wants to write to the DATA_IO register, it needs
 * to figure out the burstcount.  This is the amount of bytes it can write
 * before having to wait for the long LPC bus cycle
 *
 * Returns: 0 if error, burst count if sucess
 */
static uint16_t
tpm_tis_get_burstcount(tpm_state_t *tpm)
{
	clock_t stop;
	uint16_t burstcnt;

	ASSERT(tpm != NULL);

	/*
	 * Spec says timeout should be TIMEOUT_D
	 * burst count is TPM_STS bits 8..23
	 */
	stop = ddi_get_lbolt() + tpm->timeout_d;
	do {
		/*
		 * burstcnt is stored as a little endian value
		 * 'ntohs' doesn't work since the value is not word-aligned
		 */
		burstcnt = tpm_get8(tpm, TPM_STS + 1);
		burstcnt += tpm_get8(tpm, TPM_STS + 2) << 8;

		if (burstcnt > 0)
			return (burstcnt);

		delay(tpm->timeout_poll);
	} while (ddi_get_lbolt() < stop);

	return (0);
}

static bool
tis_fifo_make_ready(tpm_state_t *tpm)
{
	int ret;
	uint8_t status;

	status = tpm_tis_get_status(tpm);
	/* If already ready, we're done */
	if ((status & TPM_STS_CMD_READY) != 0)
		return (true);

	/*
	 * Otherwise, request the TPM to transition to the ready state, and
	 * wait until it is.
	 */
	tpm_tis_set_ready(tpm);
	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_CMD_READY, tpm->timeout_b);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: could not put the TPM "
		    "in the command ready state:"
		    "tpm_wait_for_state returned error",
		    __func__);
#endif
		return (false);
	}

	return (true);
}

int
tis_fifo_send_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsize)
{
	uint32_t ordinal;
	uint16_t burstcnt;
	int ret;

	if (bufsiz == 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: bufsiz arg is zero", __func__);
#endif
		return (EINVAL);
	}

	if (!tis_fifo_make_ready(tpm))
		return (ETIME);

	/*
	 * Now we are ready to send command
	 * TPM's burstcount dictates how many bytes we can write at a time
	 * Burstcount is dynamic if INTF_CAPABILITY for static burstcount is
	 * not set.
	 */
	while (count < bufsiz - 1) {
		burstcnt = tpm_tis_get_burstcount(tpm);
		if (burstcnt == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: tpm_get_burstcnt returned error",
			    __func__);
#endif
			ret = EIO;
			goto fail;
		}

		for (; burstcnt > 0 && count < bufsiz - 1; burstcnt--) {
			tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
			count++;
		}
		/* Wait for TPM to indicate that it is ready for more data */
		ret = tpm_tis_wait_for_stat(tpm,
		    (TPM_STS_VALID | TPM_STS_DATA_EXPECT), tpm->timeout_c);
		if (ret != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: TPM didn't enter STS_VALID "
			    "state", __func__);
#endif
			goto fail;
		}
	}
	/* We can't exit the loop above unless we wrote bufsiz-1 bytes */

	/* Write last byte */
	tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
	count++;

	/* Wait for the TPM to enter Valid State */
	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tpm didn't enter STS_VALID state",
		    __func__);
#endif
		goto fail;
	}

	status = tpm_tis_get_status(tpm);
	/* The TPM should NOT be expecing more data at this point */
	if ((status & TPM_STS_DATA_EXPECT) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: DATA_EXPECT should not be set after "
		    "writing the last byte: status=0x%08X", __func__, status);
#endif
		ret = EIO;
		goto fail;
	}

	/*
	 * Final step: Writing TPM_STS_GO to TPM_STS
	 * register will actually send the command.
	 */
	tpm_put8(tpm, TPM_STS, TPM_STS_GO);

	/* Ordinal/Command_code is located in buf[6..9] */
	orginal = BE_IN32(buf + TPM_COMMAND_CODE_OFFSET);

	ret = tpm_tis_wait_for_stat(tpm, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    tpm_get_ordinal_duration(tpm, ordinal));
	if (ret != 0) {
#ifdef DEBUG
		status = tpm_tis_get_status(tpm);
		if (!(status & TPM_STS_DATA_AVAIL) ||
		    !(status & TPM_STS_VALID)) {
			cmn_err(CE_WARN, "!%s: TPM not ready or valid "
			    "(ordinal = %d timeout = %ld status = 0x%0x)",
			    __func__, ordinal,
			    tpm_get_ordinal_duration(tpm, ordinal),
			    status);
		} else {
			cmn_err(CE_WARN, "!%s: tpm_wait_for_stat "
			    "(DATA_AVAIL | VALID) failed status = 0x%0X",
			    __func__, status);
		}
#endif
		goto fail;
	}
	return (0);

fail:
	tpm_tis_set_ready(tpm);
	tis_fifo_release_locality(tpm, tpm->locality, 0);
	return (ret);
}

static int
receive_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int size = 0;
	int retried = 0;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

	ASSERT(tpm != NULL && buf != NULL);
retry:
	while (size < bufsiz && (tpm_wait_for_stat(tpm,
	    (TPM_STS_DATA_AVAIL|TPM_STS_VALID),
	    tpm->timeout_c) == DDI_SUCCESS)) {
		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		burstcnt = tpm_get_burstcount(tpm);
		for (; burstcnt > 0 && size < bufsiz; burstcnt--) {
			buf[size++] = tpm_get8(tpm, TPM_DATA_FIFO);
		}
	}
	stsbits = tis_get_status(tpm);
	/* check to see if we need to retry (just once) */
	if (size < bufsiz && !(stsbits & TPM_STS_DATA_AVAIL) && retried == 0) {
		/* issue responseRetry (TIS 1.2 pg 54) */
		tpm_put8(tpm, TPM_STS, TPM_STS_RESPONSE_RETRY);
		/* update the retry counter so we only retry once */
		retried++;
		/* reset the size to 0 and reread the entire response */
		size = 0;
		goto retry;
	}
	return (size);
}

/* Receive the data from the TPM */
static int
tis_recv_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	int size = 0;
	uint32_t expected, status;
	uint32_t cmdresult;

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz < TPM_HEADER_SIZE) {
		/* There should be at least tag, paramsize, return code */
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data should contain at least "
		    "the header which is %d bytes long",
		    __func__, TPM_HEADER_SIZE);
#endif
		goto OUT;
	}

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	size = receive_data(tpm, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: recv TPM_HEADER failed, size = %d",
		    __func__, size);
#endif
		goto OUT;
	}

	cmdresult = tpm_getbuf32(buf, TPM_RETURN_OFFSET);

	/* Get 'paramsize'(4 bytes)--it includes tag and paramsize */
	expected = tpm_getbuf32(buf, TPM_PARAMSIZE_OFFSET);
	if (expected > bufsiz) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: paramSize is bigger "
		    "than the requested size: paramSize=%d bufsiz=%d result=%d",
		    __func__, (int)expected, (int)bufsiz, cmdresult);
#endif
		goto OUT;
	}

	/* Read in the rest of the data from the TPM */
	size += receive_data(tpm, (uint8_t *)&buf[TPM_HEADER_SIZE],
	    expected - TPM_HEADER_SIZE);
	if (size < expected) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data length (%d) "
		    "is less than expected (%d)", __func__, size, expected);
#endif
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);

	status = tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM didn't set stsValid after its I/O: "
		    "status = 0x%08X", __func__, status);
#endif
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM_STS_DATA_AVAIL is set:0x%08X",
		    __func__, status);
#endif
		goto OUT;
	}

	/*
	 * Release the control of the TPM after we are done with it
	 * it...so others can also get a chance to send data
	 */
	tis_release_locality(tpm, tpm->locality, 0);

OUT:
	tpm_set_ready(tpm);
	tis_release_locality(tpm, tpm->locality, 0);
	return (size);
}

/*
 * Checks whether the given locality is active
 * Use TPM_ACCESS register and the masks TPM_ACCESS_VALID,TPM_ACTIVE_LOCALITY
 */
static bool
tpm_tis_locality_active(tpm_t *tpm, uint8_t locality)
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

bool
tpm_tis_request_locality(tpm_state_t *tpm, uint_t locality)
{
	clock_t timeout;
	int ret;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));

	if (tpm_tis_locality_active(tpm, locality)) {
		tpm->tpm_locality = locality;
		return (true);
	}

	tpm_put8_loc(tpm, locality, TPM_ACCESS, TPM_ACCESS_REQUEST_USE);
	timeout = ddi_get_lbolt() + tpm->timeout_a;

	while (tis_check_active_locality(tpm, locality) != DDI_SUCCESS) {
		if (ddi_get_lbolt() >= timeout) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: (interrupt-disabled) "
			    "tis_request_locality timed out (timeout_a = %ld)",
			    __func__, tpm->timeout_a);
#endif
			return (false);
		}
		delay(tpm->timeout_poll);
	}

	tpm->tpm_locality = locality;
	return (true);
}

void
tpm_tis_relinquish_locality(tpm_state_t *tpm, uint8_t locality, bool force)
{
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	if (force ||
	    (tpm_get8_loc(tpm, locality, TPM_ACCESS) &
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) ==
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) {
		/*
		 * Writing 1 to active locality bit in TPM_ACCESS
		 * register reliquishes the control of the locality
		 */
		tpm_put8_loc(tpm, locality, TPM_ACCESS,
		    TPM_ACCESS_ACTIVE_LOCALITY);
	}
}

static uint_t
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
	cv_signal(tpm->tpm_intr_cv);

	return (DDI_INTR_CLAIMED);
}

int
tpm_tis_init(tpm_t *tpm)
{
	return (0);
}

int
tpm_tis_exec_cmd(tpm_client_t *c)
{
	return (0);
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
