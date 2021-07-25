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
 * Copyright 2021 Jason King
 */

#include "tpm_tis.h"

static uint8_t
tis_fifo_get_status(tpm_state_t *tpm)
{
	return (tpm_get8(tpm, TPM_STS));
}

static void
tis_fifo_set_ready(tpm)
{
	tpm_put8(tpm, TPM_STS, TPM_STS_CMD_READY);
}

static int
tpm_fifo_wait_for_stat(tpm_state_t *tpm, uint8_t mask, clock_t timeout)
{
	clock_t absolute_timeout = ddi_get_lbolt() + timeout;

	/* Using polling */
	while ((tis_fifo_get_status(tpm) & mask) != mask) {
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
 * Whenever the driver wants to write to the DATA_IO register, it must need
 * to figure out the burstcount.  This is the amount of bytes it can write
 * before having to wait for long LPC bus cycle
 *
 * Returns: 0 if error, burst count if sucess
 */
static uint16_t
tpm_fifo_get_burstcount(tpm_state_t *tpm) {
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

		if (burstcnt)
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

	status = tis_fifo_get_status(tpm);
	/* If already ready, we're done */
	if ((status & TPM_STS_CMD_READY) != 0)
		return (true);

	/*
	 * Otherwise, request the TPM to transition to the ready state, and
	 * wait until it is.
	 */
	tpm_fifo_set_ready(tpm);
	ret = tpm_fifo_wait_for_stat(tpm, TPM_STS_CMD_READY, tpm->timeout_b);
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
		burstcnt = tpm_fifo_get_burstcount(tpm);
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
		ret = tpm_fifo_wait_for_stat(tpm,
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
	ret = tpm_fifo_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tpm didn't enter STS_VALID state",
		    __func__);
#endif
		goto fail;
	}

	status = tis_fifo_get_status(tpm);
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
	ordinal = load32(buf, TPM_COMMAND_CODE_OFFSET);

	ret = tpm_fifo_wait_for_stat(tpm, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    tpm_get_ordinal_duration(tpm, ordinal));
	if (ret != 0) {
#ifdef DEBUG
		status = tis_fifo_get_status(tpm);
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
	tpm_fifo_set_ready(tpm);
	tis_fifo_release_locality(tpm, tpm->locality, 0);
	return (ret);
}

bool
tis_fifo_request_locality(tpm_state_t *tpm, uint_t locality)
{
	return (false);
}

void
tis_fifo_relinquish_locality(tpm_state_t *tpm)
{
}
