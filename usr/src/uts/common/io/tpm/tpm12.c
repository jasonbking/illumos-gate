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
 */

/* TSC Ordinals */
static const TPM_DURATION_T tpm12_ords_duration[TPM_ORDINAL_MAX] = {
	TPM_UNDEFINED,		/* 0 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 5 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 10 */
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_LONG,
	TPM_LONG,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_LONG,
	TPM_SHORT,		/* 20 */
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_SHORT,		/* 25 */
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_MEDIUM,		/* 30 */
	TPM_LONG,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,		/* 35 */
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_MEDIUM,		/* 40 */
	TPM_LONG,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,		/* 45 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_LONG,
	TPM_MEDIUM,		/* 50 */
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 55 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_MEDIUM,		/* 60 */
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_MEDIUM,		/* 65 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 70 */
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 75 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_LONG,		/* 80 */
	TPM_UNDEFINED,
	TPM_MEDIUM,
	TPM_LONG,
	TPM_SHORT,
	TPM_UNDEFINED,		/* 85 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 90 */
	TPM_LONG,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,		/* 95 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_MEDIUM,		/* 100 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 105 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 110 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,		/* 115 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_LONG,		/* 120 */
	TPM_LONG,
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_SHORT,
	TPM_SHORT,		/* 125 */
	TPM_SHORT,
	TPM_LONG,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,		/* 130 */
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_UNDEFINED,		/* 135 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 140 */
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 145 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 150 */
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,		/* 155 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 160 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 165 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_LONG,		/* 170 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 175 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_MEDIUM,		/* 180 */
	TPM_SHORT,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_MEDIUM,		/* 185 */
	TPM_SHORT,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 190 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 195 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 200 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,
	TPM_SHORT,		/* 205 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_MEDIUM,		/* 210 */
	TPM_UNDEFINED,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_MEDIUM,
	TPM_UNDEFINED,		/* 215 */
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,
	TPM_SHORT,		/* 220 */
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_SHORT,
	TPM_UNDEFINED,		/* 225 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 230 */
	TPM_LONG,
	TPM_MEDIUM,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 235 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 240 */
	TPM_UNDEFINED,
	TPM_MEDIUM,
};

/* TPM connection ordinals */
static const uint8_t tsc12_ords_duration[TSC_ORDINAL_MAX] = {
	TPM_UNDEFINED,		/* 0 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,		/* 5 */
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_UNDEFINED,
	TPM_SHORT,		/* 10 */
	TPM_SHORT,
};

/*
 * Get the actual timeouts supported by the TPM by issuing TPM_GetCapability
 * with the subcommand TPM_CAP_PROP_TIS_TIMEOUT
 * TPM_GetCapability (TPM Main Part 3 Rev. 94, pg.38)
 */
static int
tpm12_get_timeouts(tpm_state_t *tpm)
{
	int ret;
	uint32_t timeout;   /* in milliseconds */
	uint32_t len;

	/* The buffer size (30) needs room for 4 timeout values (uint32_t) */
	uint8_t buf[30] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TPM_CAP_Prop */
		0, 0, 0, 4,	/* SUB_CAP size in bytes */
		0, 0, 1, 21	/* TPM_CAP_PROP_TIS_TIMEOUT(0x115) */
	};

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: itpm_command failed", __func__);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Get the length of the returned buffer
	 * Make sure that there are 4 timeout values returned
	 * length of the capability response is stored in data[10-13]
	 * Also the TPM is in network byte order
	 */
	len = load32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len != 4 * sizeof (uint32_t)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: capability response size should be %d"
		    "instead len = %d",
		    __func__, (int)(4 * sizeof (uint32_t)), (int)len);
#endif
		return (DDI_FAILURE);
	}

	/* Get the four timeout's: a,b,c,d (they are 4 bytes long each) */
	timeout = load32(buf, TPM_CAP_TIMEOUT_A_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_A;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_a = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_B_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_B;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_b = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_C_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_C;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_c = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_D_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_D;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_d = drv_usectohz(timeout);

	return (DDI_SUCCESS);
}

clock_t
tpm12_get_ordinal_duration(tpm_state_t *tpm, uint8_t ordinal)
{
	uint8_t index;

	ASSERT(tpm != NULL);

	/* Default and failure case for IFX */
	/* Is it a TSC_ORDINAL? */
	if (ordinal & TSC_ORDINAL_MASK) {
		if (ordinal >= TSC_ORDINAL_MAX) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: tsc ordinal: %d exceeds MAX: %d",
			    __func__, ordinal, TSC_ORDINAL_MAX);
#endif
			return (0);
		}
		index = tsc12_ords_duration[ordinal];
	} else {
		if (ordinal >= TPM_ORDINAL_MAX) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: ordinal %d exceeds MAX: %d",
			    __func__, ordinal, TPM_ORDINAL_MAX);
#endif
			return (0);
		}
		index = tpm12_ords_duration[ordinal];
	}

	if (index > TPM_DURATION_MAX_IDX) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: duration index '%d' is out of bounds",
		    __func__, index);
#endif
		return (0);
	}
	return (tpm->duration[index]);
}

/*
 * Initialize TPM1.2 device
 * 1. Find out supported interrupt capabilities
 * 2. Set up interrupt handler if supported (some BIOSes don't support
 * interrupts for TPMS, in which case we set up polling)
 * 3. Determine timeouts and commands duration
 */
int
tpm12_init(tpm_state_t *tpm)
{
	char *str = NULL;
	uint32_t intf_caps;
	uint8_t family;
	int ret;

	/*
	 * Temporarily set up timeouts before we get the real timeouts
	 * by issuing TPM_CAP commands (but to issue TPM_CAP commands,
	 * you need TIMEOUTs defined...chicken and egg problem here.
	 * TPM timeouts: Convert the milliseconds to clock cycles
	 */
	tpm->timeout_a = drv_usectohz(TIS_TIMEOUT_A);
	tpm->timeout_b = drv_usectohz(TIS_TIMEOUT_B);
	tpm->timeout_c = drv_usectohz(TIS_TIMEOUT_C);
	tpm->timeout_d = drv_usectohz(TIS_TIMEOUT_D);
	/*
	 * Do the same with the duration (real duration will be filled out
	 * when we call TPM_GetCapability to get the duration values from
	 * the TPM itself).
	 */
	tpm->duration[TPM_SHORT] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_MEDIUM] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_LONG] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_UNDEFINED] = drv_usectohz(TPM_DEFAULT_DURATION);

	/* Find out supported capabilities */
	intf_caps = tpm_get32(tpm, TPM_INTF_CAP);

	if ((intf_caps & ~(TPM_INTF_MASK)) != 0) {
		cmn_err(CE_WARN, "!%s: bad intf_caps value 0x%0x",
		    __func__, intf_caps);
		return (DDI_FAILURE);
	}

	/* These two interrupts are mandatory */
	if (!(intf_caps & TPM_INTF_INT_LOCALITY_CHANGE_INT)) {
		cmn_err(CE_WARN,
		    "!%s: Mandatory capability Locality Change Int "
		    "not supported", __func__);
		return (DDI_FAILURE);
	}
	if (!(intf_caps & TPM_INTF_INT_DATA_AVAIL_INT)) {
		cmn_err(CE_WARN, "!%s: Mandatory capability Data Available Int "
		    "not supported.", __func__);
		return (DDI_FAILURE);
	}

	/*
	 * Before we start writing anything to TPM's registers,
	 * make sure we are in locality 0
	 */
	ret = tis_request_locality(tpm, DEFAULT_LOCALITY);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: Unable to request locality %d", __func__,
		    DEFAULT_LOCALITY);
		return (DDI_FAILURE);
	} /* Now we can refer to the locality as tpm->locality */

	tpm->timeout_poll = drv_usectohz(TPM_POLLING_TIMEOUT);
	tpm->intr_enabled = 0;

	/* Get the real timeouts from the TPM */
	ret = tpm12_get_timeouts(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_timeouts error", __func__);
		return (DDI_FAILURE);
	}

	ret = tpm12_get_duration(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_duration error", __func__);
		return (DDI_FAILURE);
	}

	/* This gets the TPM version information */
	ret = tpm12_get_version(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_version error", __func__);
		return (DDI_FAILURE);
	}

	/*
	 * Unless the TPM completes the test of its commands,
	 * it can return an error when the untested commands are called
	 */
	ret = tpm12_continue_selftest(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_continue_selftest error", __func__);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}
