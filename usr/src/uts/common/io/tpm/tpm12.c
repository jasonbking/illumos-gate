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

#include <sys/byteorder.h>
#include <sys/crypto/api.h>

#include "tpm_ddi.h"
#include "tpm_tis.h"

/*
 * In order to test the 'millisecond bug', we test if DURATIONS and TIMEOUTS
 * are unreasonably low...such as 10 milliseconds (TPM isn't that fast).
 * and 400 milliseconds for long duration
 */
#define	TEN_MILLISECONDS		10000	/* 10 milliseconds */
#define	FOUR_HUNDRED_MILLISECONDS	400000	/* 4 hundred milliseconds */

/*
 * Historically, only one connection has been allowed to TPM1.2 devices,
 * with tssd (or equivalent) arbitrating access between multiple clients.
 */
#define	TPM12_CLIENT_MAX	1

#define	TPM_TAG_RQU_COMMAND		((uint16_t)0x00c1)

/* The TPM1.2 Commands we are using */
#define	TPM_ORD_GetCapability		0x00000065u
#define	TPM_ORG_ContinueSelfTest	0x00000053u
#define	TPM_ORD_GetRandom		0x00000046u
#define	TPM_ORD_StirRandom		0x00000047u

/* The maximum amount of bytes allowed for TPM_ORD_StirRandom */
#define	TPM12_SEED_MAX		255

/*
 * This is to address some TPMs that does not report the correct duration
 * and timeouts.  In our experience with the production TPMs, we encountered
 * time errors such as GetCapability command from TPM reporting the timeout
 * and durations in milliseconds rather than microseconds.  Some other TPMs
 * report the value 0's
 *
 * Short Duration is based on section 11.3.4 of TIS specifiation, that
 * TPM_GetCapability (short duration) commands should not be longer than 750ms
 * and that section 11.3.7 states that TPM_ContinueSelfTest (medium duration)
 * should not be longer than 1 second.
 */
#define	DEFAULT_SHORT_DURATION	750000
#define	DEFAULT_MEDIUM_DURATION	1000000
#define	DEFAULT_LONG_DURATION	300000000
#define	DEFAULT_TIMEOUT_A	750000
#define	DEFAULT_TIMEOUT_B	2000000
#define	DEFAULT_TIMEOUT_C	750000
#define	DEFAULT_TIMEOUT_D	750000

/*
 * TPM input/output buffer offsets
 */

typedef enum {
	TPM_CAP_RESPSIZE_OFFSET = 10,
	TPM_CAP_RESP_OFFSET = 14,
} TPM_CAP_RET_OFFSET_T;

typedef enum {
	TPM_CAP_TIMEOUT_A_OFFSET = 14,
	TPM_CAP_TIMEOUT_B_OFFSET = 18,
	TPM_CAP_TIMEOUT_C_OFFSET = 22,
	TPM_CAP_TIMEOUT_D_OFFSET = 26,
} TPM_CAP_TIMEOUT_OFFSET_T;

typedef enum {
	TPM_CAP_DUR_SHORT_OFFSET = 14,
	TPM_CAP_DUR_MEDIUM_OFFSET = 18,
	TPM_CAP_DUR_LONG_OFFSET = 22,
} TPM_CAP_DURATION_OFFSET_T;

#define	TPM_CAP_VERSION_INFO_OFFSET	14
#define	TPM_CAP_VERSION_INFO_SIZE	15

/* TSC Ordinals */
static const tpm_duration_t tpm12_ords_duration[TPM_ORDINAL_MAX] = {
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
static const tpm_duration_t tsc12_ords_duration[TSC_ORDINAL_MAX] = {
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
tpm12_get_timeouts(tpm_t *tpm)
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

	ret = tpm_exec_internal(tpm, DEFAULT_LOCALITY, buf, sizeof (buf));
	if (ret != 0) {
		/* XXX: ereport? */
		dev_err(tpm->tpm_dip, CE_WARN, "%s: command failed: %d",
		    __func__, ret);
		return (ret);
	}

	/*
	 * Get the length of the returned buffer
	 * Make sure that there are 4 timeout values returned
	 * length of the capability response is stored in data[10-13]
	 * Also the TPM is in network byte order
	 */
	len = tpm_getbuf32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len != 4 * sizeof (uint32_t)) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: incorrect capability "
		    "response size: expected %d received %u", __func__,
		     (int)(4 * sizeof (uint32_t)), len);
		return (EIO);
	}

	/* Get the four timeout's: a,b,c,d (they are 4 bytes long each) */
	timeout = tpm_getbuf32(buf, TPM_CAP_TIMEOUT_A_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_A;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->tpm_timeout_a = drv_usectohz(timeout);

	timeout = tpm_getbuf32(buf, TPM_CAP_TIMEOUT_B_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_B;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->tpm_timeout_b = drv_usectohz(timeout);

	timeout = tpm_getbuf32(buf, TPM_CAP_TIMEOUT_C_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_C;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->tpm_timeout_c = drv_usectohz(timeout);

	timeout = tpm_getbuf32(buf, TPM_CAP_TIMEOUT_D_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_D;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->tpm_timeout_d = drv_usectohz(timeout);

	return (0);
}

/*
 * Get the actual timeouts supported by the TPM by issuing TPM_GetCapability
 * with the subcommand TPM_CAP_PROP_TIS_DURATION
 * TPM_GetCapability (TPM Main Part 3 Rev. 94, pg.38)
 */
static int
tpm12_get_duration(tpm_t *tpm)
{
	tpm_tis_t *tis = &tpm->tpm_u.tpmu_tis;
	int ret;
	uint32_t duration;
	uint32_t len;
	uint8_t buf[30] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TPM_CAP_Prop */
		0, 0, 0, 4,	/* SUB_CAP size in bytes */
		0, 0, 1, 32	/* TPM_CAP_PROP_TIS_DURATION(0x120) */
	};

	ret = tpm_exec_internal(tpm, DEFAULT_LOCALITY, buf, sizeof (buf));
	if (ret != 0) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: command failed: %d",
		    __func__, ret);
		return (EIO);
	}

	/*
	 * Get the length of the returned buffer
	 * Make sure that there are 3 duration values (S,M,L: in that order)
	 * length of the capability response is stored in data[10-13]
	 * Also the TPM is in network byte order
	 */
	len = tpm_getbuf32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len != 3 * sizeof (uint32_t)) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: incorrect capability "
		    "response size: expected %d received %u", __func__,
		     (int)(3 * sizeof (uint32_t)), len);
		return (EIO);
	}

	duration = tpm_getbuf32(buf, TPM_CAP_DUR_SHORT_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_SHORT_DURATION;
	} else if (duration < TEN_MILLISECONDS) {
		duration *= 1000;
	}
	tis->ttis_duration[TPM_SHORT] = drv_usectohz(duration);

	duration = tpm_getbuf32(buf, TPM_CAP_DUR_MEDIUM_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_MEDIUM_DURATION;
	} else if (duration < TEN_MILLISECONDS) {
		duration *= 1000;
	}
	tis->ttis_duration[TPM_MEDIUM] = drv_usectohz(duration);

	duration = tpm_getbuf32(buf, TPM_CAP_DUR_LONG_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_LONG_DURATION;
	} else if (duration < FOUR_HUNDRED_MILLISECONDS) {
		duration *= 1000;
	}
	tis->ttis_duration[TPM_LONG] = drv_usectohz(duration);

	/* Just make the undefined duration be the same as the LONG */
	tis->ttis_duration[TPM_UNDEFINED] = tis->ttis_duration[TPM_LONG];

	return (0);
}

static int
tpm12_get_version(tpm_t *tpm)
{
	int ret;
	uint32_t len;
	char vendorId[5];
	/* If this buf is too small, the "vendor specific" data won't fit */
	uint8_t buf[64] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 18,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 0x1A,	/* TPM_CAP_VERSION_VAL */
		0, 0, 0, 0,	/* SUB_CAP size in bytes */
	};

	ret = tpm_exec_internal(tpm, DEFAULT_LOCALITY, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: command failed: %d",
		    __func__, ret);
		return (ret);
	}

	/*
	 * Get the length of the returned buffer.
	 */
	len = tpm_getbuf32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len < TPM_CAP_VERSION_INFO_SIZE) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "%s: unexpected response length; expected %d actual %d",
		    __func__, TPM_CAP_VERSION_INFO_SIZE, len);
		return (EIO);
	}

	bcopy(buf + TPM_CAP_VERSION_INFO_OFFSET, &tpm->vers_info,
	    TPM_CAP_VERSION_INFO_SIZE);

	bcopy(tpm->vers_info.tpmVendorID, vendorId,
	    sizeof (tpm->vers_info.tpmVendorID));
	vendorId[4] = '\0';

	cmn_err(CE_NOTE, "!TPM found: Ver %d.%d, Rev %d.%d, "
	    "SpecLevel %d, errataRev %d, VendorId '%s'",
	    tpm->vers_info.version.major,	/* Version */
	    tpm->vers_info.version.minor,
	    tpm->vers_info.version.revMajor,	/* Revision */
	    tpm->vers_info.version.revMinor,
	    (int)ntohs(tpm->vers_info.specLevel),
	    tpm->vers_info.errataRev,
	    vendorId);

	/*
	 * This driver only supports TPM Version 1.2
	 */
	if (tpm->vers_info.version.major != 1 &&
	    tpm->vers_info.version.minor != 2) {
		cmn_err(CE_WARN, "!%s: Unsupported TPM version (%d.%d)",
		    __func__,
		    tpm->vers_info.version.major,		/* Version */
		    tpm->vers_info.version.minor);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

clock_t
tpm12_get_ordinal_duration(tpm_t *tpm, uint32_t ordinal)
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
 * To prevent the TPM from complaining that certain functions are not tested
 * we run this command when the driver attaches.
 * For details see Section 4.2 of TPM Main Part 3 Command Specification
 */
static int
tpm12_continue_selftest(tpm_t *tpm)
{
	int ret;
	uint8_t buf[10] = {
		0, 193,		/* TPM_TAG_RQU COMMAND */
		0, 0, 0, 10,	/* paramsize in bytes */
		0, 0, 0, 83	/* TPM_ORD_ContinueSelfTest */
	};

	/* Need a longer timeout */
	ret = tpm_exec_internal(tpm, DEFAULT_LOCALITY, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: command timed out",
		    __func__);
		return (ret);
	}

	return (DDI_SUCCESS);
}

#if 0
/*
 * Header + length of seed data (as BE32 int) + max amount of seed a TPM12
 * can accept in a single command.
 */
#define	SEED_BUF_LEN (TPM_HEADER_SIZE + sizeof (uint32_t) + TPM12_SEED_MAX)

int
tpm12_seed_random(tpm_t *tpm, uchar_t *buf, size_t buflen)
{
	if (buflen == 0 || buflen > TPM12_SEED_MAX || buf == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* Total length = header + seed length + seed data */
	uint32_t	len = TPM_HEADER_SIZE + sizeof (uint32_t) + buflen;
	int		ret;
	uint8_t		cmdbuf[SEED_BUF_LEN] = { 0 };

	BE_OUT16(cmdbuf + TPM_TAG_OFFSET,		TPM_TAG_RQU_COMMAND);
	BE_OUT16(cmdbuf + TPM_PARAMSIZE_OFFSET,		len);
	BE_OUT32(cmdbuf + TPM_COMMAND_CODE_OFFFSET,	TPM_ORD_StirRandom);
	BE_OUT32(cmdbuf + TPM_HEADER_SIZE,		buflen);
	bcopy(cmdbuf + TPM_HEADER_SIZE + sizeof (uint32_t), buf, buflen);

	/* Acquire lock for exclusive use of TPM */
	TPM_EXCLUSIVE_LOCK(tpm);

	ret = tpm_io_lock(tpm);
	/* Timeout reached */
	if (ret)
		return (CRYPTO_BUSY);

	/* Command doesn't return any data */
	ret = itpm_command(tpm, cmdbuf, len, NULL, 0);
	tpm_unlock(tpm);

	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s failed", __func__);
#endif
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

#define	RNDHDR_SIZE	(TPM_HEADER_SIZE + sizeof (uint32_t))

int
tpm12_generate_random(tpm_t *tpm, uchar_t *buf, size_t buflen)
{
	if (buflen == 0 || buf == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	int		ret;
	uint32_t	cmdlen = RNDHDR_SIZE;
	uint8_t		cmdbuf[RNDHDR_SIZE] = { 0 };

	BE_OUT16(cmdbuf + TPM_TAG_OFFSET,		TPM_TAG_RQU_COMMAND);
	BE_OUT32(cmdbuf + TPM_PARAMSIZE_OFFSET,		RNDHDR_SIZE);
	BE_OUT32(cmdbuf + TPM_COMMAND_CODE_OFFSET,	TPM_ORD_GetRandom);
	BE_OUT32(cmdbuf + TPM_HEADER_SIZE,		buflen);

	/* Acquire lock for exclusive use of TPM */
	TPM_EXCLUSIVE_LOCK(tpm);

	ret = tpm_io_lock(tpm);
	/* Timeout reached */
	if (ret)
		return (CRYPTO_BUSY);

	ret = itpm_command(tpm, cmdbuf, cmdlen, buf, buflen);
	tpm_unlock(tpm);

	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s failed", __func__);
#endif
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}
#endif

/*
 * Initialize TPM1.2 device
 * 1. Find out supported interrupt capabilities
 * 2. Set up interrupt handler if supported (some BIOSes don't support
 * interrupts for TPMS, in which case we set up polling)
 * 3. Determine timeouts and commands duration
 */
bool
tpm12_init(tpm_t *tpm)
{
	tpm_tis_t *tis = &tpm->tpm_u.tpmu_tis;
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
	tpm->tpm_timeout_a = drv_usectohz(TIS_TIMEOUT_A);
	tpm->tpm_timeout_b = drv_usectohz(TIS_TIMEOUT_B);
	tpm->tpm_timeout_c = drv_usectohz(TIS_TIMEOUT_C);
	tpm->tpm_timeout_d = drv_usectohz(TIS_TIMEOUT_D);
	/*
	 * Do the same with the duration (real duration will be filled out
	 * when we call TPM_GetCapability to get the duration values from
	 * the TPM itself).
	 */
	tis->ttis_duration[TPM_SHORT] = drv_usectohz(TPM_DEFAULT_DURATION);
	tis->ttis_duration[TPM_MEDIUM] = drv_usectohz(TPM_DEFAULT_DURATION);
	tis->ttis_duration[TPM_LONG] = drv_usectohz(TPM_DEFAULT_DURATION);
	tis->ttis_duration[TPM_UNDEFINED] = drv_usectohz(TPM_DEFAULT_DURATION);

	/* Find out supported capabilities */
	intf_caps = tpm_get32(tpm, TPM_INTF_CAP);

	if ((intf_caps & ~(TPM_INTF_MASK)) != 0) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: bad intf_caps value 0x%0x",
		    __func__, intf_caps);
		return (false);
	}

	/* These two interrupts are mandatory */
	if (!(intf_caps & TPM_INTF_INT_LOCALITY_CHANGE_INT)) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "%s: mandatory capability locality change interrupt "
		    "not supported", __func__);
		return (false);
	}
	if (!(intf_caps & TPM_INTF_INT_DATA_AVAIL_INT)) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "%s: mandatory capability data available interrupt "
		    "not supported.", __func__);
		return (false);
	}

	tpm->tpm_timeout_poll = drv_usectohz(TPM_POLLING_TIMEOUT);
	tpm->tpm_use_interrupts = false;

	/* Get the real timeouts from the TPM */
	ret = tpm12_get_timeouts(tpm);
	if (ret != DDI_SUCCESS) {
		return (false);
	}

	ret = tpm12_get_duration(tpm);
	if (ret != DDI_SUCCESS) {
		return (false);
	}

	/* This gets the TPM version information */
	ret = tpm12_get_version(tpm);
	if (ret != DDI_SUCCESS) {
		return (false);
	}


	/* XXX: Cleanup */
	char buf[32];

	(void) snprintf(buf, sizeof (buf), "%d.%d",
	    tpm->vers_info.version.major,
	    tpm->vers_info.version.minor);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "tpm-version", buf);

	(void) snprintf(buf, sizeof (buf), "%d.%d",
	    tpm->vers_info.version.revMajor,
	    tpm->vers_info.version.revMinor);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "tpm-revision", buf);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "tpm-speclevel",
	    ntohs(tpm->vers_info.specLevel));
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "tpm-errata-revision",
	    tpm->vers_info.errataRev);

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
