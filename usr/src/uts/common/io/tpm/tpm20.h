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

#ifndef _TPM20_H
#define	_TPM20_H

#ifdef __cplusplus
extern "C" {
#endif

struct tpm;

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

#define	TPM_ST_NO_SESSIONS 0x8001

#define	TPM_RC	uint32_t

/*
 * The TPM2.0 commands that have explicit timeouts. These might get removed
 * in lieu of a common header file listing all of the commands.
 *
 * Taken from s 6.5.2, Table 12, of
 * "Trusted Platform Module Library Part 2: Structures", Rev 01.59
 */
#define	TPM_CC	uint32_t

#define	TPM_CC_Startup			(TPM_CC)(0x00000144)
#define	TPM_CC_SelfTest			(TPM_CC)(0x00000143)
#define	TPM_CC_GetRandom		(TPM_CC)(0x0000017b)
#define	TPM_CC_StirRandom		(TPM_CC)(0x00000146)
#define	TPM_CC_HashSequenceStart	(TPM_CC)(0x00000186)
#define	TPM_CC_SequenceUpdate		(TPM_CC)(0x0000015c)
#define	TPM_CC_SequenceComplete		(TPM_CC)(0x0000013e)
#define	TPM_CC_EventSequenceComplete	(TPM_CC)(0x00000185)
#define	TPM_CC_VerifySignature		(TPM_CC)(0x00000177)
#define	TPM_CC_PCR_Extend		(TPM_CC)(0x00000182)
#define	TPM_CC_HierarchyControl		(TPM_CC)(0x00000121)
#define	TPM_CC_HierarchyChangeAuth	(TPM_CC)(0x00000129)
#define	TPM_CC_GetCapability		(TPM_CC)(0x0000017a)
#define	TPM_CC_NV_Read			(TPM_CC)(0x0000014e)
#define	TPM_CC_Create			(TPM_CC)(0x00000153)
#define	TPM_CC_CreatePrimary		(TPM_CC)(0x00000131)
#define	TPM_CC_CreateLoaded		(TPM_CC)(0x00000191)

#define	TPM_RC_SUCCESS			0

/* Table 2:22 From Part 4 */
#define	TPM_CAP_FIRST			0x00000000
#define	TPM_CAP_COMMANDS		0x00000002
#define	TPM_CAP_TPM_PROPERTIES		0x00000006

typedef uint32_t TPM_PT;
#define	PT_GROUP			0x00000100
#define	PT_FIXED			(PT_GROUP * 1)
#define	TPM_PT_FIRMWARE_VERSION_1	(PT_FIXED + 11)
#define	TPM_PT_FIRMWARE_VERSION_2	(PT_FIXED + 12)
#define	TPM_PT_MAX_COMMAND_SIZE		(PT_FIXED + 30)
#define	TPM_PT_MAX_RESPONSE_SIZE	(PT_FIXED + 31)
#define	TPM_PT_MAX_OBJECT_CONTEXT	(PT_FIXED + 33)
#define	TPM_PT_MAX_SESSION_CONTEXT	(PT_FIXED + 34)
#define	TPM_PT_TOTAL_COMMANDS		(PT_FIXED + 41)

/* TPM2.0 Command attributes */
#define	TPM_CCA_IDX(cc)		((cc) & 0xffff)
#define	TPM_CCA_CHDL(cc)	(((cc) >> 25) & 0x7)	/* # handles in req */
#define	TPM_CCA_RHDL(cc)	(((cc) >> 28) & 0x1)	/* # handles in resp */
#define	TPM_CCA_VEND(cc)	((cc) & (1U << 29))	/* is vendor cmd */
#define	TPM_CCA_NV(cc)		((cc) & (1U << 22))	/* may write to NV */
/* May flush arbitrary # of contexts */
#define	TPM_CCA_EXTENSIVE(cc)	((cc) & (1U << 23))
/* Any transient handle in cmd is flushed at completion */
#define	TPM_CCA_FLUSHED(cc)	((cc) & (1U << 24))

bool tpm20_init(struct tpm *);
int tpm20_seed_random(struct tpm *, uchar_t *, size_t);
int tpm20_generate_random(struct tpm *, uchar_t *, size_t);
tpm_duration_t tpm20_get_duration_type(tpm_t *, const uint8_t *);
clock_t tpm20_get_timeout(tpm_t *, const uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TPM20_H */
