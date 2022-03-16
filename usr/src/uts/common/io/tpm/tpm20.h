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
 * Copyright 2022 Jason King
 */

#ifndef _TPM20_H
#define	_TPM20_H

#ifdef __cplusplus
extern "C" {
#endif

struct tpm_state;

/*
 * From 6.5.1.4, Table 18 (all in milliseconds)
 */
#define	TPM20_TIMEOUT_A	750
#define	TPM20_TIMEOUT_B	2000
#define	TPM20_TIMEOUT_C	200
#define	TPM20_TIMEOUT_D	30

#define	TPM20_TIMEOUT_CANCEL	TPM20_TIMEOUT_B

/*
 * The TPM2.0 commands that have explicit timeouts. These might get removed
 * in lieu of a common header file listing all of the commands.
 *
 * Taken from s 6.5.2, Table 12, of
 * "Trusted Platform Module Library Part 2: Structures", Rev 01.59
 */
#define	TPM_CC_Startup			0x00000144
#define	TPM_CC_SelfTest			0x00000143
#define	TPM_CC_GetRandom		0x0000017b
#define	TPM_CC_HashSequenceStart	0x00000186
#define	TPM_CC_SequenceUpdate		0x0000015c
#define	TPM_CC_SequenceComplete		0x0000013e
#define	TPM_CC_EventSequenceComplete	0x00000185
#define	TPM_CC_VerifySignature		0x00000177
#define	TPM_CC_PCR_Extend		0x00000182
#define	TPM_CC_HierarchyControl		0x00000121
#define	TPM_CC_HierarchyChangeAuth	0x00000129
#define	TPM_CC_GetCapability		0x0000017a
#define	TPM_CC_NV_Read			0x0000014e

int tpm20_init(struct tpm_state *);
clock_t tpm20_get_timeout(struct tpm_state *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _TPM20_H */
