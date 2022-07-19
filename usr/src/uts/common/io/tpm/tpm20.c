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

#include <sys/debug.h>
#include "tpm_ddi.h"
#include "tpm20.h"

bool
tpm20_init(tpm_t *tpm)
{
	/*
	 * TPM2.0 defines explicit timeouts (unlike TPM1.2 where there are
	 * default timeouts, but the TPM can advertise it's own timeout
	 * values if desired).
	 */
	tpm->tpm_timeout_a = TPM20_TIMEOUT_A;
	tpm->tpm_timeout_b = TPM20_TIMEOUT_B;
	tpm->tpm_timeout_c = TPM20_TIMEOUT_C;
	tpm->tpm_timeout_d = TPM20_TIMEOUT_D;

	return (true);
}

clock_t
tpm20_get_timeout(uint32_t cmd)
{
	switch (cmd) {
	case TPM_CC_Startup:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_SelfTest:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_GetRandom:
		return (TPM20_TIMEOUT_B);
	case TPM_CC_HashSequenceStart:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_SequenceUpdate:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_SequenceComplete:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_EventSequenceComplete:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_VerifySignature:
		return (TPM20_TIMEOUT_B);
	case TPM_CC_PCR_Extend:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_HierarchyControl:
		return (TPM20_TIMEOUT_B);
	case TPM_CC_HierarchyChangeAuth:
		return (TPM20_TIMEOUT_B);
	case TPM_CC_GetCapability:
		return (TPM20_TIMEOUT_A);
	case TPM_CC_NV_Read:
		return (TPM20_TIMEOUT_B);
	default:
		return (TPM20_TIMEOUT_B);
	}
}
