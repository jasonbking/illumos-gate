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

int
tpm20_init(tpm_state_t *tpm)
{
	/*
	 * TPM2.0 defines explicit timeouts (unlike TPM1.2 where there are
	 * default timeouts, but the TPM can advertise it's own timeout
	 * values if desired).
	 */
	tpm->timeout_a = TPM20_TIMEOUT_A;
	tpm->timeout_b = TPM20_TIMEOUT_B;
	tpm->timeout_c = TPM20_TIMEOUT_C;
	tpm->timeout_d = TPM20_TIMEOUT_D;

	switch (tpm->iftype) {
	case TPM_IF_FIFO:
		return (tpm20_fifo_init(tpm));
	case TPM_IF_CRB:
		return (tpm_crb_init(tpm));
	}
}

clock_t
tpm20_get_timeout(tpm_state_t *tpm __unused, uint32_t cmd)
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
