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
 * Copyright 2024 Jason King
 * Copyright 2025 RackTop Systems, Inc.
 */

#ifndef _TPM20_H
#define	_TPM20_H

#include "tss2_tpm2_types.h"

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

/* TPM2.0 Command attributes */
#define	TPM2_CCA_IDX(cc)	((cc) & 0xffff)
#define	TPM2_CCA_CHDL(cc)	(((cc) >> 25) & 0x7)	/* # handles in req */
#define	TPM2_CCA_RHDL(cc)	(((cc) >> 28) & 0x1)	/* # handles in resp */
#define	TPM2_CCA_VEND(cc)	((cc) & (1U << 29))	/* is vendor cmd */
#define	TPM2_CCA_NV(cc)		((cc) & (1U << 22))	/* may write to NV */
/* May flush arbitrary # of contexts */
#define	TPM2_CCA_EXTENSIVE(cc)	((cc) & (1U << 23))
/* Any transient handle in cmd is flushed at completion */
#define	TPM2_CCA_FLUSHED(cc)	((cc) & (1U << 24))

typedef uint32_t tpm_hdl_t;

typedef enum tpm20_hdl_type {
	TPM20_HDL_UNKNOWN,
	TPM20_HDL_PCR,		/* PCR Index */
	TPM20_HDL_NVIDX,	/* NV Index */
	TPM20_HDL_HMAC,		/* HMAC Session Handle */
	TPM20_HDL_POLICY,	/* Policy Session Handle */
	TPM20_HDL_PERM,		/* Permanent resource handle */
	TPM20_HDL_TRANSIENT,	/* Transient object handle */
	TPM20_HDL_PERSIST,	/* Persistent object handle */
} tpm_hdl_type_t;

static inline tpm_hdl_type_t
tpm_handle_type(const tpm_hdl_t h)
{
	switch (h >> 24) {
	case 0x00:
		return (TPM20_HDL_PCR);
	case 0x01:
		return (TPM20_HDL_NVIDX);
	case 0x02:
		return (TPM20_HDL_HMAC);
	case 0x03:
		return (TPM20_HDL_POLICY);
	case 0x40:
		return (TPM20_HDL_PERM);
	case 0x80:
		return (TPM20_HDL_TRANSIENT);
	case 0x81:
		return (TPM20_HDL_PERSIST);
	default:
		return (TPM20_HDL_UNKNOWN);
	}
}

static inline bool
tpm_handle_is_session(const tpm_hdl_t h)
{
	uint32_t val = h >> 24;

	/*
	 * HMAC and Policy sessions are the only currently known session
	 * handle types.
	 */
	if (val == 0x02 || val == 0x03)
		return (true);
	return (false);
}

bool tpm20_init(struct tpm *);

TPM2_RC tpm20_get_properties(struct tpm_client *, uint32_t,
    uint32_t, bool (*)(uint32_t, uint32_t, bool, void *), void *);

TPM2_RC tpm20_seed_random(struct tpm_client *, void *, size_t);
TPM2_RC tpm20_generate_random(struct tpm_client *, void *, size_t);
uint32_t tpm20_get_ccattr(struct tpm *, TPM2_CC);
TPM2_RC tpm20_get_cmd_attr(struct tpm_client *, uint32_t,
    uint32_t *);
TPM2_RC tpm20_context_load(struct tpm_client *, void *);
TPM2_RC tpm20_context_save(struct tpm_client *, uint32_t, void *,
    size_t);
TPM2_RC tpm20_context_flush(struct tpm_client *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _TPM20_H */
