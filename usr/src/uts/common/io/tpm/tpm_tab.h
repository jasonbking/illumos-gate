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

#ifndef _TPM_TAB_H
#define	_TPM_TAB_H

#ifdef __cplusplus
extern "C" {
#endif

struct tpm_client;

int tpm_tab_init(struct tpm_client *);
void tpm_tab_fini(struct tpm_client *);

#ifdef __cplusplus
}
#endif

#endif /* _TPM_TAB_H */
