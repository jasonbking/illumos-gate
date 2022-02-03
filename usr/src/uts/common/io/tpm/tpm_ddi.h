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

#ifndef	_TPM_DDI_H
#define	_TPM_DDI_H

#include "tpm_tis.h"

/* Duration index is SHORT, MEDIUM, LONG, UNDEFINED */
#define	TPM_DURATION_MAX_IDX	3

/*
 * IO buffer size: this seems sufficient, but feel free to modify
 * This should be at minimum 765
 */
#define	TPM_IO_BUF_SIZE		4096

#define	TPM_IO_TIMEOUT		10000000

/*
 * The byte offsets of various fields in a TPM command. These are the same
 * for TPM1.2 and TPM2.0. The header size is also the same.
 */
#define	TPM_HEADER_SIZE			10

#define	TPM_TAG_OFFSET			0
#define	TPM_PARAMSIZE_OFFSET		2
#define	TPM_RETURN_OFFSET		6
#define	TPM_COMMAND_CODE_OFFSET		6

/*
 * Flags to keep track of for the allocated resources
 * so we know what to deallocate later on
 */
enum tpm_ddi_resources_flags {
	TPM_OPENED = 0x001,
	TPM_DIDMINOR = 0x002,
	TPM_DIDREGSMAP = 0x004,
	TPM_DIDINTMUTEX = 0x008,
	TPM_DIDINTCV = 0x010,
	TPM_DID_IO_ALLOC = 0x100,
	TPM_DID_IO_MUTEX = 0x200,
	TPM_DID_IO_CV = 0x400,
	TPM_DID_MUTEX = 0x800,
	TPM_DID_SOFT_STATE = 0x1000,
#ifdef sun4v
	TPM_HSVC_REGISTERED = 0x2000
#endif
};

/*
 * TPM interface methods. TPM_IF_TIS and TPM_IF_FIFO are effectively
 * identical except that TPM_IF_FIFO supports the TPM_INTF_CAPABILITY_x
 * registers.
 */
typedef enum tpm_if_t {
	TPM_IF_TIS,	/* TPM 1.2 and TPM 2.0 */
	TPM_IF_FIFO,	/* TPM 2.0 only */
	TPM_IF_CRB,	/* TPM 2.0 only */
} tpm_if_t;

typedef enum tpm_family {
	TPM_FAMILY_1_2,
	TPM_FAMILY_2_0,
} tpm_family_t;

typedef enum tpm_tis_xfer_size {
	TPM_TIS_XFER_LEGACY,
	TPM_TIS_XFER_8,
	TPM_TIS_XFER_32,
	TPM_TIS_XFER_64,
} tpm_tis_xfer_size_t;

/* TIS/FIFO specific data */
typedef struct tpm_tis {
	tpm_tis_xfer_size_t	ttis_xfer_size;	
	uint32_t		ttis_intr;
} tpm_tis_t;

/* CRB Interface specific data */
typedef struct tpm_crb {
	uint64_t	tcrb_cmd_off;
	size_t		tcrb_cmb_size;
	uint64_t	tcrb_resp_off;
	size_t		tcrb_resp_size;
	uint32_t	tcrb_intr;
} tpm_crb_t;

typedef struct tpm tpm_t;
typedef struct tpm_client tpm_client_t;

struct tpm {
	/* TPM specific */
	TPM_CAP_VERSION_INFO vers_info;

	/* OS specific */
	dev_info_t		*tpm_dip;
	int			tpm_instance;
	ddi_acc_handle_t	tpm_handle;

	kmutex_t		tpm_lock;
	kcondvar_t		tpm_cv;
	uint8_t			*tpm_addr;	/* TPM mapped address */
	ddi_intr_handle_t	*tpm_harray;
	tpm_state_t		tpm_state;
	uint_t			tpm_client_count;
	uint_t			tpm_client_max;
	uint_t			tpm_intr_pri;
	bool			tpm_intr_enabled;
	bool			tpm_exclusive;	/* Only allow 1 client */

	tpm_client_t		*tpm_active;
	ddi_taskq_t		tpm_taskq;

	tpm_if_t		tpm_iftype;
	union {
		tpm_tis_t	tpmu_tis;
		tpm_crb_t	tpmu_crb;
	} tpm_u;

	uint8_t			tpm_locality;	/* locality during cmd exec */

	uint32_t flags;		/* flags to keep track of what is allocated */
	clock_t duration[4];	/* short,medium,long,undefined */

	clock_t			tpm_timeout_a;
	clock_t			tpm_timeout_b;
	clock_t			tpm_timeout_c;
	clock_t			tpm_timeout_d;
	clock_t timeout_poll;

	int			(*tpm_exec)(tpm_client_t *);
	int			(*tpm_cancel)(tpm_client_t *);
	void			(*tpm_set_interrupts)(tpm_client_t *, bool);

	/* For power management. */
	kmutex_t	pm_mutex;
	kcondvar_t	suspend_cv;
	uint32_t	suspended;

	tpm_if_t	iftype;

	enum tis_tpm_family	tpm_family;
	enum tis_intf_ver	intf_ver;
	enum tis_xfer_size	xfer_size;

	crypto_kcf_provider_handle_t	n_prov;
};

typedef enum tpm_mode {
	TPM_MODE_RDONLY =	0,
	TPM_MODE_WRITE =	(1 << 0),
	TPM_MODE_NONBLOCK =	(1 << 1),
} tpm_mode_t;

/*
 * A client normally cycles through these states in the order they are listed.
 * However, errors will cancel any pending operations and reset the client
 * state back to TPM_CLIENT_IDLE.
 */
typedef enum tpm_client_state {
	TPM_CLIENT_IDLE,		/* No command in progress */
	TPM_CLIENT_CMD_RECEPTION,	/* Reading command from client */
	TPM_CLIENT_CMD_EXECUTION,	/* Command is running on TPM */
	TPM_CLIENT_CMD_COMPLETION,	/* Write command to client */
} tpm_client_state_t;

struct tpm_client {
	kmutex_t		tpmc_lock;
	kcondvar_t		tpmc_cv;
	tpm_t			*tpmc_tpm;		/* Write once (WO) */
	tpm_mode_t		tpmc_mode;		/* WO */
	tpm_client_state_t	tpmc_state;		/* RW */
	pollhead_t		tpmc_pollhead;		/* RW */
	uint8_t			*tpmc_buf;		/* RW */
	size_t			tpmc_buflen;		/* WO */
	size_t			tpmc_bufused;		/* RW */
	size_t			tpmc_bufread;		/* RW */
	int			tpmc_instance;		/* WO */
	uint8_t			tpmc_locality;		/* RW */
	int			tpmc_cmdresult;		/* RW */
};

#define	TPM_LOCALITY_MAX	4
#define	TPM_OFFSET_MAX		0x0fff

static inline uint32
tpm_getbuf32(uchar_t *ptr, uint32_t offset)
{
	return (BE_IN32(ptr + offset));
}

uint8_t tpm_get8(tpm_state_t *, unsigned long);
uint32_t tpm_get32(tpm_state_t *, unsigned long);
uint64_t tpm_get64(tpm_state_t *, unsigned long);
void tpm_put8(tpm_state_t *, unsigned long, uint8_t);


int tpm12_seed_random(tpm_state_t *, uchar_t *, size_t);
int tpm12_generate_random(tpm_state_t *, uchar_t *, size_t);
int tpm12_init(tpm_state_t *);

int tpm20_init(tpm_state_t *);
int tpm20_seed_random(tpm_state_t *, uchar_t *, size_t);
int tpm20_generate_random(tpm_state_t *, uchar_t *, size_t);

#endif	/* _TPM_DDI_H */
