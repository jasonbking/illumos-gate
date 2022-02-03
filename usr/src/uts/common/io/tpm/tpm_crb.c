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

#include "tpm_tis.h"
#include "tpm_ddi.h"

/*
 * CRB Register offsets. From TCG PC Client Platform TPM Profile Specification
 * for TPM 2.0 Version 1.05 Revision 14
 */
#define	TPM_LOC_STATE		0x00
#define	TPM_LOC_STATE_REG_VALID		0x80
#define	TPM_LOC_STATE_LOC_ASSIGNED	0x02
#define	TPM_LOC_ACTIVE(x) 		(((x) >> 2) & 0x7)

#define	TPM_LOC_CTRL		0x08
#define	TPM_LOC_CTRL_SEIZE		0x04
#define	TPM_LOC_CTRL_RELINQUISH		0x02
#define	TPM_LOC_CTRL_REQUEST		0x01

#define	TPM_LOC_STS		0x0c
#define	TPM_CRB_INTF_ID		0x30
#define	TPM_CRB_CTRL_EXT	0x38

#define	TPM_CRB_CTRL_REQ	0x40
#define	TPM_CRB_CTRL_REQ_GO_IDLE	0x02
#define	TPM_CRB_CTRL_REQ_CMD_READY	0x01

#define	TPM_CRB_CTRL_STS	0x44
#define	TPM_CRB_CTRL_STS_IDLE		0x02
#define	TPM_CRB_CTRL_STS_ONLINE		0x01
#define	TPM_CRB_CTRL_CANCEL	0x48
#define	TPM_CRB_CTRL_START	0x4c

#define	TPM_CRB_INT_ENABLE	0x50
#define	TPM_CRB_INT_EN_GLOBAL		0x80000000
#define	TPM_CRB_INT_EN_LOC_CHANGED	0x00000008
#define	TPM_CRB_INT_EN_EST_CLEAR	0x00000004
#define	TPM_CRB_INT_EN_CMD_READY	0x00000002
#define	TPM_CRB_INT_ENT_START_INT	0x00000001

#define	TPM_CRB_INT_STS		0x54
#define	TPM_CRB_INT_LOC_CHANGED		0x00000008
#define	TPM_CRB_INT_EST_CLEAR		0x00000004
#define	TPM_CRB_INT_CMD_READY		0x00000002
#define	TPM_CRB_INT_START		0x00000001

#define	TPM_CRB_CTRL_CMD_SIZE	0x58
#define	TPM_CRB_CTRL_CMD_LADDR	0x5c
#define	TPM_CRB_CTRL_CMD_HADDR	0x60
#define	TPM_CRB_CTRL_RSP_SIZE	0x64
#define	TPM_CRB_CTRL_RSP_ADDR	0x68

#define	TPM_CRB_DATA_BUFFER	0x80

static int
tpm_crb_wait_u32(tpm_t *tpm, unsigned long reg, uint32_t mask, uint32_t val,
    clock_t timeout)
{
	return (0);
}

static int
tpm_crb_go_idle(tpm_t *tpm)
{
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_GO_IDLE);

	/* Now wait for bit to clear */
	return (tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_GO_IDLE, 0), tpm->tpm_timeout_c);
}

static int
tpm_crb_go_ready(tpm_t *tpm)
{
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_CMD_READY);
	return (tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_CMD_READY, 0), tpm->tpm_timeout_c);
}

int
tpm_crb_init(tpm_t *tpm)
{
	/*
	 * The cmd address register is not at an 8-byte aligned offset, so
	 * it must be read as two 32-bit values.
	 */
	tpm->crb_cmd_off = tpm_get32(tpm, TPM_CRB_CMD_LADDR) |
	    tpm_get32(tpm, TPM_CRB_CMD_HADDR) << 32;
	tpm->crb_cmdbuf_size = tpm_get32(tpm, TPM_CRB_CMD_SIZE);

	/*
	 * The command response buffer address is however at an 8-byte
	 * aligned offset.
	 */
	tpm->crb_resp_off = tpm_get64(tpm, TPM_CRB_RSP_ADDR);
	tpm->crb_respbuf_size = tpm_get32(tpm, TPM_CRB_RSP_SIZE);

	/*
	 * The command and response buffer may be the same offset. If they are,
	 * the buffer sizes SHALL be the same (Table 25).
	 */
	if (tpm->crb_cmd_off == tpm->crb_resp_off &&
	    tpm->crb_cmdbuf_size != tpm->crb_respbuf_size) {
		cmn_err(CE_WARN, "!%s: tpm shared command and response buffer "
		    "have different sizes (cmd size %llu != resp size %llu)",
		    __func__, tpm->crb_cmdbuf_size, tpm->crb_respbuf_size);
		return (EIO);
	}

	tpm->iftype = TPM_IF_CRB;

	return (0);
}

int
tpm_crb_send_data(tpm_t *c, uint8_t *buf, size_t buflen)
{
	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	ASSERT(MUTEX_HELD(&c->tpmc_tpm->tpm_lock));
	ASSERT3S(c->tpmc_tpm->tpm_iftype, ==, TPM_IF_CRB);

	tpm_t *tpm = c->tpmc_tpm;
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	int ret;

	ret = tpm_crb_request_locality(tpm, c->tpmc_locality);
	if (ret != 0) {
		return (ret);
	}

	ret = tpm_crb_go_idle(tpm);
	if (ret != 0) {
		return (ret);
	}

	ret = tpm_crb_go_ready(tpm);
	if (ret != 0) {
		return (ret);
	}

	clock_t timeout = get_timeout(buf, buflen);

	bcopy(buf, tpm->tpm_addr + crb->tcrb_cmd_off, buflen);
	tpm_put32(tpm, TPM_CRB_CTRL_START, 1);
	ret = tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_START, 1, 0, timeout);

	return (0);
}

int
tpm_crb_request_locality(tpm_t *tpm, uint8_t locality)
{
	ASSERT(MUTEX_HELD(&tpm->tpm_lock));

	uint32_t status;

	/*
	 * TPM_CRB_LOC_STATE is mirrored across all localities (to enable
	 * determination of the active locality), so it doesn't matter
	 * which locality is used to read the state.
	 */
	status = tpm_get32(tpm, TPM_CRB_LOC_STATE);

	/* If we can't determine the current locality, punt. */
	if ((status & TPM_LOC_STATE_REG_VALID) == 0) {
		return (EIO);
	}

	/* Locality is already active. Nothing to do. */
	if (TPM_LOC_ACTIVE(status) == locality) {
		tpm->tpm_locality = locality;
		return (0);
	}

	if ((status & mask) != mask) {
		return (EIO);
	}

	if (TPM_LOC_ACTIVE(status) == locality) {
		return (0);
	}

	/*
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32_loc(tpm, locality, TPM_LOC_CTRL, TPM_LOC_CTRL_REQUEST);
	ret = tpm_wait_for_u32(tpm, TPM_LOC_STATE, req_mask, req_mask,
	    tpm->timeout_c);

	if (ret == 0) {
		tpm->tpm_locality = locality;
		return (0);
	}

	/*
	 * TODO: This should probably generate a fault event and possibly
	 * disable access to the TPM. Need to research more.
	 */
	return (ret);
}

int
tpm_crb_release_locality(tpm_t *tpm, uint8_t locality)
{
	/*
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32(tpm, TPM_LOC_CTRL, TPM_LOC_CTRL_RELINQUISH);
	return (0);
}

int
tpm_crb_exec_cmd(tpm_client_t *c
