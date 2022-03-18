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
#define	TPM_LOC_ACTIVE(x)		(((x) >> 2) & 0x7)
#define	TPM_LOC_ASSIGNED(x)		\
	(((x) & TPM_LOC_STATE_LOC_ASSIGNED) == TPM_LOC_STATE_LOC_ASSIGNED)

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


/* Make sure our bitfield is large enough */
CTASSERT(sizeof (uint32_t) >= NBBY*TCRB_ST_MAX);
#define	B(x) ((uint32_t)1 << ((uint_t)x))

/* For each state, a bit field indicating which next states are allowed */
static uint32_t tpm_crb_state_tbl[TCRB_ST_MAX] = {
	[TCRB_ST_IDLE] = B(TCRB_ST_READY),
	[TCRB_ST_READY] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_READY)|B(TCRB_ST_CMD_RECEPTION),
	[TCRB_ST_CMD_RECEPTION] =
	    B(TCRB_ST_READY)|B(TCRB_ST_CMD_RECEPTION|B(TCRB_ST_CMD_EXECUTION),
	[TCRB_ST_CMD_EXECUTION] = B(TCRB_ST_CMD_COMPLETION),
	[TCRB_ST_CMD_COMPLETION] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_READY)|B(TCRB_ST_CMD_COMPLETION)|
	    B(TCRB_ST_CMD_RECEPTION),
};

static void
tpm_crb_set_state(tpm_t *tpm, tpm_crb_state_t next_state)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

	VERIFY3S(next_state, <, TCRB_ST_MAX);

	mutex_enter(&crb->tcrb_lock);

	/* Make sure the next state is generally allowed */
	VERIFY((tpm_crb_state_tbl[crb->tcrb_state] & B(next_state)) != 0);

	/* More specific checks */
	switch (crb->tcrb_state) {
	case TCRB_ST_CMD_COMPLETION:
		switch (next_state) {
			case TCRB_ST_READY:
				/*
				 * CMD_COMPLETION -> READY only allowed when
				 * idle bypass feature is supported.
				 */
				VERIFY(crb->tcrb_idle_bypass);
				break;
			default:
				break;
		}
		break;
	default:
		break;
	}

	crb->tcrb_state = next_state;
	mutex_exit(&crb->tcrb_lock);
}

static int
tpm_crb_wait_u32(tpm_t *tpm, unsigned long reg, uint32_t mask, uint32_t val,
    clock_t timeout, bool intr_wait)
{
	clock_t deadline;
	uint32_t status;
	int ret = 0;

	if (!tpm->tpm_use_interrupts)
		intr_wait = false;

	/* Use an absolute timeout since other interrupts may wake us. */
	deadline = ddi_get_lbolt() + timeout;

	while (((status = tpm_get32(reg)) & mask) != val) {
		if (intr_wait) {
			ret = cv_timedwait(&tpm->tpm_intr_cv, &tpm->tpm_lock,
			    deadline);
			if (ret == -1) {
				/* Check one final time */
				status = tpm_get32(reg) & mask;
				if (status != val) {
					goto timedout;
				}

				return (0);
			}
		} else {
			if (ddi_get_lbolt() >= deadline) {
				goto timedout;
			}

			delay(tpm->tpm_timeout_poll);
		}
	}

	return (0);

timedout:
#ifdef DEBUG
	dev_err(tpm->tpm_dip, CE_WARN, "!%s: timeout (%ld usecs) waiting for "
	    "reg 0x%lx & 0x%x == 0x%x", __func__, drv_hztousec(timeout),
	    reg, mask, val);
#endif
	return (ETIME);
}

static int
tpm_crb_go_idle(tpm_t *tpm)
{
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_GO_IDLE);

	/* Now wait for bit to clear */
	return (tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_GO_IDLE, 0, tpm->tpm_timeout_c, false));
}

static int
tpm_crb_go_ready(tpm_t *tpm)
{
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_CMD_READY);

	return (tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_CMD_READY, 0, tpm->tpm_timeout_c, true));
}

int
tpm_crb_init(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

	mutex_init(&crb->tcrb_lock, NULL, MUTEX_DRIVER, NULL);
	crb->tcrb_state = TCRB_ST_IDLE;

	/*
	 * The cmd address register is not at an 8-byte aligned offset, so
	 * it must be read as two 32-bit values.
	 */
	crb->tcrb_cmd_off = tpm_get32(tpm, TPM_CRB_CMD_LADDR) |
	    tpm_get32(tpm, TPM_CRB_CMD_HADDR) << 32;
	crb->tcrb_cmdbuf_size = tpm_get32(tpm, TPM_CRB_CMD_SIZE);

	/*
	 * The command response buffer address is however at an 8-byte
	 * aligned offset.
	 */
	crb->tcrb_resp_off = tpm_get64(tpm, TPM_CRB_RSP_ADDR);
	crb->tcrb_respbuf_size = tpm_get32(tpm, TPM_CRB_RSP_SIZE);

	/*
	 * The command and response buffer may be the same offset. If they are,
	 * the buffer sizes SHALL be the same (Table 25).
	 */
	if (crb->tcrb_cmd_off == crb->tcrb_resp_off &&
	    crb->tcrb_cmdbuf_size != crb->tcrb_respbuf_size) {
		cmn_err(CE_WARN, "!%s: tpm shared command and response buffer "
		    "have different sizes (cmd size %llu != resp size %llu)",
		    __func__, crb->tcrb_cmdbuf_size, crb->tcrb_respbuf_size);
		return (EIO);
	}

	tpm->tpm_iftype = TPM_IF_CRB;

	return (0);
}

static uint_t
tpm_crb_intr(caddr_t arg0, caddr_t arg1)
{
	tpm_t *tpm = (tpm_t *)arg0;

	return (0);
}

int
tpm_crb_send_data(tpm_client_t *c, uint8_t *buf, size_t buflen)
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

	/* XXX: should this be replaced with a 64-bit copy loop? */
	bcopy(buf, tpm->tpm_addr + crb->tcrb_cmd_off, buflen);

	tpm_put32(tpm, TPM_CRB_CTRL_START, 1);
	ret = tpm_crb_wait_u32(tpm, TPM_CRB_CTRL_START, 1, 0, timeout, true);

	return (ret);
}

int
tpm_crb_request_locality(tpm_t *tpm, uint8_t locality)
{
	ASSERT(MUTEX_HELD(&tpm->tpm_lock));

	uint32_t status;
	uint32_t mask;

	/*
	 * TPM_CRB_LOC_STATE is mirrored across all localities (to allow
	 * determination of the active locality), so it doesn't matter
	 * which locality is used to read the state.
	 */
	status = tpm_get32(tpm, TPM_CRB_LOC_STATE);

	/* If we can't determine the current locality, punt. */
	if ((status & TPM_LOC_STATE_REG_VALID) == 0) {
		return (EIO);
	}

	/* Locality is already active. Nothing to do. */
	if (TPM_LOC_ASSIGNED(status) &&
	    TPM_LOC_ACTIVE(status) == locality) {
		tpm->tpm_locality = locality;
		return (0);
	}

	mask = TPM_LOC_STATE_REG_VALID | TPM_LOC_STATE_LOC_ASSIGNED |
	    (uint32_t)locality & 0x7 << 2;

	/*
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32_loc(tpm, locality, TPM_LOC_CTRL, TPM_LOC_CTRL_REQUEST);

	ret = tpm_wait_for_u32(tpm, TPM_CRB_LOC_STATE, mask, mask,
	    tpm->tpm_timeout_c, true);
	if (ret == 0) {
		tpm->tpm_locality = locality;
		return (0);
	}

	/*
	 * TODO: This should probably generate an fm event and possibly
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
tpm_crb_exec_cmd(tpm_client_t *c)
{

	int ret;

	ret = tpm_crb_send_data(c, c->tpmc_buf, c->tpmc_bufused);
	if (ret != 0) {
		return (ret);
	}

	/* XXX: read in the response */
	return (ret);
}
