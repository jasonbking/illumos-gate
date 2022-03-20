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
#define	TPM_CRB_CTRL_STS_FATAL		0x01
#define	TPM_CRB_CTRL_CANCEL	0x48
#define	TPM_CRB_CTRL_START	0x4c

#define	TPM_CRB_INT_ENABLE	0x50
#define	TPM_CRB_INT_EN_GLOBAL		0x80000000
#define	TPM_CRB_INT_EN_LOC_CHANGED	0x00000008
#define	TPM_CRB_INT_EN_EST_CLEAR	0x00000004
#define	TPM_CRB_INT_EN_CMD_READY	0x00000002
#define	TPM_CRB_INT_ENT_START		0x00000001

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
	    B(TCRB_ST_IDLE)|B(TCRB_ST_CMD_RECEPTION|B(TCRB_ST_CMD_EXECUTION),
	[TCRB_ST_CMD_EXECUTION] = B(TCRB_ST_CMD_COMPLETION),
	[TCRB_ST_CMD_COMPLETION] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_READY)|B(TCRB_ST_CMD_COMPLETION)|
	    B(TCRB_ST_CMD_RECEPTION),
};

static void
tpm_crb_set_state(tpm_t *tpm, tpm_crb_state_t next_state)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3S(next_state, <, TCRB_ST_MAX);

	/* Make sure the next state is generally allowed */
	VERIFY((tpm_crb_state_tbl[crb->tcrb_state] & B(next_state)) != 0);

	/* More specific checks */
	switch (crb->tcrb_state) {
	case TCRB_ST_CMD_COMPLETION:
		switch (next_state) {
			case TCRB_ST_CMD_RECEPTION:
			case TCRB_ST_READY:
				/*
				 * Only allowed when
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
}

static int
tpm_crb_go_idle(tpm_t *tpm)
{
	tpm_crb_t *crb = tpm->tpm_u.tpmu_crb;
	uint32_t status;
	int ret;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));

	status = tpm_get32(tpm, TPM_CRB_CTRL_STS);
	if ((status & TPM_CRB_CTRL_STS_FATAL) != 0) {
		/* XXX: fm err? */
		return (EIO);
	}

	if ((status & TPM_CRB_CTRL_STS_IDLE) != 0) {
		/*
		 * If the TPM is reporting it's in the IDLE state, we
		 * should agree.
		 */
		VERIFY3S(crb->tcrb_state, ==, TPM_ST_IDLE);
		return (0);
	}

	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_GO_IDLE);

	ret = tpm_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_GO_IDLE, 0, tpm->tpm_timeout_c, false);
	if (ret != 0)
		return (ret);

	/*
	 * The TPM should assert the idle state in TPM_CRB_CTRL_STS once
	 * idle. If not, we abort.
	 */
	status = tpm_get32(tpm, TPM_CRB_CTRL_STS);
	if ((status & TPM_CRB_CTRL_STS_IDLE) == 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "TPM cleared goIdle bit, but did not update tpmIdle");
		/* XXX: fm err? */
		return (EIO);
	}

	tpm_crb_set_state(tpm, TPM_ST_IDLE);
	return (0);
}

static int
tpm_crb_go_ready(tpm_t *tpm)
{
	int ret;

	VERIFY(MUTEX_HELD(tpm->tpm_lock));

	/*
	 * Per Table 35, if we are already in the READY state and assert
	 * cmdReady, the TPM will just clear the bit and remain in the
	 * READY state.
	 */
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_CMD_READY);
	ret = tpm_wait_u32(tpm, TPM_CRB_CTRL_REQ,
	    TPM_CRB_CTRL_REQ_CMD_READY, 0, tpm->tpm_timeout_c, true);
	if (ret == 0) {
		tpm_crb_set_state(tpm, TPM_ST_READY);
		return (0);
	}

	/* If we timed out, try to go back to the idle state */
	(void) tpm_crb_go_idle(tpm);
	return (ret);
}

int
tpm_crb_init(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

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
tpm_crb_intr(caddr_t arg0, caddr_t arg1 __unused)
{
	const uint32_t intr_mask = TPM_CRB_INT_LOC_CHANGED|
	    TPM_CRB_INT_EST_CLEAR|TPM_CRB_INT_CMD_READY|TPMM_CRB_INT_START;

	tpm_t *tpm = (tpm_t *)arg0;
	uint32_t status;

	status = tpm_get32(tpm, TPM_CRB_INT_SYS);
	if ((status & intr_mask) == 0) {
		/* Wasn't us */
		return (DDI_INTR_UNCLAIMED);
	}

	/* Ack the interrupt */
	tpm_put32(tpm, status);

	/*
	 * For now at least, it's just enough to signal the waiting
	 * command to recheck the appropriate registers.
	 *
	 * TODO: It might be nice to have dtrace sdt probes for each
	 * type of interrupt.
	 */
	cv_signal(tpm->tpm_intr_cv);

	return (DDI_INTR_CLAIMED);
}

static int
tpm_crb_send_data(tpm_client_t *c, uint8_t *buf, size_t buflen)
{
	tpm_t *tpm = c->tpmc_tpm;
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	int ret;

	ret = tpm_crb_go_idle(tpm);
	if (ret != 0) {
		return (ret);
	}

	ret = tpm_crb_go_ready(tpm);
	if (ret != 0) {
		return (ret);
	}

	clock_t timeout = get_timeout(buf, buflen);

	/*
	 * Technically, the TPM doesn't transition into the Command Reception
	 * state until the first byte is written, but nothing should get
	 * inbetween us doing this, so we update the state first.
	 */
	tpm_crb_set_state(tpm, TCRB_ST_CMD_RECEPTION);

	/* XXX: should this be replaced with a 64-bit copy loop? */
	bcopy(buf, tpm->tpm_addr + crb->tcrb_cmd_off, buflen);

	tpm_put32(tpm, TPM_CRB_CTRL_START, 1);
	tpm_crb_set_state(tpm, TCRB_ST_CMD_EXECUTION);

	return (ret);
}

static int
tpm_crb_recv_data(tpm_client_t *c, uint8_t *buf, size_t buflen, size_t *rlenp)
{
	tpm_t *tpm = c->tpmc_tpm;
	int ret;

	/* We should be given a buffer large enough to hold any response */
	VERIFY3U(buflen, >=, TPM_IO_BUF_SIZE);

	ret = tpm_wait_u32(tpm, TPM_CRB_CTRL_START, 1, 0, timeout, false);
	if (ret != 0) {
		return (ret);
	}

	tpm_crb_set_state(tpm, TCRB_ST_CMD_RECEPTION);

	/* First, read in the header */
	bcopy(tpm->tpm_addr, buf, TPM_HEADER_SIZE);

	/* Check for sanity. */
	size_t resp_len = BE_IN32(buf + TPM_PARAMSIZE_OFFSET);

	if (resp_len > buflen) {
		/* XXX: fm report? */
		dev_err(tpm->tpm_dip, "received and excessively large (%lu) "
		    "sized response", (unsigned long)resp_len);

		/* Try to recover by going idle */
		(void) tpm_crb_go_idle(tpm);
		return (ret);
	}

	/* Read in rest of the response */
	bcopy(tpm->tpm_addr + TPM_HEADER_SIZE, buf + TPM_HEADER_SIZE,
	    resp_len - TPM_HEADER_SIZE);
	*rlenp = resp_len;

	return (0);
}

static int
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

static int
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
	tpm_t *tpm = c->tpmc_tpm;
	int ret, ret2;

	VERIFY3S(tpm->tpm_iftype, ==, TPM_IF_CRB);

	VERIFY(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3S(c->tpmc_state, ==, TPMC_CLIENT_CMD_EXECUTION);

	mutex_enter(&tpm->tpm_lock);
	mutex_exit(&c->tpmc_lock);

	ret = tpm_crb_request_locality(tpm, c->tpmc_locality);
	if (ret != 0) {
		mutex_exit(&tpm->tpm_lock);
		return (ret);
	}

	ret = tpm_crb_send_data(c, c->tpmc_buf, c->tpmc_bufused);
	if (ret != 0) {
		goto done;
	}

	c->tpmc_bufread = 0;
	ret = tpm_crb_recv_data(c, c->tpmc_buf, c->tpmc_buflen,
	     &c->tpmc_bufused);

done:
	/*
	 * Release the locality after completion to allow a lower value
	 * locality to use the TPM.
	 */
	ret2 = tpm_crb_release_locality(tpm, c->tpmc_locality);
	mutex_exit(&tpm->tpm_lock);

	mutex_enter(&c->tpmc_lock);
	c->tpmc_state = TPM_CLIENT_CMD_COMPLETION;
	return ((ret != 0) ? ret : ret2);
}

int
tpm_crb_cancel_cmd(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

	VERIFY(MUTEX_HELD(&c->tpmc_lock));
	/*
	 * We should only be called when the client is in the process of
	 * executing a command.
	 */
	VERIFY3S(c->tpmc_state, ==, TPMC_CLIENT_CMD_EXECUTION);

	mutex_enter(&tpm->tpm_lock);

	/* We also should't be called from the tpm service thread either. */
	VERIFY3U(curthread->t_did, !=, tpm->tpm_thread_id);

	tpm->tpm_thr_cancelreq = true;
	cv_signal(tpm->tpm_thr_cv);

	if (tpm_client_nonblock(c)) {
		mutex_exit(&tpm->tpm_lock);
		return (0);
	}

	while (tpm->tpm_thr_cancelreq) {
		int ret = cv_wait_sig(&tpm->tpm_thr_cv, &tpm->tpm_lock);

		if (ret == 0) {
			mutex_exit(&tpm->tpm_lock);
			return (EINTR);
		}
	}

	mutex_exit(&tpm->tpm_lock);
	return (0);

	tpm_client_reset(c);
	return (0);
}

void
tpm_crb_intr_mgmt(tpm_t *tpm, bool enable)
{
	if (enable) {
		tpm_put32(tpm, TPM_CRB_INT_ENABLE,
		    TPM_CRB_INT_EN_GLOBAL|TPM_CRB_INT_EN_LOC_CHANGED|
		    TPM_CRB_INT_EN_EST_CLEAR|TPM_CRB_INT_EN_CMD_READY|
		    TPM_CRB_INT_EN_START);
	} else {
		tpm_put32(tpm, TPM_CRB_INT_ENABLE, 0);
	}
}
