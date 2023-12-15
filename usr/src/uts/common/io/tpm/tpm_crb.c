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

#include <sys/sysmacros.h>
#include "tpm_ddi.h"
#include "tpm_tis.h"
#include "tpm20.h"

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
#define	TPM_LOC_SET(x)			(((uint32_t)(x) & 0x7) << 2)

#define	TPM_LOC_CTRL		0x08
#define	TPM_LOC_CTRL_SEIZE		0x04
#define	TPM_LOC_CTRL_RELINQUISH		0x02
#define	TPM_LOC_CTRL_REQUEST		0x01

#define	TPM_LOC_STS		0x0c
#define	TPM_CRB_INTF_ID		0x30
#define	TPM_CRB_INTF_XFER(x)	\
    ((tpm_crb_xfer_size_t)(BE_16(((x) >> 11) & 0x3)))
#define	TPM_CRB_INTF_RID(x)	(((x) >> 24) & 0xff)
#define	TPM_CRB_INTF_VID(x)	(((x) >> 32) & 0xffff)
#define	TPM_CRB_INTF_DID(x)	(((x) >> 48) & 0xffff)
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
#define	TPM_CRB_INT_EN_START		0x00000001

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
CTASSERT(sizeof (uint32_t) * NBBY >= TCRB_ST_MAX);
#define	B(x) ((uint32_t)1 << ((uint_t)x))

/* For each state, a bit field indicating which next states are allowed */
static uint32_t tpm_crb_state_tbl[TCRB_ST_MAX] = {
	[TCRB_ST_IDLE] = B(TCRB_ST_READY),
	[TCRB_ST_READY] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_READY)|B(TCRB_ST_CMD_RECEPTION),
	[TCRB_ST_CMD_RECEPTION] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_CMD_RECEPTION)|B(TCRB_ST_CMD_EXECUTION),
	[TCRB_ST_CMD_EXECUTION] = B(TCRB_ST_CMD_COMPLETION),
	[TCRB_ST_CMD_COMPLETION] =
	    B(TCRB_ST_IDLE)|B(TCRB_ST_READY)|B(TCRB_ST_CMD_COMPLETION)|
	    B(TCRB_ST_CMD_RECEPTION),
};

static inline bool
state_allowed(tpm_crb_state_t curr, tpm_crb_state_t next)
{
	VERIFY3S(curr, <, TCRB_ST_MAX);
	VERIFY3S(next, <, TCRB_ST_MAX);

	if ((tpm_crb_state_tbl[curr] & B(next)) != 0)
		return (true);
	return (false);
}

static void
crb_set_state(tpm_t *tpm, tpm_crb_state_t next_state)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3S(next_state, <, TCRB_ST_MAX);

	/* Make sure the next state is generally allowed */
	VERIFY(state_allowed(crb->tcrb_state, next_state));

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

static bool
crb_is_go_idle_done(tpm_t *tpm)
{
	return (tpm_get32(tpm, TPM_CRB_CTRL_REQ) == 0 ? true : false);
}

static int
crb_go_idle(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint32_t status;
	int ret;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));

	status = tpm_get32(tpm, TPM_CRB_CTRL_STS);
	if ((status & TPM_CRB_CTRL_STS_FATAL) != 0) {
		/* XXX: fm err? */
		return (SET_ERROR(EIO));
	}

	if ((status & TPM_CRB_CTRL_STS_IDLE) != 0) {
		/*
		 * If the TPM is reporting it's in the IDLE state, we
		 * should agree.
		 */
		VERIFY3S(crb->tcrb_state, ==, TCRB_ST_IDLE);
		return (0);
	}

	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_GO_IDLE);
	ret = tpm_wait(tpm, crb_is_go_idle_done, tpm->tpm_timeout_c);
	if (ret != 0) {
		if (ret == ETIME) {
			tpm_ereport_timeout(tpm, TPM_CRB_CTRL_REQ,
			    tpm->tpm_timeout_c, __func__);
		}
		return (ret);
	}

	/*
	 * The TPM should assert the idle state in TPM_CRB_CTRL_STS once
	 * idle. If not, we abort.
	 */
	status = tpm_get32(tpm, TPM_CRB_CTRL_STS);
	if ((status & TPM_CRB_CTRL_STS_IDLE) == 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "TPM cleared goIdle bit, but did not update tpmIdle");
		/* XXX: fm err? */
		return (SET_ERROR(EIO));
	}

	crb_set_state(tpm, TCRB_ST_IDLE);
	return (0);
}

static bool
crb_is_go_ready_done(tpm_t *tpm)
{
	return (tpm_get32(tpm, TPM_CRB_CTRL_REQ) == 0 ? true : false);
}

static int
crb_go_ready(tpm_t *tpm)
{
	int ret;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));

	/*
	 * Per Table 35, if we are already in the READY state and assert
	 * cmdReady, the TPM will just clear the bit and remain in the
	 * READY state.
	 */
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_CMD_READY);
	ret = tpm_wait(tpm, crb_is_go_ready_done, tpm->tpm_timeout_c);
	if (ret == 0) {
		crb_set_state(tpm, TCRB_ST_READY);
		return (0);
	}

	/* If we timed out, try to go back to the idle state */
	(void) crb_go_idle(tpm);
	return (ret);
}

bool
crb_init(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint64_t id;

	id = tpm_get64(tpm, TPM_CRB_INTF_ID);
	tpm->tpm_did = TPM_CRB_INTF_DID(id);
	tpm->tpm_vid = TPM_CRB_INTF_VID(id);
	tpm->tpm_rid = TPM_CRB_INTF_RID(id);
	crb->tcrb_xfer_size = TPM_CRB_INTF_XFER(id);
	crb->tcrb_state = TCRB_ST_IDLE;

	/*
	 * The cmd address register is not at an 8-byte aligned offset, so
	 * it must be read as two 32-bit values.
	 */
	crb->tcrb_cmd_off = tpm_get32(tpm, TPM_CRB_CTRL_CMD_LADDR) |
	    (uint64_t)tpm_get32(tpm, TPM_CRB_CTRL_CMD_HADDR) << 32;
	crb->tcrb_cmd_size = tpm_get32(tpm, TPM_CRB_CTRL_CMD_SIZE);

	/*
	 * The command response buffer address is however at an 8-byte
	 * aligned offset.
	 */
	crb->tcrb_resp_off = tpm_get64(tpm, TPM_CRB_CTRL_RSP_ADDR);
	crb->tcrb_resp_size = tpm_get32(tpm, TPM_CRB_CTRL_RSP_SIZE);

	/*
	 * The command and response buffer may be the same offset. If they are,
	 * the buffer sizes SHALL be the same (Table 25).
	 */
	if (crb->tcrb_cmd_off == crb->tcrb_resp_off &&
	    crb->tcrb_cmd_size != crb->tcrb_resp_size) {
		cmn_err(CE_WARN, "!%s: tpm shared command and response buffer "
		    "have different sizes (cmd size %lu != resp size %lu)",
		    __func__, crb->tcrb_cmd_size, crb->tcrb_resp_size);
		return (false);
	}

	/* CRB always implies a TPM 2.0 device */
	return (tpm20_init(tpm));
}

uint_t
crb_intr(caddr_t arg0, caddr_t arg1 __unused)
{
	const uint32_t intr_mask = TPM_CRB_INT_LOC_CHANGED|
	    TPM_CRB_INT_EST_CLEAR|TPM_CRB_INT_CMD_READY|TPM_CRB_INT_START;

	tpm_t *tpm = (tpm_t *)arg0;
	uint32_t status;

	status = tpm_get32(tpm, TPM_CRB_INT_STS);
	if ((status & intr_mask) == 0) {
		/* Wasn't us */
		return (DDI_INTR_UNCLAIMED);
	}

	/* Ack the interrupt */
	tpm_put32(tpm, TPM_CRB_INT_STS, status);

	/*
	 * For now at least, it's just enough to signal the waiting
	 * command to recheck the appropriate registers.
	 *
	 * TODO: It might be nice to have dtrace sdt probes for each
	 * type of interrupt.
	 */
	cv_signal(&tpm->tpm_thr_cv);

	return (DDI_INTR_CLAIMED);
}

static int
crb_send_data(tpm_t *tpm, const uint8_t *buf, size_t amt)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint8_t *destp;
	size_t xfer_chunk = 1;
	int ret;

	VERIFY3U(amt, >=, TPM_HEADER_SIZE);
	VERIFY3U(tpm_cmdlen(buf), ==, amt);

	ret = crb_go_idle(tpm);
	if (ret != 0) {
		return (ret);
	}

	ret = crb_go_ready(tpm);
	if (ret != 0) {
		return (ret);
	}

	/*
	 * Technically, the TPM doesn't transition into the Command Reception
	 * state until the first byte is written, but nothing should get
	 * inbetween us doing this, so we update the state first.
	 */
	crb_set_state(tpm, TCRB_ST_CMD_RECEPTION);

	switch (crb->tcrb_xfer_size) {
	case TPM_CRB_XFER_4:
		xfer_chunk = 4;
		break;
	case TPM_CRB_XFER_8:
		xfer_chunk = 8;
		break;
	case TPM_CRB_XFER_32:
		xfer_chunk = 32;
		break;
	case TPM_CRB_XFER_64:
		xfer_chunk = 64;
		break;
	}

	destp = tpm->tpm_addr + crb->tcrb_cmd_off;
	while (amt > 0) {
		/* Copy in xfer_amt chunks. */
		size_t xfer_amt = MIN(xfer_chunk, amt);

		if (xfer_amt < 4) {
			xfer_amt = 1;
		}

		bcopy(buf, destp, xfer_amt);
		buf += xfer_amt;
		destp += xfer_amt;
		amt -= xfer_amt;	
	}

	tpm_put32(tpm, TPM_CRB_CTRL_START, 1);
	crb_set_state(tpm, TCRB_ST_CMD_EXECUTION);

	return (ret);
}

static bool
crb_data_ready(tpm_t *tpm)
{
	/*
	 * Writing a 1 to this register starts execution of a command.
	 * The TPM will return 0 once the command has completed execution.
	 */
	return (tpm_get32(tpm, TPM_CRB_CTRL_START) == 0 ? true : false);
}

static int
crb_recv_data(tpm_t *tpm, uint8_t *buf, size_t buflen)
{
	crb_set_state(tpm, TCRB_ST_CMD_RECEPTION);

	/* First, read in the header */
	bcopy(tpm->tpm_addr, buf, TPM_HEADER_SIZE);

	/* Check for sanity. */
	uint32_t resp_len = tpm_cmdlen(buf);

	if (resp_len > buflen) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "received excessively large (%lu) sized response",
		    (unsigned long)resp_len);

		/* Try to recover by going idle */
		(void) crb_go_idle(tpm);

		/* XXX: Better error? */
		return (SET_ERROR(ENOSPC));
	}

	/* Read in rest of the response */
	bcopy(tpm->tpm_addr + TPM_HEADER_SIZE, buf + TPM_HEADER_SIZE,
	    resp_len - TPM_HEADER_SIZE);
	return (0);
}

static bool
crb_request_locality_done(tpm_t *tpm)
{
	uint32_t val = tpm_get32(tpm, TPM_LOC_STATE);
	uint32_t mask = TPM_LOC_STATE_REG_VALID | TPM_LOC_STATE_LOC_ASSIGNED |
	    TPM_LOC_SET(tpm->tpm_locality);

	return ((tpm_get32(tpm, TPM_LOC_STATE) & mask) == mask ? true : false);
}

static int
crb_request_locality(tpm_t *tpm, uint8_t locality)
{
	uint32_t status;
	int ret;
	uint8_t old_locality;

	ASSERT(MUTEX_HELD(&tpm->tpm_lock));

	/*
	 * TPM_CRB_LOC_STATE is mirrored across all localities (to allow
	 * determination of the active locality), so it doesn't matter
	 * which locality is used to read the state.
	 */
	status = tpm_get32(tpm, TPM_LOC_STATE);

	/* If we can't determine the current locality, punt. */
	if ((status & TPM_LOC_STATE_REG_VALID) == 0) {
		return (SET_ERROR(EIO));
	}

	/* Locality is already active. Nothing to do. */
	if (TPM_LOC_ASSIGNED(status) &&
	    TPM_LOC_ACTIVE(status) == locality) {
		tpm->tpm_locality = locality;
		return (0);
	}

	/*
	 * Set the new locality now so the tpm_put32() command writes the
	 * request to the correct locality request register. If we fail,
	 * we restore the old value.
	 */
	old_locality = tpm->tpm_locality;
	tpm->tpm_locality = locality;

	/*
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32(tpm, TPM_LOC_CTRL, TPM_LOC_CTRL_REQUEST);
	ret = tpm_wait(tpm, crb_request_locality_done, tpm->tpm_timeout_c);
	if (ret != 0) {
		/*
		 * XXX: Should this generate an ereport? Maybe even disable
		 * access to the TPM?
		 */
		tpm->tpm_locality = old_locality;
		return (ret);
	}

	return (ret);
}

static int
crb_release_locality(tpm_t *tpm, uint8_t locality)
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
crb_exec_cmd(tpm_t *tpm, uint8_t loc, uint8_t *buf, size_t buflen)
{
	uint32_t cmdlen;
	int ret, ret2;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3S(tpm->tpm_iftype, ==, TPM_IF_CRB);
	VERIFY3U(buflen, >=, TPM_HEADER_SIZE);

	cmdlen = tpm_cmdlen(buf);
	VERIFY3U(cmdlen, >=, TPM_HEADER_SIZE);
	VERIFY3U(cmdlen, <=, buflen);

	ret = crb_request_locality(tpm, loc);
	if (ret != 0) {
		return (ret);
	}

	ret = crb_send_data(tpm, buf, cmdlen);
	if (ret != 0) {
		goto done;
	}

	ret = tpm_wait_cmd(tpm, buf, crb_data_ready);
	if (ret != 0) {
		goto done;
	}

	ret = crb_recv_data(tpm, buf, buflen);

	/*
	 * PTP 6.5.3.9.2 The TPM shall maintin the respone in the buffer
	 * until a receipt of write of 1 to TPM_CRB_CTRL_REQ_x.goIdle.
	 *
	 * The wording suggests the response could possibly be maintained
	 * once in the idle state, but it's the best we can do to prevent
	 * any snooping of the last response after we're done with it.
	 */
	(void) crb_go_idle(tpm);

done:
	/*
	 * Release the locality after completion to allow a lower value
	 * locality to use the TPM.
	 */
	ret2 = crb_release_locality(tpm, loc);
	return ((ret != 0) ? ret : ret2);
}

void
crb_cancel_cmd(tpm_t *tpm, tpm_duration_t to)
{
	/* TODO */
}

void
crb_intr_mgmt(tpm_t *tpm, bool enable)
{
	VERIFY(tpm->tpm_use_interrupts);

	if (enable) {
		tpm_put32(tpm, TPM_CRB_INT_ENABLE,
		    TPM_CRB_INT_EN_GLOBAL|TPM_CRB_INT_EN_LOC_CHANGED|
		    TPM_CRB_INT_EN_EST_CLEAR|TPM_CRB_INT_EN_CMD_READY|
		    TPM_CRB_INT_EN_START);
	} else {
		tpm_put32(tpm, TPM_CRB_INT_ENABLE, 0);
	}
}
