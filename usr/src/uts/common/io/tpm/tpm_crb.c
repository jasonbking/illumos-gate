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
#include <sys/acpica.h>
#include "tpm_ddi.h"
#include "tpm_tis.h"

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
#define	TPM_CRB_INTF_XFER_4	((uint32_t)0 << 11)
#define	TPM_CRB_INTF_XFER_8	((uint32_t)1 << 11)
#define	TPM_CRB_INTF_XFER_32	((uint32_t)2 << 11)
#define	TPM_CRB_INTF_XFER_64	((uint32_t)3 << 11)
#define	TPM_CRB_INTF_XFER(x)	((x) & TPM_CRB_INTF_XFER_64)
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

static const uint32_t crb_xfer_sizes[] = { 64, 32, 8, 4};

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

static inline tpm_crb_state_t
crb_state(tpm_t *tpm)
{
	return (tpm->tpm_u.tpmu_crb.tcrb_state);
}

static void
crb_set_state(tpm_t *tpm, tpm_crb_state_t next_state)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;

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

static inline uint32_t
crb_xfer_chunk(const tpm_crb_t *crb, uint32_t amt)
{
	for (uint_t i = 0; i < ARRAY_SIZE(crb_xfer_sizes); i++) {
		if (amt >= crb_xfer_sizes[i] && crb->tcrb_xfer_size >= amt) {
			return (crb->tcrb_xfer_size);
		}
	}

	/* The minimum CRB transfer size */
	return (4);
}

static bool
crb_is_go_idle_done(tpm_t *tpm, bool final, clock_t to, const char *func)
{
	if (tpm_get32(tpm, TPM_CRB_CTRL_REQ) == 0) {
		return (true);
	}

	if (final) {
		tpm_ereport_timeout(tpm, TPM_CRB_CTRL_REQ, to, func);
	}

	return (false);
}

static int
crb_go_idle(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint32_t status;
	int ret;

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
	ret = tpm_wait(tpm, crb_is_go_idle_done, tpm->tpm_timeout_c, __func__);
	if (ret != 0) {
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
crb_is_go_ready_done(tpm_t *tpm, bool final, clock_t to, const char *func)
{
	if (tpm_get32(tpm, TPM_CRB_CTRL_REQ) == 0) {
		return (true);
	}

	if (final) {
		tpm_ereport_timeout(tpm, TPM_CRB_CTRL_REQ, to, func);
	}

	return (false);
}

static int
crb_go_ready(tpm_t *tpm)
{
	int ret;

	/*
	 * Per Table 35, if we are already in the READY state and assert
	 * cmdReady, the TPM will just clear the bit and remain in the
	 * READY state.
	 */
	tpm_put32(tpm, TPM_CRB_CTRL_REQ, TPM_CRB_CTRL_REQ_CMD_READY);
	ret = tpm_wait(tpm, crb_is_go_ready_done, tpm->tpm_timeout_c, __func__);
	if (ret == 0) {
		crb_set_state(tpm, TCRB_ST_READY);
		return (0);
	}

	/* If we timed out, try to go back to the idle state */
	(void) crb_go_idle(tpm);
	return (ret);
}

/*
 * The location of the command and response buffer are given as physical
 * addresses by the TPM_CRB_CTRL_{CMD,RSP}_ADDR registers. The PC Client
 * Specific Platform TPM Profile Specification says a compliant implementation
 * should return the address of TPM_CRB_DATA_BUFFER_x (e.g. base + 0x80),
 * implying that the command and response buffer should share the same
 * address. At the same time, it allows for two different addresses and
 * reserves a large portion of the register space for it.
 *
 * To be as accomidating as possible, we will accept any physical address
 * for the cmd and resp buffer whose physical address is in the range
 * [base + TPM_CRB_DATA_BUFFER, base + 0x1000). We will reject any
 * TPM that presents addresses outside of this range.
 *
 * For conveinence, we store the address as the offset from the base using
 * the physical base address provided by ACPI.
 */
static ACPI_STATUS
crb_addr_to_offset(ACPI_RESOURCE *res, void *arg)
{
	tpm_t *tpm = arg;
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint32_t base, len, end;

	if (res->Type != ACPI_RESOURCE_TYPE_FIXED_MEMORY32)
		return (AE_OK);

	base = res->Data.FixedMemory32.Address;
	len = res->Data.FixedMemory32.AddressLength;

	/*
	 * Sanity check. This is supposed to be within the 32-bit address
	 * range.
	 */
	if (__builtin_uadd_overflow(base, len, &end)) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM memory resource length (0x%x) is too large for "
		    "base physical address (0x%x)", base, len);
		return (AE_BAD_ADDRESS);
	}

	/*
	 * We've already checked the register size by now, so the length
	 * of the address resource should be sane.
	 */
	VERIFY3U(len, >=, 0x1000);

	if (crb->tcrb_cmd_off < base ||
	    crb->tcrb_cmd_off + crb->tcrb_cmd_size > base + 0x1000) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM CRB command buffer [0x%lx, 0x%lx) is outside of "
		    "register range [0x%x, 0x%x) of device.",
		    crb->tcrb_cmd_off, crb->tcrb_cmd_off + crb->tcrb_cmd_size,
		    base, base + len);
		return (AE_BAD_ADDRESS);
	}

	if (crb->tcrb_resp_off < base ||
	    crb->tcrb_resp_off + crb->tcrb_resp_size > base + 0x1000) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!TPM CRB response buffer [0x%lx, 0x%lx) is outside of "
		    "register range [0x%x, 0x%x) of device.",
		    crb->tcrb_resp_off,
		    crb->tcrb_resp_off + crb->tcrb_resp_size,
		    base, base + len);
		return (AE_BAD_ADDRESS);
	}

	crb->tcrb_cmd_off -= base;
	crb->tcrb_resp_off -= base;

	/*
	 * Don't need to walk any more resources, successfully terminate
	 * the walk.
	 */
	return (AE_CTRL_TERMINATE);
}

bool
crb_init(tpm_t *tpm)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint64_t id;
	ACPI_HANDLE handle;
	ACPI_STATUS status;

	id = tpm_get64(tpm, TPM_CRB_INTF_ID);
	tpm->tpm_did = TPM_CRB_INTF_DID(id);
	tpm->tpm_vid = TPM_CRB_INTF_VID(id);
	tpm->tpm_rid = TPM_CRB_INTF_RID(id);
	switch (TPM_CRB_INTF_XFER(id)) {
	case TPM_CRB_INTF_XFER_4:
		crb->tcrb_xfer_size = 4;
		break;
	case TPM_CRB_INTF_XFER_8:
		crb->tcrb_xfer_size = 8;
		break;
	case TPM_CRB_INTF_XFER_32:
		crb->tcrb_xfer_size = 32;
		break;
	case TPM_CRB_INTF_XFER_64:
		crb->tcrb_xfer_size = 64;
		break;
	default:
		dev_err(tpm->tpm_dip, CE_PANIC,
		    "impossible CRB transfer size: 0x%lx",
		    TPM_CRB_INTF_XFER(id));
	}
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
	 * The command and response buffer may be the same address. If they are,
	 * the buffer sizes SHALL be the same (Table 25).
	 */
	if (crb->tcrb_cmd_off == crb->tcrb_resp_off &&
	    crb->tcrb_cmd_size != crb->tcrb_resp_size) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!%s: tpm shared command and response buffer "
		    "have different sizes (cmd size %u != resp size %u)",
		    __func__, crb->tcrb_cmd_size, crb->tcrb_resp_size);
		return (false);
	}

	status = acpica_get_handle(tpm->tpm_dip, &handle);
	if (ACPI_FAILURE(status)) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!%s: failed to get ACPI handle for device", __func__);
		return (false);
	}

	status = AcpiWalkResources(handle, "_CRS", crb_addr_to_offset, tpm);
	if (ACPI_FAILURE(status))
		return (false);

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
crb_send_data(tpm_t *tpm, const uint8_t *buf, uint32_t buflen)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	uint8_t *dest = tpm->tpm_addr + crb->tcrb_cmd_off;
	uint32_t cmdlen = tpm_cmdlen(buf);
	int ret;

	ret = crb_go_idle(tpm);
	if (ret != 0) {
		return (ret);
	}

	ret = crb_go_ready(tpm);
	if (ret != 0) {
		return (ret);
	}

	mutex_enter(&tpm->tpm_lock);
	if (tpm->tpm_thr_cancelreq) {
		mutex_exit(&tpm->tpm_lock);
		return (SET_ERROR(ECANCELED));
	}
	mutex_exit(&tpm->tpm_lock);

	/*
	 * Technically, the TPM doesn't transition into the Command Reception
	 * state until the first byte is written, but nothing should get
	 * inbetween us doing this, so we update the state first.
	 */
	crb_set_state(tpm, TCRB_ST_CMD_RECEPTION);

	bcopy(buf, dest, cmdlen);
	return (0);
}

static bool
crb_data_ready_cmd(tpm_t *tpm, bool final, uint16_t cmd, clock_t to,
    const char *func)
{
	/*
	 * Writing a 1 to this register starts execution of a command.
	 * The TPM will return 0 once the command has completed execution.
	 */
	if (tpm_get32(tpm, TPM_CRB_CTRL_START) == 0) {
		return (true);
	}

	if (final) {
		tpm_ereport_timeout_cmd(tpm, cmd, to, func);
	}

	return (false);
}

static int
crb_start(tpm_t *tpm, const uint8_t *buf)
{
	mutex_enter(&tpm->tpm_lock);
	if (tpm->tpm_thr_cancelreq) {
		mutex_exit(&tpm->tpm_lock);
		return (SET_ERROR(ECANCELED));
	}
	mutex_exit(&tpm->tpm_lock);

	tpm_put32(tpm, TPM_CRB_CTRL_START, 1);
	crb_set_state(tpm, TCRB_ST_CMD_EXECUTION);

	return (tpm_wait_cmd(tpm, buf, crb_data_ready_cmd, __func__));
}

static bool
crb_data_ready_cancel(tpm_t *tpm, bool final, clock_t to, const char *func)
{
	/*
	 * Writing a 1 to this register starts execution of a command.
	 * The TPM will return 0 once the command has completed execution.
	 */
	if (tpm_get32(tpm, TPM_CRB_CTRL_START) == 0) {
		return (true);
	}

	if (final) {
		tpm_ereport_timeout(tpm, to, TPM_CRB_CTRL_CANCEL, func);
	}

	return (false);
}

static int
crb_recv_data(tpm_t *tpm, uint8_t *buf, uint32_t buflen)
{
	tpm_crb_t *crb = &tpm->tpm_u.tpmu_crb;
	const uint8_t *src = tpm->tpm_addr + crb->tcrb_resp_off;
	uint32_t resplen;

	VERIFY3U(buflen, >=, crb->tcrb_resp_size);
	VERIFY0(buflen & 3);

	mutex_enter(&tpm->tpm_lock);
	if (tpm->tpm_thr_cancelreq) {
		mutex_exit(&tpm->tpm_lock);
		return (SET_ERROR(ECANCELED));
	}
	mutex_exit(&tpm->tpm_lock);

	crb_set_state(tpm, TCRB_ST_CMD_COMPLETION);

	bzero(buf, buflen);

	bcopy(src, buf, TPM_HEADER_SIZE);
	resplen = tpm_cmdlen(buf);

	/* Any response should fit in the TPM's own response buffer */
	if (resplen > crb->tcrb_resp_size) {
		/* TODO: ereport */
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!received excessively large (%u) sized response",
		    resplen);

		/* Try to recover by going idle */
		(void) crb_go_idle(tpm);

		return (SET_ERROR(EINVAL));
	}

	if (resplen > buflen) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!response (%u) larger than buffer (%u)",
		    resplen, buflen);

		(void) crb_go_idle(tpm);
		return (SET_ERROR(E2BIG));
	}

	if (resplen < TPM_HEADER_SIZE) {
		/* TODO: ereport */
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!received header with invalid response length (%u)",
		    resplen);

		(void) crb_go_idle(tpm);
		return (SET_ERROR(EINVAL));
	}

	bcopy(src + TPM_HEADER_SIZE, buf + TPM_HEADER_SIZE,
	    resplen - TPM_HEADER_SIZE);

	return (0);
}

static bool
crb_request_locality_done(tpm_t *tpm, bool final, clock_t to, const char *func)
{
	uint32_t mask = TPM_LOC_STATE_REG_VALID | TPM_LOC_STATE_LOC_ASSIGNED |
	    TPM_LOC_SET(tpm->tpm_locality);

	if ((tpm_get32(tpm, TPM_LOC_STATE) & mask) == mask) {
		return (true);
	}

	if (final) {
		tpm_ereport_timeout(tpm, TPM_LOC_STATE, to, func);
	}

	return (false);
}

static int
crb_request_locality(tpm_t *tpm, uint8_t locality)
{
	uint32_t status;
	int8_t orig;
	int ret;

	VERIFY3U(locality, <, tpm->tpm_n_locality);

	/*
	 * TPM_CRB_LOC_STATE is mirrored across all localities (to allow
	 * determination of the active locality), so it doesn't matter
	 * which locality is used to read the state.
	 */
	status = tpm_get32_loc(tpm, locality, TPM_LOC_STATE);

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
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32_loc(tpm, locality, TPM_LOC_CTRL, TPM_LOC_CTRL_REQUEST);

	orig = tpm->tpm_locality;
	tpm->tpm_locality = locality;

	ret = tpm_wait(tpm, crb_request_locality_done, tpm->tpm_timeout_c,
	    __func__);
	if (ret != 0) {
		tpm->tpm_locality = orig;
	}

	return (ret);
}

static void
crb_release_locality(tpm_t *tpm)
{
	/*
	 * The TPM_LOC_CTRL_REQUEST register is write only. Bits written as
	 * 0 are ignored, so we don't need to read | OR to set a flag -- just
	 * write the value with the desired flags set.
	 */
	tpm_put32(tpm, TPM_LOC_CTRL, TPM_LOC_CTRL_RELINQUISH);
	tpm->tpm_locality = -1;
}

static void
crb_exec_finish(tpm_t *tpm)
{
	/*
	 * If the TPM is executing a command and we're now trying to finish,
	 * that means we never read the results either because we timed out
	 * executing or were asked to cancel. Either way, we have to
	 * explicitly tell the TPM to cancel what it's doing and then
	 * we can clean up.
	 */
	if (crb_state(tpm) == TCRB_ST_CMD_EXECUTION) {
		int ret;

		tpm_put32(tpm, TPM_CRB_CTRL_CANCEL, 1);
		ret = tpm_wait(tpm, crb_data_ready_cancel, tpm->tpm_timeout_b,
		    __func__);
		if (ret != 0) {
			return;
		}

		crb_set_state(tpm, TCRB_ST_CMD_COMPLETION);

		/*
		 * Clear the cancel bit so subsequent requests will be
		 * processed.
		 */
		tpm_put32(tpm, TPM_CRB_CTRL_CANCEL, 0);
	}

	(void) crb_go_idle(tpm);
	(void) crb_release_locality(tpm);
}

int
crb_exec_cmd(tpm_t *tpm, uint8_t loc, uint8_t *buf, size_t buflen)
{
	uint32_t cmdlen;
	int ret;

	VERIFY(tpm_can_access(tpm));
	VERIFY3S(tpm->tpm_iftype, ==, TPM_IF_CRB);
	VERIFY3U(buflen, >=, TPM_HEADER_SIZE);

	cmdlen = tpm_cmdlen(buf);
	VERIFY3U(cmdlen, >=, TPM_HEADER_SIZE);
	VERIFY3U(cmdlen, <=, buflen);

	if (tpm_cmdlen(buf) > tpm->tpm_u.tpmu_crb.tcrb_cmd_size) {
		return (SET_ERROR(E2BIG));
	}

	VERIFY(crb_state(tpm) == TCRB_ST_IDLE ||
	    crb_state(tpm) == TCRB_ST_READY);

	ret = crb_request_locality(tpm, loc);
	if (ret != 0) {
		return (ret);
	}

	ret = crb_send_data(tpm, buf, buflen);
	if (ret != 0) {
		goto done;
	}

	ret = crb_start(tpm, buf);
	if (ret != 0) {
		goto done;
	}

	ret = crb_recv_data(tpm, buf, buflen);

done:
	/*
	 * If we were cancelled, we defer putting the TPM into the
	 * ready state (which stops any current execution) and releasing
	 * the locality until after we've released the client to prevent
	 * it from blocking while waiting for the TPM to stop execution.
	 */
	if (ret == ECANCELED) {
		return (ret);
	}

	crb_exec_finish(tpm);
	return (ret);
}

void
crb_cancel_cmd(tpm_t *tpm, tpm_duration_t to)
{
	VERIFY(tpm_can_access(tpm));

	/* We should be called after the TPM thread has acked the cancel req */
	VERIFY(!tpm->tpm_thr_cancelreq);

	crb_exec_finish(tpm);
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
