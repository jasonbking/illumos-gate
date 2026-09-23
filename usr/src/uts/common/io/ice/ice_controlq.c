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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * This file implements the control queue interface
 *
 * XXX Assumptions we need to document: every register is the same in terms of
 * format, but the address is different.
 *  - Need to mention that RQ must be programmed before use
 *  - Need to mention that get version command is first command
 *  - Need to mention shutdown command
 */

#include <sys/sdt.h>
#include "ice.h"

/*
 * In general, the various registers and bits from hardware are supposed to be
 * the same for programing the various registers. We check that this hasn't
 * changed below and define a single definition for them so as to keep the code
 * simpler.
 */
CTASSERT(ICE_REG_PF_FW_ATQBAL != ICE_REG_PF_FW_ARQBAL);
CTASSERT(ICE_REG_PF_FW_ATQBAH != ICE_REG_PF_FW_ARQBAH);
CTASSERT(ICE_REG_PF_FW_ATQLEN != ICE_REG_PF_FW_ARQLEN);
CTASSERT(ICE_REG_PF_FW_ATQH != ICE_REG_PF_FW_ARQH);
CTASSERT(ICE_REG_PF_FW_ATQT != ICE_REG_PF_FW_ARQT);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQLEN_MASK == ICE_REG_PC_FW_ARQLEN_ATQLEN_MASK);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQVFE == ICE_REG_PC_FW_ARQLEN_ATQVFE);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQOVFL == ICE_REG_PC_FW_ARQLEN_ATQOVFL);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQCRIT == ICE_REG_PC_FW_ARQLEN_ATQCRIT);
CTASSERT(ICE_REG_PC_FW_ATQLEN_ATQENABLE == ICE_REG_PC_FW_ARQLEN_ATQENABLE);

#define	ICE_CONTROLQ_LEN_MASK	ICE_REG_PC_FW_ATQLEN_ATQLEN_MASK
#define	ICE_CONTROLQ_ENABLE	ICE_REG_PC_FW_ATQLEN_ATQENABLE

/*
 * These are default times for us to wait for commands to complete. The default
 * is to wait 10ms for up to 100 times.
 */
clock_t icq_controlq_delay = 10000;	/* 10ms in us */
uint_t icq_controlq_count = 100;

/*
 * How many times to retry and delay between retries when the controlq
 * encounters a critical error. From section 9.5.10.1, the queue is
 * stopped when this happens, and we can try to reset the queue.
 */
uint_t icq_controlq_reinit_retries = 10;
clock_t icq_controlq_reinit_delay = 100000;	/* 100ms in us */

typedef struct ice_cq_errmap {
	ice_cq_errno_t	ier_errno;
	const char	*ier_msg;
} ice_cq_errmap_t;

const char *
ice_controlq_errstr(ice_cq_errno_t cq_err)
{
#define	ERRSTR(_x) case ICE_CQ_##_x: return (#_x)
	switch (cq_err) {
	ERRSTR(SUCCESS);
	ERRSTR(EPERM);
	ERRSTR(ENOENT);
	ERRSTR(ESRCH);
	ERRSTR(EINTR);
	ERRSTR(EIO);
	ERRSTR(ENXIO);
	ERRSTR(E2BIG);
	ERRSTR(EAGAIN);
	ERRSTR(ENOMEM);
	ERRSTR(EACCESS);
	ERRSTR(EFAULT);
	ERRSTR(EBUSY);
	ERRSTR(EEXIST);
	ERRSTR(EINVAL);
	ERRSTR(ENOTTY);
	ERRSTR(ENOSPC);
	ERRSTR(ERANGE);
	ERRSTR(EFLUSHED);
	ERRSTR(BAD_ADDR);
	ERRSTR(EMODE);
	ERRSTR(EFBIG);
	ERRSTR(ESBCOMP);
	ERRSTR(RC_ENOSEC);
	ERRSTR(RC_EBADSIG);
	ERRSTR(RC_ESVN);
	ERRSTR(RC_EBADMAN);
	ERRSTR(RC_EBADBUF);
	ERRSTR(EACCES_BMCU);
	default:
		return ("Unknown");
	}
#undef ERRSTR
}

/*
 * The strings are mostly verbatim from Table 9-34. In a few instances
 * (e.g. ICE_CQ_ENOMEM) is used to make clear the error is from the
 * NIC and not the kernel.
 */
const char *
ice_controlq_errmsg(ice_cq_errno_t cq_err)
{
	switch (cq_err) {
	case ICE_CQ_SUCCESS:
		return ("No error");
	case ICE_CQ_EPERM:
		return ("Operation not permitted");
	case ICE_CQ_ENOENT:
		return ("No such element");
	case ICE_CQ_ESRCH:
		return ("Bad opcode");
	case ICE_CQ_EINTR:
		return ("Opreation interrupted");
	case ICE_CQ_EIO:
		return ("I/O error or firmware internal error");
	case ICE_CQ_ENXIO:
		return ("No such resource");
	case ICE_CQ_E2BIG:
		return ("Argument too long");
	case ICE_CQ_EAGAIN:
		return ("Try again");
	case ICE_CQ_ENOMEM:
		return ("(device) Out of memory");
	case ICE_CQ_EACCESS:
		return ("Permission denied");
	case ICE_CQ_EFAULT:
		return ("Bad address");
	case ICE_CQ_EBUSY:
		return ("Device or resource busy");
	case ICE_CQ_EEXIST:
		return ("Attempt to create something that exists");
	case ICE_CQ_EINVAL:
		return ("Invalid argument");
	case ICE_CQ_ENOTTY:
		return ("Not a typewriter");
	case ICE_CQ_ENOSPC:
		return ("No space left for device allocation failure");
	case ICE_CQ_ENOSYS:
		return ("Function not implemented");
	case ICE_CQ_ERANGE:
		return ("Parameter out of range");
	case ICE_CQ_EFLUSHED:
		return ("Command flushed because a previous command completed "
		    "in error");
	case ICE_CQ_BAD_ADDR:
		return ("Internal error. Descriptor contains a bad pointer");
	case ICE_CQ_EMODE:
		return ("Operation not allowed in current device mode");
	case ICE_CQ_EFBIG:
		return ("File too big");
	case ICE_CQ_ESBCOMP:
		return ("Cannot find enough space for the message in the "
		    "sideband or mailbox queue");
	case ICE_CQ_RC_ENOSEC:
		return ("Missing security manifest");
	case ICE_CQ_RC_EBADSIG:
		return ("Bad RSA signature");
	case ICE_CQ_RC_ESVN:
		return ("SVN number prohibits this package");
	case ICE_CQ_RC_EBADMAN:
		return ("Manifest hash mismatches manifest");
	case ICE_CQ_RC_EBADBUF:
		return ("Buffer hash mismatches manifest");
	case ICE_CQ_EACCES_BMCU:
		return ("BMC update in progress");
	default:
		return ("Unknown");
	}
}

int
ice_controlq_err_to_errno(ice_cq_errno_t cq_err)
{
	switch (cq_err) {
	case ICE_CQ_SUCCESS:
		return (0);
	case ICE_CQ_EPERM:
		return (EPERM);
	case ICE_CQ_ENOENT:
		return (ENOENT);
	case ICE_CQ_ESRCH:
		return (ESRCH);
	case ICE_CQ_EINTR:
		return (EINTR);
	case ICE_CQ_EIO:
		return (EIO);
	case ICE_CQ_ENXIO:
		return (ENXIO);
	case ICE_CQ_E2BIG:
		return (E2BIG);
	case ICE_CQ_EAGAIN:
		return (EAGAIN);
	case ICE_CQ_ENOMEM:
		return (ENOMEM);
	case ICE_CQ_EACCESS:
		return (EACCES);
	case ICE_CQ_EFAULT:
		return (EFAULT);
	case ICE_CQ_EBUSY:
		return (EBUSY);
	case ICE_CQ_EEXIST:
		return (EEXIST);
	case ICE_CQ_EINVAL:
		return (EINVAL);
	case ICE_CQ_ENOTTY:
		return (ENOTTY);
	case ICE_CQ_ENOSPC:
		return (ENOSPC);
	case ICE_CQ_ERANGE:
		return (ERANGE);
	case ICE_CQ_EFLUSHED:
	case ICE_CQ_BAD_ADDR:
	case ICE_CQ_EMODE:
		/* TODO */
		return (EIO);
	case ICE_CQ_EFBIG:
		return (EFBIG);
	case ICE_CQ_ESBCOMP:
	case ICE_CQ_RC_ENOSEC:
	case ICE_CQ_RC_EBADSIG:
	case ICE_CQ_RC_ESVN:
	case ICE_CQ_RC_EBADMAN:
	case ICE_CQ_RC_EBADBUF:
	case ICE_CQ_EACCES_BMCU:
		/* TODO */
		return (EIO);
	default:
		return (EIO);
	}
}

static uint_t
ice_controlq_incr(ice_controlq_t *cqp, uint_t val)
{
	ASSERT3U(val, <, cqp->icq_nents);
	val++;
	val %= cqp->icq_nents;
	return (val);
}

static void
ice_controlq_free(ice_controlq_t *cqp)
{
	if (cqp->icq_data_dma != NULL) {
		uint_t i;
		ASSERT3U(cqp->icq_nents, !=, 0);

		for (i = 0; i < cqp->icq_nents; i++) {
			ice_dma_free(&cqp->icq_data_dma[i]);
		}
		kmem_free(cqp->icq_data_dma, sizeof (ice_dma_buffer_t) *
		    cqp->icq_nents);
	}
	ice_dma_free(&cqp->icq_dma);
	cv_destroy(&cqp->icq_cv);
	mutex_destroy(&cqp->icq_lock);
}

static bool
ice_controlq_alloc(ice_t *ice, ice_controlq_t *cqp)
{
	size_t len;
	uint_t i;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;

	ASSERT3U(cqp->icq_nents, !=, 0);
	ASSERT3U(cqp->icq_bufsize, !=, 0);

	mutex_init(&cqp->icq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cqp->icq_cv, NULL, CV_DRIVER, NULL);

	len = cqp->icq_nents * sizeof (ice_cq_desc_t);
	ice_dma_acc_attr(ice, &acc);
	ice_dma_transfer_controlq_attr(ice, &attr);
	if (!ice_dma_alloc(ice, &cqp->icq_dma, &attr, &acc, true, len,
	    false)) {
		ice_controlq_free(cqp);
		ice_error(ice, "!failed to allocate controlq ring");
		return (false);
	}

	cqp->icq_desc = (ice_cq_desc_t *)cqp->icq_dma.idb_va;
	len = sizeof (ice_dma_buffer_t) * cqp->icq_nents;
	cqp->icq_data_dma = kmem_zalloc(len, KM_NOSLEEP);
	if (cqp->icq_data_dma == NULL) {
		ice_error(ice, "!failed to allocate %lu bytes to track "
		    "contorlq buffers");
		ice_controlq_free(cqp);
		return (false);
	}

	for (i = 0; i < cqp->icq_nents; i++) {
		if (!ice_dma_alloc(ice, &cqp->icq_data_dma[i], &attr, &acc,
		    true, cqp->icq_bufsize, false)) {
			ice_error(ice, "!failed to allocate controlq buffer %u",
			    i);
			ice_controlq_free(cqp);
			return (false);
		}
	}

	return (true);
}

static void
ice_controlq_pf_sq_regs(ice_controlq_t *cqp)
{
	cqp->icq_reg_head = ICE_REG_PF_FW_ATQH;
	cqp->icq_reg_tail = ICE_REG_PF_FW_ATQT;
	cqp->icq_reg_len = ICE_REG_PF_FW_ATQLEN;
	cqp->icq_reg_base_hi = ICE_REG_PF_FW_ATQBAH;
	cqp->icq_reg_base_lo = ICE_REG_PF_FW_ATQBAL;
}

static void
ice_controlq_pf_rq_regs(ice_controlq_t *cqp)
{
	cqp->icq_reg_head = ICE_REG_PF_FW_ARQH;
	cqp->icq_reg_tail = ICE_REG_PF_FW_ARQT;
	cqp->icq_reg_len = ICE_REG_PF_FW_ARQLEN;
	cqp->icq_reg_base_hi = ICE_REG_PF_FW_ARQBAH;
	cqp->icq_reg_base_lo = ICE_REG_PF_FW_ARQBAL;
}

/*
 * This is part of the teardown sequence as described in '9.5.4 Driver Unload
 * and Queue Shutdown'. It is assumed that someone has already called the queue
 * shutdown admin command.
 */
static void
ice_controlq_stop(ice_t *ice, ice_controlq_t *cqp)
{
	uint32_t val;

	if ((cqp->icq_flags & ICE_CONTROLQ_F_ENABLED) == 0) {
		return;
	}

	/*
	 * Make sure to turn off the enable bit first.
	 */
	val = ice_reg_read(ice, cqp->icq_reg_len);
	val &= ~ICE_CONTROLQ_ENABLE;
	ice_reg_write(ice, cqp->icq_reg_len, val);

	/*
	 * Now zero all the rest of the registers
	 */
	ice_reg_write(ice, cqp->icq_reg_len, 0);
	ice_reg_write(ice, cqp->icq_reg_base_hi, 0);
	ice_reg_write(ice, cqp->icq_reg_base_lo, 0);
	ice_reg_write(ice, cqp->icq_reg_head, 0);
	ice_reg_write(ice, cqp->icq_reg_tail, 0);

	cqp->icq_flags &= ~ICE_CONTROLQ_F_ENABLED;
}

/*
 * Follow the steps in '9.5.3 Initialization' to program and enable a given
 * controlq. Note, there are other constraints that are required to use the
 * controlq before it can generally be used.
 */
static void
ice_controlq_program(ice_t *ice, ice_controlq_t *cqp, uint_t tail)
{
	/*
	 * First zero the head and tail.
	 */
	ice_reg_write(ice, cqp->icq_reg_head, 0);
	ice_reg_write(ice, cqp->icq_reg_tail, 0);
	cqp->icq_head = 0;
	cqp->icq_tail = tail;

	/*
	 * Program the base and length registers, setting the enable bit.
	 */
	ice_reg_write(ice, cqp->icq_reg_base_lo,
	    cqp->icq_dma.idb_cookie.dmac_laddress & UINT32_MAX);
	ice_reg_write(ice, cqp->icq_reg_base_hi,
	    cqp->icq_dma.idb_cookie.dmac_laddress >> 32);

	VERIFY0(cqp->icq_nents & ~ICE_CONTROLQ_LEN_MASK);
	ice_reg_write(ice, cqp->icq_reg_len, cqp->icq_nents |
	    ICE_CONTROLQ_ENABLE);

	/*
	 * Update the tail now if it's non-zero.
	 */
	if (tail != 0) {
		ice_reg_write(ice, cqp->icq_reg_tail, tail);
	}

	cqp->icq_flags |= ICE_CONTROLQ_F_ENABLED;
}

/*
 * Reset a receive queue element into a state that makes sense for hardware to
 * receive it.
 */
static void
ice_controlq_rq_desc_reset(ice_controlq_t *cqp, uint_t ent)
{
	ice_cq_desc_t *desc;
	ice_dma_buffer_t *dmap;
	uint16_t flags = ICE_CQ_DESC_FLAGS_BUF;

	VERIFY3U(ent, <, cqp->icq_nents);
	desc = &cqp->icq_desc[ent];
	dmap = &cqp->icq_data_dma[ent];
	bzero(desc, sizeof (*desc));

	if (cqp->icq_bufsize > ICE_CQ_LARGE_BUF) {
		flags |= ICE_CQ_DESC_FLAGS_LB;
	}

	desc->icqd_flags = LE_16(flags);
	desc->icqd_data_len = LE_16(cqp->icq_bufsize);
	desc->icqd_command.icc_generic.iccg_data_high =
	    LE_32(dmap->idb_cookie.dmac_laddress >> 32);
	desc->icqd_command.icc_generic.iccg_data_low =
	    LE_32(dmap->idb_cookie.dmac_laddress & UINT32_MAX);
}

/*
 * Stop and reprogram both control queues using the DMA memory that is
 * already allocated for them, then confirm that firmware is responsive
 * again by issuing a get-version command over the (freshly reprogrammed)
 * admin send queue.
 *
 * Must be called with neither control queue's icq_lock held.
 */
static bool
ice_controlq_reinit(ice_t *ice)
{
	uint_t i;
	ice_fw_info_t ifi;

	mutex_enter(&ice->ice_asq.icq_lock);
	ice_controlq_stop(ice, &ice->ice_asq);
	ice_controlq_program(ice, &ice->ice_asq, 0);
	ice->ice_asq.icq_flags &= ~ICE_CONTROLQ_F_DEAD;
	cv_broadcast(&ice->ice_asq.icq_cv);
	mutex_exit(&ice->ice_asq.icq_lock);

	mutex_enter(&ice->ice_arq.icq_lock);
	ice_controlq_stop(ice, &ice->ice_arq);
	for (i = 0; i < ice->ice_arq.icq_nents; i++) {
		ice_controlq_rq_desc_reset(&ice->ice_arq, i);
	}
	ICE_DMA_SYNC(&ice->ice_arq.icq_dma, DDI_DMA_SYNC_FORDEV);
	ice_controlq_program(ice, &ice->ice_arq, ice->ice_arq.icq_nents - 1);
	ice->ice_arq.icq_flags &= ~ICE_CONTROLQ_F_DEAD;
	cv_broadcast(&ice->ice_arq.icq_cv);
	mutex_exit(&ice->ice_arq.icq_lock);

	return (ice_cmd_get_version(ice, &ifi));
}

/*
 * Recover the control queues after a critical firmware error. Per the
 * datasheet, firmware requires that "software reads and reports the error,
 * and then resets the queue". A single reset attempt may race with
 * firmware still recovering from whatever condition caused the critical
 * error, so retry with delays before giving up.
 */
static bool
ice_controlq_recover(ice_t *ice)
{
	uint_t i;

	ice_error(ice, "critical control queue error detected, attempting "
	    "to recover");

	for (i = 0; i < icq_controlq_reinit_retries; i++) {
		if (ice_controlq_reinit(ice)) {
			ice_error(ice, "!recovered control queue after "
			    "critical firmware error (%u attempt%s)", i + 1,
			    i == 0 ? "" : "s");
			return (true);
		}

		delay(drv_usectohz(icq_controlq_reinit_delay));
	}

	ice_error(ice, "failed to recover control queue after critical "
	    "firmware error after %u attempts", icq_controlq_reinit_retries);
	return (false);
}

void
ice_controlq_fini(ice_t *ice)
{
	/*
	 * Attempt to shutdown the queue. If we can't, drive on.
	 */
	if (!ice_cmd_queue_shutdown(ice, true)) {
		ice_error(ice, "!failed to shut down command queue, continuing "
		    "with controlq teardown");
	}
	ice_controlq_stop(ice, &ice->ice_arq);
	ice_controlq_stop(ice, &ice->ice_asq);
	ice_controlq_free(&ice->ice_arq);
	ice_controlq_free(&ice->ice_asq);
	mutex_destroy(&ice->ice_fwlog_lock);
}

bool
ice_controlq_init(ice_t *ice)
{
	uint_t i;
	int ret;

	mutex_init(&ice->ice_fwlog_lock, NULL, MUTEX_DRIVER, NULL);
	for (i = 0; i < ICE_CQ_FW_LOG_ID_MAX; i++) {
		ice->ice_fwlog_levels[i].iclm_module_id = i;
		ice->ice_fwlog_levels[i].iclm_log_level =
		    ICE_CQ_FW_LOG_LEVEL_NONE;
	}

	ice->ice_asq.icq_nents = ICE_CONTROLQ_SQ_NENTS;
	ice->ice_asq.icq_bufsize = ICE_CONTROLQ_BUFSIZE;
	ice->ice_arq.icq_nents = ICE_CONTROLQ_RQ_NENTS;
	ice->ice_arq.icq_bufsize = ICE_CONTROLQ_BUFSIZE;

	if (!ice_controlq_alloc(ice, &ice->ice_asq)) {
		mutex_destroy(&ice->ice_fwlog_lock);
		return (false);
	}

	if (!ice_controlq_alloc(ice, &ice->ice_arq)) {
		ice_controlq_free(&ice->ice_asq);
		mutex_destroy(&ice->ice_fwlog_lock);
		return (false);
	}

	ice_controlq_pf_sq_regs(&ice->ice_asq);
	ice_controlq_program(ice, &ice->ice_asq, 0);

	ice_controlq_pf_rq_regs(&ice->ice_arq);
	for (i = 0; i < ice->ice_arq.icq_nents; i++) {
		ice_controlq_rq_desc_reset(&ice->ice_arq, i);

	}
	ICE_DMA_SYNC(&ice->ice_arq.icq_dma, DDI_DMA_SYNC_FORDEV);
	ice_controlq_program(ice, &ice->ice_arq, ice->ice_arq.icq_nents - 1);

	if ((ret = ice_regs_check(ice)) != DDI_FM_OK) {
		ice_error(ice, "failed to program registers: FM I/O error: %d",
		    ret);
		/*
		 * It may be a little silly to try and shut down in face of an
		 * error, but we might as well give it a shot before we fail to
		 * attach.
		 */
		ice_controlq_fini(ice);
		return (false);
	}

	return (true);
}

/*
 * Translate a FW health status code into a short human-readable description.
 * Based on the list of codes and suggested remedies described by Intel's
 * datasheet/reference driver.
 */
static const char *
ice_health_status_str(uint16_t code)
{
	switch (code) {
	case ICE_CQ_HEALTH_STATUS_INFO_RECOVERY:
		return ("device is in firmware recovery mode; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_FLASH_ACCESS:
		return ("the flash chip cannot be accessed");
	case ICE_CQ_HEALTH_STATUS_ERR_NVM_AUTH:
		return ("NVM authentication failed; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_OROM_AUTH:
		return ("option ROM authentication failed; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_DDP_AUTH:
		return ("DDP package authentication failed; "
		    "update to latest base driver and DDP package");
	case ICE_CQ_HEALTH_STATUS_ERR_NVM_COMPAT:
		return ("NVM image is incompatible; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_OROM_COMPAT:
		return ("option ROM is incompatible; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_DCB_MIB:
		return ("supplied MIB file is invalid, DCB reverted to "
		    "default configuration");
	case ICE_CQ_HEALTH_STATUS_ERR_UNKNOWN_MOD_STRICT:
	case ICE_CQ_HEALTH_STATUS_ERR_UNKNOWN_MOD_LENIENT:
		return ("an unsupported module was detected; "
		    "check cable connection or replace the module/cable");
	case ICE_CQ_HEALTH_STATUS_ERR_MOD_TYPE:
		return ("module type is not supported; "
		    "change or replace the module or cable");
	case ICE_CQ_HEALTH_STATUS_ERR_MOD_QUAL:
		return ("module is not qualified");
	case ICE_CQ_HEALTH_STATUS_ERR_MOD_COMM:
		return ("device cannot communicate with the module");
	case ICE_CQ_HEALTH_STATUS_ERR_MOD_CONFLICT:
		return ("unresolved module conflict");
	case ICE_CQ_HEALTH_STATUS_ERR_MOD_NOT_PRESENT:
		return ("module is not present");
	case ICE_CQ_HEALTH_STATUS_INFO_MOD_UNDERUTILIZED:
		return ("underutilized module");
	case ICE_CQ_HEALTH_STATUS_ERR_INVALID_LINK_CFG:
		return ("invalid link configuration");
	case ICE_CQ_HEALTH_STATUS_ERR_PORT_ACCESS:
		return ("port hardware access error; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_PORT_UNREACHABLE:
		return ("a port is unreachable");
	case ICE_CQ_HEALTH_STATUS_INFO_PORT_SPEED_MOD_LIMITED:
		return ("port speed is limited due to module");
	case ICE_CQ_HEALTH_STATUS_ERR_PARALLEL_FAULT:
		return ("all configured link modes failed to establish "
		    "link; check link partner connection/configuration");
	case ICE_CQ_HEALTH_STATUS_INFO_PORT_SPEED_PHY_LIMITED:
		return ("port speed is limited by PHY capabilities");
	case ICE_CQ_HEALTH_STATUS_ERR_NETLIST_TOPO:
		return ("LOM topology netlist is corrupted; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_NETLIST:
		return ("unrecoverable netlist error; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_TOPO_CONFLICT:
		return ("port topology conflict");
	case ICE_CQ_HEALTH_STATUS_ERR_LINK_HW_ACCESS:
		return ("unrecoverable hardware access error; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_LINK_RUNTIME:
		return ("unrecoverable runtime error; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_DNL_INIT:
		return ("link management engine failed to initialize; "
		    "update to the latest NVM image");
	case ICE_CQ_HEALTH_STATUS_ERR_PHY_NVM_PROG:
		return ("PHY NVM programming error");
	case ICE_CQ_HEALTH_STATUS_ERR_PHY_FW_LOAD:
		return ("PHY firmware load error");
	case ICE_CQ_HEALTH_STATUS_ERR_NVM_SEC_VIOLATION:
		return ("NVM security violation");
	case ICE_CQ_HEALTH_STATUS_ERR_OROM_SEC_VIOLATION:
		return ("option ROM security violation");
	case ICE_CQ_HEALTH_STATUS_ERR_MNG_TIMEOUT:
		return ("manageability transaction timeout");
	case ICE_CQ_HEALTH_STATUS_ERR_BMC_RESET:
		return ("BMC reset detected");
	case ICE_CQ_HEALTH_STATUS_ERR_LAST_MNG_FAIL:
		return ("last manageability transaction failed");
	case ICE_CQ_HEALTH_STATUS_ERR_RESOURCE_ALLOC_FAIL:
		return ("resource allocation failed");
	case ICE_CQ_HEALTH_STATUS_ERR_FW_LOOP:
		return ("firmware detected a loop condition");
	case ICE_CQ_HEALTH_STATUS_ERR_FW_PFR_FAIL:
		return ("firmware-initiated PF reset failed");
	case ICE_CQ_HEALTH_STATUS_ERR_LAST_FAIL_AQ:
		return ("last admin queue command failed");
	default:
		return ("unknown health status code");
	}
}

/*
 * Decode and log a FW health status event (ICE_CQ_OP_GET_HEALTH_STATUS),
 * which arrives asynchronously over the ARQ once enabled via
 * ice_cmd_set_health_status_config(). The event's associated data buffer
 * contains an array of ice_cq_health_status_elem_t entries.
 */
static void
ice_controlq_health_status_event(ice_t *ice, ice_controlq_t *cqp, uint_t ent)
{
	ice_cq_desc_t *desc = &cqp->icq_desc[ent];
	ice_dma_buffer_t *dmap = &cqp->icq_data_dma[ent];
	ice_cq_health_status_elem_t *elem;
	uint16_t count, i, max;
	const char *source;

	ICE_DMA_SYNC(dmap, DDI_DMA_SYNC_FORKERNEL);

	count = LE_16(desc->icqd_command.icc_get_health_status.
	    icchs_status_count);

	max = LE_16(desc->icqd_data_len) / sizeof (ice_cq_health_status_elem_t);
	if (count > max) {
		ice_error(ice, "received a health status event with an "
		    "invalid count: %u, truncating to %u", count, max);
		count = max;
	}

	elem = (ice_cq_health_status_elem_t *)dmap->idb_va;
	for (i = 0; i < count; i++, elem++) {
		const char *str;
		uint32_t data1, data2;
		uint16_t code = LE_16(elem->icchse_status_code);
		uint16_t esrc = LE_16(elem->icchse_event_source);

		/*
		 * We already log adminq failures, and in some cases failure may
		 * be an expected condition (e.g. getting device/function
		 * caps), so ignore adminq failures.
		 */
		if (code == ICE_CQ_HEALTH_STATUS_ERR_LAST_FAIL_AQ) {
			continue;
		}

		switch (esrc) {
		case ICE_CQ_HEALTH_STATUS_SOURCE_PF:
			source = "PF";
			break;
		case ICE_CQ_HEALTH_STATUS_SOURCE_PORT:
			source = "port";
			break;
		case ICE_CQ_HEALTH_STATUS_SOURCE_GLOBAL:
			source = "global";
			break;
		default:
			source = "unknown";
			break;
		}

		str = ice_health_status_str(code);
		data1 = LE_32(elem->icchse_data1);
		data2 = LE_32(elem->icchse_data2);

		ice_error(ice, "!%s health status event (code 0x%x): %s "
		    "(data 0x%x, 0x%x)", source, code, str, data1, data2);

		if (DDI_FM_EREPORT_CAP(ice->ice_fm_caps)) {
			char buf[FM_MAX_CLASS];
			uint64_t ena;

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    ICE_FM_SERVICE_ICE, "hse");
			ena = fm_ena_generate(0, FM_ENA_FMT1);

			ddi_fm_ereport_post(ice->ice_dip, buf, ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
			    FM_EREPORT_VERS0,
			    "code", DATA_TYPE_UINT16, code,
			    "desc", DATA_TYPE_STRING, str,
			    "source", DATA_TYPE_STRING, source,
			    "data1", DATA_TYPE_UINT32, data1,
			    "data2", DATA_TYPE_UINT32, data2,
			    NULL);

			/*
			 * For now, these are treated as informational only.
			 * With more experience, we may wish to have
			 * some events mark the device degraded.
			 */
			ddi_fm_service_impact(ice->ice_dip,
			    DDI_SERVICE_UNAFFECTED);
		}
	}
}

/*
 * Handle a FW logging event (ICE_CQ_OP_FW_LOGS_EVENT), which arrives
 * asynchronously over the ARQ once registered via ice_cmd_fw_log_register().
 * The associated data buffer contains an opaque, FW-formatted log message.
 * Rather than logging these to the console (which would be excessively
 * noisy), we fire an SDT probe with the raw message so it can be consumed
 * live with DTrace, e.g.:
 *
 *   dtrace -n 'sdt:ice::fwlog-message { tracemem(arg0, arg1); }'
 */
static void
ice_controlq_fwlog_event(ice_t *ice, ice_controlq_t *cqp, uint_t ent)
{
	ice_cq_desc_t *desc = &cqp->icq_desc[ent];
	ice_dma_buffer_t *dmap = &cqp->icq_data_dma[ent];
	uint16_t len = LE_16(desc->icqd_data_len);

	if (len == 0) {
		return;
	}

	ICE_DMA_SYNC(dmap, DDI_DMA_SYNC_FORKERNEL);

	DTRACE_PROBE2(ice__fwlog__message, uint8_t *, (uint8_t *)dmap->idb_va,
	    uint16_t, len);
}

/*
 * Process all extant entries in the receive side control queue. For each entry
 * received, turn around and prepare it again. The main item that we expect to
 * receive information about are link status notifications. These should all be
 * amortized and dealt with at the end. We note that we receive such link status
 * events, but as we need to send another one to re-arm it, we wait until we
 * have that in place before we do anything else.
 */
ice_work_task_t
ice_controlq_rq_process(ice_t *ice)
{
	ice_controlq_t *cqp = &ice->ice_arq;
	uint_t head, len;
	ice_work_task_t ret = ICE_WORK_NONE;

	mutex_enter(&cqp->icq_lock);
	len = ice_reg_read(ice, cqp->icq_reg_len);

	/*
	 * In the event that we have an overflow, assume that we've missed some
	 * number of work link status events. Normal processing of the queue
	 * below should cause us to hopefully recover.
	 *
	 * XXX There is probably other processing required here.
	 */
	if ((len & ICE_REG_PC_FW_ARQLEN_ATQOVFL) != 0) {
		ice_error(ice, "admin rq overflow");
		ret |= ICE_WORK_LINK_STATUS_EVENT;
	}

	if ((len & ICE_REG_PC_FW_ARQLEN_ATQCRIT) != 0) {
		ice_error(ice, "admin rq critical error");
		mutex_exit(&cqp->icq_lock);

		/*
		 * Per the E810 datasheet (9.5.10.1, "Critical Error
		 * Indication"), firmware has already stopped this queue;
		 * recovery requires the driver to reset it. The receive
		 * queue is fully reprogrammed as part of that recovery, so
		 * there is nothing left in it for us to walk afterwards.
		 * See the comment in ice_cmd_submit() on ice_ctlq_recovering.
		 */
		if (atomic_cas_32(&ice->ice_ctlq_recovering, 0, 1) == 0) {
			(void) ice_controlq_recover(ice);
			atomic_and_32(&ice->ice_ctlq_recovering, 0);
		}

		return (ret);
	}

	head = ice_reg_read(ice, cqp->icq_reg_head);
	/* XXX DMA Sync */

	while (head != cqp->icq_head) {
		uint16_t opcode;
		ice_cq_desc_t *desc;

		desc = &cqp->icq_desc[cqp->icq_head];
		opcode = LE_16(desc->icqd_opcode);
		switch (opcode) {
		case ICE_CQ_OP_GET_LINK_STATUS:
			ret |= ICE_WORK_LINK_STATUS_EVENT;
			break;
		case ICE_CQ_OP_GET_HEALTH_STATUS:
			ice_controlq_health_status_event(ice, cqp,
			    cqp->icq_head);
			break;
		case ICE_CQ_OP_FW_LOGS_EVENT:
			ice_controlq_fwlog_event(ice, cqp, cqp->icq_head);
			break;
		default:
			ice_error(ice, "reiceved unknown ARQ opcode: 0x%x, "
			    "ignoring", opcode);
		}

		/*
		 * Reset the descriptor for service in the ring.
		 */
		ice_controlq_rq_desc_reset(cqp, cqp->icq_head);
		cqp->icq_head = ice_controlq_incr(cqp, cqp->icq_head);
		cqp->icq_tail = ice_controlq_incr(cqp, cqp->icq_tail);
		ice_reg_write(ice, cqp->icq_reg_tail, cqp->icq_tail);
	}
	mutex_exit(&cqp->icq_lock);

	return (ret);
}

/*
 * Initialize a command structure for a basic direct command.
 */
static void
ice_cmd_direct_init(ice_cq_desc_t *desc, ice_cq_opcode_t op)
{
	bzero(desc, sizeof (ice_cq_desc_t));

	desc->icqd_flags = LE_16(ICE_CQ_DESC_FLAGS_SI);
	desc->icqd_opcode = LE_16(op);
}

static void
ice_cmd_indirect_init(ice_cq_desc_t *desc, ice_cq_opcode_t op, uint16_t len,
    bool fw_read_buf)
{
	uint16_t flags;
	bzero(desc, sizeof (ice_cq_desc_t));

	ASSERT3U(len, <=, ICE_CQ_MAX_BUF);
	flags = ICE_CQ_DESC_FLAGS_SI | ICE_CQ_DESC_FLAGS_BUF;
	if (fw_read_buf) {
		flags |= ICE_CQ_DESC_FLAGS_RD;
	}
	if (len >= ICE_CQ_LARGE_BUF) {
		flags |= ICE_CQ_DESC_FLAGS_LB;
	}

	desc->icqd_flags = LE_16(flags);
	desc->icqd_opcode = LE_16(op);
	desc->icqd_data_len = LE_16(len);
}

typedef enum {
	ICE_CMD_COPY_NONE	= 0,
	ICE_CMD_COPY_TO_DEV	= 0x1,
	ICE_CMD_COPY_FROM_DEV	= 0x2,
	ICE_CMD_COPY_BOTH	= 3
} ice_cmd_copy_t;

/*
 * Submit a command to the send queue, bump the register that indicates that we
 * own it,
 */
static bool
ice_cmd_submit(ice_t *ice, ice_controlq_t *cqp, ice_cq_desc_t *desc, void *buf,
    ice_cmd_copy_t copy)
{
	uint_t i;
	ice_cq_desc_t *hwd;
	ice_dma_buffer_t *extra = NULL;

#ifdef	DEBUG
	if (buf == NULL) {
		ASSERT3U(copy, ==, ICE_CMD_COPY_NONE);
	} else {
		ASSERT3U(copy, !=, ICE_CMD_COPY_NONE);
		switch (copy) {
		case ICE_CMD_COPY_TO_DEV:
		case ICE_CMD_COPY_FROM_DEV:
		case ICE_CMD_COPY_BOTH:
			break;
		default:
			panic("ice bad command copy type: 0x%x", copy);
		}
	}
#endif

	mutex_enter(&cqp->icq_lock);
	while ((cqp->icq_flags & ICE_CONTROLQ_F_BUSY) != 0) {
		cv_wait(&cqp->icq_cv, &cqp->icq_lock);
	}

	/*
	 * If we don't believe the queue can't be used, then there's no point
	 * even trying to go any further. However, we must make sure that we
	 * notify anyone else who may be attempting to use it.
	 */
	if ((cqp->icq_flags & ICE_CONTROLQ_F_DEAD) != 0) {
		cv_broadcast(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);
		return (false);
	}

	cqp->icq_flags |= ICE_CONTROLQ_F_BUSY;
	mutex_exit(&cqp->icq_lock);

	hwd = &cqp->icq_desc[cqp->icq_tail];
	bcopy(desc, hwd, sizeof (ice_cq_desc_t));

	/*
	 * Check if we need to set up the secondary DMA buffer.
	 */
	if (buf != NULL) {
		ice_cq_cmd_generic_t *gen;

		extra = &cqp->icq_data_dma[cqp->icq_tail];
		gen = &hwd->icqd_command.icc_generic;
		gen->iccg_data_high = LE_32(extra->idb_cookie.dmac_laddress >>
		    32);
		gen->iccg_data_low = LE_32(extra->idb_cookie.dmac_laddress &
		    UINT32_MAX);

		/*
		 * XXX Come back to this, if hw returns a bad value, we'll
		 * overwrite our buffers, but this gets us off the ground
		 */
		bzero(extra->idb_va, extra->idb_len);
		if ((copy & ICE_CMD_COPY_TO_DEV) != 0) {
			bcopy(buf, extra->idb_va, LE_16(hwd->icqd_data_len));
		}
		ICE_DMA_SYNC(extra, DDI_DMA_SYNC_FORDEV);
	}

	ICE_DMA_SYNC(&cqp->icq_dma, DDI_DMA_SYNC_FORDEV);

	cqp->icq_tail = ice_controlq_incr(cqp, cqp->icq_tail);
	ice_reg_write(ice, cqp->icq_reg_tail, cqp->icq_tail);
	for (i = 0; i < icq_controlq_count; i++) {
		uint32_t head;

		head = ice_reg_read(ice, cqp->icq_reg_head);
		if (head == cqp->icq_tail)
			break;

		delay(drv_usectohz(icq_controlq_delay));
	}

	cqp->icq_head = ice_reg_read(ice, cqp->icq_reg_head);
	mutex_enter(&cqp->icq_lock);
	cqp->icq_flags &= ~ICE_CONTROLQ_F_BUSY;

	if (cqp->icq_head != cqp->icq_tail) {
		bool critical;
		uint32_t len;

		len = ice_reg_read(ice, cqp->icq_reg_len);
		critical = (len & ICE_REG_PC_FW_ATQLEN_ATQCRIT) != 0;

		ice_error(ice, "Command 0x%x timed out%s! Marking adminq dead",
		    LE_16(desc->icqd_opcode),
		    critical ? " due to a critical firmware error" : "");
		cqp->icq_flags |= ICE_CONTROLQ_F_DEAD;
		cv_signal(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);

		/*
		 * If firmware reported a critical error, attempt to recover
		 * the control queues per the E810 datasheet (9.5.10.1).
		 * ice_ctlq_recovering is used to claim the right to recover
		 * so that the get-version liveness check that
		 * ice_controlq_recover() issues (which comes back through
		 * here on the admin send queue) cannot recursively trigger
		 * another recovery attempt if it also times out.
		 */
		if (critical &&
		    atomic_cas_32(&ice->ice_ctlq_recovering, 0, 1) == 0) {
			(void) ice_controlq_recover(ice);
			atomic_and_32(&ice->ice_ctlq_recovering, 0);
		}

		return (false);
	}

	ICE_DMA_SYNC(&cqp->icq_dma, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Verify that DD is set.
	 */
	if ((LE_16(hwd->icqd_flags) & ICE_CQ_DESC_FLAGS_DD) == 0) {
		ice_error(ice, "Hardware incremented tail, but DD missing "
		    "from command 0x%x, flags: 0x%x; marking admin queue dead",
		    LE_16(desc->icqd_opcode), LE_16(desc->icqd_flags));
		cqp->icq_flags |= ICE_CONTROLQ_F_DEAD;
		cv_signal(&cqp->icq_cv);
		mutex_exit(&cqp->icq_lock);
		return (false);
	}

	bcopy(hwd, desc, sizeof (ice_cq_desc_t));
	if ((copy & ICE_CMD_COPY_FROM_DEV) != 0) {
		ICE_DMA_SYNC(extra, DDI_DMA_SYNC_FORKERNEL);
		bcopy(extra->idb_va, buf, LE_16(hwd->icqd_data_len));
	}

	cv_signal(&cqp->icq_cv);
	mutex_exit(&cqp->icq_lock);
	return (true);
}

static bool
ice_cmd_result(ice_cq_desc_t *desc, ice_cq_errno_t *errp, uint8_t *hwcode)
{
	uint16_t ret = LE_16(desc->icqd_id_ret);

	if (ret == 0) {
		*errp = ICE_CQ_SUCCESS;
		*hwcode = 0;
		return (true);
	}

	*errp = (ret & ICE_CQ_ERR_CODE_MASK);
	*hwcode = ((ret & ICE_CQ_ERR_CODE_FW_MASK) >> ICE_CQ_ERR_CODE_FW_SHIFT);

	return (false);
}

static bool
ice_cmd_ckerr(ice_t *ice, ice_cq_desc_t *desc, const ice_cq_errmap_t *em,
    const char *msg, ...)
{
	const char *emsg;
	ice_cq_errno_t err;
	uint8_t hw;

	if (ice_cmd_result(desc, &err, &hw)) {
		return (true);
	}

	/* Use more context specific error messages if given */
	emsg = ice_controlq_errmsg(err);
	while (em != NULL && em->ier_msg != NULL) {
		if (em->ier_errno == err) {
			emsg = em->ier_msg;
			break;
		}
		em++;
	}

	va_list ap;
	char buf[256];

	va_start(ap, msg);
	(void) vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	ice_error(ice, "%s command failed with: %s (%s - %u) (fw private: %x)",
	    buf, emsg, ice_controlq_errstr(err), err, hw);

	return (false);
}

/*
 * Query the firmware for its version information and store that on the ice_t as
 * appropriate.
 */
bool
ice_cmd_get_version(ice_t *ice, ice_fw_info_t *ifi)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_get_version_t	*gvp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_GET_VER);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "get version")) {
		return (false);
	}

	gvp = &desc.icqd_command.icc_get_version;
	ifi->ifi_fw_branch = gvp->iccgv_fw_branch;
	ifi->ifi_fw_branch = gvp->iccgv_fw_branch;
	ifi->ifi_fw_major = gvp->iccgv_fw_major;
	ifi->ifi_fw_minor = gvp->iccgv_fw_minor;
	ifi->ifi_fw_patch = gvp->iccgv_fw_patch;
	ifi->ifi_aq_branch = gvp->iccgv_aq_branch;
	ifi->ifi_aq_major = gvp->iccgv_aq_major;
	ifi->ifi_aq_minor = gvp->iccgv_aq_minor;
	ifi->ifi_aq_patch = gvp->iccgv_aq_patch;
	ifi->ifi_rom_build = LE_32(gvp->iccgv_rom_build);
	ifi->ifi_fw_build = LE_32(gvp->iccgv_fw_build);

	return (true);
}

bool
ice_cmd_driver_version(ice_t *ice, uint8_t maj, uint8_t min, uint8_t patch,
    uint8_t rc, const char *str)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_driver_version_t	*dv;
	size_t				slen = 0;

	if (str != NULL) {
		slen = strlen(str);
	}

	dv = &desc.icqd_command.icc_driver_version;
	dv->iccdv_major = maj;
	dv->iccdv_minor = min;
	dv->iccdv_build = patch;
	dv->iccdv_sub_build = rc;
	ice_cmd_indirect_init(&desc, ICE_CQ_OP_DRIVER_VERSION, slen, true);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, (void *)str,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "send driver version"));
}

bool
ice_cmd_queue_shutdown(ice_t *ice, bool unload)
{
	ice_cq_desc_t desc;
	ice_cq_cmd_queue_shutdown_t *qsp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_QUEUE_SHUTDOWN);
	qsp = &desc.icqd_command.icc_queue_shutdown;
	if (unload) {
		qsp->iccqs_flags |= ICE_CQ_CMD_QUEUE_SHUTDOWN_UNLOADING;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "queue shutdown"));
}

bool
ice_cmd_clear_pf_config(ice_t *ice)
{
	ice_cq_desc_t	desc;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_CLEAR_PF_CONFIGURATION);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "clear pf config"));
}

bool
ice_cmd_clear_pxe(ice_t *ice)
{
	ice_cq_desc_t		desc;
	ice_cq_errno_t		err;
	uint8_t			hw;
	ice_cq_cmd_clear_pxe_t *cpp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_CLEAR_PXE);
	cpp = &desc.icqd_command.icc_clear_pxe;
	cpp->icccp_flags = ICE_CQ_CLEAR_PXE_FLAG;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	/*
	 * If PXE has already been cleared, then this command is defined to
	 * return EEXIST. We need to check against that and not fail the command
	 * if that happens.
	 */
	if (!ice_cmd_result(&desc, &err, &hw) && err != ICE_CQ_EEXIST) {
		return (ice_cmd_ckerr(ice, &desc, NULL, "clear pxe"));
	}

	return (true);
}

bool
ice_cmd_release_nvm(ice_t *ice)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_request_resource_t	*rsrc;

#ifdef	DEBUG
	mutex_enter(&ice->ice_nvm.in_lock);
	ASSERT(ice->ice_nvm.in_flags & ICE_NVM_LOCKED);
	mutex_exit(&ice->ice_nvm.in_lock);
#endif

	ice_cmd_direct_init(&desc, ICE_CQ_OP_RELEASE_RESOURCE);
	rsrc = &desc.icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(ICE_CQ_RESOURCE_NVM);
	rsrc->iccrr_res_number = 0;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "NVM release resource")) {
		return (false);
	}

	mutex_enter(&ice->ice_nvm.in_lock);
	ice->ice_nvm.in_flags &= ~ICE_NVM_LOCKED;
	mutex_exit(&ice->ice_nvm.in_lock);

	return (true);
}

static ice_cq_cmd_request_resource_t *
ice_cmd_init_acq_res(ice_cq_desc_t *desc, uint16_t res, bool write, uint32_t to)
{
	ice_cq_cmd_request_resource_t *rsrc;

	ice_cmd_direct_init(desc, ICE_CQ_OP_REQUEST_RESOURCE);
	rsrc = &desc->icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(res);
	if (write) {
		rsrc->iccrr_acc_type = LE_16(ICE_CQ_ACCESS_WRITE);
	} else {
		rsrc->iccrr_acc_type = LE_16(ICE_CQ_ACCESS_READ);
	}
	rsrc->iccrr_timeout = LE_32(to);
	rsrc->iccrr_res_number = 0;

	return (rsrc);
}

/*
 * NVM and change lock are firmware-arbitrated resources shared across
 * every PF of a physical device (the NVM by only one PF at a time; the
 * change lock guards the device-wide DDP package/flex-pipe tables -- see
 * the comment above ice_cmd_acquire_change_lock() below), so acquiring
 * either of them may need to retry.
 *
 * Per the datasheet, when a Request Resource Ownership command for either
 * of these two resources fails with EBUSY, the timeout field of the
 * completion is overwritten by firmware to indicate the maximum time (in
 * ms) that the *current* owner of the resource has left to hold it (and
 * not the timeout we requested).
 *
 * As we poll, we use that to limit how long we'll continue to poll.
 *
 * NOTE: this helper cannot be used for the Global Config Lock
 * (ICE_CQ_RESOURCE_GLOBAL_CONFIG): that resource does not signal
 * contention via EBUSY at all -- see ice_cmd_acquire_global_lock() below.
 */
#define	ICE_CQ_ACQ_POLL_MS	10

static bool
ice_cmd_acquire_res(ice_t *ice, uint16_t res, bool write, uint32_t req_timeout,
    const char *what)
{
	uint32_t	timeout = 0;
	bool		first = true;

	for (;;) {
		ice_cq_desc_t			desc;
		ice_cq_cmd_request_resource_t	*rsrc;
		ice_cq_errno_t			err;
		uint32_t			cur_owner_timeout;
		uint8_t				hw;

		rsrc = ice_cmd_init_acq_res(&desc, res, write, req_timeout);

		if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
		    ICE_CMD_COPY_NONE)) {
			return (false);
		}

		if (ice_cmd_result(&desc, &err, &hw)) {
			return (true);
		}

		if (err != ICE_CQ_EBUSY) {
			(void) ice_cmd_ckerr(ice, &desc, NULL, what);
			return (false);
		}

		/*
		 * The completion's timeout field holds the current
		 * owner's remaining hold time. Use it to adjust our
		 * own timeout on the first loop iteration as long as
		 * the timeout is non-zero.
		 */
		cur_owner_timeout = LE_32(rsrc->iccrr_timeout);
		if (first) {
			timeout = cur_owner_timeout;
			first = false;
		}

		if (timeout == 0 || cur_owner_timeout == 0) {
			(void) ice_cmd_ckerr(ice, &desc, NULL, what);
			return (false);
		}

		delay(drv_usectohz(ICE_CQ_ACQ_POLL_MS * 1000));
		timeout = (timeout > ICE_CQ_ACQ_POLL_MS) ?
		    timeout - ICE_CQ_ACQ_POLL_MS : 0;
	}
}

bool
ice_cmd_acquire_nvm(ice_t *ice, bool write)
{
	uint32_t req_timeout;

	req_timeout = write ?
	    ICE_CQ_TIMEOUT_NVM_WRITE : ICE_CQ_TIMEOUT_NVM_READ;

#ifdef	DEBUG
	mutex_enter(&ice->ice_nvm.in_lock);
	ASSERT0(ice->ice_nvm.in_flags & ICE_NVM_LOCKED);
	mutex_exit(&ice->ice_nvm.in_lock);
#endif

	if (!ice_cmd_acquire_res(ice, ICE_CQ_RESOURCE_NVM, write, req_timeout,
	    "NVM request resource")) {
		return (false);
	}

	mutex_enter(&ice->ice_nvm.in_lock);
	ice->ice_nvm.in_flags |= ICE_NVM_LOCKED;
	mutex_exit(&ice->ice_nvm.in_lock);

	return (true);
}

bool
ice_cmd_nvm_read(ice_t *ice, uint16_t module, uint32_t offset, uint16_t *lenp,
    uint16_t *outp, bool last, bool skip_shadow)
{
	ice_cq_desc_t		desc;
	uint32_t		bpage, fpage;
	ice_cq_cmd_nvm_read_t	*read;

	ice_nvm_t *nvm = &ice->ice_nvm;
	uint16_t len = *lenp;

#ifdef DEBUG
	mutex_enter(&nvm->in_lock);
	VERIFY(nvm->in_flags & ICE_NVM_LOCKED);
	mutex_exit(&nvm->in_lock);
#endif

	/*
	 * We can only read up to 4k at a time and we cannot cross a 4k sector.
	 * Also, we only have three bytes of offset, therefore if offset has
	 * invalid bits set, that's an error.
	 */
	if ((offset & 0xff000000) != 0 || len == 0 || len > nvm->in_sector) {
		ice_error(ice, "invalid nvm read offset or length");
		return (false);
	}
	bpage = offset & ~(nvm->in_sector - 1);
	/*
	 * Use the offset of the last byte actually read (offset + len - 1),
	 * to determine which sector the read ends in.
	 */
	fpage = (offset + len - 1) & ~(nvm->in_sector - 1);
	if (bpage != fpage) {
		ice_error(ice, "NVM read crosses pages, 0x%x, 0x%x",
		    bpage, fpage);
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_NVM_READ, len, false);
	read = &desc.icqd_command.icc_nvm_read;
	read->iccnr_offset[0] = offset & 0xff;
	read->iccnr_offset[1] = (offset >> 8) & 0xff;
	read->iccnr_offset[2] = (offset >> 16) & 0xff;
	if (last) {
		read->iccnr_flags |= ICE_CQ_NVM_READ_LAST_COMMAND;
	}
	if (skip_shadow) {
		read->iccnr_flags |= ICE_CQ_NVM_READ_SKIP_SHADOW;
	}
	read->iccnr_module_type = LE_16(module);
	read->iccnr_length = LE_16(len);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, outp,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "NVM read %d bytes at off 0x%x",
	    len, offset)) {
		return (false);
	}

	*lenp = LE_16(desc.icqd_data_len);

	return (true);
}

/*
 * The global config lock guards the DDP package download itself and is
 * shared across every PF of the device: all of a device's PFs attach
 * independently (and hence may call this concurrently, e.g. right after a
 * power cycle).
 *
 * Unlike every other shared resource, this one does NOT signal contention
 * via an EBUSY completion of the "Request Resource Ownership" command --
 * per the datasheet, that command always completes successfully for this
 * resource ID. Instead, firmware reports the real disposition in the
 * command-specific Status field:
 *
 *   - ICE_CQ_GLBL_STAT_SUCCESS: we now own the lock and must download the
 *     package (and eventually release the lock).
 *
 *   - ICE_CQ_GLBL_STAT_INPROGRESS: another PF currently owns the lock and
 *     is (or is about to be) downloading the package; poll and retry,
 *     bounded by the current owner's remaining hold time (reported in the
 *     Timeout field, exactly as with a normal EBUSY completion).
 *
 *   - ICE_CQ_GLBL_STAT_COMPLETED: another PF already downloaded an
 *     identical package; we were not granted the lock and there is no
 *     download for us to do, but this is not an error -- the caller
 *     should skip the actual package download (and must not attempt to
 *     release a lock it was never granted) but should otherwise proceed
 *     as if the download had succeeded.
 *
 * *heldp is set to indicate whether we were actually granted the lock
 * (and hence must release it once done), which is only meaningful when
 * this function returns true.
 */
bool
ice_cmd_acquire_global_lock(ice_t *ice, bool write, bool *heldp)
{
	uint32_t	timeout = 0;
	bool		first = true;

	*heldp = false;

	for (;;) {
		ice_cq_desc_t			desc;
		ice_cq_cmd_request_resource_t	*rsrc;
		ice_cq_errno_t			err;
		uint32_t			cur_owner_timeout;
		uint16_t			status;
		uint8_t				hw;

		rsrc = ice_cmd_init_acq_res(&desc,
		    ICE_CQ_RESOURCE_GLOBAL_CONFIG, write,
		    ICE_CQ_TIMEOUT_GLOBAL_CONFIG);

		if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
		    ICE_CMD_COPY_NONE)) {
			return (false);
		}

		if (!ice_cmd_result(&desc, &err, &hw)) {
			(void) ice_cmd_ckerr(ice, &desc, NULL,
			    "acquire global config lock");
			return (false);
		}

		status = LE_16(rsrc->iccrr_status);
		switch (status) {
		case ICE_CQ_GLBL_STAT_SUCCESS:
			*heldp = true;
			return (true);
		case ICE_CQ_GLBL_STAT_COMPLETED:
			return (true);
		case ICE_CQ_GLBL_STAT_INPROGRESS:
			break;
		default:
			ice_error(ice, "unexpected global config lock "
			    "status 0x%x", status);
			return (false);
		}

		/*
		 * As with EBUSY on other resources, the Timeout field of
		 * an ICE_CQ_GLBL_STAT_INPROGRESS completion reports the
		 * current owner's remaining hold time; use it to bound how
		 * long we continue polling.
		 */
		cur_owner_timeout = LE_32(rsrc->iccrr_timeout);
		if (first) {
			timeout = cur_owner_timeout;
			first = false;
		}

		if (timeout == 0 || cur_owner_timeout == 0) {
			ice_error(ice, "timed out waiting for global "
			    "config lock");
			return (false);
		}

		delay(drv_usectohz(ICE_CQ_ACQ_POLL_MS * 1000));
		timeout = (timeout > ICE_CQ_ACQ_POLL_MS) ?
		    timeout - ICE_CQ_ACQ_POLL_MS : 0;
	}
}

bool
ice_cmd_release_global_lock(ice_t *ice)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_request_resource_t	*rsrc;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_RELEASE_RESOURCE);
	rsrc = &desc.icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(ICE_CQ_RESOURCE_GLOBAL_CONFIG);
	rsrc->iccrr_res_number = 0;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "release global config lock"));
}

/*
 * The change lock guards the shared flex-pipe package tables (XLT1, XLT2,
 * profile ID TCAM, and field vector/extraction sequence tables) that
 * ice_cmd_update_pkg() writes to. These tables are a device-wide (not
 * per-PF) hardware resource, so every "Update Package" AQ command must be
 * bracketed by acquiring/releasing this lock.
 *
 * Since it's possible two different PFs on the same device may be
 * configuring RSS concurrently (e.g. after a reset), we retry on busy
 * instead of immediately failing.
 */
bool
ice_cmd_acquire_change_lock(ice_t *ice, bool write)
{
	return (ice_cmd_acquire_res(ice, ICE_CQ_RESOURCE_CHANGE_LOCK, write,
	    ICE_CQ_TIMEOUT_CHANGE_LOCK, "acquire change lock"));
}

bool
ice_cmd_release_change_lock(ice_t *ice)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_request_resource_t	*rsrc;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_RELEASE_RESOURCE);
	rsrc = &desc.icqd_command.icc_request_resource;
	rsrc->iccrr_res_id = LE_16(ICE_CQ_RESOURCE_CHANGE_LOCK);
	rsrc->iccrr_res_number = 0;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "release change lock"));
}

/*
 * We need to obtain all of the capabilities based on the type listed. We do
 * this in two pases. The first to get the exact number of capabilities, the
 * second to get all of them. We guess a given number of caps, but throw that
 * out
 */
bool
ice_cmd_get_caps(ice_t *ice, bool device, uint_t *ncapsp,
    ice_capability_t **capp)
{
	ice_cq_desc_t		desc;
	uint_t			ncaps = 1;
	ice_capability_t	*cap;
	uint16_t		len;
	ice_cq_opcode_t		op;
	const char		*opstr;
	ice_cq_errno_t		err;
	uint8_t			hw;

	if (device) {
		op = ICE_CQ_OP_DISCOVER_DEVICE_CAPS;
		opstr = "device";
	} else {
		op = ICE_CQ_OP_DISCOVER_FUNCTION_CAPS;
		opstr = "function";
	}

	len = ncaps * sizeof (*cap);
	cap = kmem_zalloc(sizeof (*cap) * ncaps, KM_SLEEP);

	ice_cmd_indirect_init(&desc, op, len, false);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, cap,
	    ICE_CMD_COPY_FROM_DEV)) {
		goto err;
	}

	if (!ice_cmd_result(&desc, &err, &hw) && err != ICE_CQ_ENOMEM) {
		ice_error(ice, "get %s capabilities failed with: %s (%s - %u) "
		    "(fw private: %x)", opstr, ice_controlq_errmsg(err),
		    ice_controlq_errstr(err), err, hw);
		goto err;
	}

	kmem_free(cap, sizeof (*cap) * ncaps);
	cap = NULL;
	/*
	 * The number of capabilities are returned in param 1.
	 */
	ncaps = LE_32(desc.icqd_command.icc_generic.iccg_param1);
	if (UINT16_MAX / sizeof (*cap) > ICE_CQ_MAX_BUF) {
		ice_error(ice, "invalid number of caps returned, would "
		    "overflow max buf");
		goto err;
	}

	len = ncaps * sizeof (*cap);
	cap = kmem_zalloc(len, KM_SLEEP);

	ice_cmd_indirect_init(&desc, op, len, false);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, cap,
	    ICE_CMD_COPY_FROM_DEV)) {
		goto err;
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "get %s capabilities", opstr)) {
		goto err;
	}

	*ncapsp = ncaps;
	*capp = cap;

	return (true);
err:
	if (cap != NULL) {
		kmem_free(cap, sizeof (*cap) * ncaps);
	}
	return (false);
}

bool
ice_cmd_mac_read(ice_t *ice, uint8_t *addr)
{
	uint8_t				buf[ICE_CQ_MANAGE_MAC_READ_BUFSIZE];
	ice_cq_desc_t			desc;
	uint8_t				i, maxaddr;
	ice_hw_mac_t			*macp;
	ice_cq_cmd_manage_mac_read_t	*cmdp;
	uint16_t			flags;

	bzero(buf, sizeof (buf));

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_MANAGE_MAC_READ, sizeof (buf),
	    false);
	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "read MAC address")) {
		return (false);
	}

	cmdp = &desc.icqd_command.icc_mac_read;
	macp = (ice_hw_mac_t *)buf;

	flags = LE_16(cmdp->iccmmr_flags);
	if ((flags & ICE_CQ_MANAGE_MAC_READ_LAN_VALID) == 0) {
		ice_error(ice, "failed to obtain a valid MAC address");
		return (false);
	}

	/*
	 * Determine the maximum valid MAC address we can have here. Since we
	 * only have a fixed buffer size, use that as a starting point and then
	 * take the minimum of that and hardware.
	 */
	maxaddr = ICE_CQ_MANAGE_MAC_READ_BUFSIZE / sizeof (ice_hw_mac_t);
	for (i = 0; i < MIN(maxaddr, cmdp->iccmmr_count); i++) {
		if (macp->ihm_type == ICE_HW_MAC_TYPE_LAN) {
			if (macp->ihm_mac[0] & 0x01) {
				ice_error(ice, "encountered illegal mcast "
				    "address as primary MAC: %02x:%02x:%02x:"
				    "%02x:%02x:%02x", macp->ihm_mac[0],
				    macp->ihm_mac[1], macp->ihm_mac[2],
				    macp->ihm_mac[3], macp->ihm_mac[4],
				    macp->ihm_mac[5]);
				continue;
			}

			if (macp->ihm_mac[0] == 0 && macp->ihm_mac[1] == 0 &&
			    macp->ihm_mac[2] == 0 && macp->ihm_mac[3] == 0 &&
			    macp->ihm_mac[4] == 0 && macp->ihm_mac[5] == 0) {
				ice_error(ice, "encountered all zeros MAC");
				continue;
			}

			bcopy(macp->ihm_mac, addr, ETHERADDRL);

			return (true);
		}
	}

	ice_error(ice, "failed to find a valid MAC address");
	return (false);
}

bool
ice_cmd_get_phy_abilities(ice_t *ice, ice_phy_abilities_t *datap,
    bool modules)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_get_phy_abilities_t	*phy;
	uint16_t			flags;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_PHY_ABILITIES,
	    sizeof (*datap), false);
	phy = &desc.icqd_command.icc_phy_abilities;
	flags = ICE_CQ_GET_PHY_ABILITIES_REPORT_MEDIA;
	if (modules) {
		flags |= ICE_CQ_GET_PHY_ABILITIES_REPORT_MODS;
	}
	phy->iccgpa_param0 = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, datap,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "read PHY abilities%s",
	    modules ? " (report mods)" : "")) {
		return (false);
	}

	/*
	 * Fix up endian issues.
	 */
	datap->ipa_eee = LE_16(datap->ipa_eee);
	datap->ipa_eeer = LE_16(datap->ipa_eeer);

	return (true);
}

/*
 * Per the E810 datasheet (3.2.4.1.1), this only takes effect on the link
 * once the caller either issues a Setup Link and Restart
 * Auto-Negotiation command (ice_cmd_setup_link()) or sets
 * ICE_PHY_CFG_AUTO_LINK_UPDATE in cfgp->ipc_caps to have firmware issue it
 * automatically.
 */
bool
ice_cmd_set_phy_config(ice_t *ice, const ice_phy_config_t *cfgp)
{
	ice_cq_desc_t		desc;
	ice_phy_config_t	data;

	bcopy(cfgp, &data, sizeof (data));
	data.ipc_eee = LE_16(data.ipc_eee);
	data.ipc_eeer = LE_16(data.ipc_eeer);

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SET_PHY_CONFIG, sizeof (data),
	    true);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, &data,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set PHY config"));
}

bool
ice_cmd_get_link_status(ice_t *ice, ice_link_status_t *linkp, ice_lse_t lse)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_get_link_status_t	*status;
	const char			*lsestr = "";
	uint16_t			flags;
	uint16_t			len = ICE_LINK_STATUS_LEN_V1;

	if (ice->ice_mac_type == ICE_MAC_E830) {
		len = ICE_LINK_STATUS_LEN_V2;
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_LINK_STATUS, len, false);
	status = &desc.icqd_command.icc_get_link_status;
	switch (lse) {
	case ICE_LSE_NO_CHANGE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_NOP;
		lsestr = "no change";
		break;
	case ICE_LSE_ENABLE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_ENABLE;
		lsestr = "enable";
		break;
	case ICE_LSE_DISABLE:
		flags = ICE_CQ_GET_LINK_STATUS_LSE_DISABLE;
		lsestr = "disable";
		break;
	default:
		return (false);
	}
	status->iccgls_flags = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, linkp,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "get link status (%s)", lsestr)) {
		return (false);
	}

	linkp->ils_frame = LE_16(linkp->ils_frame);
	linkp->ils_curspeed = LE_16(linkp->ils_curspeed);

	return (true);
}

bool
ice_cmd_set_event_mask(ice_t *ice, uint16_t mask)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_set_event_mask_t	*emp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SET_EVENT_MASK);
	emp = &desc.icqd_command.icc_set_event_mask;
	emp->iccsem_mask = LE_16(mask);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set event mask (0x%x)", mask));
}

bool
ice_cmd_setup_link(ice_t *ice, bool enable)
{
	ice_cq_desc_t		desc;
	ice_cq_cmd_setup_link_t	*setup;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SETUP_LINK);
	setup = &desc.icqd_command.icc_setup_link;
	setup->iccsl_flags = ICE_CQ_SETUP_LINK_RESTART_LINK;
	if (enable) {
		setup->iccsl_flags |= ICE_CQ_SETUP_LINK_ENABLE_LINK;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "setup link"));
}

bool
ice_cmd_set_port_id_led(ice_t *ice, bool blink)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_set_port_id_led_t	*led;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SET_PORT_ID_LED);
	led = &desc.icqd_command.icc_set_port_id_led;
	led->iccspil_ident_mode = blink ? ICE_CQ_PORT_ID_LED_BLINK :
	    ICE_CQ_PORT_ID_LED_ORIG;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL,
	    "set port identification LED %s", blink ? "on" : "off"));
}

/*
 * Read up to ICE_CQ_SFF_EEPROM_MAX_LEN bytes from a plugged in SFP/QSFP
 * module's EEPROM over I2C. bus_addr is the 8-bit I2C device address
 * (typically 0xA0 for the base EEPROM, or 0xA2 for the SFP diagnostic
 * page); offset is the byte offset within that page to begin reading at.
 */
bool
ice_cmd_sff_eeprom(ice_t *ice, uint8_t bus_addr, uint16_t offset, void *data,
    uint8_t length)
{
	ice_cq_desc_t		desc;
	ice_cq_cmd_sff_eeprom_t	*sff;

	if (data == NULL || length == 0 ||
	    length > ICE_CQ_SFF_EEPROM_MAX_LEN || (offset & 0xff00) != 0) {
		return (false);
	}

	/*
	 * Despite us only doing read requests, the NIC appears to demand
	 * that the RD bit is set for any SFF request (read or write) even
	 * though the NIC does not read our buffer when reading SFF
	 * data. The FreeBSD and Linux drives do the same, and without it
	 * the request will fail with EINVAL.
	 */
	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SFF_EEPROM, length, true);
	sff = &desc.icqd_command.icc_sff_eeprom;
	sff->iccse_i2c_bus_addr = LE_16((bus_addr >> 1) &
	    ICE_CQ_SFF_EEPROM_I2C_7BIT_MASK);
	sff->iccse_i2c_mem_addr = LE_16(offset & 0xff);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, data,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL,
	    "read SFF eeprom at offset 0x%x", offset));
}

bool
ice_cmd_get_switch_config(ice_t *ice, void *buf, size_t bufsize, uint16_t first,
    uint16_t *neltsp, uint16_t *nexteltp)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_get_switch_config_t	*config;
	ice_hw_switch_config_t		*swconf;
	uint16_t			nelts, i;

	/*
	 * Hardware says that the maximum allowed size is 2k. Limit this if it
	 * would otherwise be too large.
	 */
	bufsize = MIN(bufsize, ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX);
	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_SWITCH_CONFIG, bufsize,
	    false);
	config = &desc.icqd_command.icc_get_switch_config;
	config->iccgsc_next_elt = LE_16(first);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "get link status")) {
		return (false);
	}

	nelts = LE_16(config->iccgsc_nelts);
	if (nelts > bufsize / sizeof (ice_hw_switch_config_t)) {
		ice_error(ice, "hardware told us we had more elements than we "
		    "gave it buffer for, got %u switch elements, but the "
		    "buffer was %lx bytes large", nelts, bufsize);
		return (false);
	}

	*neltsp = nelts;
	*nexteltp = LE_16(config->iccgsc_next_elt);

	swconf = buf;
	for (i = 0; i < nelts; i++) {
		swconf[i].isc_vsi_info = LE_16(swconf[i].isc_vsi_info);
		swconf[i].isc_swid = LE_16(swconf[i].isc_swid);
		swconf[i].isc_pfid = LE_16(swconf[i].isc_pfid);
	}

	return (true);
}

/*
 * This sets the MTU on the physical port of the NIC, which can be
 * different (though for sanity >=) the MTU of a VSI. More technically, it
 * appears TX rings are capped at this value, while RX rings can have
 * their own MTU (again for sanity <= this MTU).
 *
 * In other words, if one considers the ice NIC as a switch with the
 * physical port being the uplink and the VSIs as the 'ports' exposed to
 * the OS, this sets the MTU on the uplink port.
 *
 * We make sure this is set at the max, and then enforce the MTU via
 * mac(9E).
 */
bool
ice_cmd_set_max_mtu(ice_t *ice, uint16_t mtu)
{
	ice_cq_cmd_set_mac_cfg_t	*mac;
	ice_cq_desc_t			desc;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SET_MAC_CONFIG);
	mac = &desc.icqd_command.icc_set_mac_cfg;
	mac->iccsmc_mtu = LE_16(mtu);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set mac config"));
}

bool
ice_cmd_free_vsi(ice_t *ice, ice_vsi_t *vsi, bool keep)
{
	ice_cq_desc_t		desc;
	ice_cq_cmd_free_vsi_t	*freep;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to remove non-active VSI with ID %u",
		    vsi->ivsi_id);
		return (false);
	}

	ice_cmd_direct_init(&desc, ICE_CQ_OP_FREE_VSI);
	freep = &desc.icqd_command.icc_free_vsi;
	freep->iccfv_vsi = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);
	if (keep) {
		freep->iccfv_flags = LE_16(ICE_CQ_VSI_KEEP_ALLOC);
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "free vsi %u", vsi->ivsi_id));
}

bool
ice_cmd_add_vsi(ice_t *ice, ice_vsi_t *vsi)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_add_vsi_t		*add;
	ice_cq_cmd_add_vsi_reply_t	*reply;
	uint16_t			hw_type;

	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0 &&
	    vsi->ivsi_id >= ICE_MAX_VSIS) {
		ice_error(ice, "asked to remove VSI ID %u larger than maximum",
		    vsi->ivsi_id);
		return (false);
	}

	if (vsi->ivsi_type != ICE_VSI_TYPE_PF) {
		ice_error(ice, "asked to add support for a non-PF VSI");
		return (false);
	}

	if (vsi->ivsi_id > ICE_VSI_MAX) {
		ice_error(ice, "vsi id %u is too large", vsi->ivsi_id);
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_ADD_VSI,
	    sizeof (vsi->ivsi_ctxt), true);
	add = &desc.icqd_command.icc_add_vsi;

	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0) {
		add->iccav_vsi = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);
	}

	switch (vsi->ivsi_type) {
	case ICE_VSI_TYPE_PF:
		hw_type = ICE_CQ_VSI_TYPE_PF;
		break;
	case ICE_VSI_TYPE_VF:
		hw_type = ICE_CQ_VSI_TYPE_VF;
		break;
	case ICE_VSI_TYPE_VMDQ2:
		hw_type = ICE_CQ_VSI_TYPE_VMDQ2;
		break;
	case ICE_VSI_TYPE_EMP_MNG:
		hw_type = ICE_CQ_VSI_TYPE_EMP_MNG;
		break;
	default:
		ice_error(ice, "invalid hardware VSI type: %u",
		    vsi->ivsi_type);
		return (false);
	}
	add->iccav_type = LE_16(hw_type);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, &vsi->ivsi_ctxt,
	    ICE_CMD_COPY_BOTH)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "add vsi %u", vsi->ivsi_id)) {
		return (false);
	}

	if ((vsi->ivsi_flags & ICE_VSI_F_POOL_ALLOC) == 0) {
		return (true);
	}

	/*
	 * For pool based allocations we need to get the VSI ID out from the
	 * results.
	 */

	reply = &desc.icqd_command.icc_add_vsi_reply;
	vsi->ivsi_id = LE_16(reply->iccavr_vsi) & ICE_CQ_VSI_MASK;

	return (true);
}

bool
ice_cmd_set_rss_key(ice_t *ice, ice_vsi_t *vsi, void *buf, uint_t len)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_set_rss_key_t	*set_key;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to set up RSS for an inactive VSI: %u",
		    vsi->ivsi_id);
		return (false);
	}

	if (buf == NULL || len != ICE_RSS_KEY_LENGTH) {
		ice_error(ice, "invalid key length or buffer passed to RSS "
		    "set key: %p/%u", buf, len);
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SET_RSS_KEY, len, true);
	set_key = &desc.icqd_command.icc_set_rss_key;
	set_key->iccsrk_vsi_id = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set rss key (VSI %u)",
	    vsi->ivsi_id));
}

bool
ice_cmd_set_rss_lut(ice_t *ice, ice_vsi_t *vsi, void *buf, uint_t len)
{
	ice_cq_desc_t			desc;
	uint16_t			flags;
	ice_cq_cmd_set_rss_lut_t	*lut;
	uint16_t			lut_type, lut_size;

	if ((vsi->ivsi_flags & ICE_VSI_F_ACTIVE) == 0) {
		ice_error(ice, "asked to set up RSS for an inactive VSI: %u",
		    vsi->ivsi_id);
		return (false);
	}

	if (buf == NULL) {
		ice_error(ice, "invalid buffer passed to RSS set lut: %p",
		    buf);
		return (false);
	}

	/*
	 * The main per-PF VSI uses the PF-wide RSS LUT, which comes in one
	 * of three sizes (see ice_hw.h's ICE_RSS_LUT_SIZE_PF_*), reported by
	 * firmware via the RSS capability (see ice->ice_rss_table_size).
	 * VF/VMDQ VSIs use the small, fixed-size per-VSI LUT instead. This
	 * must match what was set up for the VSI in ice_vsi_context_fill().
	 */
	if (vsi->ivsi_type == ICE_VSI_TYPE_PF) {
		lut_type = ICE_CQ_RSS_LUT_TYPE_PF;

		switch (len) {
		case ICE_RSS_LUT_SIZE_PF_128:
			lut_size = ICE_CQ_RSS_LUT_SIZE_PF_128;
			break;
		case ICE_RSS_LUT_SIZE_PF_512:
			lut_size = ICE_CQ_RSS_LUT_SIZE_PF_512;
			break;
		case ICE_RSS_LUT_SIZE_PF_2K:
			lut_size = ICE_CQ_RSS_LUT_SIZE_PF_2K;
			break;
		default:
			ice_error(ice, "invalid PF RSS lut length passed to "
			    "RSS set lut: %u", len);
			return (false);
		}
	} else {
		if (len != ICE_RSS_LUT_SIZE_VSI) {
			ice_error(ice, "invalid VSI RSS lut length passed to "
			    "RSS set lut: %u", len);
			return (false);
		}
		lut_type = ICE_CQ_RSS_LUT_TYPE_VSI;
		lut_size = ICE_CQ_RSS_LUT_SIZE_VSI;
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_SET_RSS_LUT, len, true);
	lut = &desc.icqd_command.icc_set_rss_lut;
	lut->iccsrl_vsi_id = LE_16(vsi->ivsi_id | ICE_CQ_VSI_VALID);

	flags = 0;
	flags = ICE_CQ_RSS_LUT_SET_TYPE(flags, lut_type);
	flags = ICE_CQ_RSS_LUT_SET_SIZE(flags, lut_size);
	lut->iccsrl_flags = LE_16(flags);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set rss lut (VSI %u)",
	    vsi->ivsi_id));
}

bool
ice_cmd_get_default_scheduler(ice_t *ice, void *buf, size_t len,
    uint16_t *nbranches)
{
	ice_cq_desc_t				desc;
	ice_cq_cmd_query_default_scheduler_t	*sched;

	if (len != ICE_CQ_QUERY_DEFAULT_SCHED_BUF_SIZE) {
		ice_error(ice, "passed illegal buf size to get default "
		    "scheduling command");
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_QUERY_DEFAULT_SCHEDULER,
	    len, false);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "query default TX scheduler")) {
		return (false);
	}

	sched = &desc.icqd_command.icc_query_default_scheduler;
	*nbranches = LE_16(sched->iccqds_nbranches);

	return (true);
}

bool
ice_cmd_get_sched_resource_alloc(ice_t *ice, void *buf, size_t *buflenp)
{
	ice_cq_desc_t		desc;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_QUERY_SCHED_RES_ALLOC,
	    *buflenp, false);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL,
	    "query scheduler resource allocation")) {
		return (false);
	}

	*buflenp = LE_16(desc.icqd_data_len);
	return (true);
}

bool
ice_cmd_add_sched_elements(ice_t *ice, uint16_t *ngroup,
    ice_hw_sched_grp_t *groups)
{
	ice_hw_sched_grp_t		*gp;
	ice_cq_cmd_add_sched_elements_t	*add;
	ice_cq_desc_t			desc;
	size_t				len;
	uint_t				i;

	len = 0;
	gp = groups;
	for (i = 0; i < *ngroup; i++) {
		size_t grplen;
		size_t nelems = LE_32(gp->ihsg_nelems);

		grplen = nelems * sizeof (ice_hw_sched_elem_t);
		len += sizeof (*gp) + grplen;

		gp = (ice_hw_sched_grp_t *)&gp->ihsg_elems[nelems];
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_ADD_SCHED_ELEMENTS, len, true);

	add = &desc.icqd_command.icc_add_sched_elements;
	add->iccase_ngroups = LE_16(*ngroup);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, groups,
	    ICE_CMD_COPY_BOTH)) {
		return (false);
	}

	*ngroup = LE_16(add->iccase_nadded);

	return (ice_cmd_ckerr(ice, &desc, NULL, "add scheduler elements"));
}

bool
ice_cmd_del_sched_elements(ice_t *ice, uint16_t *ngroup,
    ice_hw_delete_sched_elements_t *elts)
{
	ice_hw_delete_sched_elements_t		*ep;
	ice_cq_cmd_delete_sched_elements_t	*del;
	ice_cq_desc_t				desc;
	uint_t					i;
	size_t					len = 0;

	ep = elts;
	for (i = 0; i < *ngroup; i++) {
		uint8_t *p = (uint8_t *)ep;
		size_t grplen;

		grplen = sizeof (*ep) +
		    LE_32(ep->ihdse_nelements) * sizeof (uint32_t);

		len += grplen;

		p += grplen;
		ep = (ice_hw_delete_sched_elements_t *)p;
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_DELETE_SCHED_ELEMENTS, len,
	    true);

	del = &desc.icqd_command.icc_del_sched_elements;
	del->iccdse_ngroups = LE_16(*ngroup);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, elts,
	    ICE_CMD_COPY_BOTH)) {
		return (false);
	}

	/*
	 * The datasheet says that the number of groups successfully
	 * deleted is set even on error. It's unclear on the exact semantics
	 * (i.e. which groups) on error. The assumption (since it's likely
	 * the simplest behavior) is that it stops processing on the first
	 * error encountered. E.g. if 3 groups are submitted and it fails
	 * with 2 groups deleted, the first two groups submitted were the
	 * ones that were deleted while the last group was not.
	 */
	*ngroup = LE_16(del->iccdse_ndeleted);

	return (ice_cmd_ckerr(ice, &desc, NULL, "delete scheduler elements"));
}

/*
 * Add a TX queue to a VSI. Currently we only support adding one TX queue
 * at a time.
 */
bool
ice_cmd_add_txq_grp(ice_t *ice, ice_vsi_t *vsi, ice_tx_ring_t *txr,
    ice_hw_txq_context_t *ctx)
{
	ice_hw_txq_group_t	*grp;
	ice_hw_txq_perq_t	*perq;
	ice_cq_cmd_add_txq_t	*add_txq;
	ice_sched_node_t	*parent;
	size_t			len;
	ice_cq_desc_t		desc;

	CTASSERT(sizeof (ice_hw_txq_group_t) + sizeof (ice_hw_txq_perq_t) <=
	    UINT16_MAX);

	parent = ice_tx_sched_txq_parent(vsi);
	ASSERT3P(parent, !=, NULL);

	len = sizeof (ice_hw_txq_group_t) + sizeof (ice_hw_txq_perq_t);

	grp = kmem_zalloc(len, KM_SLEEP);
	perq = &grp->ihtg_perq[0];

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_ADD_TXQ, len, true);
	add_txq = &desc.icqd_command.icc_add_txq;

	add_txq->iccat_ngrp = 1;

	grp->ihtg_teid = parent->isn_teid;
	grp->ihtg_nqueue = 1;

	/*
	 * Currently, we use a contiguous span of TX queue ids
	 * from the hardware, so we do not need to do any mapping of
	 * ids. If we start supporting multiple VSIs or RDMA, this
	 * will likely need to change.
	 */
	perq->ihtp_qid = txr->itxr_index;

	perq->ihtp_valid_sect =
	    ICE_HW_TXQ_PERQ_VALID_SECT_GENERIC |
	    ICE_HW_TXQ_PERQ_VALID_SECT_CIR |
	    ICE_HW_TXQ_PERQ_VALID_SECT_EIR;

	perq->ihtp_generic = 0;

	perq->ihtp_cir_bw_id = LE_16(ICE_SCHED_DEFAULT_PROFILE_ID);
	perq->ihtp_cir_bw_wfq_weights = LE_16(ICE_SCHED_DEFAULT_WEIGHT);

	perq->ihtp_eir_bw_id = LE_16(ICE_SCHED_DEFAULT_PROFILE_ID);
	perq->ihtp_eir_bw_wfq_weights = LE_16(ICE_SCHED_DEFAULT_WEIGHT);

	if (!ice_txq_context_write(ice, ctx, &perq->ihtp_ctx[0],
	    sizeof (perq->ihtp_ctx))) {
		ice_error(ice, "Failed to write TX queue context");
		kmem_free(grp, len);
		return (false);
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, grp,
	    ICE_CMD_COPY_BOTH)) {
		kmem_free(grp, len);
		ice_error(ice, "Failed to add TX queue to group");
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "add TX queue group")) {
		kmem_free(grp, len);
		return (false);
	}

	txr->itxr_teid = LE_32(perq->ihtp_qteid);
	ASSERT3U(txr->itxr_teid, !=, ICE_TX_SCHED_TEID_INVALID);

	mutex_enter(&ice->ice_tx_sched_lock);

	VERIFY3P(ice_tx_sched_alloc_node(ice, parent, txr->itxr_teid,
	    ICE_TX_SCHED_ET_LEAF), !=, NULL);

	mutex_exit(&ice->ice_tx_sched_lock);

	kmem_free(grp, len);
	return (true);
}

/*
 * From Table 10-38, the buffer passed to the NIC must be aligned to 4
 * bytes
 */
#define	DISABLE_SZ \
	(P2ROUNDUP(sizeof (ice_hw_txq_disable_grp_t) + 1 * sizeof (uint16_t), \
	sizeof (uint32_t)))

bool
ice_cmd_disable_queue(ice_t *ice, ice_tx_ring_t *txr)
{
	uint8_t				buf[DISABLE_SZ] = { 0 };
	ice_hw_txq_disable_grp_t	*grp;
	ice_cq_cmd_txq_disable_flow_t	*df;
	ice_sched_node_t		*txnode;
	ice_cq_desc_t			desc;
	bool				ret = false;
	uint16_t			qid = 0;

	qid = ICE_TX_TXQ_SET_QUID(qid, txr->itxr_index);
	qid = ICE_TX_TXQ_SET_QTYPE(qid, ICE_TX_TXQ_QID_LAN);

	grp = (ice_hw_txq_disable_grp_t *)buf;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_DISABLE_FLOW, DISABLE_SZ, true);

	mutex_enter(&ice->ice_tx_sched_lock);

	txnode = ice_tx_sched_find_node(ice, ice->ice_tx_sched_root,
	    txr->itxr_teid);
	ASSERT3P(txnode, !=, NULL);
	ASSERT3P(txnode->isn_parent, !=, NULL);

	grp->txqd_pteid = LE_32(txnode->isn_parent->isn_teid);
	grp->txqd_nqueue = 1;		/* single byte */
	grp->txqd_qids[0] = LE_16(qid);

	df = &desc.icqd_command.icc_txq_disable_flow;
	df->icctdf_flags = ICE_CQ_DISABLE_FLOW_F_NORESET;
	df->icctdf_timeout = ICE_CQ_DISABLE_FLOW_SET_TIMEOUT(5);
	df->icctdf_nqgrp = 1;		/* Single byte */

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, grp,
	    ICE_CMD_COPY_TO_DEV)) {
		goto done;
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "disable TX queue %u",
	    txr->itxr_index)) {
		goto done;
	}

	VERIFY(ice_tx_sched_del_elt(ice, txnode, false));
	txr->itxr_teid = ICE_TX_SCHED_TEID_INVALID;

	ret = true;

done:
	mutex_exit(&ice->ice_tx_sched_lock);
	return (ret);
}

/* Add/Remove/Update switch rules */
bool
ice_cmd_switch_rules(ice_t *ice, ice_cq_opcode_t op, uint16_t nrules,
    void *rules, size_t len)
{
	const char			*opstr = "";
	ice_cq_cmd_add_switch_rule_t	*add_rule;
	ice_cq_desc_t			desc;

	switch (op) {
	case ICE_CQ_OP_ADD_SW_RULES:
		opstr = "add";
		break;
	case ICE_CQ_OP_UPDATE_SW_RULES:
		opstr = "update";
		break;
	case ICE_CQ_OP_REMOVE_SW_RULES:
		opstr = "remove";
		break;
	default:
		dev_err(ice->ice_dip, CE_PANIC, "%s: invalid op 0x%x", __func__,
		    op);
	}

	ice_cmd_indirect_init(&desc, op, len, true);

	add_rule = &desc.icqd_command.icc_add_switch_rule;
	add_rule->iccasr_nrules = LE_16(nrules);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, rules,
	    ICE_CMD_COPY_BOTH)) {
		ice_error(ice, "failed switch %s operation", opstr);
		return (false);
	}

	/*
	 * XXX: do we resync the data back from the device? the add
	 * command at least updates the descriptor with the assigned index
	 * from the hardware, which we need to later reference it.
	 */
	return (ice_cmd_ckerr(ice, &desc, NULL, "%s switch rules", opstr));
}

bool
ice_cmd_get_package_info_list(ice_t *ice, void *buf, size_t bufsz)
{
	ice_cq_desc_t	desc;

	/*
	 * The command expects the buffer size to be 4096 bytes. For
	 * conveinence, we allow the buffer to be larger. However at most
	 * the first 4096 bytes will be written to buf.
	 */
	if (bufsz < ICE_CQ_GET_PKG_INFO_BUF_SZ) {
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_GET_PKG_INFO,
	    ICE_CQ_GET_PKG_INFO_BUF_SZ, false);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "get package info list"));
}

/*
 * Retrieve the current internal die temperature (in degrees Celsius) along
 * with its warning/critical/fatal thresholds. Any of the threshold output
 * pointers may be NULL if not needed.
 *
 * Note that the datasheet doesn't document this, this is reverse
 * engineered from the FreeBSD driver.
 */
bool
ice_cmd_get_sensor_reading(ice_t *ice, int8_t *tempp, uint8_t *warnp,
    uint8_t *critp, uint8_t *fatalp)
{
	ice_cq_desc_t				 desc;
	ice_cq_cmd_get_sensor_reading_t		*reqp;
	ice_cq_cmd_get_sensor_reading_resp_t	*respp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_GET_SENSOR_READING);
	reqp = &desc.icqd_command.icc_get_sensor_reading;
	reqp->iccgsr_sensor = ICE_CQ_SENSOR_INT_TEMP;
	reqp->iccgsr_format = ICE_CQ_SENSOR_INT_TEMP_FORMAT;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "get sensor reading")) {
		return (false);
	}

	respp = &desc.icqd_command.icc_get_sensor_reading_resp;
	*tempp = respp->iccgsrr_temp;

	if (warnp != NULL) {
		*warnp = respp->iccgsrr_temp_warning_threshold;
	}

	if (critp != NULL) {
		*critp = respp->iccgsrr_temp_critical_threshold;
	}

	if (fatalp != NULL) {
		*fatalp = respp->iccgsrr_temp_fatal_threshold;
	}

	return (true);
}

/*
 * Ask firmware to start (or stop) sending FW health status events over the
 * ARQ for the requested set of event_source flags (a combination of
 * ICE_CQ_HEALTH_STATUS_SET_* values).
 */
bool
ice_cmd_set_health_status_config(ice_t *ice, uint8_t event_source)
{
	ice_cq_desc_t				 desc;
	ice_cq_cmd_set_health_status_config_t	*hscp;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_SET_HEALTH_STATUS_CONFIG);
	hscp = &desc.icqd_command.icc_set_health_status_config;
	hscp->icchsc_event_source = event_source;

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set health status config"));
}

/*
 * Set the FW logging configuration (opcode 0xFF30). "entries" is expected to
 * contain "nentries" module_id/log_level pairs. "options" is a combination
 * of ICE_CQ_FW_LOG_CONF_{UART,AQ}_EN, and "resolution" is the number of log
 * events the firmware should batch before delivering an ARQ event (only
 * relevant when ICE_CQ_FW_LOG_CONF_AQ_EN is set).
 */
bool
ice_cmd_set_fw_log_config(ice_t *ice, const ice_cq_fw_log_module_t *entries,
    uint16_t nentries, uint8_t options, uint16_t resolution)
{
	ice_cq_desc_t		desc;
	ice_cq_cmd_fw_log_t	*cmdp;
	size_t			bufsz;

	bufsz = nentries * sizeof (ice_cq_fw_log_module_t);

	if (nentries == 0 || bufsz > ICE_CQ_MAX_BUF) {
		ice_error(ice, "invalid FW logging module count: %u",
		    nentries);
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_FW_LOGS_CONFIG, bufsz, true);
	cmdp = &desc.icqd_command.icc_fw_log;
	cmdp->icfl_cmd_flags = ICE_CQ_FW_LOG_CONF_SET_VALID | options;
	cmdp->icfl_ops.cfg.log_resolution = LE_16(resolution);
	cmdp->icfl_ops.cfg.mdl_cnt = LE_16(nentries);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, (void *)entries,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "set FW logging config"));
}

/*
 * Register (or unregister) the PF to receive FW logging events over the
 * ARQ, per the ICE_CQ_FW_LOG_CONF_AQ_EN configuration set by a prior call
 * to ice_cmd_set_fw_log_config().
 */
bool
ice_cmd_fw_log_register(ice_t *ice, bool reg)
{
	ice_cq_desc_t	desc;

	ice_cmd_direct_init(&desc, ICE_CQ_OP_FW_LOGS_REGISTER);
	if (reg) {
		desc.icqd_command.icc_fw_log.icfl_cmd_flags =
		    ICE_CQ_FW_LOG_AQ_REGISTER;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, NULL,
	    ICE_CMD_COPY_NONE)) {
		return (false);
	}

	return (ice_cmd_ckerr(ice, &desc, NULL, "%sregister FW logging",
	    reg ? "" : "un"));
}

/*
 * Read one chunk (up to ICE_CQ_MAX_BUF bytes) of opaque internal FW/HW
 * debug data (opcode 0xFF08). This is a simple pass-through of a single AQ
 * call; the caller is responsible for iterating with the returned
 * next-cluster/next-table/next-index values until the firmware indicates
 * there is no more data for the requested cluster.
 */
bool
ice_cmd_debug_dump(ice_t *ice, uint16_t cluster_id, uint16_t table_id,
    uint32_t idx, void *buf, uint16_t bufsz, uint16_t *ret_lenp,
    uint16_t *ret_clusterp, uint16_t *ret_tablep, uint32_t *ret_idxp)
{
	ice_cq_desc_t			desc;
	ice_cq_cmd_debug_dump_t		*cmdp;

	if (bufsz == 0 || bufsz > ICE_CQ_MAX_BUF) {
		ice_error(ice, "invalid debug dump buffer size: %u", bufsz);
		return (false);
	}

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_DEBUG_DUMP_INTERNALS, bufsz,
	    false);
	cmdp = &desc.icqd_command.icc_debug_dump;
	cmdp->icdd_cluster_id = LE_16(cluster_id);
	cmdp->icdd_table_id = LE_16(table_id);
	cmdp->icdd_idx = LE_32(idx);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, buf,
	    ICE_CMD_COPY_FROM_DEV)) {
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "debug dump")) {
		return (false);
	}

	cmdp = &desc.icqd_command.icc_debug_dump;
	*ret_lenp = LE_16(desc.icqd_data_len);
	*ret_clusterp = LE_16(cmdp->icdd_cluster_id);
	*ret_tablep = LE_16(cmdp->icdd_table_id);
	*ret_idxp = LE_32(cmdp->icdd_idx);

	return (true);
}

static const ice_cq_errmap_t ice_download_pkg_errs[] = {
	{ ICE_CQ_EFAULT, "data address field was 0" },
	{ ICE_CQ_EINVAL, "an element within the package data was invalid" },
	{ ICE_CQ_EACCESS, "attempt to overwrite the default package" },
	{ ICE_CQ_EBUSY, "NVM is busy" },
	{ 0, NULL }
};

bool
ice_cmd_download_pkg(ice_t *ice, const void *pkg, size_t len, bool last)
{
	ice_cq_cmd_download_pkg_t	*pkgp;
	ice_cq_desc_t			desc;
	uint32_t			offset, info;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_DOWNLOAD_PKG, len, true);
	pkgp = &desc.icqd_command.icc_download_pkg;

	if (last) {
		pkgp->iccdp_flags = 0x1;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, (void *)pkg,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	offset = LE_32(desc.icqd_command.icc_generic.iccg_param0);
	info = LE_32(desc.icqd_command.icc_generic.iccg_param1);

	return (ice_cmd_ckerr(ice, &desc, ice_download_pkg_errs,
	    "download package (offset %u info %u)", offset, info));
}

static const ice_cq_errmap_t ice_update_pkg_errs[] = {
	{ ICE_CQ_EFAULT, "data address field was 0" },
	{ ICE_CQ_EINVAL, "unrecognized section number" },
	{ ICE_CQ_ERANGE, "invalid section offset" },
	{ 0, NULL }
};

bool
ice_cmd_update_pkg(ice_t *ice, const void *pkg, size_t len, bool last)
{
	ice_cq_cmd_download_pkg_t	*pkgp;
	ice_cq_desc_t			desc;
	uint32_t			offset, info;

	ice_cmd_indirect_init(&desc, ICE_CQ_OP_UPDATE_PKG, len, true);
	pkgp = &desc.icqd_command.icc_download_pkg;

	if (last) {
		pkgp->iccdp_flags = 0x01;
	}

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, (void *)pkg,
	    ICE_CMD_COPY_TO_DEV)) {
		return (false);
	}

	offset = LE_32(desc.icqd_command.icc_generic.iccg_param0);
	info = LE_32(desc.icqd_command.icc_generic.iccg_param1);

	return (ice_cmd_ckerr(ice, &desc, ice_update_pkg_errs,
	    "update package (offset %u info %u)", offset, info));
}

static uint32_t
ice_res_entry_size(const ice_res_entry_t *res, uint16_t nres)
{
	uint32_t	len = 0;
	uint_t		i;

	for (i = 0; i < nres; i++) {
		uint16_t type = ICE_RES_INFO_TYPE(LE_16(res->ire_info));
		uint16_t ndesc = LE_16(res->ire_ndesc);

		switch (type) {
		case ICE_RES_TYPE_FLU:
		case ICE_RES_TYPE_FDIR_GUARANTEED_ENTRIES:
		case ICE_RES_TYPE_FDIR_SHARED_ENTRIES:
			/*
			 * From Table 7-34:
			 * Each entry actually consists of 2 descriptors,
			 * so the amount is 2x ndesc in the struct passed
			 * to the NIC. We just need to know how many to skip
			 * over.
			 */
			ndesc *= 2;
			break;
		default:
			break;
		}

		len += sizeof (*res) + ndesc * sizeof (uint16_t);

		res = (const ice_res_entry_t *)(&res->ire_descs[ndesc]);
	}

	return (len);
}

static bool
ice_cmd_res_common(ice_t *ice, ice_res_entry_t *res, uint16_t *nres, bool alloc)
{
	const char			*opstr = "";
	ice_cq_cmd_allocate_resource_t	*ares;
	ice_cq_opcode_t			op;
	ice_cq_desc_t			desc;
	uint32_t			len;

	len = ice_res_entry_size(res, *nres);
	if (alloc) {
		op = ICE_CQ_OP_ALLOCATE_RESOURCE;
		opstr = "allocate";
	} else {
		op = ICE_CQ_OP_FREE_RESOURCE;
		opstr = "free";
	}

	ice_cmd_indirect_init(&desc, op, len, true);
	ares = &desc.icqd_command.icc_allocate_resource;
	ares->iccar_nres = LE_16(*nres);

	if (!ice_cmd_submit(ice, &ice->ice_asq, &desc, (void *)res,
	    ICE_CMD_COPY_BOTH)) {
		ice_error(ice, "failed %s resource operation", opstr);
		return (false);
	}

	if (!ice_cmd_ckerr(ice, &desc, NULL, "%s resource", opstr))
		return (false);

	*nres = LE_16(ares->iccar_nres);
	return (true);
}

bool
ice_cmd_allocate_resource(ice_t *ice, ice_res_entry_t *res, uint16_t *nres)
{
	return (ice_cmd_res_common(ice, res, nres, true));
}

bool
ice_cmd_free_resource(ice_t *ice, ice_res_entry_t *res, uint16_t nres)
{
	return (ice_cmd_res_common(ice, res, &nres, false));
}
