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
 * Copyright 2023 Jason King
 */

#include <sys/devops.h>		/* used by dev_ops */
#include <sys/conf.h>		/* used by dev_ops,cb_ops */
#include <sys/modctl.h>		/* for _init,_info,_fini,mod_* */
#include <sys/ddi.h>		/* used by all entry points */
#include <sys/sunddi.h>		/* used by all entry points */
#include <sys/cmn_err.h>	/* used for debug outputs */
#include <sys/types.h>		/* used by prop_op, ddi_prop_op */

#include <sys/file.h>		/* used by open, close */
#include <sys/errno.h>		/* used by open,close,read,write */
#include <sys/open.h>		/* used by open,close,read,write */
#include <sys/cred.h>		/* used by open,close,read */
#include <sys/uio.h>		/* used by read */
#include <sys/stat.h>		/* defines S_IFCHR */
#include <sys/poll.h>
#include <sys/id_space.h>
#include <sys/stddef.h>
#include <sys/proc.h>
#include <sys/atomic.h>

#include <sys/byteorder.h>	/* for ntohs, ntohl, htons, htonl */
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/sdt.h>

#include <sys/tpm.h>

#include "tpm_tis.h"
#include "tpm_ddi.h"

extern bool tpm_debug;

void
tpm_dbg(const tpm_t *tpm, int level, const char *fmt, ...)
{
	if (!tpm_debug) {
		return;
	}

	va_list	ap;

	va_start(ap, fmt);
	if (tpm != NULL && tpm->tpm_dip != NULL) {
		vdev_err(tpm->tpm_dip, level, fmt, ap);
	} else {
		vcmn_err(level, fmt, ap);
	}
	va_end(ap);
}

int
tpm_cancel(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;
	int ret;

	/* We should't be called from the tpm service thread either. */
	VERIFY3P(curthread, !=, tpm->tpm_thread);
	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
		return (0);
	case TPM_CLIENT_CMD_RECEPTION:
	case TPM_CLIENT_CMD_COMPLETION:
		tpm_client_reset(c);
		return (0);
	case TPM_CLIENT_CMD_DISPATCH:
		mutex_enter(&tpm->tpm_lock);
		if (list_link_active(&c->tpmc_node)) {
			/*
			 * If we're still on the pending list, the tpm thread
			 * has not started processing our request. We can
			 * merely remove ourself from the list and reset.
			 */
			list_remove(&tpm->tpm_pending, c);
			mutex_exit(&tpm->tpm_lock);

			/* Release reference from list */
			tpm_client_refrele(c);

			tpm_client_reset(c);
			return (0);
		}

		/*
		 * The tpm thread has pulled us off the list, but
		 * since we were able to acquire tpmc_lock, it has
		 * not been able to transition to
		 * TPM_CLIENT_CMD_EXECUTION (because we always grab
		 * the client lock, then the tpm lock, there is a
		 * small window in the tpm thread where it's removed
		 * the next client from the list, but has not yet
		 * acquired the client lock to update the status).
		 * Tell the tpm thread to just cancel instead
		 * of executing the command.
		 *
		 * The tpm svc thread will release it's refhold.
		 * This way a non-blocking client can cancel and
		 * have it processed in the background.
		 */
		tpm->tpm_thr_cancelreq = true;
		break;
	case TPM_CLIENT_CMD_EXECUTION:

		/* The tpm thread is busy, so we have to signal it */
		mutex_enter(&tpm->tpm_lock);
		tpm->tpm_thr_cancelreq = true;
		cv_signal(&tpm->tpm_thr_cv);

		break;
	default:
		cmn_err(CE_PANIC, "unexpected tpm connection state 0x%x",
		    c->tpmc_state);
	}
	mutex_exit(&c->tpmc_lock);

	while (tpm->tpm_thr_cancelreq) {
		ret = cv_wait_sig(&tpm->tpm_thr_cv, &tpm->tpm_lock);

		if (ret == 0) {
			mutex_exit(&tpm->tpm_lock);
			return (SET_ERROR(EINTR));
		}
	}
	mutex_exit(&tpm->tpm_lock);

	mutex_enter(&c->tpmc_lock);
	tpm_client_reset(c);
	return (0);
}

void
tpm_dispatch_cmd(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;

	VERIFY(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3S(c->tpmc_state, ==, TPM_CLIENT_CMD_RECEPTION);

	c->tpmc_state = TPM_CLIENT_CMD_DISPATCH;

	mutex_enter(&tpm->tpm_lock);
	tpm_client_refhold(c);			/* ref for svc thread */
	list_insert_tail(&tpm->tpm_pending, c);
	cv_signal(&tpm->tpm_thr_cv);
	mutex_exit(&tpm->tpm_lock);
}

int
tpm_exec_internal(tpm_t *tpm, tpm_client_t *c)
{
	uint32_t cmdlen;
	int ret;

	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	ASSERT(c->tpmc_iskernel);
	ASSERT3S(c->tpmc_state, ==, TPM_CLIENT_CMD_RECEPTION);
	ASSERT3U(c->tpmc_bufused, <=, c->tpmc_buflen);

	cmdlen = c->tpmc_bufused;

	/* We should always write at least the TPM header */
	ASSERT3U(cmdlen, >=, TPM_HEADER_SIZE);

	/*
	 * Set the length field of the TPM header to the amount written.
	 */
	BE_OUT32(c->tpmc_buf + TPM_PARAMSIZE_OFFSET, cmdlen);

	if (tpm->tpm_thread != NULL) {
		tpm_dispatch_cmd(c);

		while (c->tpmc_state != TPM_CLIENT_CMD_COMPLETION) {
			cv_wait(&c->tpmc_cv, &c->tpmc_lock);
		}
	} else {
		/*
		 * If the kernel thread doesn't exist, the client
		 * should be the internal client (so it can issue
		 * commands during startup).
		 */
		VERIFY3P(tpm->tpm_internal_client, ==, c);

		/*
		 * The return value of tpm_exec_client() is the same as
		 * c->tpmc_cmdresult, so we don't need to care about it.
		 */
		(void) tpm_exec_client(c);
	}

	ret = c->tpmc_cmdresult;
	if (ret != 0)
		tpm_client_reset(c);

	return (ret);
}

/*
 * Transmit the command to the TPM. This should only be used by the
 * tpm exec thread and during attach.
 */
int
tpm_exec_client(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;
	int ret = 0;

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	/* We should have the full command, and should be a valid size. */
	VERIFY3U(c->tpmc_bufused, >=, TPM_HEADER_SIZE);
	VERIFY3U(c->tpmc_bufused, ==, tpm_cmdlen(c->tpmc_buf));

	c->tpmc_state = TPM_CLIENT_CMD_EXECUTION;

	mutex_enter(&tpm->tpm_lock);
	mutex_exit(&c->tpmc_lock);

	switch (tpm->tpm_iftype) {
	case TPM_IF_TIS:
	case TPM_IF_FIFO:
		ret = tis_exec_cmd(tpm, c->tpmc_locality, c->tpmc_buf,
		    c->tpmc_buflen);
		break;
	case TPM_IF_CRB:
		ret = crb_exec_cmd(tpm, c->tpmc_locality, c->tpmc_buf,
		    c->tpmc_buflen);
		break;
	default:
		dev_err(tpm->tpm_dip, CE_PANIC, "%s: invalid iftype %d",
		    __func__, tpm->tpm_iftype);
	}

	mutex_exit(&tpm->tpm_lock);

	mutex_enter(&c->tpmc_lock);

	c->tpmc_cmdresult = ret;
	c->tpmc_state = TPM_CLIENT_CMD_COMPLETION;

	switch (ret) {
	case ECANCELED:
		c->tpmc_bufused = 0;
		c->tpmc_bufread = 0;
		break;
	case 0:
		/*
		 * If we succeeded, the amount of output will be in the
		 * returned header.
		 */
		c->tpmc_bufused = tpm_getbuf32(c->tpmc_buf,
		    TPM_PARAMSIZE_OFFSET);
		c->tpmc_bufread = 0;
		break;
	}

	cv_signal(&c->tpmc_cv);
	pollwakeup(&c->tpmc_pollhead, POLLIN);

	/* We were called with tpmc_lock held, return with tpmc_lock held */
	return (ret);
}

void
tpm_exec_thread(void *arg)
{
	tpm_t *tpm = arg;

	for (;;) {
		int ret = 0;
		tpm_duration_t dur;

		mutex_enter(&tpm->tpm_lock);
		while (!tpm->tpm_thr_quit && list_is_empty(&tpm->tpm_pending)) {
			cv_wait(&tpm->tpm_thr_cv, &tpm->tpm_lock);
		}

		if (tpm->tpm_thr_quit) {
			mutex_exit(&tpm->tpm_lock);
			return;
		}

		tpm_client_t *c = list_remove_head(&tpm->tpm_pending);

		mutex_exit(&tpm->tpm_lock);

		/*
		 * If there was a spurious wakeup, go back to waiting for
		 * a command.
		 */
		if (c == NULL) {
			continue;
		}

		mutex_enter(&c->tpmc_lock);
		mutex_enter(&tpm->tpm_lock);

		/*
		 * This is somewhat subtle. We remove the client from the
		 * list, but there is a small window of opportunity between
		 * releasing the tpm lock and acquiring the client lock
		 * where a client could cancel. In this scenario, the
		 * cancelling client will set tpmc_cancelled prior to
		 * releasing the client lock, and wait for us to acknowledge
		 * the cancellation by signaling tpmc_cv.
		 */
		if (tpm->tpm_thr_cancelreq) {
			tpm->tpm_thr_cancelreq = false;
			cv_signal(&tpm->tpm_thr_cv);

			mutex_exit(&tpm->tpm_lock);
			mutex_exit(&c->tpmc_lock);

			tpm_client_refrele(c);
			continue;
		}

		/*
		 * We need the duration type in case we're cancelled.
		 */
		dur = tpm_get_duration_type(tpm, c->tpmc_buf);

		ret = tpm_exec_client(c);
		mutex_exit(&c->tpmc_lock);

		tpm_client_refrele(c);

		if (ret == ECANCELED) {
			mutex_enter(&tpm->tpm_lock);

			VERIFY(tpm->tpm_thr_cancelreq);
			tpm->tpm_thr_cancelreq = false;
			cv_signal(&tpm->tpm_thr_cv);

			mutex_exit(&tpm->tpm_lock);

			switch (tpm->tpm_iftype) {
			case TPM_IF_TIS:
			case TPM_IF_FIFO:
				tis_cancel_cmd(tpm, dur);
				break;
			case TPM_IF_CRB:
				crb_cancel_cmd(tpm, dur);
				break;
			}
		}
	}
}

/*
 * Wait up to timeout ticks for cond(tpm) to be true. This should be used
 * for conditions where there's no potential concern about the timing used.
 * Basically anything but waiting for a command to complete.
 */
int
tpm_wait(tpm_t *tpm, bool (*cond)(tpm_t *, bool, clock_t, const char *),
    clock_t timeout, const char *func)
{
	clock_t deadline, now;
	int ret = 0;

	/*
	 * We should never be called in a context where we can receive a
	 * signal.
	 */
	VERIFY(!ddi_can_receive_sig());

	deadline = ddi_get_lbolt() + timeout;

	mutex_enter(&tpm->tpm_lock);
	while ((now = ddi_get_lbolt()) <= deadline && !tpm->tpm_thr_cancelreq) {
		if (cond(tpm, false, timeout, func)) {
			goto done;
		}

		(void) cv_timedwait(&tpm->tpm_thr_cv, &tpm->tpm_lock, deadline);
	}

	if (tpm->tpm_thr_cancelreq) {
		ret = SET_ERROR(ECANCELED);
	} else if (!cond(tpm, true, timeout, func)) {
		ret = SET_ERROR(ETIME);
	}

done:
	mutex_exit(&tpm->tpm_lock);
	return (ret);
}

/*
 * Wait for command in buf to complete execution. `done` is a transport
 * (TIS/FIFO/CRB) specific callback to determine if the command has
 * completed.
 *
 * Commands can have both an expected duration as well as a timeout,
 * as well as potentially caring about TPM_WAIT_POLL, so the semantics
 * are a bit different than tpm_wait().
 */
int
tpm_wait_cmd(tpm_t *tpm, const uint8_t *buf,
    bool (*done)(tpm_t *, bool, uint16_t, clock_t, const char *),
    const char *func)
{
	clock_t exp_done, deadline, now, to;
	uint16_t cmd = tpm_cmd(buf);

	/*
	 * We should never be called in a context where we can receive
	 * a signal. In fact, we should only be called from the worker
	 * thread.
	 */
	VERIFY(!ddi_can_receive_sig());
	VERIFY3P(curthread, ==, tpm->tpm_thread);

	now = ddi_get_lbolt();

	/*
	 * Commands can have both an expected duration as well as a timeout.
	 * The difference being that the expection duration is how long the
	 * command should take to execute (but can take longer), while
	 * exceeding the timeout means something's gone wrong, and the
	 * request should be abandoned.
	 *
	 * If the command has an expected duration, we wait the expected
	 * amount of time and use the supplied callback (done) to check if
	 * the command has completed. If interrupts are enabled, we may
	 * check sooner if the TPM triggers an interrupt. While executing
	 * a command, the TPM should only trigger an interrupt when the
	 * command is complete, however even if it triggers an interrupt for
	 * another reason, we'll just determine the command is not yet
	 * complete and go back to waiting.
	 *
	 * The exception to this behavior is if the wait mode is
	 * TPM_WAIT_POLLONCE.  In this instance, we check exactly one time --
	 * after the command timeout.
	 */
	to = tpm_get_timeout(tpm, buf);
	deadline = now + to;

	exp_done = (tpm->tpm_wait != TPM_WAIT_POLLONCE) ?  now + to : 0;
	VERIFY3S(exp_done, <=, deadline);

	/*
	 * Wait for the expected command duration, or until we are
	 * interrupted due to cancellation or receiving a 'command done'
	 * interrupt.
	 */
	mutex_enter(&tpm->tpm_lock);
	while ((now = ddi_get_lbolt()) <= exp_done && !tpm->tpm_thr_cancelreq) {
		(void) cv_timedwait(&tpm->tpm_thr_cv, &tpm->tpm_lock, exp_done);

		if (tpm->tpm_thr_cancelreq) {
			mutex_exit(&tpm->tpm_lock);
			return (ECANCELED);
		}

		/*
		 * We either received an interrupt or reached the expected
		 * command duration, check if the command is finished.
		 */
		if (done(tpm, false, cmd, to, func)) {
			mutex_exit(&tpm->tpm_lock);
			return (0);
		}
	}

	/*
	 * Command is taking longer than expected, either start periodically
	 * polling (if allowed), or wait until the timeout is reached
	 * (and check again).
	 */
	while ((now = ddi_get_lbolt()) <= deadline) {
		clock_t when = 0;

		switch (tpm->tpm_wait) {
		case TPM_WAIT_POLLONCE:
		case TPM_WAIT_INTR:
			when = deadline;
			break;
		case TPM_WAIT_POLL:
			when = ddi_get_lbolt() + tpm->tpm_timeout_poll;
			break;
		}
	
		(void) cv_timedwait(&tpm->tpm_thr_cv, &tpm->tpm_lock, when);
		if (tpm->tpm_thr_cancelreq) {
			mutex_exit(&tpm->tpm_lock);
			return (ECANCELED);
		}

		if (tpm->tpm_wait == TPM_WAIT_POLLONCE) {
			continue;
		}

		if (done(tpm, false, cmd, to, __func__)) {
			mutex_exit(&tpm->tpm_lock);
			return (0);
		}
	}

	if (!done(tpm, true, cmd, to, func)) {
		return (SET_ERROR(ETIME));
	}

	return (0);
}

tpm_duration_t
tpm_get_duration_type(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	if (cmd < TPM12_ORDINAL_MAX) {
		return (tpm12_get_duration_type(tpm, buf));
	}
	return (tpm20_get_duration_type(tpm, buf));
}

clock_t
tpm_get_duration(tpm_t *tpm, const uint8_t *buf)
{
	tpm_duration_t dur;

	dur = tpm_get_duration_type(tpm, buf);
	return (tpm->tpm_duration[dur]);
}

clock_t
tpm_get_timeout(tpm_t *tpm, const uint8_t *buf)
{
	uint32_t cmd = tpm_cmd(buf);

	if (cmd < TPM12_ORDINAL_MAX) {
		return (tpm12_get_timeout(tpm, cmd));
	}

	return (tpm20_get_timeout(tpm, buf));
}

/*
 * TPM accessor functions
 */
static inline uintptr_t
tpm_locality_offset(uint8_t locality)
{
	VERIFY3U(locality, <=, TPM_LOCALITY_MAX);

	/*
	 * Each locality (0-4) is a block of 0x1000 start at the base address.
	 * E.g. locality 0 is addr + (0x0000-0x0FFF), locality 1 is
	 * addr + (0x1000 - 0x1FFF), etc. This is the same for both the
	 * TIS/FIFO and CRB interfaces.
	 */
	return (0x1000 * locality);
}

static inline void *
tpm_reg_addr(const tpm_t *tpm, unsigned long offset)
{
	VERIFY3U(offset, <=, TPM_OFFSET_MAX);

	return (tpm->tpm_addr + tpm_locality_offset(tpm->tpm_locality)
	    + offset);
}

uint8_t
tpm_get8(tpm_t *tpm, unsigned long offset)
{
	return (ddi_get8(tpm->tpm_handle, tpm_reg_addr(tpm, offset)));
}

uint8_t
tpm_get8_loc(tpm_t *tpm, uint8_t locality, unsigned long offset)
{
	uintptr_t eff_off = tpm_locality_offset(locality) + offset;

	ASSERT3U(locality, <, tpm->tpm_n_locality);
	VERIFY3U(offset, <=, TPM_OFFSET_MAX);
	return (ddi_get8(tpm->tpm_handle, tpm->tpm_addr + eff_off));
}

uint32_t
tpm_get32(tpm_t *tpm, unsigned long offset)
{
	return (ddi_get32(tpm->tpm_handle, tpm_reg_addr(tpm, offset)));
}

uint64_t
tpm_get64(tpm_t *tpm, unsigned long offset)
{
	return (ddi_get64(tpm->tpm_handle, tpm_reg_addr(tpm, offset)));
}

void
tpm_put8(tpm_t *tpm, unsigned long offset, uint8_t value)
{
	ddi_put8(tpm->tpm_handle, tpm_reg_addr(tpm, offset), value);
}

void
tpm_put8_loc(tpm_t *tpm, uint8_t locality, unsigned long offset, uint8_t value)
{
	uintptr_t eff_off = tpm_locality_offset(locality) + offset;

	ASSERT3U(locality, <, tpm->tpm_n_locality);
	VERIFY3U(offset, <=, TPM_OFFSET_MAX);
	ddi_put8(tpm->tpm_handle, tpm->tpm_addr + eff_off, value);
}

void
tpm_put32(tpm_t *tpm, unsigned long offset, uint32_t value)
{
	ddi_put32(tpm->tpm_handle, tpm_reg_addr(tpm, offset), value);
}

/*
 * Starts a new command with an internal client.
 * This blocks until the client is free and returns with
 * tpmc_lock held.
 */
void
tpm_int_newcmd(tpm_client_t *c, uint16_t sess, uint32_t cmd)
{
	uint8_t *buf = c->tpmc_buf;

	mutex_enter(&c->tpmc_lock);

	while (c->tpmc_state != TPM_CLIENT_IDLE)
		cv_wait(&c->tpmc_cv, &c->tpmc_lock);

	ASSERT3U(c->tpmc_buflen, >=, TPM_HEADER_SIZE);

	c->tpmc_state = TPM_CLIENT_CMD_RECEPTION;

	bzero(buf, c->tpmc_buflen);

	BE_OUT16(buf, sess);
	buf += sizeof (uint16_t);

	/* Skip length for now */
	buf += sizeof (uint32_t);

	BE_OUT32(buf, cmd);
	buf += sizeof (uint32_t);

	c->tpmc_bufused = (size_t)(buf - c->tpmc_buf);
}

void
tpm_int_put8(tpm_client_t *c, uint8_t val)
{
	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3U(c->tpmc_bufused + sizeof (uint8_t), <=, c->tpmc_buflen);
	c->tpmc_buf[c->tpmc_bufused] = val;
	c->tpmc_bufused += sizeof (uint8_t);
}

void
tpm_int_put16(tpm_client_t *c, uint16_t val)
{
	uint8_t *buf = c->tpmc_buf + c->tpmc_bufused;

	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3U(c->tpmc_bufused + sizeof (uint16_t), <=, c->tpmc_buflen);
	BE_OUT16(buf, val);
	c->tpmc_bufused += sizeof (uint16_t);
}

void
tpm_int_put32(tpm_client_t *c, uint32_t val)
{
	uint8_t *buf = c->tpmc_buf + c->tpmc_bufused;

	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3U(c->tpmc_bufused + sizeof (uint32_t), <=, c->tpmc_buflen);
	BE_OUT32(buf, val);
	c->tpmc_bufused += sizeof (uint32_t);
}

void
tpm_int_copy(tpm_client_t *c, const void *src, size_t len)
{
	uint8_t *buf = c->tpmc_buf + c->tpmc_bufused;

	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	VERIFY3U(c->tpmc_bufused + len, <=, c->tpmc_buflen);

	bcopy(src, buf, len);
	c->tpmc_bufused += len;
}

uint32_t
tpm_int_rc(tpm_client_t *c)
{
	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	return (tpm_getbuf32(c->tpmc_buf, TPM_RETURN_OFFSET));
}

/*
 * From TCG TPM Vendor ID Registry Family 1.2 and 2.0
 * Version 1.06 Revision 0.94
 */
static struct {
	uint16_t	vid;
	const char	*vstr;
} vid_tbl[] = {
	{ 0x1022, "AMD" },
	{ 0x6688, "Ant" },
	{ 0x1114, "Atmel" },
	{ 0x14E4, "Broadcom" },
	{ 0xC5C0, "Cisco" },
	{ 0x232B, "FlySlice Technologies" },
	{ 0x232A, "Fuzhou Rockchip" },
	{ 0x6666, "Google" },
	{ 0x103C, "HPI" },
	{ 0x1590, "HPE" },
	{ 0x8888, "Huawei" },
	{ 0x1014, "IBM" },
	{ 0x15D1, "Infineon" },
	{ 0x8086, "Intel" },
	{ 0x17AA, "Lenovo" },
	{ 0x1414, "Microsoft" },
	{ 0x100B, "National Semi" },
	{ 0x1B4E, "Nationz" },
	{ 0x1050, "Nuvoton Technology nee Winbind" },
	{ 0x1011, "Qualcomm" },
	{ 0x144D, "Samsung" },
	{ 0x19FA, "Sinosun" },
	{ 0x1055, "SMSC" },
	{ 0x025E, "Solidigm" },
	{ 0x104A, "STMicroelectronics" },
	{ 0x104C, "Texas Instruments" },
};

const char *
tpm_hwvend_str(uint16_t vid)
{
	for (uint_t i = 0; i < ARRAY_SIZE(vid_tbl); i++) {
		if (vid_tbl[i].vid == vid) {
			return (vid_tbl[i].vstr);
		}
	}

	return ("Unknown");
}
