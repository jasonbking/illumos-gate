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

#include <sys/byteorder.h>	/* for ntohs, ntohl, htons, htonl */

#include <sys/tpm.h>

#ifdef sun4v
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#endif

#include <tss/platform.h>	/* from SUNWtss */
#include <tss/tpm.h>		/* from SUNWtss */

#include "tpm_tis.h"
#include "tpm_ddi.h"

typedef bool (*tpm_attach_fn_t)(tpm_t *);
typedef void (tpm_cleanup_fn_t)(tpm_t *);

typedef struct tpm_attach_desc {
	tpm_attach_seq_t	tad_seq;
	const char		*tad_name;
	tpm_attach_fn_t		tad_attach;
	tpm_cleanup_fn_t	tad_cleanup;
} tpm_attach_desc_t;

/*
 * In order to test the 'millisecond bug', we test if DURATIONS and TIMEOUTS
 * are unreasonably low...such as 10 milliseconds (TPM isn't that fast).
 * and 400 milliseconds for long duration
 */
#define	TEN_MILLISECONDS		10000	/* 10 milliseconds */
#define	FOUR_HUNDRED_MILLISECONDS	400000	/* 4 hundred milliseconds */

/* For now, we assume a system will only have a single TPM device. */
#define	TPM_CTL_MINOR		0

#define	DEFAULT_LOCALITY	0

/*
 * Explicitly not static as it is a tunable. Set to true to enable
 * debug messages.
 */
bool				tpm_debug = false;

static id_space_t		tpm_minors;
static void			*tpm_statep = NULL;

#ifdef __x86
static ddi_device_acc_attr_t	tpm_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
};
#endif

/* Can we accept write(2) requests without blocking? */
static inline bool
tpmc_is_writemode(const tpm_client_t *c)
{
	ASSERT(MUTEX_HELD(&c->tpmc_client));

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
	case TPM_CLIENT_CMD_RECEPTION:
		return (true);
	default:
		return (false);
	}
}

/* Can we accept read(2) requests without blocking? */
static inline bool
tpmc_is_readmode(const tpm_client_t *c)
{
	ASSERT(MUTEX_HELD(&c->tpmc_client));

	return ((c->tpmc_state == TPM_CLIENT_CMD_COMPLETION) ? true : false);
}

void
tpm_dbg(const tpm_t *tpm, const char *fmt, ...)
{
	if (!tpm->debug) {
		return;
	}

	va_list	ap;
	char	msg[1024];

	va_start(ap, msg);
	(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	va_end(ap);

	if (tpm != NULL && tpm->tpm_dip != NULL) {
		dev_err(tpm->tpm_dip, CE_NOTE, "!%s", msg);
	} else {
		cmn_err(CE_NOTE, "!%s", msg);
	}
}

static void
tpm_client_reset(tpm_client_t *c)
{
	ASSERT(MUTEX_HELD(&c->tpmc_lock));

	bzero(c->tpmc_buf, c->tpmc_buflen);
	c->tpmc_bufused = c->tpmc_bufread = 0;
	c->tpmc_state = TPM_CLIENT_IDLE;
	c->tpmc_cmdresult = 0;
	cv_broadcast(&c->tpmc_cv);
	pollwakeup(&c->tpmc_pollhead, POLLOUT);
}

static void
tpm_cancel(tpm_client_t *c)
{
	tpm_t *tpm;

	mutex_enter(&c->tpmc_lock);
	tpm = c->tpmc_tpm;

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
		break;
	case TPM_CLIENT_CMD_RECEPTION:
	case TPM_CLIENT_CMD_COMPLETION:
		tpm_client_reset(c);
		break;
	case TPM_CLIENT_CMD_EXECUTION:
		tpm->tpm_cancel(c);
		tpm_client_reset(c);
		break;
	case TPM_CLIENT_WAIT_FOR_TPM: {
		int ret;

		c->tpmc_cancelled = true;
		membar_producer();

		/*
		 * The taskq is waiting on tpm_cv, so we have to wake up
		 * all of the clients waiting so our client will see
		 * the request has been cancelled. In practice, the number
		 * of expected connections is expected to be small enough
		 * that doing a broadcast shouldn't present a problem.
		 */
		cv_broadcast(&c->tpmc_tpm->tpm_cv);

		/*
		 * Cancelling an in-process command may take some time.
		 * While we can't 'undo' the cancellation, we can at least
		 * stop blocking the caller, and just let the cleanup happen
		 * asynchronously.
		 */
		while (c->tpmc_cancelled)
			ret = cv_wait_sig(&c->tpmc_cv, &tpmc->tpmc_lock);

		if (ret != 0)
			tpm_client_reset(c);

		mutex_exit(&c->tpmc_lock);
		break;
	}
	default:
		cmn_err(CE_PANIC, "unexpected tpm connection state 0x%x",
		    c->tpmc_state);
	}

	mutex_exit(&c->tpmc_lock);
}

static int
tpm_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	tpm_t *tpm;
	tpm_conn_t *conn;
	int minor;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	if (getminor(*devp) != TPM_CTL_MINOR) {
		return (ENXIO);
	}

	/* Opening the TPM O_WRONLY makes no sense */
	if ((flag & FREAD) != FREAD) {
		/* XXX: Better value? */
		return (EINVAL);
	}

	tpm = ddi_get_soft_state(tpm_statep, TPM_CTL_MINOR);

	mutex_enter(&tpm->tpm_lock);

	IMPLY(tpm->tpm_exclusive, tpm->tpm_client_count == 1);
	if (tpm->tpm_client_count == tpm->tpm_client_max ||
	    tpm->tpm_exclusive ||
	    tpm->tpm_client_count > 0 && ((flag & FEXCL) == FEXCL)) {
		mutex_exit(&tpm->tpm_lock);
		return (EBUSY);
	}
	tpm->tpm_client_count++;
	if ((flag & FEXCL) == FEXCL) {
		tpm->tpm_exclusive = true;
	}
	mutex_exit(&tpm->tpm_lock);

	minor = id_alloc_nosleep(tpm_minors);
	if (minor == -1) {
		return (EBUSY);
	}

	if (ddi_soft_state_zalloc(tpm_statep, minor) != DDI_SUCCESS) {
		id_free(tpm_minors, minor);
		return (ENOMEM);
	}
	conn = ddi_get_soft_state(tpm_statep, minor);

	mutex_init(&conn->tpmc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&conn->tpmc_cv, NULL, CV_DRIVER, NULL);
	conn->tpmc_tpm = tpm;
	conn->tpmc_state = TPM_STATE_IDLE;
	conn->tpmc_buf = kmem_zalloc(TPM_IO_BUF_SIZE, KM_SLEEP);
	conn->tpmc_buflen = TPM_IO_BUF_SIZE;
	conn->tpmc_locality = DEFAULT_LOCALITY;

	if ((flag & FWRITE) == FWRITE) {
		conn->tpmc_mode |= TPM_CONN_WRITE;
	}
	if ((flag & FNDELAY) == FNDELAY) {
		conn->tpmc_mode |= TPM_CONN_NONBLOCK;
	}

	*devp = makedevice(getmajor(*devp), minor);
	return (0);		
}

static int
tpm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	tpm_t *tpm;
	tpm_conn_t *c;
	int minor;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	minor = getminor(dev);

	conn = ddi_get_soft_state(tpm_statep, minor);
	if (conn == NULL) {
		return (ENXIO);
	}

	tpm_cancel(c);

	mutex_enter(&c->tpmc_lock);

	tpm = conn->tpmc_tpm;
	mutex_enter(&tpm->tpm_lock);
	VERIFY3U(tpm->tpm_client_count, >, 0);
	IMPLY(tpm->tpm_exclusive, tpm->tpm_client_count == 1);
	tpm->tpm_conn_count--;
	tpm->tpm_exclusive = false;
	mutex_exit(&tpm->tpm_lock);

	bzero(c->tpmc_buf, c->tpmc_buflen);
	kmem_free(c->tpmc_buf, c->tpmc_buflen);

	cv_destroy(c->tpmc_cv);
	mutex_exit(&c->tpmc_lock);
	mutex_destroy(&c->tpmc_lock);

	ddi_soft_state_free(tpm_statep, minor);
	id_space_free(tpm_minors, minor);
	return (0);
}

static size_t
tpm_uio_size(const struct uio_t *uiop)
{
	size_t amt = 0;

	for (uint_t i = 0; i < uiop->uio_iovcnt; i++) {
		amt += uiop->uio_iov[i].iov_len;
	}

	return (amt);
}

static void
tpm_exec_cmd(void *arg)
{
	tpm_client_t	*c = arg;
	tpm_t		*tpm;
	int		ret;

	/*
	 * Since we are executing, that gives us exclusive access to
	 * tpmc->tpm_buf. We can drop tpmc_lock so to allow cancellations,
	 * etc. to be able to come in and not be blocked.
	 */
	mutex_enter(&c->tpmc_lock);
	VERIFY3S(c->tpmc_state, ==, TPMC_CLIENT_CMD_DISPATCH);
	tpm = c->tpmc_tpm;
	mutex_enter(&tpm->tpm_lock);
	c->tpmc_state = TPM_CLIENT_WAIT_FOR_TPM;
	mutex_exit(&c->tpmc_lock);

	while (tpm->tpm_active != NULL && !c->tpmc_cancelled) {
		cv_wait(&tpm->tpm_cv, &tpm->tpm_lock);
	}

	if (c->tpmc_cancelled) {
		mutex_exit(&tpm->tpm_lock);
		mutex_enter(&c->tpmc_lock);
		goto cancelled;
	}

	tpm->tpm_active = c;
	mutex_exit(&tpm->tpm_lock);

	mutex_enter(&c->tpmc_lock);
	if (c->tpmc_cancelled) {
		goto cancelled;
	}
	c->tpmc_state = TPM_CLIENT_CMD_EXECUTION;
	mutex_exit(&c->tpmc_lock);

	ret = tpm->tpm_exec(c);

	mutex_enter(&c->tpmc_lock);
	c->tpmc_cmdresult = ret;
	c->tpmc_state = TPM_CLIENT_CMD_COMPLETION;
	cv_signal(&c->tpmc_cv);
	pollwakeup(&c->tpmc_pollhead, POLLIN);
	mutex_exit(&c->tpmc_lock);

	return;

cancelled:
	c->tpmc_cancelled = false;
	c->tpmc_cmdresult = ECANCELED;
	cv_signal(&c->tpmc_cv);
	mutex_exit(&c->tpmc_lock);
}

static int
tpm_dispatch_cmd(tpm_client_t *c)
{
	ASSERT(MUTEX_HELD(&c->tpmc_lock));
	ASSERT3S(c->tpmc_state, ==, TPM_CLIENT_CMD_RECEPTION);
	ASSERT3U(c->tpmc_bufused, >=, TPM_HEADER_SIZE);

	tpm_t *tpm;
	size_t cmd_len = BE_IN32(c->tpmc_buf + TPM_PARAMSIZE_OFFSET);
	uint_t flags;
	int ret;

	/*
	 * We should only be dispatching once the full command has been
	 * received.
	 */
	VERIFY3U(c->tpmc_buflen, ==, cmd_len);

	if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
		flags = DDI_NOSLEEP;
	} else {
		flags = DDI_SLEEP;
	}

	tpm = c->tpmc_tpm;

	mutex_enter(&tpm->tpm_lock);
	ret = ddi_taskq_dispatch(&tpm->tpm_taskq, tpm_exec_cmd, c, flags);
	mutex_exit(&tpm->tpm_lock);

	if (ret != DDI_SUCCESS) {
		/*
		 * AFAIK, ddi_taskq_dispatch() can only fail due to lack of
		 * memory, so assume it's retryable.
		 */
		return (EAGAIN);
	}

	c->tpmc_state = TPM_CLIENT_CMD_DISPATCH;
	return (0);
}

static int
tpm_write(dev_t dev, struct uio_t *uiop, cred_t *credp)
{
	tpm_client_t *c;

	c = ddi_get_soft_state(tpm_statep, getminor(dev));
	if (c == NULL) {
		return (ENXIO);
	}

	mutex_enter(&c->tpmc_lock);

	size_t amt_copied = 0;
	size_t amt_avail = tpm_uio_size(uiop);
	size_t amt_needed = c->tpmc_buflen - c->tpmc_bufused;
	size_t to_copy = 0;
	int ret = 0;

	if ((c->tpmc_mode & TPM_MODE_WRITE) != 0) {
		/* XXX better return value? */
		ret = EIO;
		goto done;
	}

	if (!tpmc_is_writemode(c)) {
		if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
			ret = EAGAIN;
			goto done;
		}

		/*
		 * If we weren't in a writing mode when write(2) was called,
		 * we want to explicitly wait for the TPM_CLIENT_IDLE state
		 * since preumably that means we have a new command (and
		 * not a fragment of an in-process command).
		 */
		while (c->tpmc_state != TPM_CLIENT_IDLE) {
			ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
			if (ret == 0) {
				ret = EINTR;
				goto done;
			}
		}
		break;
	}

	/*
	 * Gather the TPM header. This will contain the total amount of
	 * data to write for the command.
	 */
	if (c->tpmc_bufused < TPM_HEADER_SIZE) {
		to_copy = MIN(TPM_HEADER_SIZE - c->tpmc_bufused, amt_avail);

		ret = uiomove(c->tpmc_buf + c->tpmc_bufused, to_copy, UIO_WRITE,
		    uiop);
		if (ret != 0) {
			goto abort;
		}

		if (c->tpmc_state == TPM_CLIENT_IDLE) {
			c->tpmc_state = TPM_CLIENT_CMD_RECEPTION;
			cv_broadcast(&c->tpmc_cv);
		}

		c->tpmc_bufused += to_copy;
		amt_copied +- to_copy;
		if (c->tpmc_bufused < TPM_HEADER_SIZE) {
			goto done;
		}
	}

	/*
	 * If we get this far, we should have at least TPM_HEADER_SIZE bytes
	 * copied in. The TPM header (1.2 and 2.0) includes the total size
	 * of the request (at TPM_PARAMSIZE_OFFSET), so we can calculate
	 * the amount of additional data needed in the request.
	 */
	ASSERT3U(c->tpmc_bufused, >=, TPM_HEADER_SIZE);
	amt_needed = BE_IN32(c->tpmc_buf + TPM_PARAMSIZE_OFFSET);

	if (amt_needed > c->tpmc_buflen) {
		/*
		 * Request is too large.
		 * XXX: Better error value? tpmc_buflen should be sized to
		 * hold any valid command, so if we were passed an oversized
		 * request, it's obviously invalid.
		 */
		ret = EIO;
		goto done;
	}
	amt_needed -= c->tpmc_bufused;

	to_copy = MIN(amt_needed, amt_avail);
	ret = uiomove(c->tpmc_buf + c->tpmc_bufused, to_copy, UIO_WRITE, uiop);
	if (ret != 0) {
		goto done;
	}
	c->tpmc_bufused += to_copy;
	amt_copied +- to_copy;

	if (to_copy < amt_needed) {
		goto done;
	}

	ret = tpm_dispatch_cmd(c);

done:
	if (ret != 0) {
		/*
		 * If we fail for any reason, undo any data we've copied so
		 * the same write(2) can be retried.
		 */
		VERIFY3U(amt_copied, <=, c->tpmc_buflen);
		VERIFY3U(amt_copied, <=, c->tpmc_bufused);
		bzero(c->tpmc_buf + c->tpmc_bufused - amt_copied, amt_copied);
		c->tpmc_bufused -= amt_copied;
		if (c->tpmc_bufused == 0) {
			c->tpmc_state = TPM_CLIENT_IDLE;
			cv_broadcast(&c->tpmc_cv);
		}
	}

	if (tpmc_is_writemode(c)) {
		pollwakeup(&c->tpmc_pollhead, POLLOUT);
	}
	mutex_exit(&c->tpmc_lock);
	return (ret);

abort:
	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	return (ret);
}

static int
tpm_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm_client_t *c;
	int ret = 0;

	c = ddi_get_soft_state(tpm_statep, getminor(dev));
	if (c == NULL) {
		return (ENXIO);
	}

	mutex_enter(&c->tpmc_lock);

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
	case TPM_CLIENT_CMD_RECEPTION:
	case TPM_CLIENT_CMD_DISPATCH:
	case TPM_CLIENT_CMD_EXECUTION:
		if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
			mutex_exit(&c->tpmc_lock);
			return (EAGAIN);
		}

		while (c->tpmc_state != TPM_CLIENT_CMD_COMPLETION) {
			ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
			if (ret == 0) {
				mutex_exit(&c->tpmc_lock);
				return (EINTR);
			}
		}
		break;
	}

	if (c->tpmc_cmdresult != 0) {
		int ret = c->tpmc_cmdresult;

		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (ret);
	}

	size_t amt_avail = tpm_uio_size(uiop);
	size_t to_copy = MIN(amt_avail, c->tpmc_bufused - c->tpmc_bufread);

	ret = uiomove(c->tpmc_buf + c->tpmc_bufread, to_copy, UIO_READ, uiop);
	if (ret != 0) {
		goto done;
	}

	c->tpmc_bufread += to_copy;
	if (c->tpmc_bufread == c->tpmc_bufused) {
		/* Entire response has been read, switch back to idle */
		tpm_client_reset(c);
	}

done:
	mutex_exit(&c->tpmc_lock);
	return (ret);
}

static int
tpm_ioctl(dev_t dev, int cmd, intptr_t data, int md, cred_t *cr, int *rv)
{
	tpm_client_t *c;
	int err = 0;
	int val;

	c = ddi_get_soft_state(tpm_statep, getminor(dev));
	if (c == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case TPMIOC_GETVERSION:
		switch (c->tpmc_tpm->tpm_family) {
		case TPM_FAMILY_1_2:
			val = TPMDEV_VERSION_1_2;
			break;
		case TPM_FAMILY_2_0:
			val = TPMDEV_VERSION_2_0;
			break;
		default:
			return (EINVAL);
		}

		if (ddi_copyout(&val, (void *)data, sizeof (val), md) != 0) {
			err = EFAULT;
		}
		break;
	case TPMIOC_SETLOCALITY:
		if ((c->tpmc_mode & TPM_CONN_WRITE) != 0) {
			/* XXX: better value? didn't open for write */
			err = ENXIO;
			break;
		}

		if (ddi_copyin((void *)data, &val, sizeof (val), md) != 0) {
			err = EFAULT;
			break;
		}

		if (val < 0 || val > TPM_LOCALITY_MAX) {
			err = EINVAL;
			break;
		}

		/*
		 * XXX: For now we only allow access to locality 0.
		 */
		if (val != 0) {
			err = EPERM;
			break;
		}

		/* Only change locality while the client is idle. */
		mutex_enter(&c->tpmc_lock);
		if (c->tpmc_state != TPMC_CLIENT_IDLE) {
			if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
				err = EAGAIN;
				mutex_exit(&c->tpmc_lock);
				goto done;
			}
			while (c->tpmc_state != TPMC_CLIENT_IDLE) {
				ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
				if (ret == 0) {
					ret = EINTR;
					goto done;
				}
			}
		}
		conn->tpmc_locality = val;
		mutex_exit(&c->tpmc_lock);
		break;
	case TPMIOC_CANCEL:
		tpm_cancel(c);
		break;
	case TPMIOC_MAKESTICKY:
		/* XXX: TODO */
		err = ENOTSUP;
		break;
	default:
		err = ENOTTY;
	}

done:
	return (err);
}

static int
tpm_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead *phpp)
{
	tpm_client_t *c;

	c = ddi_get_soft_state(tpm_statep, getminor(dev));
	if (c == NULL) {
		return (ENXIO);
	}

	mutex_enter(&c->tpmc_lock);
	*reventsp = 0;

	if (tpmc_is_writemode(c)) {
		*reventsp |= POLLOUT;
	}
	if (tpmc_is_readmode(c)) {
		*reventsp |= POLLIN;
	}
	*reventsp &= events;

	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &conn->tpmc_pollhead;
	}
	mutex_exit(&conn->tpmc_lock);

	return (0);
}

/*
 * Inline code to get exclusive lock on the TPM device and to make sure
 * the device is not suspended.  This grabs the primary TPM mutex (pm_mutex)
 * and then checks the suspend status.  If suspended, it will wait until
 * the device is "resumed" before releasing the pm_mutex and continuing.
 */
#define	TPM_EXCLUSIVE_LOCK(tpm)  { \
	mutex_enter(&tpm->pm_mutex); \
	while (tpm->suspended) \
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex); \
	mutex_exit(&tpm->pm_mutex); }

/*
 * TPM commands to get the TPM's properties, e.g.,timeout
 */
static int
tpm_quiesce(dev_info_t *dip __unused)
{
	return (DDI_SUCCESS);
}

int
tpm_wait_for_u32(tpm_t *tpm, uint32_t reg, uint32_t mask, uint32_t val,
    clock_t timeout)
{
	clock_t deadline = ddi_get_lbolt() + timeout;

	while ((tpm_get32(tpm, reg) & mask) != val) {
		if (ddi_get_lbolt() >= deadline) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: polling timeout (%ld usecs)",
			    __func__, drv_hztousec(timeout));
#endif
			return (ETIME);
		}

		delay(tpm->timeout_poll);
	}

	return (0);
}

/*
 * Auxilary Functions
 */

/*
 * Internal TPM Transmit Function:
 * Calls implementation specific sendto and receive
 * The code assumes that the buffer is in network byte order
 */
int
itpm_command(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	uint32_t count;

	ASSERT(tpm != NULL && buf != NULL);

	/* The byte order is network byte order so convert it */
	count = tpm_getbuf32(buf, TPM_PARAMSIZE_OFFSET);

	if (count == 0 || (count > bufsiz)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: invalid byte count value "
		    "(%d > bufsiz %d)", __func__, (int)count, (int)bufsiz);
#endif
		return (DDI_FAILURE);
	}

	/* Send the command */
	ret = tis_send_data(tpm, buf, count);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_send_data failed with error %x",
		    __func__, ret);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Now receive the data from the tpm
	 * Should at least receive "the common" 10 bytes (TPM_HEADER_SIZE)
	 */
	ret = tis_recv_data(tpm, buf, bufsiz);
	if (ret < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_recv_data failed", __func__);
#endif
		return (DDI_FAILURE);
	}

	/* Check the return code */
	ret = tpm_getbuf32(buf, TPM_RETURN_OFFSET);
	if (ret != TPM_SUCCESS) {
		if (ret == TPM_E_DEACTIVATED)
			cmn_err(CE_WARN, "!%s: TPM is deactivated", __func__);
		else if (ret == TPM_E_DISABLED)
			cmn_err(CE_WARN, "!%s: TPM is disabled", __func__);
		else
			cmn_err(CE_WARN, "!%s: TPM error code 0x%0x",
			    __func__, ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
tpm_resume(tpm_t *tpm)
{
	mutex_enter(&tpm->pm_mutex);
	if (!tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_FAILURE);
	}
	tpm->suspended = 0;
	cv_broadcast(&tpm->suspend_cv);
	mutex_exit(&tpm->pm_mutex);

	return (DDI_SUCCESS);
}

#ifdef amd64
static bool
tpm_attach_regs(tpm_t *tpm)
{
	uint_t idx;
	int nregs;
	int ret;

	ret = ddi_dev_nregs(tpm->tpm_dip, &nregs);
	if (ret != DDI_SUCCESS) {
		return (false);
	}

	if (nregs < 0) {
		dev_err(tpm->tpm_dip, CE_WARN, "ddi_dev_nregs failed: %d",
		    nregs);
		return (false);
	}

	/*
	 * TPM vendors put the TPM registers in different
	 * slots in their register lists.  They are not always
	 * the 1st set of registers, for instance.
	 * Loop until we find the set that matches the expected
	 * register size (0x5000).
	 */
	for (idx = 0; idx < nregs; i++) {
		off_t regsize;

		ret = ddi_dev_regsize(tpm->tpm_dip, idx, &regsize);
		if (ret != DDI_SUCCESS) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "ddi_dev_regsize failed: %d", ret);
			return (false);
		}

		/* The TIS spec says the TPM registers must be 0x5000 bytes */
		if (regsize == 0x5000) {
			break;
		}
	}

	if (idx == nregs) {
		return (false);
	}

	ret = ddi_regs_map_setup(tpm->tpm_dip, idx, (caddr_t *)&tpm->tpm_addr,
	    0, regsize, &tpm_acc_attr, &tpm->tpm_handle);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "failed to map tpm registers: %d", ret);
		return (false);
	}

	return (true);
}

static void
tpm_cleanup_regs(tpm_t *tpm)
{
	ddi_regs_map_free(&tpm->tpm_handle);
}

static bool
tpm_attach_intr_alloc(tpm_t *tpm)
{
	int types = 0;
	int nintrs = 0;
	int navail = 0;
	int ret;

	if (!tpm->tpm_use_interrupts) {
		return (true);
	}

	if (ddi_intr_get_supported_types(tpm->tpm_dip, &types) != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "could not get supported interrupts");
		return (false);
	}

	if ((types & DDI_INTR_TYPE_FIXED) != 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "fixed interrupts are not supported");
		return (false);
	}

	if (ddi_intr_get_nintrs(tpm->tpm_dip, DDI_INTR_TYPE_FIXED,
	    &nintrs) != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "could not count %s interrupts", "FIXED");
		return (false);
	}

	if (nintrs < 1) {
		dev_err(tpm->tpm_dip, CE_WARN, "no interrupts supported");
		return (false);
	}

	if (nintrs != 1) {
		/* No matter what, we're just going to use one interrupt */
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "!device supports unexpected number (%d) of interrupts",
		    nintrs);
		nintrs = 1;
	}

	ret = ddi_intr_alloc(tpm->tpm_dip, tpm->tpm_harray, DDI_INTR_TYPE_FIXED,
	    0, 1, &tpm->tpm_nintr, DDI_INTR_ALLOC_STRICT);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "interrupt allocation failure %d", ret);
		return (false);
	}

	return (true);
}

static void
tpm_cleanup_intr_alloc(tpm_t *tpm)
{
	if (!tpm->tpm_use_interrupts) {
		return;
	}

	VERIFY3S(ddi_intr_free(tpm_>tpm_harray), ==, DDI_SUCCESS);
}

static bool
tpm_attach_intr_hdlrs(tpm_t *tpm)
{
	uint_t i;
	int ret;

	if (!tpm->tpm_use_interrupts) {
		return (true);
	}

	for (i = 0; i < tpm->tpm_nintr; i++) {
		ret = ddi_intr_add_handler(tpm->tpm_harray[i], tpm->tpm_isr,
		    tpm, NULL);
		if (ret != DDI_SUCCESS) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "failed to attach interrupt %u handler: %d",
			    i, ret);
			goto fail;
		}
	}

	return (true);

fail:
	while (i > 0) {
		ret = ddi_intr_remove_handler(tpm->tpm_harray[--i]);
		VERIFY3S(ret, ==, DDI_SUCCESS);
	}

	return (false);
}

static void
tpm_cleanup_intr_hdlrs(tpm_t *tpm)
{
	uint_t i;
	int ret;

	if (!tpm->tpm_use_interrupts) {
		return;
	}

	i = tpm->tpm_nintr;
	while (i > 0) {
		ret = ddi_intr_remove_handler(tpm->tpm_harray[--i]);
		VERIFY3S(ret, ==, DDI_SUCCESS);
	}
}
#endif /* amd64 */

static bool
tpm_attach_sync(tpm_t *tpm)
{
	void *pri = tpm->tpm_use_interrupts ?
	    DDI_INTR_PRI(tpm->tpm_intr_pri) : NULL;

	mutex_init(&tpm->tpm_lock, NULL, MUTEX_DRIVER, pri);
	cv_init(&tpm->tpm_cv, NULL, CV_DRIVER, pri);
}

static void
tpm_cleanup_sync(tpm_t *tpm)
{
	cv_destroy(&tpm->tpm_cv);
	mutex_destroy(&tpm->tpm_lock);
}

static bool
tpm_attach_minor_node(tpm_t *tpm)
{
	int ret;

	ret = ddi_create_minor_node(tpm->tpm_dip, "tpm", S_IFCHR,
	    ddi_get_instance(tpm->tpm_dip), DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "failed to create minor node: %d", ret);
		return (false);
	}

	return (true);
}

static void
tpm_cleanup_minor_node(tpm_t *tpm)
{
	ddi_remove_minor_node(tpm->tpm_dip, NULL);
}

#ifdef sun4v
static uint64_t hsvc_tpm_minor = 0;
static hsvc_info_t hsvc_tpm = {
	HSVC_REV_1, NULL, HSVC_GROUP_TPM, 1, 0, NULL
};

static bool
tpm_attach_hsvc(tpm_t *tpm)
{
	int ret;

	ret = hsvc_register(&hsvc_tpm, &hscv_tpm_minor);
	if (ret != 0) {
		dev_err(tpm->tpm_dip,CE_WARN,
		    "failed to register with hypervisor: 0x%0x", ret);
		return (false);
	}

	return (true);
}

static void
tpm_cleanup_hsvc(tpm_t *tpm)
{
	hsvc_unregister(&hsvc_tpm);
}
#endif

static bool
tpm_attach_rng(tpm_t *tpm)
{
	return (true);
}

static void
tpm_cleanup_rng(tpm_t *tpm)
{
}

static tpm_attach_desc_t tpm_attach_tbl[TPM_ATTACH_NUM_ENTRIES] = {
#ifdef amd64
	[TPM_ATTACH_REGS] = {
		.tad_seq = TPM_ATTACH_REGS,
		.tad_name = "registers",
		.tad_attach = tpm_attach_regs,
		.tad_cleanup = tpm_cleanup_regs,
	},
#endif
#ifdef sun4v
	[TPM_ATTACH_HSVC] = {
		.tad_seq = TPM_ATTACH_HSVC,
		.tad_name = "hypervisor",
		.tad_attach = tpm_attach_hsvc,
		.tad_cleanup = tpm_cleanup_hsvc,
	},
#endif
	[TPM_ATTACH_DEV_INIT] = {
		.tad_seq = TPM_ATTACH_DEV_INIT,
		.tad_name = "device initialization",
		.tad_attach = tpm_attach_dev_init,
		.tad_cleanup = tpm_cleanup_dev_init,
	},
#ifdef amd64
	[TPM_ATTACH_INTR_ALLOC] = {
		.tad_seq = TPM_ATTACH_INTR_ALLOC,
		.tad_name = "interrupt allocation",
		.tad_attach = tpm_attach_intr_alloc,
		.tad_cleanup = tpm_cleanup_intr_alloc,
	},
	[TPM_ATTACH_INTR_HDLRS] = {
		.tad_seq = TPM_ATTACH_INTR_HDLRS,
		.tad_name = "interrupt handlers",
		.tad_attach = tpm_attach_intr_hdlr,
		.tad_cleanup = tpm_cleanup_intr_hdlr,
	},
#endif
	[TPM_ATTACH_SYNC] = {
		.tad_seq = TPM_ATTACH_SYNC,
		.tad_name = "synchronization",
		.tad_attach = tpm_attach_sync,
		.tad_cleanup = tpm_cleanup_sync,
	},
	[TPM_ATTACH_MINOR_NODE] = {
		.tad_seq = TPM_ATTACH_MINOR_NODE,
		.tad_name = "minor node",
		.tad_attach = tpm_attach_minor_node,
		.tad_cleanup = tpm_cleanup_minor_node,
	},
	[TPM_ATTACH_RAND] = {
		.tad_seq = TPM_ATTACH_RAND,
		.tad_name = "rng provider",
		.tad_attach = tpm_attach_rng,
		.tad_cleanup = tpm_cleanup_rng,
	},
};

static void
tpm_cleanup(tpm_t *tpm)
{
	if (tpm == NULL || tpm->tpm_attach_seq == 0) {
		return;
	}

	VERIFY3U(tpm->tpm_attach_seq, <, TPM_ATTACH_NUM_ENTRIES);

	while (tpm->tpm_attach_seq > 0) {
		tpm_attach_seq_t seq = --tpm->tpm_attach_seq;
		tpm_attach_desc_t desc = &tpm_attach_tbl[seq];

		tpm_dbg(tpm, "running cleanup sequence %s (%d)",
			desc->tad_name, seq);

		desc->tad_cleanup(tpm);
	}

	ASSERT3U(tpm->tpm_attach_seq, ==, 0);
}

static int
tpm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	tpm_t *tpm = NULL;
	int ret;
	int instance;

	instance = ddi_get_instance(dip);
	if (instance < 0) {
		return (DDI_FAILURE);
	}

	/* Nothing out of ordinary here */
	switch (cmd) {
	case DDI_ATTACH:
		ret = ddi_soft_state_zalloc(tpm_statep, instance);
		if (ret != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "failed to allocate device soft state");
			return (DDI_FAILURE);
		}

		tpm = ddi_get_soft_state(tpm_statep, instance);
		tpm->tpm_dip = dip;
		tpm->tpm_instance = instance;
		break;
	case DDI_RESUME:
		tpm = ddi_get_soft_state(tpm_statep, instance);
		if (tpm == NULL) {
			dev_err(dip, CE_WARN,
			    "failed to retreive device soft state");
			return (DDI_FAILURE);
		}

		return (tpm_resume(tpm));
	default:
		return (DDI_FAILURE);
	}

	for (uint_t i = 0; i < ARRAY_SIZE(tpm_attach_tbl); i++) {
		tpm_attach_desc_t *desc = &tpm_attach_tbl[i];

		tpm_dbg(tpm, "running attach sequence %s (%d)", desc->tad_name,
		    desc->tad_seq);

		if (!desc->tad_attach(tpm)) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "attach sequence failed %s (%d)", desc->tad_desc,
			    desc->tad_seq);
			tpm_cleanup(tpm);
			return (DDI_FAILURE);
		}

		tpm_dbg(tpm, "attach sequence completed: %s (%d)",
			desc->tad-name, desc->tad_seq);
		tpm->tpm_seq = desc->tad_seq;
	}

	/* Set the suspend/resume property */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");

	char buf[32];

	(void) snprintf(buf, sizeof (buf), "%d.%d",
	    tpm->vers_info.version.major,
	    tpm->vers_info.version.minor);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "tpm-version", buf);

	(void) snprintf(buf, sizeof (buf), "%d.%d",
	    tpm->vers_info.version.revMajor,
	    tpm->vers_info.version.revMinor);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "tpm-revision", buf);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "tpm-speclevel",
	    ntohs(tpm->vers_info.specLevel));
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "tpm-errata-revision",
	    tpm->vers_info.errataRev);

	if (tpm->tpm_use_interrupts) {
		tpm->tpm_set_interrupts(tpm, true);
	}

	return (DDI_SUCCESS);
}

static int
tpm_suspend(tpm_t *tpm)
{
	if (tpm == NULL)
		return (DDI_FAILURE);

	mutex_enter(&tpm->pm_mutex);
	if (tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_SUCCESS);
	}
	tpm->suspended = 1;
	mutex_exit(&tpm->pm_mutex);

	return (DDI_SUCCESS);
}

static int
tpm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	tpm_t *tpm;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (instance < 0)
		return (DDI_FAILURE);

	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "failed to retreive instance %d soft state",
		    instance);
		return (ENXIO);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (tpm_suspend(tpm));
	default:
		return (DDI_FAILURE);
	}

	tpm_cleanup(tpm);
	ddi_soft_state_free(tpm_statep, instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tpm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	int instance;
	tpm_t *tpm;

	instance = ddi_get_instance(dip);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = tpm->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = 0;
		break;
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: cmd %d is not implemented", __func__,
		    cmd);
#endif
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * This is to deal with the contentions for the iobuf
 */
static inline int
tpm_io_lock(tpm_t *tpm)
{
	int ret;
	clock_t timeout;

	mutex_enter(&tpm->iobuf_lock);
	ASSERT(mutex_owned(&tpm->iobuf_lock));

	timeout = ddi_get_lbolt() + drv_usectohz(TPM_IO_TIMEOUT);

	/* Wait until the iobuf becomes free with the timeout */
	while (tpm->iobuf_inuse) {
		ret = cv_timedwait(&tpm->iobuf_cv, &tpm->iobuf_lock, timeout);
		if (ret <= 0) {
			/* Timeout reached */
			mutex_exit(&tpm->iobuf_lock);
#ifdef DEBUG
			cmn_err(CE_WARN, "!tpm_io_lock:iorequest timed out");
#endif
			return (ETIME);
		}
	}
	tpm->iobuf_inuse = 1;
	mutex_exit(&tpm->iobuf_lock);
	return (0);
}

/*
 * TPM accessor functions
 */
#ifdef sun4v
extern uint64_t
hcall_tpm_get(uint64_t, uint64_t, uint64_t, uint64_t *);

extern uint64_t
hcall_tpm_put(uint64_t, uint64_t, uint64_t, uint64_t);

uint8_t
tpm_get8(tpm_t *tpm, unsigned long offset)
{
	uint64_t value;

	(void) hcall_tpm_get(tpm->locality, offset, sizeof (uint8_t), &value);
	return ((uint8_t)value);
}

uint32_t
tpm_get32(tpm_t *tpm, unsigned long offset)
{
	uint64_t value;

	(void) hcall_tpm_get(tpm->locality, offset, sizeof (uint32_t), &value);
	return ((uint32_t)value);
}

void
tpm_put8(tpm_t *tpm, unsigned long offset, uint8_t value)
{
	(void) hcall_tpm_put(tpm->locality, offset, sizeof (uint8_t), value);
}

uint8_t
tpm_get8_loc(tpm_t *tpm __unused, uint8_t loc, unsigned long offset)
{
	uint64_t value;

	(void) hcall_tpm_get(loc, offset, sizeof (uint8_t), &value);
	return ((uint8_t)value);
}

void
tpm_put8_loc(tpm_t *tpm __unused, unsigned long offset, uint8_t loc,
    uint8_t value)
{
	(void) hcall_tpm_put(loc, offfset, sizeof (uint8_t), value);
}

#elif defined(amd64)

static inline uintptr_t
tpm_locality_offset(uint8_t locality)
{
	VERIFY(locality, <=, TPM_LOCALITY_MAX);

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
	return (ddi_get8(tpm->tpm_handle, tpm_reg_addr(tpm, offset));
}

uint8_t
tpm_get8_loc(tpm_t *tpm, uint8_t locality, unsigned long offset)
{
	uintptr_t eff_off = tpm_locality_offset(locality) + offset;

	VERIFY3U(offset, <=, TPM_OFFSET_MAX);
	return (ddi_get8(tpm->tpm_handle, tpm->tpm_addr + eff_off));
}

uint32_t
tpm_get32(tpm_t *tpm, unsigned long offset)
{
	return (ddi_get32(tpm->tpm_handle, tpm_reg_addr(tpm, offset));
}

uint64_t
tpm_get64(tpm_t *tpm, unsigned long offset)
{
	return (ddi_get64(tpm->tpm_handle, tpm_reg_addr(tpm, offset));
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

	VERIFY3U(offset, <=, TPM_OFFSET_MAX);
	ddi_put8(tpm->tpm_handle, tpm->tpm_addr + eff_off, value);
}
#else
#error TPM Accessor functions not defined for platform
#endif

static struct cb_ops tpm_cb_ops = {
	.cb_rev =		CB_REV,
	.cb_flag =		D_MP,

	.cb_open =		tpm_open,
	.cb_close =		tpm_close,
	.cb_strategy =		nodev,
	.cb_read =		tpm_read,
	.cb_write =		tpm_write,
	.cb_ioctl =		tpm_ioctl,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		tpm_chpoll,
	.cb_propop =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev,
};

static struct dev_ops tpm_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,

	.devo_attach =		tpm_attach,
	.devo_detach =		tpm_detach,
	.devo_quiesce =		tpm_quiesce,

	.devo_cb_ops =		&tpm_cb_ops,

	.devo_getinfo =		tpm_getinfo,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset =		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"TPM driver",
	.drv_dev_ops =		&tpm_dev_ops,
};

static struct modlinkage tpm_ml = {
	.ml_rev =	MODREV_1,
	.ml_linkage =	{ &modldrv, NULL },
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&tpm_statep, sizeof (tpm_t), 1);
	if (ret) {
		cmn_err(CE_WARN, "!%s: ddi_soft_state_init failed: %d",
		    __func__, ret);
		return (ret);
	}
	ret = mod_install(&tpm_ml);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: mod_install returned %d",
		    __func__, ret);
		ddi_soft_state_fini(&tpm_statep);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	int ret;
	ret = mod_info(&tpm_ml, modinfop);
	if (ret == 0)
		cmn_err(CE_WARN, "!%s: mod_info failed: %d", __func__, ret);

	return (ret);
}

int
_fini()
{
	int ret;

	ret = mod_remove(&tpm_ml);
	if (ret != 0)
		return (ret);

	ddi_soft_state_fini(&tpm_statep);

	return (ret);
}
