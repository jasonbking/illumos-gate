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

/*
 * In order to test the 'millisecond bug', we test if DURATIONS and TIMEOUTS
 * are unreasonably low...such as 10 milliseconds (TPM isn't that fast).
 * and 400 milliseconds for long duration
 */
#define	TEN_MILLISECONDS	10000	/* 10 milliseconds */
#define	FOUR_HUNDRED_MILLISECONDS 400000	/* 4 hundred milliseconds */

#define	DEFAULT_LOCALITY 0

/*
 * At least initially, we assume a system will only have a single hardware
 * TPM device.
 */
#define	TPM_CTL_MINOR	0

/*
 * Internal TPM command functions
 */
static int itpm_command(tpm_t *tpm, uint8_t *buf, size_t bufsiz);

/* Auxilliary */
static int receive_data(tpm_t *, uint8_t *, size_t);
static inline int tpm_io_lock(tpm_t *);
static inline void tpm_unlock(tpm_t *);
static void tpm_cleanup(dev_info_t *, tpm_t *);

/*
 * Sun DDI/DDK entry points
 */
static int tpm_attach(dev_info_t *, ddi_attach_cmd_t);
static int tpm_detach(dev_info_t *, ddi_detach_cmd_t);
static int tpm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int tpm_quiesce(dev_info_t *);

static int tpm_open(dev_t *, int, int, cred_t *);
static int tpm_close(dev_t, int, int, cred_t *);
static int tpm_read(dev_t, struct uio *, cred_t *);
static int tpm_write(dev_t, struct uio *, cred_t *);
static int tpm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int tpm_chpoll(dev_t, short, int, short *, struct pollhead **);

static id_space_t		tpm_minors;
static void			*tpm_statep = NULL;

#ifdef __x86
static ddi_device_acc_attr_t	tpm_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
};
#endif

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

	mutex_enter(&c->tpmc_lock);

	/* XXX: Cancel any pending operations */

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
	VERIFY3S(c->tpmc_state, ==, TPMC_CLIENT_CMD_EXECUTION);
	tpm = c->tpmc_tpm;
	mutex_enter(&tpm->tpm_lock);
	mutex_exit(&c->tpmc_lock);

	while (tpm->tpm_active != NULL) {
		cv_wait(&tpm->tpm_cv, &tpm->tpm_lock);
	}
	tpm->tpm_active = c;
	mutex_exit(&tpm->tpm_lock);

	ret = tpm->tpm_exec(c);

	mutex_enter(&c->tpmc_lock);
	c->tpmc_cmdresult = ret;
	c->tpmc_state = TPM_CLIENT_CMD_COMPLETION;
	cv_broadcast(&c->tpmc_cv);
	pollwakeup(&c->tpmc_pollhead, POLLIN);
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

	c->tpmc_state = TPM_CLIENT_CMD_EXECUTION;
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

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
	case TPM_CLIENT_CMD_RECEPTION:
		break;
	case TPM_CLIENT_CMD_EXECUTION:
	case TPM_CLIENT_CMD_COMPLETION:
		if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
			ret = EAGAIN;
			goto done;
		}

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
			cv_broadcast(&c->tpmc_cv);
		}

		c->tpmc_state = TPM_CLIENT_CMD_RECEPTION;
		c->tpmc_bufused += to_copy;
		amt_copied +- to_copy;
		if (c->tpmc_bufused < TPM_HEADER_SIZE) {
			pollwakeup(&c->tpmc_pollhead, POLLOUT);
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
		pollwakeup(&c->tpmc_pollhead, POLLOUT);
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
		}
	}

	if (c->tpmc_state != TPM_CLIENT_CMD_EXECUTION) {
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
	case TPM_CLIENT_CMD_EXECUTION:
	case TPM_CLIENT_CMD_RECEPTION:
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
		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		return (EIO);
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
		mutex_enter(&c->tpmc_lock);
		switch (c->tpmc_state) {
		case TPM_CLIENT_IDLE:
			break;
		case TPM_CLIENT_CMD_RECEPTION:
		case TPM_CLIENT_CMD_COMPLETION:
			tpm_client_reset(c);
			break;
		case TPM_CLIENT_CMD_EXECUTION:
			mutex_enter(&c->tpmc_tpm->tpm_lock);
			VERIFY3P(c->tpmc_tpm->tpm_active, ==, c);
			c->tpmc_tpm->tpm_active = NULL;
			mutex_exit(&c->tpmc_tpm->tpm_lock);

			tpm_client_reset(c);
			mutex_exit(&c->tpmc_lock);
			break;
		}
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

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
	case TPM_CLIENT_CMD_RECEPTION:
		*reventsp |= POLLOUT;
		break;
	case TPM_CLIENT_CMD_EXECUTION:
		break;
	case TPM_CLIENT_CMD_COMPLETION:
		*reventsp |= POLLIN;
		break;
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
receive_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int size = 0;
	int retried = 0;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

	ASSERT(tpm != NULL && buf != NULL);
retry:
	while (size < bufsiz && (tpm_wait_for_stat(tpm,
	    (TPM_STS_DATA_AVAIL|TPM_STS_VALID),
	    tpm->timeout_c) == DDI_SUCCESS)) {
		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		burstcnt = tpm_get_burstcount(tpm);
		for (; burstcnt > 0 && size < bufsiz; burstcnt--) {
			buf[size++] = tpm_get8(tpm, TPM_DATA_FIFO);
		}
	}
	stsbits = tis_get_status(tpm);
	/* check to see if we need to retry (just once) */
	if (size < bufsiz && !(stsbits & TPM_STS_DATA_AVAIL) && retried == 0) {
		/* issue responseRetry (TIS 1.2 pg 54) */
		tpm_put8(tpm, TPM_STS, TPM_STS_RESPONSE_RETRY);
		/* update the retry counter so we only retry once */
		retried++;
		/* reset the size to 0 and reread the entire response */
		size = 0;
		goto retry;
	}
	return (size);
}

/* Receive the data from the TPM */
static int
tis_recv_data(tpm_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	int size = 0;
	uint32_t expected, status;
	uint32_t cmdresult;

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz < TPM_HEADER_SIZE) {
		/* There should be at least tag, paramsize, return code */
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data should contain at least "
		    "the header which is %d bytes long",
		    __func__, TPM_HEADER_SIZE);
#endif
		goto OUT;
	}

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	size = receive_data(tpm, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: recv TPM_HEADER failed, size = %d",
		    __func__, size);
#endif
		goto OUT;
	}

	cmdresult = tpm_getbuf32(buf, TPM_RETURN_OFFSET);

	/* Get 'paramsize'(4 bytes)--it includes tag and paramsize */
	expected = tpm_getbuf32(buf, TPM_PARAMSIZE_OFFSET);
	if (expected > bufsiz) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: paramSize is bigger "
		    "than the requested size: paramSize=%d bufsiz=%d result=%d",
		    __func__, (int)expected, (int)bufsiz, cmdresult);
#endif
		goto OUT;
	}

	/* Read in the rest of the data from the TPM */
	size += receive_data(tpm, (uint8_t *)&buf[TPM_HEADER_SIZE],
	    expected - TPM_HEADER_SIZE);
	if (size < expected) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data length (%d) "
		    "is less than expected (%d)", __func__, size, expected);
#endif
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);

	status = tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM didn't set stsValid after its I/O: "
		    "status = 0x%08X", __func__, status);
#endif
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM_STS_DATA_AVAIL is set:0x%08X",
		    __func__, status);
#endif
		goto OUT;
	}

	/*
	 * Release the control of the TPM after we are done with it
	 * it...so others can also get a chance to send data
	 */
	tis_release_locality(tpm, tpm->locality, 0);

OUT:
	tpm_set_ready(tpm);
	tis_release_locality(tpm, tpm->locality, 0);
	return (size);
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

#ifdef sun4v
static uint64_t hsvc_tpm_minor = 0;
static hsvc_info_t hsvc_tpm = {
	HSVC_REV_1, NULL, HSVC_GROUP_TPM, 1, 0, NULL
};
#endif

/*
 * Sun DDI/DDK entry points
 */
static int
tpm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int instance;
#ifndef sun4v
	int idx, nregs;
#endif
	tpm_t *tpm = NULL;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (instance < 0)
		return (DDI_FAILURE);

	/* Nothing out of ordinary here */
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(statep, instance) == DDI_SUCCESS) {
			tpm = ddi_get_soft_state(statep, instance);
			if (tpm == NULL) {
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!%s: cannot get state information.",
				    __func__);
#endif
				return (DDI_FAILURE);
			}
			tpm->dip = dip;
		} else {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: cannot allocate state information.",
			    __func__);
#endif
			return (DDI_FAILURE);
		}
		break;
	case DDI_RESUME:
		tpm = ddi_get_soft_state(statep, instance);
		if (tpm == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: cannot get state information.",
			    __func__);
#endif
			return (DDI_FAILURE);
		}
		return (tpm_resume(tpm));
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: cmd %d is not implemented", __func__,
		    cmd);
#endif
		ret = DDI_FAILURE;
		goto FAIL;
	}

	/* Zeroize the flag, which is used to keep track of what is allocated */
	tpm->flags = 0;

#ifdef sun4v
	ret = hsvc_register(&hsvc_tpm, &hsvc_tpm_minor);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: failed to register with "
		    "hypervisor: 0x%0x", __func__, ret);
		goto FAIL;
	}
	tpm->flags |= TPM_HSVC_REGISTERED;
#else
	tpm->accattr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	tpm->accattr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	tpm->accattr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	idx = 0;
	ret = ddi_dev_nregs(tpm->dip, &nregs);
	if (ret != DDI_SUCCESS)
		goto FAIL;

	/*
	 * TPM vendors put the TPM registers in different
	 * slots in their register lists.  They are not always
	 * the 1st set of registers, for instance.
	 * Loop until we find the set that matches the expected
	 * register size (0x5000).
	 */
	for (idx = 0; idx < nregs; idx++) {
		off_t regsize;

		if ((ret = ddi_dev_regsize(tpm->dip, idx, &regsize)) !=
		    DDI_SUCCESS)
			goto FAIL;
		/* The TIS spec says the TPM registers must be 0x5000 bytes */
		if (regsize == 0x5000)
			break;
	}
	if (idx == nregs) {
		ret = DDI_FAILURE;
		goto FAIL;
	}

	ret = ddi_regs_map_setup(tpm->dip, idx, (caddr_t *)&tpm->addr,
	    (offset_t)0, (offset_t)0x5000,
	    &tpm->accattr, &tpm->handle);

	if (ret != DDI_SUCCESS) {
		goto FAIL;
	}
	tpm->flags |= TPM_DIDREGSMAP;
#endif
	/* Enable TPM device according to the TIS specification */
	ret = tis_init(tpm);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_init() failed with error %d",
		    __func__, ret);
#endif

		/* We need to clean up the ddi_regs_map_setup call */
		if (tpm->flags & TPM_DIDREGSMAP) {
			ddi_regs_map_free(&tpm->handle);
			tpm->handle = NULL;
			tpm->flags &= ~TPM_DIDREGSMAP;
		}
		goto FAIL;
	}

	/* Initialize the inter-process lock */
	mutex_init(&tpm->dev_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&tpm->pm_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tpm->suspend_cv, NULL, CV_DRIVER, NULL);

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

	mutex_enter(&tpm->pm_mutex);
	tpm->suspended = 0;
	mutex_exit(&tpm->pm_mutex);

	tpm->flags |= TPM_DID_MUTEX;

	/* Initialize the buffer and the lock associated with it */
	tpm->bufsize = TPM_IO_BUF_SIZE;
	tpm->iobuf = kmem_zalloc((sizeof (uint8_t))*(tpm->bufsize), KM_SLEEP);
	tpm->flags |= TPM_DID_IO_ALLOC;

	mutex_init(&tpm->iobuf_lock, NULL, MUTEX_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_MUTEX;

	cv_init(&tpm->iobuf_cv, NULL, CV_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_CV;

	/* Create minor node */
	ret = ddi_create_minor_node(dip, "tpm", S_IFCHR, ddi_get_instance(dip),
	    DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: ddi_create_minor_node failed", __func__);
#endif
		goto FAIL;
	}
	tpm->flags |= TPM_DIDMINOR;

#ifdef KCF_TPM_RNG_PROVIDER
	/* register RNG with kcf */
	if (tpmrng_register(tpm) != DDI_SUCCESS)
		cmn_err(CE_WARN, "!%s: tpm RNG failed to register with kcf",
		    __func__);
#endif

	return (DDI_SUCCESS);
FAIL:
	if (tpm != NULL) {
		tpm_cleanup(dip, tpm);
		ddi_soft_state_free(statep, instance);
		tpm = NULL;
	}

	return (DDI_FAILURE);
}

/*
 * Called by tpm_detach and tpm_attach (only on failure)
 * Free up the resources that are allocated
 */
static void
tpm_cleanup(dev_info_t *dip, tpm_t *tpm)
{
	if (tpm == NULL)
		return;

#ifdef KCF_TPM_RNG_PROVIDER
	(void) tpmrng_unregister(tpm);
#endif

#ifdef sun4v
	if (tpm->flags & TPM_HSVC_REGISTERED) {
		(void) hsvc_unregister(&hsvc_tpm);
		tpm->flags &= ~(TPM_HSVC_REGISTERED);
	}
#endif
	if (tpm->flags & TPM_DID_MUTEX) {
		mutex_destroy(&tpm->dev_lock);
		mutex_destroy(&tpm->pm_mutex);
		cv_destroy(&tpm->suspend_cv);
		tpm->flags &= ~(TPM_DID_MUTEX);
	}
	if (tpm->flags & TPM_DID_IO_ALLOC) {
		ASSERT(tpm->iobuf != NULL);
		kmem_free(tpm->iobuf, (sizeof (uint8_t))*(tpm->bufsize));
		tpm->flags &= ~(TPM_DID_IO_ALLOC);
	}
	if (tpm->flags & TPM_DID_IO_MUTEX) {
		mutex_destroy(&tpm->iobuf_lock);
		tpm->flags &= ~(TPM_DID_IO_MUTEX);
	}
	if (tpm->flags & TPM_DID_IO_CV) {
		cv_destroy(&tpm->iobuf_cv);
		tpm->flags &= ~(TPM_DID_IO_CV);
	}
	if (tpm->flags & TPM_DIDREGSMAP) {
		/* Free the mapped addresses */
		if (tpm->handle != NULL)
			ddi_regs_map_free(&tpm->handle);
		tpm->flags &= ~(TPM_DIDREGSMAP);
	}
	if (tpm->flags & TPM_DIDMINOR) {
		/* Remove minor node */
		ddi_remove_minor_node(dip, NULL);
		tpm->flags &= ~(TPM_DIDMINOR);
	}
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
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}

	switch (cmd) {
	case DDI_DETACH:
		/* Body is after the switch stmt */
		break;
	case DDI_SUSPEND:
		return (tpm_suspend(tpm));
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: case %d not implemented", __func__, cmd);
#endif
		return (DDI_FAILURE);
	}

	/* Since we are freeing tpm structure, we need to gain the lock */
	tpm_cleanup(dip, tpm);

	/* Free the soft state */
	ddi_soft_state_free(statep, instance);
	tpm = NULL;

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

	ret = ddi_soft_state_init(&statep, sizeof (tpm_t), 1);
	if (ret) {
		cmn_err(CE_WARN, "!%s: ddi_soft_state_init failed: %d",
		    __func__, ret);
		return (ret);
	}
	ret = mod_install(&tpm_ml);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: mod_install returned %d",
		    __func__, ret);
		ddi_soft_state_fini(&statep);
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

	ddi_soft_state_fini(&statep);

	return (ret);
}
