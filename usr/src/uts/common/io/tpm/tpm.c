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
#include <sys/id_space.h>
#include <sys/stddef.h>
#include <sys/proc.h>
#include <sys/atomic.h>

#include <sys/byteorder.h>	/* for ntohs, ntohl, htons, htonl */
#include <sys/sysmacros.h>
#include <sys/sdt.h>

#include <sys/tpm.h>

#ifdef sun4v
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#endif

#include <tss/platform.h>	/* from SUNWtss */
#include <tss/tpm.h>		/* from SUNWtss */

#include "tpm_tis.h"
#include "tpm_ddi.h"

extern pri_t minclsyspri;

typedef bool (*tpm_attach_fn_t)(tpm_t *);
typedef void (*tpm_cleanup_fn_t)(tpm_t *);

typedef struct tpm_attach_desc {
	tpm_attach_seq_t	tad_seq;
	const char		*tad_name;
	tpm_attach_fn_t		tad_attach;
	tpm_cleanup_fn_t	tad_cleanup;
} tpm_attach_desc_t;

/* We assume a system will only have a single TPM device. */
#define	TPM_CTL_MINOR		0

#define	TPM_INTF_IFTYPE(x)	((x) & 0xf)
#define	TPM_INTF_IFTYPE_FIFO	(0x0)
#define	TPM_INTF_IFTYPE_CRB	(0x1)
#define	TPM_INTF_IFTYPE_TIS	(0xf)

/*
 * Explicitly not static as it is a tunable. Set to true to enable
 * debug messages.
 */
bool				tpm_debug = false;

static id_space_t		*tpm_minors;
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
	ASSERT(MUTEX_HELD(&c->tpmc_lock));

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
	ASSERT(MUTEX_HELD(&c->tpmc_lock));

	return ((c->tpmc_state == TPM_CLIENT_CMD_COMPLETION) ? true : false);
}

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

static tpm_client_t *
tpm_client_get(dev_t dev)
{
	tpm_client_t *c;

	c = ddi_get_soft_state(tpm_statep, getminor(dev));
	if (c == NULL) {
		return (NULL);
	}

	mutex_enter(&c->tpmc_lock);
	if (c->tpmc_closing) {
		mutex_exit(&c->tpmc_lock);
		return (NULL);
	}

	c->tpmc_refcnt++;
	return (c);
}

void
tpm_client_refhold(tpm_client_t *c)
{
	atomic_inc_uint(&c->tpmc_refcnt);
}

void
tpm_client_refrele(tpm_client_t *c)
{
	atomic_dec_uint(&c->tpmc_refcnt);	
}

void
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
	tpm_t *tpm = c->tpmc_tpm;

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
		break;
	case TPM_CLIENT_CMD_RECEPTION:
	case TPM_CLIENT_CMD_COMPLETION:
		tpm_client_reset(c);
		break;
	case TPM_CLIENT_CMD_EXECUTION:
		/*
		 * The interface specific cancellation method will
		 * reset the client state after it has completed cancelling
		 * the current command.
		 */
		switch (tpm->tpm_iftype) {
		case TPM_IF_TIS:
		case TPM_IF_FIFO:
			(void) tpm_tis_cancel_cmd(c);
			break;
		case TPM_IF_CRB:
			(void) crb_cancel_cmd(c);
			break;
		}
		break;
	case TPM_CLIENT_CMD_DISPATCH:
		if (list_link_active(&c->tpmc_node)) {
			/*
			 * If we're still on the pending list, the tpm thread
			 * has not started processing our request. We can
			 * merely remove ourself from the list and reset.
			 */
			mutex_enter(&tpm->tpm_lock);
			list_remove(&tpm->tpm_pending, c);
			mutex_exit(&tpm->tpm_lock);

			tpm_client_refrele(c);
		} else {
			/*
			 * The tpm thread has pulled us off the list, but
			 * since we were able to acquire tpmc_lock, it has
			 * not been able to transition to
			 * TPM_CLIENT_CMD_EXECUTION (because we always grab
			 * the client lock, then the tpm lock, there is a
			 * small window in the tpm thread where it's removed
			 * the next client from the list, but has not yet
			 * acquired the client lock to update the status
			 * ). Tell the tpm thread to just cancel instead
			 * of executing the command.
			 *
			 * The tpm svc thread will release it's refhold.
			 * This way a non-blocking client can cancel and
			 * have it processed in the background.
			 */
			c->tpmc_cancelled = true;

			while (c->tpmc_cancelled) {
				cv_wait(&c->tpmc_cv, &c->tpmc_lock);
			}
		}
		tpm_client_reset(c);
		break;
	default:
		cmn_err(CE_PANIC, "unexpected tpm connection state 0x%x",
		    c->tpmc_state);
	}
}

static int
tpm_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	tpm_t *tpm;
	tpm_client_t *c;
	int minor;

	if (otype != OTYP_CHR) {
		return (SET_ERROR(EINVAL));
	}

	if (drv_priv(credp) != 0) {
		return (SET_ERROR(EPERM));
	}

	if (getminor(*devp) != TPM_CTL_MINOR) {
		return (SET_ERROR(ENXIO));
	}

	/* Opening the TPM O_WRONLY makes no sense */
	if ((flag & FREAD) != FREAD) {
		/* XXX: Better value? */
		return (SET_ERROR(EINVAL));
	}

	tpm = ddi_get_soft_state(tpm_statep, TPM_CTL_MINOR);

	mutex_enter(&tpm->tpm_lock);

	IMPLY(tpm->tpm_exclusive, tpm->tpm_client_count == 1);
	if (tpm->tpm_client_count == tpm->tpm_client_max ||
	    tpm->tpm_exclusive ||
	    tpm->tpm_client_count > 0 && ((flag & FEXCL) == FEXCL)) {
		mutex_exit(&tpm->tpm_lock);
		return (SET_ERROR(EBUSY));
	}
	tpm->tpm_client_count++;
	if ((flag & FEXCL) == FEXCL) {
		tpm->tpm_exclusive = true;
	}
	mutex_exit(&tpm->tpm_lock);

	minor = id_alloc_nosleep(tpm_minors);
	if (minor == -1) {
		return (SET_ERROR(EBUSY));
	}

	if (ddi_soft_state_zalloc(tpm_statep, minor) != DDI_SUCCESS) {
		id_free(tpm_minors, minor);
		return (SET_ERROR(ENOMEM));
	}
	c = ddi_get_soft_state(tpm_statep, minor);

	void *pri = tpm->tpm_use_interrupts ?
	    DDI_INTR_PRI(tpm->tpm_intr_pri) : NULL;

	mutex_init(&c->tpmc_lock, NULL, MUTEX_DRIVER, pri);
	cv_init(&c->tpmc_cv, NULL, CV_DRIVER, pri);

	c->tpmc_tpm = tpm;
	c->tpmc_minor = minor;
	c->tpmc_state = TPM_CLIENT_IDLE;
	c->tpmc_buf = kmem_zalloc(TPM_IO_BUF_SIZE, KM_SLEEP);
	c->tpmc_buflen = TPM_IO_BUF_SIZE;
	c->tpmc_locality = DEFAULT_LOCALITY;

	if ((flag & FWRITE) == FWRITE) {
		c->tpmc_mode |= TPM_MODE_WRITE;
	}
	if ((flag & FNDELAY) == FNDELAY) {
		c->tpmc_mode |= TPM_MODE_NONBLOCK;
	}

	*devp = makedevice(getmajor(*devp), minor);
	return (0);
}

void
tpm_client_cleanup(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;

	mutex_enter(&tpm->tpm_lock);
	VERIFY3U(tpm->tpm_client_count, >, 0);
	IMPLY(tpm->tpm_exclusive, tpm->tpm_client_count == 1);
	tpm->tpm_client_count--;
	tpm->tpm_exclusive = false;
	mutex_exit(&tpm->tpm_lock);

	bzero(c->tpmc_buf, c->tpmc_buflen);
	kmem_free(c->tpmc_buf, c->tpmc_buflen);

	cv_destroy(&c->tpmc_cv);
	mutex_exit(&c->tpmc_lock);
	mutex_destroy(&c->tpmc_lock);

	ddi_soft_state_free(tpm_statep, c->tpmc_minor);
	id_free(tpm_minors, c->tpmc_minor);
}

static int
tpm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	tpm_client_t *c;

	if (otyp != OTYP_CHR) {
		return (SET_ERROR(EINVAL));
	}

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	c->tpmc_closing = true;

	tpm_cancel(c);

	/*
	 * After cancelling, we have to wait for the client to become idle
	 * to ensure the tpm thread is not using the client.
	 */
	while (c->tpmc_state != TPM_CLIENT_IDLE) {
		int ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);

		if (ret <= 0) {
			mutex_exit(&c->tpmc_lock);
			return (SET_ERROR(EAGAIN));
		}
	}

	tpm_client_cleanup(c);
	return (0);
}

static size_t
tpm_uio_size(const struct uio *uiop)
{
	size_t amt = 0;

	for (uint_t i = 0; i < uiop->uio_iovcnt; i++) {
		amt += uiop->uio_iov[i].iov_len;
	}

	return (amt);
}

static void
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

static int
tpm_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm_client_t *c;

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	size_t amt_copied = 0;
	size_t amt_avail = tpm_uio_size(uiop);
	size_t amt_needed = 0;
	size_t to_copy = 0;
	int ret = 0;

	if ((c->tpmc_mode & TPM_MODE_WRITE) != 0) {
		/* XXX better return value? */
		ret = SET_ERROR(EIO);
		goto done;
	}

	if (!tpmc_is_writemode(c)) {
		if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
			ret = SET_ERROR(EAGAIN);
			goto done;
		}

		/*
		 * If we weren't in a writing mode when write(2) was called,
		 * we want to explicitly wait for the TPM_CLIENT_IDLE state
		 * since presumably that means we have a new command (and
		 * not a fragment of an in-process command).
		 */
		while (c->tpmc_state != TPM_CLIENT_IDLE) {
			ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
			if (ret == 0) {
				ret = SET_ERROR(EINTR);
				goto done;
			}
		}
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
		amt_copied += to_copy;
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
	amt_needed = tpm_cmdlen(c->tpmc_buf);

	if (amt_needed > c->tpmc_buflen) {
		/*
		 * Request is too large.
		 * XXX: Better error value? tpmc_buflen should be sized to
		 * hold any valid command, so if we were passed an oversized
		 * request, it's obviously invalid.
		 */
		ret = SET_ERROR(EIO);
		goto done;
	} else if (amt_needed < TPM_HEADER_SIZE) {
		/*
		 * Request is too small.
		 * XXX: Better error value?
		 */
		ret = SET_ERROR(EIO);
		goto done;
	}

	/*
	 * The length parameter is the total length of the command, including
	 * the fixed sized header. Reduce the amount needed by the amount
	 * read in so far.
	 */
	amt_needed -= c->tpmc_bufused;

	to_copy = MIN(amt_needed, amt_avail);
	ret = uiomove(c->tpmc_buf + c->tpmc_bufused, to_copy, UIO_WRITE, uiop);
	if (ret != 0) {
		goto done;
	}
	c->tpmc_bufused += to_copy;
	amt_copied += to_copy;

	if (to_copy < amt_needed) {
		goto done;
	}

	tpm_dispatch_cmd(c);

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
	tpm_client_refrele(c);
	return (ret);

abort:
	tpm_client_reset(c);
	mutex_exit(&c->tpmc_lock);
	tpm_client_refrele(c);
	return (ret);
}

static int
tpm_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm_client_t *c;
	int ret = 0;

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	switch (c->tpmc_state) {
	case TPM_CLIENT_IDLE:
	case TPM_CLIENT_CMD_RECEPTION:
	case TPM_CLIENT_CMD_DISPATCH:
	case TPM_CLIENT_CMD_EXECUTION:
		if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
			mutex_exit(&c->tpmc_lock);
			tpm_client_refrele(c);
			return (SET_ERROR(EAGAIN));
		}

		while (c->tpmc_state != TPM_CLIENT_CMD_COMPLETION) {
			ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
			if (ret == 0) {
				mutex_exit(&c->tpmc_lock);
				tpm_client_refrele(c);
				return (SET_ERROR(EINTR));
			}
		}
		break;
	case TPM_CLIENT_CMD_COMPLETION:
		break;
	}

	if (c->tpmc_cmdresult != 0) {
		int ret = c->tpmc_cmdresult;

		tpm_client_reset(c);
		mutex_exit(&c->tpmc_lock);
		tpm_client_refrele(c);
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
	tpm_client_refrele(c);
	return (ret);
}

static int
tpm_ioctl(dev_t dev, int cmd, intptr_t data, int md, cred_t *cr, int *rv)
{
	tpm_client_t *c;
	int ret = 0;
	int val;

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

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
			dev_err(c->tpmc_tpm->tpm_dip, CE_PANIC,
			    "invalid TPM version");
		}

		if (ddi_copyout(&val, (void *)data, sizeof (val), md) != 0) {
			ret = SET_ERROR(EFAULT);
		}
		break;
	case TPMIOC_SETLOCALITY:
		if ((c->tpmc_mode & TPM_MODE_WRITE) != 0) {
			/* XXX: better value? didn't open for write */
			ret = SET_ERROR(ENXIO);
			break;
		}

		if (ddi_copyin((void *)data, &val, sizeof (val), md) != 0) {
			ret = SET_ERROR(EFAULT);
			break;
		}

		if (val < 0 || val > TPM_LOCALITY_MAX) {
			ret = SET_ERROR(EINVAL);
			break;
		}

		/*
		 * XXX: For now we only allow access to locality 0.
		 */
		if (val != 0) {
			ret = SET_ERROR(EPERM);
			break;
		}

		/* Only change locality while the client is idle. */
		if (c->tpmc_state != TPM_CLIENT_IDLE) {
			if ((c->tpmc_mode & TPM_MODE_NONBLOCK) != 0) {
				ret = SET_ERROR(EAGAIN);
				goto done;
			}
			while (c->tpmc_state != TPM_CLIENT_IDLE) {
				ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);
				if (ret == 0) {
					ret = SET_ERROR(EINTR);
					goto done;
				}
			}
		}
		c->tpmc_locality = val;
		break;
	case TPMIOC_CANCEL:
		tpm_cancel(c);
		break;
	case TPMIOC_MAKESTICKY:
		/* XXX: TODO */
		ret = SET_ERROR(ENOTSUP);
		break;
	default:
		ret = SET_ERROR(ENOTTY);
	}

done:
	mutex_exit(&c->tpmc_lock);
	tpm_client_refrele(c);
	return (ret);
}

static int
tpm_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	tpm_client_t *c;

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	*reventsp = 0;

	if (tpmc_is_writemode(c)) {
		*reventsp |= POLLOUT;
	}
	if (tpmc_is_readmode(c)) {
		*reventsp |= POLLIN;
	}
	*reventsp &= events;

	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &c->tpmc_pollhead;
	}
	mutex_exit(&c->tpmc_lock);

	tpm_client_refrele(c);
	return (0);
}

int
tpm_exec_internal(tpm_t *tpm, uint8_t loc, uint8_t *buf, size_t buflen)
{
	int ret = 0;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3U(buflen, >=, TPM_HEADER_SIZE);

	switch (tpm->tpm_iftype) {
	case TPM_IF_TIS:
	case TPM_IF_FIFO:
		ret = tis_exec_cmd(tpm, loc, buf, buflen);
		break;
	case TPM_IF_CRB:
		ret = crb_exec_cmd(tpm, loc, buf, buflen);
		break;
	default:
		dev_err(tpm->tpm_dip, CE_PANIC, "%s: invalid iftype %d",
		    __func__, tpm->tpm_iftype);
	}

	return (ret);
}

static int
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

	ret = tpm_exec_internal(tpm, c->tpmc_locality, c->tpmc_buf,
	    c->tpmc_buflen);
	if (ret == 0) {
		c->tpmc_bufread = 0;
	}

	mutex_enter(&c->tpmc_lock);
	c->tpmc_state = TPM_CLIENT_CMD_COMPLETION;

	/* Return with tpmc_lock held */
	return (ret);
}

static void
tpm_exec_thread(void *arg)
{
	tpm_t *tpm = arg;

	for (;;) {
		int ret = 0;

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

		mutex_enter(&c->tpmc_lock);
		/*
		 * This is somewhat subtle. We remove the client from the
		 * list, but there is a small window of opportunity between
		 * releasing the tpm lock and acquiring the client lock
		 * where a client could cancel. In this scenario, the
		 * cancelling client will set tpmc_cancelled prior to
		 * releasing the client lock, and wait for us to acknowledge
		 * the cancellation by signaling tpmc_cv.
		 */
		if (c->tpmc_cancelled) {
			c->tpmc_cancelled = false;
			cv_signal(&c->tpmc_cv);
			mutex_exit(&c->tpmc_lock);

			continue;
		}

		ret = tpm_exec_client(c);

		/* tpm_exec_cmd() should return with tpmc_lock held */
		VERIFY(MUTEX_HELD(&c->tpmc_lock));

		c->tpmc_cmdresult = ret;
		cv_signal(&c->tpmc_cv);
		pollwakeup(&c->tpmc_pollhead, POLLIN);
		mutex_exit(&c->tpmc_lock);

		tpm_client_refrele(c);
	}
}

static clock_t
tpm_get_waittime(tpm_t *tpm, tpm_wait_t wait_type, clock_t now,
    clock_t deadline)
{
	clock_t until;

	switch (wait_type) {
	case TPM_WAIT_POLLONCE:
	case TPM_WAIT_INTR:
		return (deadline);
	case TPM_WAIT_POLL:
		until = now + tpm->tpm_timeout_poll;
		return ((until < deadline) ? until : deadline);
	}

	cmn_err(CE_PANIC, "invalid wait_type %d", wait_type);

	/*NOTREACHED*/
	return (0);
}

/*
 * Wait for a register to return a (possibly masked) value.
 *
 * If intr is set, wait the full timeout value and expect an interrupt
 * will likely wake us sooner when the condition we're checking has been satisified.
 *
 * If intr is not set, check every tpm->tpm_timeout_poll cycles.
 *
 * If tpm->tpm_wait == TPM_WAIT_POLLONCE, always wait the full timeout value
 * regardless of the setting of wait_intr.
 */
static int
tpm_wait_common(tpm_t *tpm, unsigned long reg, uint32_t mask, uint32_t value,
    clock_t timeout, bool intr,
    uint32_t (*getf)(tpm_t *, unsigned long, uint32_t)) {
	clock_t deadline, now;
	uint32_t status;
	int ret = 1;
	tpm_wait_t wait;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));

	wait = intr ? tpm->tpm_wait : tpm_wait_nointr(tpm);
	deadline = ddi_get_lbolt() + timeout;
	while ((now = ddi_get_lbolt()) < deadline) {
		status = getf(tpm, reg, mask);
		if (mask == value)
			break;

		clock_t until = tpm_get_waittime(tpm, wait, now, deadline);
		ret = cv_timedwait(&tpm->tpm_intr_cv, &tpm->tpm_lock, until);
	}

	/* If we timed out, check the status one final time */
	if (ret <= 0) {
		status = getf(tpm, reg, mask);
		if (status != value) {
			goto timedout;
		}
	}

	return (0);

timedout:
	/* XXX: Generate ereport? */
	dev_err(tpm->tpm_dip, CE_WARN,
	    "%s: timeout (%ld usecs) waiting for reg 0x%lx & 0x%x == 0x%x\n",
	    __func__, drv_hztousec(timeout), reg, mask, value);
	return (ETIME);
}

static uint32_t
tpm_wait_u32f(tpm_t *tpm, unsigned long reg, uint32_t mask)
{
	return (tpm_get32(tpm, reg) & mask);
}

int
tpm_wait_u32(tpm_t *tpm, unsigned long reg, uint32_t mask, uint32_t val,
    clock_t timeout, bool intr)
{
	return (tpm_wait_common(tpm, reg, mask, val, timeout, intr,
	    tpm_wait_u32f));
}

static uint32_t
tpm_wait_u8f(tpm_t *tpm, unsigned long reg, uint32_t mask)
{
	uint32_t val = tpm_get8(tpm, reg) & 0xff;
	return (val & mask);
}

int
tpm_wait_u8(tpm_t *tpm, unsigned long reg, uint8_t mask, uint8_t val,
    clock_t timeout, bool intr)
{
	return (tpm_wait_common(tpm, reg, mask, val, timeout, intr,
	    tpm_wait_u8f));
}

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

		delay(tpm->tpm_timeout_poll);
	}

	return (0);
}

/*
 * Auxilary Functions
 */

static int
tpm_resume(tpm_t *tpm)
{
#if 0
	mutex_enter(&tpm->pm_mutex);
	if (!tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_FAILURE);
	}
	tpm->suspended = 0;
	cv_broadcast(&tpm->suspend_cv);
	mutex_exit(&tpm->pm_mutex);
#endif
	return (DDI_SUCCESS);
}

#ifdef __amd64
static bool
tpm_attach_regs(tpm_t *tpm)
{
	uint_t idx;
	int nregs;
	int ret;
	off_t regsize = 0;

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
	 * TPM 1.2 vendors put the TPM registers in different
	 * slots in their register lists.  They are not always
	 * the 1st set of registers, for instance.
	 * Loop until we find the set that matches the expected
	 * register size (0x5000).
	 *
	 * For TPM 2.0 devices, we'll always end up using the
	 * first register set.
	 */
	for (idx = 0; idx < nregs; idx++) {
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
tpm_attach_dev_init(tpm_t *tpm)
{
	uint32_t id;

	/*
	 * The lower 32 bits of the interface id register are identical
	 * between the FIFO and CRB interfaces to facilitate distinguishing
	 * between interface types.
	 */
	id = tpm_get32(tpm, TPM_INTERFACE_ID);

	switch (TPM_INTF_IFTYPE(id)) {
	case TPM_INTF_IFTYPE_TIS:
		tpm->tpm_iftype = TPM_IF_TIS;
		/*
		 * For TPMs using the TIS 1.3 interface, tpm_tis_init()
		 * will set tpm_family since both TPM1.2 and TPM2.0
		 * devices can use this interface.
		 */
		return (tpm_tis_init(tpm));
	case TPM_INTF_IFTYPE_FIFO:
		tpm->tpm_iftype = TPM_IF_FIFO;
		tpm->tpm_family = TPM_FAMILY_2_0;
		/*
		 * While the id value can be also be used to determine the
		 * VID/DID/RID of the TPM module for TPM2.0 devices using
		 * the FIFO interface, it can also be read from specific
		 * registers that will also work for TPM1.2 and TPM2.0
		 * modules using the TIS interface, so tpm_tis_init()
		 * will set the properties for both TIS and FIFO.
		 */
		return (tpm_tis_init(tpm));
	case TPM_INTF_IFTYPE_CRB:
		tpm->tpm_iftype = TPM_IF_CRB;
		tpm->tpm_family = TPM_FAMILY_2_0;
		return (crb_init(tpm));
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "tpm-deviceid", tpm->tpm_did);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "tpm-vendorid", tpm->tpm_vid);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "tpm-revision", tpm->tpm_rid);

	return (true);
}

static void
tpm_cleanup_dev_init(tpm_t *tpm)
{
	/* Nothing needed */
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

	if (ddi_intr_get_navail(tpm->tpm_dip, DDI_INTR_TYPE_FIXED,
	    &navail) != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "could not determine available interrupts");
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

	tpm->tpm_harray = kmem_zalloc(navail* sizeof (ddi_intr_handle_t),
	    KM_SLEEP);
	ret = ddi_intr_alloc(tpm->tpm_dip, tpm->tpm_harray,
	    DDI_INTR_TYPE_FIXED, 0, 1, &tpm->tpm_nintr, DDI_INTR_ALLOC_STRICT);
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

	for (uint_t i = 0; i < tpm->tpm_nintr; i++) {
		VERIFY3S(ddi_intr_free(tpm->tpm_harray[i]), ==, DDI_SUCCESS);
	}
	kmem_free(tpm->tpm_harray, tpm->tpm_nintr * sizeof (ddi_intr_handle_t));
}

static bool
tpm_attach_intr_hdlrs(tpm_t *tpm)
{
	ddi_intr_handler_t *isr = NULL;
	uint_t i;
	int ret;

	if (!tpm->tpm_use_interrupts) {
		return (true);
	}

	switch (tpm->tpm_iftype) {
	case TPM_IF_TIS:
	case TPM_IF_FIFO:
		isr = tpm_tis_intr;
		break;
	case TPM_IF_CRB:
		isr = crb_intr;
		break;
	}
	
	for (i = 0; i < tpm->tpm_nintr; i++) {
		ret = ddi_intr_add_handler(tpm->tpm_harray[i], isr, tpm, NULL);
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
	cv_init(&tpm->tpm_thr_cv, NULL, CV_DRIVER, pri);
	cv_init(&tpm->tpm_intr_cv, NULL, CV_DRIVER, pri);
	return (true);
}

static void
tpm_cleanup_sync(tpm_t *tpm)
{
	cv_destroy(&tpm->tpm_intr_cv);
	cv_destroy(&tpm->tpm_thr_cv);
	mutex_destroy(&tpm->tpm_lock);
}

static bool
tpm_attach_thread(tpm_t *tpm)
{
	list_create(&tpm->tpm_pending, sizeof (tpm_client_t),
	    offsetof(tpm_client_t, tpmc_node));
	tpm->tpm_thread = thread_create(NULL, 0, tpm_exec_thread, tpm, 0,
	    &p0, TS_RUN, minclsyspri);
	return (true);
}

static void
tpm_cleanup_thread(tpm_t *tpm)
{
	if (tpm->tpm_thread != NULL) {
		kt_did_t tid = tpm->tpm_thread->t_did;

		tpm->tpm_thr_quit = true;
		membar_producer();
		cv_signal(&tpm->tpm_thr_cv);
		thread_join(tid);
		tpm->tpm_thread = NULL;
	}
	list_destroy(&tpm->tpm_pending);
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
		dev_err(tpm->tpm_dip, CE_WARN,
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
#ifdef __amd64
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
#ifdef __amd64
	[TPM_ATTACH_DEV_INIT] = {
		.tad_seq = TPM_ATTACH_DEV_INIT,
		.tad_name = "device initialization",
		.tad_attach = tpm_attach_dev_init,
		.tad_cleanup = tpm_cleanup_dev_init,
	},
	[TPM_ATTACH_INTR_ALLOC] = {
		.tad_seq = TPM_ATTACH_INTR_ALLOC,
		.tad_name = "interrupt allocation",
		.tad_attach = tpm_attach_intr_alloc,
		.tad_cleanup = tpm_cleanup_intr_alloc,
	},
	[TPM_ATTACH_INTR_HDLRS] = {
		.tad_seq = TPM_ATTACH_INTR_HDLRS,
		.tad_name = "interrupt handlers",
		.tad_attach = tpm_attach_intr_hdlrs,
		.tad_cleanup = tpm_cleanup_intr_hdlrs,
	},
#endif
	[TPM_ATTACH_SYNC] = {
		.tad_seq = TPM_ATTACH_SYNC,
		.tad_name = "synchronization",
		.tad_attach = tpm_attach_sync,
		.tad_cleanup = tpm_cleanup_sync,
	},
	[TPM_ATTACH_THREAD] = {
		.tad_seq = TPM_ATTACH_THREAD,
		.tad_name = "service thread",
		.tad_attach = tpm_attach_thread,
		.tad_cleanup = tpm_cleanup_thread,
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
	if (tpm == NULL || tpm->tpm_seq == 0) {
		return;
	}

	VERIFY3U(tpm->tpm_seq, <, TPM_ATTACH_NUM_ENTRIES);

	while (tpm->tpm_seq > 0) {
		tpm_attach_seq_t seq = --tpm->tpm_seq;
		tpm_attach_desc_t *desc = &tpm_attach_tbl[seq];

		tpm_dbg(tpm, CE_CONT, "running cleanup sequence %s (%d)\n",
		    desc->tad_name, seq);

		desc->tad_cleanup(tpm);
	}

	ASSERT3U(tpm->tpm_seq, ==, 0);
}

static int
tpm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	tpm_t *tpm = NULL;
	int ret;
	int instance;
	int use_intr, wait;

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

	tpm->tpm_locality = DEFAULT_LOCALITY;

	/*
	 * We default to polling. Once everything has been initialized,
	 * we may then switch to using interrupts.
	 */
	tpm->tpm_wait = TPM_WAIT_POLL;

	use_intr = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "use-interrupts", 1);
	tpm->tpm_use_interrupts = (use_intr != 0) ? true : false;

	for (uint_t i = 0; i < ARRAY_SIZE(tpm_attach_tbl); i++) {
		tpm_attach_desc_t *desc = &tpm_attach_tbl[i];

		tpm_dbg(tpm, CE_CONT, "!running attach sequence %s (%d)\n",
		    desc->tad_name, desc->tad_seq);

		if (!desc->tad_attach(tpm)) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "attach sequence failed %s (%d)", desc->tad_name,
			    desc->tad_seq);
			tpm_cleanup(tpm);
			return (DDI_FAILURE);
		}

		tpm_dbg(tpm, CE_CONT, "!attach sequence completed: %s (%d)\n",
		    desc->tad_name, desc->tad_seq);
		tpm->tpm_seq = desc->tad_seq;
	}

	/* Set the suspend/resume property */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");

	switch (tpm->tpm_family) {
	case TPM_FAMILY_1_2:
		tpm->tpm_wait = TPM_WAIT_POLL;
		break;
	case TPM_FAMILY_2_0:
		tpm->tpm_wait = TPM_WAIT_INTR;
		break;
	}

	wait = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "wait",
	    1);
	switch (wait) {
	case 0:
		tpm->tpm_wait = TPM_WAIT_POLL;
		break;
	case 1:
		if (!tpm->tpm_use_interrupts) {
			dev_err(tpm->tpm_dip, CE_NOTE,
			    "interrupts disabled. TPM will poll");
			tpm->tpm_wait = TPM_WAIT_POLL;
			break;
		}
		tpm->tpm_wait = TPM_WAIT_INTR;
		break;
	case 2:
		tpm->tpm_wait = TPM_WAIT_POLLONCE;
		break;
	default:
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "invalid value of 'wait' property '%d'", wait);
	}

	if (tpm->tpm_use_interrupts) {
		switch (tpm->tpm_iftype) {
		case TPM_IF_TIS:
		case TPM_IF_FIFO:
			tpm_tis_intr_mgmt(tpm, true);
			break;
		case TPM_IF_CRB:
			crb_intr_mgmt(tpm, true);
			break;
		}
	}

	return (DDI_SUCCESS);
}

static int
tpm_suspend(tpm_t *tpm)
{
	if (tpm == NULL)
		return (DDI_FAILURE);

#if 0
	mutex_enter(&tpm->pm_mutex);
	if (tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_SUCCESS);
	}
	tpm->suspended = 1;
	mutex_exit(&tpm->pm_mutex);
#endif

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

	if ((tpm = ddi_get_soft_state(tpm_statep, instance)) == NULL) {
		dev_err(dip, CE_WARN, 
		    "failed to retreive instance %d soft state", instance);
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

static int
tpm_getinfo(dev_info_t *dip __unused, ddi_info_cmd_t cmd, void *arg __unused,
    void **resultp)
{
	tpm_t *tpm;

	/* We only support a single TPM instance */
	if ((tpm = ddi_get_soft_state(tpm_statep, 0)) == NULL) {
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = tpm->tpm_dip;
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

clock_t
tpm_get_ordinal_duration(tpm_t *tpm, uint8_t ordinal)
{
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

#elif defined(__amd64)

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
	.cb_prop_op =		ddi_prop_op,
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
