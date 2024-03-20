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
 * Copyright 2024 RackTop Systems, Inc.
 */

#include <sys/devops.h>		/* used by dev_ops */
#include <sys/conf.h>		/* used by dev_ops,cb_ops */
#include <sys/modctl.h>		/* for _init,_info,_fini,mod_* */
#include <sys/ddi.h>		/* used by all entry points */
#include <sys/sunddi.h>		/* used by all entry points */
#include <sys/sunndi.h>		/* used to set HW properties */
#include <sys/ddifm.h>		/* fault management */
#include <sys/fm/io/ddi.h>
#include <sys/fm/protocol.h>
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

#include <sys/acpica.h>

#include <sys/tpm.h>

#include "tpm_tis.h"
#include "tpm_ddi.h"
#include "tpm_tab.h"

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
#define	TPM_INSTANCE(_dev)	TPM_CTL_MINOR
#define	TPM_CLIENT(_dev)	(getminor(_dev))

#define	TPM_INTF_IFTYPE(x)	((x) & 0xf)
#define	TPM_INTF_IFTYPE_FIFO	0x0
#define	TPM_INTF_IFTYPE_CRB	0x1
#define	TPM_INTF_IFTYPE_TIS	0xf
#define	TPM_INTF_CAP_LOC5	0x10

/*
 * Explicitly not static as it is a tunable. Set to true to enable
 * debug messages.
 */
#ifdef DEBUG
bool				tpm_debug = true;
#else
bool				tpm_debug = false;
#endif

static kmutex_t			tpm_clients_lock;
static refhash_t		*tpm_clients;
static id_space_t		*tpm_minors;
static void			*tpm_statep = NULL;

static ddi_device_acc_attr_t	tpm_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC,
};

static inline void
tpm_enter(tpm_t *tpm)
{
	mutex_enter(&tpm->tpm_suspend_lock);
	while (tpm->tpm_suspended) {
		cv_wait(&tpm->tpm_suspend_cv, &tpm->tpm_suspend_lock);
	}
	mutex_exit(&tpm->tpm_suspend_lock);
}

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

static tpm_client_t *
tpm_client_get(dev_t dev)
{
	tpm_client_t *c;
	int minor;

	minor = TPM_CLIENT(dev);

	mutex_enter(&tpm_clients_lock);
	c = refhash_lookup(tpm_clients, &minor);
	if (c != NULL) {
		refhash_hold(tpm_clients, c);
	}
	mutex_exit(&tpm_clients_lock);

	return (c);
}

void
tpm_client_refhold(tpm_client_t *c)
{
	mutex_enter(&tpm_clients_lock);
	refhash_hold(tpm_clients, c);
	mutex_exit(&tpm_clients_lock);
}

void
tpm_client_refrele(tpm_client_t *c)
{
	mutex_enter(&tpm_clients_lock);
	refhash_rele(tpm_clients, c);
	mutex_exit(&tpm_clients_lock);
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

static int
tpm_create_client(tpm_t *tpm, int flag, int minor, tpm_client_t **clientp)
{
	tpm_client_t *c;
	uint8_t *buf;
	void *pri;
	tpm_mode_t mode = TPM_MODE_RDONLY;
	int kmflag;
	bool is_kernel;

	IMPLY(minor == -1, clientp == &tpm->tpm_internal_client);

	if ((flag & FREAD) != FREAD) {
		/* O_WRONLY doesn't make sense for the device */
		return (SET_ERROR(EINVAL));
	}

	/* We allow O_RDONLY for things like obtaining TPM version */
	if ((flag & FWRITE) == FWRITE) {
		mode = TPM_MODE_WRITE;
	} else {
		mode = TPM_MODE_RDONLY;
	}

	if ((flag & FNDELAY) == FNDELAY) {
		kmflag = KM_NOSLEEP;
		mode |= TPM_MODE_NONBLOCK;
		if (minor == -1) {
			/* XXX: A better return value? */
			return (SET_ERROR(ENOSPC));
		}
	} else {
		kmflag = KM_SLEEP;
	}

	if ((flag & FEXCL) == FEXCL) {
		/* It doesn't make sense to support exclusive access */
		return (SET_ERROR(EINVAL));
	}

	if ((flag & FKLYR) == FKLYR) {
		is_kernel = true;
	} else {
		is_kernel = false;
	}

	pri = tpm->tpm_use_interrupts ? DDI_INTR_PRI(tpm->tpm_intr_pri) : NULL;

	c = kmem_zalloc(sizeof (*c), kmflag);
	if (c == NULL) {
		return (SET_ERROR(ENOMEM));
	}

	buf = kmem_zalloc(TPM_IO_BUF_SIZE, kmflag);
	if (buf == NULL) {
		kmem_free(c, sizeof (*c));
		return (SET_ERROR(ENOMEM));
	}

	c->tpmc_tpm = tpm;
	c->tpmc_minor = minor;
	c->tpmc_mode = mode;
	c->tpmc_iskernel = is_kernel;
	c->tpmc_state = TPM_CLIENT_IDLE;
	c->tpmc_buf = buf;
	c->tpmc_buflen = TPM_IO_BUF_SIZE;
	c->tpmc_locality = DEFAULT_LOCALITY;

	mutex_init(&c->tpmc_lock, NULL, MUTEX_DRIVER, pri);
	cv_init(&c->tpmc_cv, NULL, CV_DRIVER, pri);

	/*
	 * We cannot initialize the internal client's TAB instance until we
	 * query the TPM for the necessary parameters, but we would like
	 * to use the internal client to use during the initial setup.
	 */
	if (tpm->tpm_family == TPM_FAMILY_2_0 &&
	    clientp != &tpm->tpm_internal_client) {
		int ret;

		ret = tpm_tab_init(c);
		if (ret != 0) {
			mutex_destroy(&c->tpmc_lock);
			cv_destroy(&c->tpmc_cv);
			kmem_free(c, sizeof (*c));
			return (ret);
		}
	}

	*clientp = c;
	return (0);
}

static int
tpm_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	tpm_t *tpm;
	tpm_client_t *c;
	int minor;
	int ret;

	if (otype != OTYP_CHR) {
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Only allow root access for now. The features of a TPM2.0 device
	 * may in the future prompt us to relax this, but for now we will
	 * be conservative in who has access.
	 */
	if (drv_priv(credp) != 0) {
		return (SET_ERROR(EPERM));
	}

	if (getminor(*devp) != TPM_CTL_MINOR) {
		return (SET_ERROR(ENXIO));
	}

	tpm = ddi_get_soft_state(tpm_statep, TPM_INSTANCE(dev));

	tpm_enter(tpm);

	mutex_enter(&tpm->tpm_lock);

	if (tpm->tpm_client_count == tpm->tpm_client_max) {
		mutex_exit(&tpm->tpm_lock);
		return (SET_ERROR(EBUSY));
	}

	if ((flag & FNDELAY) == FNDELAY) {
		minor = id_alloc_nosleep(tpm_minors);
		if (minor == -1) {
			/* XXX: Better error value? */
			return (SET_ERROR(ENOSPC));
		}
	} else {
		minor = id_alloc(tpm_minors);
	}

	ret = tpm_create_client(tpm, flag, minor, &c);
	if (ret != 0) {
		id_free(tpm_minors, minor);
		mutex_exit(&tpm->tpm_lock);
		return (ret);
	}

	tpm->tpm_client_count++;
	mutex_exit(&tpm->tpm_lock);

	mutex_enter(&tpm_clients_lock);
	refhash_insert(tpm_clients, c);
	mutex_exit(&tpm_clients_lock);

	*devp = makedevice(getmajor(*devp), minor);
	return (0);
}

static void
tpm_client_dtor(void *arg)
{
	tpm_client_t *c = arg;
	tpm_t *tpm = c->tpmc_tpm;

	mutex_enter(&tpm->tpm_lock);
	if (c != tpm->tpm_internal_client) {
		VERIFY3U(tpm->tpm_client_count, >, 0);
		tpm->tpm_client_count--;
	}
	mutex_exit(&tpm->tpm_lock);

	tpm_tab_fini(c);

	bzero(c->tpmc_buf, c->tpmc_buflen);
	kmem_free(c->tpmc_buf, c->tpmc_buflen);

	cv_destroy(&c->tpmc_cv);
	mutex_destroy(&c->tpmc_lock);

	if (c != tpm->tpm_internal_client) {
		id_free(tpm_minors, c->tpmc_minor);
	}

	bzero(c, sizeof (*c));
	kmem_free(c, sizeof (*c));
}

static int
tpm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	tpm_client_t *c;
	int ret;

	if (otyp != OTYP_CHR) {
		return (SET_ERROR(EINVAL));
	}

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	tpm_enter(c->tpmc_tpm);

	mutex_enter(&c->tpmc_lock);

	ret = tpm_cancel(c);
	if (ret != 0) {
		return (ret);
	}

	/*
	 * After cancelling, we have to wait for the client to become idle
	 * to ensure the tpm thread is not using the client.
	 */
	while (c->tpmc_state != TPM_CLIENT_IDLE) {
		ret = cv_wait_sig(&c->tpmc_cv, &c->tpmc_lock);

		if (ret <= 0) {
			mutex_exit(&c->tpmc_lock);
			return (SET_ERROR(EAGAIN));
		}
	}

	mutex_exit(&c->tpmc_lock);

	mutex_enter(&tpm_clients_lock);
	refhash_remove(tpm_clients, c);
	refhash_rele(tpm_clients, c);
	mutex_exit(&tpm_clients_lock);

	return (0);
}

size_t
tpm_uio_size(const uio_t *uiop)
{
	size_t amt = 0;

	for (uint_t i = 0; i < uiop->uio_iovcnt; i++) {
		amt += uiop->uio_iov[i].iov_len;
	}

	return (amt);
}

static int
tpm_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	tpm_client_t *c;

	c = tpm_client_get(dev);
	if (c == NULL) {
		return (SET_ERROR(ENXIO));
	}

	tpm_enter(c->tpmc_tpm);

	mutex_enter(&c->tpmc_lock);

	size_t amt_copied = 0;
	size_t amt_avail = tpm_uio_size(uiop);
	size_t amt_needed = 0;
	size_t to_copy = 0;
	int ret = 0;

	if ((c->tpmc_mode & TPM_MODE_WRITE) == 0) {
		ret = SET_ERROR(EBADF);
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
		 *
		 * XXX: Better error value? tpmc_buflen should be sized to
		 * hold any valid command, so if we were passed an oversized
		 * request, it's obviously invalid. Would EINVAL make more
		 * sense?
		 */
		ret = SET_ERROR(EIO);
		goto done;
	} else if (amt_needed < TPM_HEADER_SIZE) {
		/*
		 * Request is too small.
		 *
		 * XXX: Better error value? Similar argument as above.
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

	tpm_enter(c->tpmc_tpm);

	mutex_enter(&c->tpmc_lock);

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

	tpm_enter(c->tpmc_tpm);

	mutex_enter(&c->tpmc_lock);

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
		if ((c->tpmc_mode & TPM_MODE_WRITE) == 0) {
			/*
			 * Currently, changing the locality implies opening
			 * the device in RW mode.
			 */
			ret = SET_ERROR(EBADF);
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

		if (val > c->tpmc_tpm->tpm_n_locality) {
			ret = SET_ERROR(ENOTSUP);
			break;
		}

		/*
		 * For now we only allow access to locality 0.
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
		ret = tpm_cancel(c);
		break;
	case TPMIOC_MAKESTICKY:
		/* TODO */
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

	tpm_enter(c->tpmc_tpm);

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
		*phpp = &c->tpmc_pollhead;
	}
	mutex_exit(&c->tpmc_lock);

	tpm_client_refrele(c);
	return (0);
}

static int
tpm_quiesce(dev_info_t *dip __unused)
{
	return (DDI_SUCCESS);
}

int
tpm_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

void
tpm_ereport_timeout(tpm_t *tpm, uint16_t reg, clock_t to, const char *func)
{
	uint64_t ena = fm_ena_generate(0, FM_ENA_FMT1);
	uint64_t ms;

	ms = drv_hztousec(to) / 1000;

	ddi_fm_ereport_post(tpm->tpm_dip,
	    DDI_FM_DEVICE "." DDI_FM_DEVICE_NO_RESPONSE, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
	    "tpm_interface", DATA_TYPE_STRING, tpm_iftype_str(tpm->tpm_iftype),
	    "locality", DATA_TYPE_UINT8, tpm->tpm_locality,
	    "register", DATA_TYPE_UINT16, reg,
	    "timeout", DATA_TYPE_UINT64, ms,
	    "func", DATA_TYPE_STRING, func,
	    NULL);
}

void
tpm_ereport_short_read(tpm_t *tpm, uint32_t cmd, uint32_t offset,
    uint32_t expected, uint32_t actual)
{
	uint64_t ena = fm_ena_generate(0, FM_ENA_FMT1);

	ddi_fm_ereport_post(tpm->tpm_dip,
	    DDI_FM_DEVICE "." DDI_FM_DEVICE_INVAL_STATE, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
	    "tpm_interface", DATA_TYPE_STRING, tpm_iftype_str(tpm->tpm_iftype),
	    "locality", DATA_TYPE_UINT8, tpm->tpm_locality,
	    "command", DATA_TYPE_UINT32, cmd,
	    "offset", DATA_TYPE_UINT32, offset,
	    "expected", DATA_TYPE_UINT32, expected,
	    "actual", DATA_TYPE_UINT32, actual,
	    NULL);
}

static int
tpm_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *errp, const void *arg)
{
	/* TODO */
	return (errp->fme_status);
}

static bool
tpm_attach_fm(tpm_t *tpm)
{
	ddi_iblock_cookie_t iblk;

	tpm->tpm_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    tpm->tpm_dip, DDI_PROP_DONTPASS, "fm_capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_ERRCB_CAPABLE);

	if (tpm->tpm_fm_capabilities < 0) {
		tpm->tpm_fm_capabilities = 0;
		return (true);
	}

	if (tpm->tpm_fm_capabilities & DDI_FM_ACCCHK_CAPABLE) {
		tpm->tpm_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	ddi_fm_init(tpm->tpm_dip, &tpm->tpm_fm_capabilities, &iblk);

	if (DDI_FM_ERRCB_CAP(tpm->tpm_fm_capabilities)) {
		ddi_fm_handler_register(tpm->tpm_dip, tpm_fm_error_cb, tpm);
	}

	return (true);
}

static void
tpm_cleanup_fm(tpm_t *tpm)
{
	if (tpm->tpm_fm_capabilities == 0) {
		return;
	}

	if (DDI_FM_ERRCB_CAP(tpm->tpm_fm_capabilities)) {
		ddi_fm_handler_unregister(tpm->tpm_dip);
	}

	ddi_fm_fini(tpm->tpm_dip);		
}

/*
 * TPM2.0 devices should have a TPM2 table. If we find one, we assume
 * the first register set is the one we should use.
 *
 * TODO: For eventual ARM support, we'll likely need to abstract the
 * 'start' (execute a command) method based on the contents of the
 * ACPI TPM2 table. For x86 (TIS, FIFO, or CRB) a command is always
 * started by writing to a register. For ARM, it may be a HVC or SMC.
 */
static int
tpm_attach_20(tpm_t *tpm)
{
	ACPI_TABLE_TPM2 *tpm_tbl;
	ACPI_STATUS	status;
	int		nregs;
	int		ret;
	off_t		regsize;
	uint32_t	intf;

	status = AcpiGetTable(ACPI_SIG_TPM2, 1, (ACPI_TABLE_HEADER **)&tpm_tbl);
	if (ACPI_FAILURE(status)) {
		tpm_dbg(tpm, CE_CONT, "%s: no TPM2 ACPI table\n", __func__);
		return (SET_ERROR(ENXIO));
	}

	tpm_dbg(tpm, CE_CONT, "%s: found TPM2 at 0x%llx via ACPI TPM2 table\n",
	    __func__, tpm_tbl->ControlAddress);

	switch (tpm_tbl->StartMethod) {
	case ACPI_TPM2_MEMORY_MAPPED:
	case ACPI_TPM2_COMMAND_BUFFER:
		break;
	default:
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "unsupported TPM2 start method %u", tpm_tbl->StartMethod);
		return (SET_ERROR(ENOTSUP));
	}

	ret = ddi_dev_nregs(tpm->tpm_dip, &nregs);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "found TPM2 device with no register sets, device cannot be "
		    "used");
		return (SET_ERROR(EIO));
	}

	/*
	 * A TPM2.0 device should only have 1 register set. If
	 * for some reason we've encountered one with more than
	 * one, we probably want to note it in case there's
	 * other issues using the device.
	 */
	if (nregs != 1) {
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "device has %d register sets; expecting 1", nregs);
	}
	ret = ddi_dev_regsize(tpm->tpm_dip, 0, &regsize);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN, "%s: ddi_dev_regsize failed: %d",
		    __func__, ret);
		return (SET_ERROR(EIO));
	}

	/*
	 * We expect that a TPM2.0 module will have either 1 or 5
	 * localities. Each locality requires 0x1000 space, make sure the
	 * register set is large enough for further probing.
	 */
	if (regsize < 0x1000) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "%s: register set size is too small (0x%lx)", __func__,
		    regsize);
		return (SET_ERROR(EINVAL));
	}

	ret = ddi_regs_map_setup(tpm->tpm_dip, 0, (caddr_t *)&tpm->tpm_addr,
	    0, regsize, &tpm->tpm_acc_attr, &tpm->tpm_handle);
	if (ret != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "failed to map tpm registers: %d", ret);
		return (SET_ERROR(EIO));
	}

	intf = tpm_get32(tpm, TPM_INTERFACE_ID);
	switch (TPM_INTF_IFTYPE(intf)) {
	case TPM_INTF_IFTYPE_TIS:
		if (regsize != 0x5000) {
			dev_err(tpm->tpm_dip, CE_WARN,
			    "register set size (0x%lx) is incorrect for TPM TIS"
			    "interface", regsize);
			ddi_regs_map_free(&tpm->tpm_handle);
			return (SET_ERROR(EINVAL));
		}
		tpm->tpm_n_locality = 5;
		return (0);
	case TPM_INTF_IFTYPE_FIFO:
	case TPM_INTF_IFTYPE_CRB:
		break;
	default:
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "unrecognized interface type 0x%x", TPM_INTF_IFTYPE(intf));
		ddi_regs_map_free(&tpm->tpm_handle);
		return (SET_ERROR(ENOTSUP));
	}

	/*
	 * Since we know from the earlier check that the register set size
	 * is at least 0x1000 (large enough for 1 locality), as a sanity
	 * check, make sure the register set size and what the TPM is
	 * returning agree.
	 */
	if ((intf & TPM_INTF_CAP_LOC5) != 0 && regsize != 0x5000) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "TPM advertises 5 localities but register set size is "
		    "0x%lx", regsize);
		ddi_regs_map_free(&tpm->tpm_handle);
		return (SET_ERROR(EINVAL));
	}

	tpm->tpm_n_locality = (regsize == 0x5000) ? 5 : 1;
	return (0);
}

static int
tpm_attach_12(tpm_t *tpm)
{
	/* TODO */
	return (ENOTSUP);
}

static bool
tpm_attach_regs(tpm_t *tpm)
{
	switch (tpm_attach_20(tpm)) {
	case 0:
		return (true);
	case ENXIO:
		/* Fall back to other methods */
		break;
	default:
		return (false);
	}

	switch (tpm_attach_12(tpm)) {
	case 0:
		return (true);
	case ENXIO:
		/* Fall back to searching register set */
		break;
	default:
		return (false);
	}

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
	    0, regsize, &tpm->tpm_acc_attr, &tpm->tpm_handle);
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
	char *famstr = "";
	uint32_t id;
	bool ret;

	/*
	 * The lower 32 bits of the interface id register are identical
	 * between the FIFO and CRB interfaces to facilitate distinguishing
	 * between interface types.
	 */
	id = tpm_get32(tpm, TPM_INTERFACE_ID);
	tpm_dbg(tpm, CE_NOTE, "%s: tpm_interface_id_0: 0x%08x", __func__, id);

	switch (TPM_INTF_IFTYPE(id)) {
	case TPM_INTF_IFTYPE_TIS:
		tpm->tpm_iftype = TPM_IF_TIS;

		/*
		 * For TPMs using the TIS 1.3 interface, tpm_tis_init()
		 * will set tpm_family since both TPM1.2 and TPM2.0
		 * devices can use this interface.
		 */
		ret = tpm_tis_init(tpm);
		break;
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
		ret = tpm_tis_init(tpm);
		break;
	case TPM_INTF_IFTYPE_CRB:
		tpm->tpm_iftype = TPM_IF_CRB;
		tpm->tpm_family = TPM_FAMILY_2_0;
		ret = crb_init(tpm);
		break;
	default:
		dev_err(tpm->tpm_dip, CE_NOTE,
		    "Unsupported interface type %d", TPM_INTF_IFTYPE(id));
		return (false);
	}

	if (!ret)
		return (ret);

	switch (tpm->tpm_family) {
	case TPM_FAMILY_1_2:
		famstr = "1.2";
		break;
	case TPM_FAMILY_2_0:
		famstr  = "2.0";
		break;
	}

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "device-id", tpm->tpm_did);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "vendor-id", tpm->tpm_vid);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "vendor-name", (char *)tpm_hwvend_str(tpm->tpm_vid));
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "revision-id", tpm->tpm_rid);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "tpm-interface", (char *)tpm_iftype_str(tpm->tpm_iftype));
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, tpm->tpm_dip,
	    "tpm-family", famstr);

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

	if (types == 0) {
		tpm->tpm_use_interrupts = false;
		return (true);
	}
	tpm_dbg(tpm, CE_CONT, "?supported interrupt types: 0x%b\n", types,
	    "\020\001FIXED\002MSI\003MSI-X");

	if ((types & DDI_INTR_TYPE_FIXED) == 0) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "fixed interrupts are not supported");
		return (false);
	}

	ret = ddi_intr_get_navail(tpm->tpm_dip, DDI_INTR_TYPE_FIXED,
	    &navail);
	if (ret != DDI_SUCCESS) {
		if (ret == DDI_INTR_NOTFOUND) {
			tpm->tpm_use_interrupts = false;
			return (true);
		}

		dev_err(tpm->tpm_dip, CE_WARN,
		    "could not determine available interrupts");
		return (false);
	}
	tpm_dbg(tpm, CE_CONT, "?available interrupts: %d\n", navail);

	if (ddi_intr_get_nintrs(tpm->tpm_dip, DDI_INTR_TYPE_FIXED,
	    &nintrs) != DDI_SUCCESS) {
		dev_err(tpm->tpm_dip, CE_WARN,
		    "could not count %s interrupts", "FIXED");
		return (false);
	}
	tpm_dbg(tpm, CE_CONT, "?number of interrupts: %d\n", nintrs);

	if (nintrs < 1) {
		dev_err(tpm->tpm_dip, CE_WARN, "no interrupts supported");
		tpm->tpm_use_interrupts = false;
		return (true);
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

	tpm->tpm_use_interrupts = true;
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

static bool
tpm_attach_sync(tpm_t *tpm)
{
	void *pri = tpm->tpm_use_interrupts ?
	    DDI_INTR_PRI(tpm->tpm_intr_pri) : NULL;

	mutex_init(&tpm->tpm_lock, NULL, MUTEX_DRIVER, pri);
	cv_init(&tpm->tpm_thr_cv, NULL, CV_DRIVER, pri);
	return (true);
}

static void
tpm_cleanup_sync(tpm_t *tpm)
{
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
tpm_attach_iclient(tpm_t *tpm)
{
	int ret;

	ret = tpm_create_client(tpm, FREAD|FWRITE|FKLYR, -1,
	    &tpm->tpm_internal_client);
	if (ret != 0) {
		return (false);
	}

	return (true);
}

static void
tpm_cleanup_iclient(tpm_t *tpm)
{
	tpm_client_dtor(tpm->tpm_internal_client);
	tpm->tpm_internal_client = NULL;
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

static bool
tpm_attach_kcf(tpm_t *tpm)
{
	if (ddi_prop_get_int(DDI_DEV_T_ANY, tpm->tpm_dip, DDI_PROP_DONTPASS,
	    "disable-kcf", 0) != 0) {
		return (true);
	}

	if (tpm_kcf_register(tpm) != DDI_SUCCESS)
		return (false);

	return (true);
}

static void
tpm_cleanup_kcf(tpm_t *tpm)
{
	(void) tpm_kcf_unregister(tpm);
}

static tpm_attach_desc_t tpm_attach_tbl[TPM_ATTACH_NUM_ENTRIES] = {
	[TPM_ATTACH_FM] = {
		.tad_seq = TPM_ATTACH_FM,
		.tad_name = "fault management",
		.tad_attach = tpm_attach_fm,
		.tad_cleanup = tpm_cleanup_fm,
	},
	[TPM_ATTACH_REGS] = {
		.tad_seq = TPM_ATTACH_REGS,
		.tad_name = "registers",
		.tad_attach = tpm_attach_regs,
		.tad_cleanup = tpm_cleanup_regs,
	},
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
	[TPM_ATTACH_ICLIENT] = {
		.tad_seq = TPM_ATTACH_ICLIENT,
		.tad_name = "internal client",
		.tad_attach = tpm_attach_iclient,
		.tad_cleanup = tpm_cleanup_iclient,
	},
	[TPM_ATTACH_MINOR_NODE] = {
		.tad_seq = TPM_ATTACH_MINOR_NODE,
		.tad_name = "minor node",
		.tad_attach = tpm_attach_minor_node,
		.tad_cleanup = tpm_cleanup_minor_node,
	},
	[TPM_ATTACH_KCF] = {
		.tad_seq = TPM_ATTACH_KCF,
		.tad_name = "kcf provider",
		.tad_attach = tpm_attach_kcf,
		.tad_cleanup = tpm_cleanup_kcf,
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
tpm_resume(tpm_t *tpm)
{
	mutex_enter(&tpm->tpm_suspend_lock);
	if (!tpm->tpm_suspended) {
		mutex_exit(&tpm->tpm_suspend_lock);
		return (DDI_FAILURE);
	}
	tpm->tpm_suspended = false;
	cv_broadcast(&tpm->tpm_suspend_cv);
	mutex_exit(&tpm->tpm_suspend_lock);

	return (DDI_SUCCESS);
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

	if (tpm_debug) {
		dev_err(dip, CE_CONT, "?%s: enter\n", __func__);
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
		tpm->tpm_acc_attr = tpm_acc_attr;
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
			ddi_soft_state_free(tpm_statep, instance);
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
			    "!interrupts disabled. TPM will poll");
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

	ddi_report_dev(tpm->tpm_dip);
	return (DDI_SUCCESS);
}

static int
tpm_suspend(tpm_t *tpm)
{
	if (tpm == NULL)
		return (DDI_FAILURE);

	mutex_enter(&tpm->tpm_suspend_lock);
	if (tpm->tpm_suspended) {
		mutex_exit(&tpm->tpm_suspend_lock);
		return (DDI_SUCCESS);
	}

	tpm->tpm_suspended = true;
	mutex_exit(&tpm->tpm_suspend_lock);
	return (DDI_SUCCESS);
}

static int
tpm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	tpm_t *tpm;

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

	/*
	 * If we registered with KCF, we can't detach because swrand keeps
	 * a reference to the KCF handle and KCF doesn't (currently)
	 * properly handle this (and will cause a panic).
	 */
	if (tpm->tpm_n_prov != 0) {
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
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

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

static uint64_t
tpm_client_hash(const void *e)
{
	const int *minorp = e;

	/*
	 * For now, we don't need to be particularly clever. We can just
	 * distribute over the buckets. The expectation is that the TPM
	 * operation time is going to dwarf any client lookup time by
	 * many orders of magnitude.
	 */
	return ((uint64_t)(*minorp));
}

static int
tpm_client_cmp(const void *a, const void *b)
{
	const int *l = a;
	const int *r = b;

	if (*l < *r)
		return (-1);
	if (*l > *r)
		return (1);
	return (0);
}

const char *
tpm_iftype_str(tpm_if_t iftype)
{
	switch (iftype) {
	case TPM_IF_TIS:
		return ("TIS");
	case TPM_IF_FIFO:
		return ("FIFO");
	case TPM_IF_CRB:
		return ("CRB");
	default:
		/* We were passed an undefined value, not possible */
		cmn_err(CE_PANIC, "invalid iftype %d", iftype);

#ifndef __CHECKER__
		/* smatch understands this is unreachable, gcc does not */
		return (NULL);
#endif
	}
}


/* An arbitrary prime */
#define	TPM_CLIENT_BUCKETS	7

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&tpm_statep, sizeof (tpm_t), 1);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: ddi_soft_state_init failed: %d",
		    __func__, ret);
		return (ret);
	}

	tpm_clients = refhash_create(TPM_CLIENT_BUCKETS, tpm_client_hash,
	    tpm_client_cmp, tpm_client_dtor, sizeof (tpm_client_t),
	    offsetof(tpm_client_t, tpmc_reflink),
	    offsetof(tpm_client_t, tpmc_minor), KM_SLEEP);

	CTASSERT((uint64_t)MAXMIN64 >= (uint64_t)INT_MAX);
	tpm_minors = id_space_create("tpm minor numbers", 1, INT_MAX);
	if (tpm_minors == NULL) {
		cmn_err(CE_WARN, "!%s: failed to create tpm minor id space",
		    __func__);
		refhash_destroy(tpm_clients);
		ddi_soft_state_fini(&tpm_statep);
		return (-1);
	}

	ret = mod_install(&tpm_ml);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: mod_install returned %d",
		    __func__, ret);
		id_space_destroy(tpm_minors);
		refhash_destroy(tpm_clients);
		ddi_soft_state_fini(&tpm_statep);
		return (ret);
	}

	mutex_init(&tpm_clients_lock, NULL, MUTEX_DRIVER, NULL);

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

	id_space_destroy(tpm_minors);
	refhash_destroy(tpm_clients);
	mutex_destroy(&tpm_clients_lock);

	ddi_soft_state_fini(&tpm_statep);

	return (ret);
}
