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
 * Copyright 2021 Joyent, Inc.
 */

#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>
#include <sys/kmem.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/refhash.h>

#include "vsock_mod.h"

typedef struct vsock_sock {
	refhash_link_t	vs_link;

	uint64_t	vs_lcid;
	uint64_t	vs_rcid;
	uint32_t	vs_lport;
	uint32_t	vs_rport;

	/* XXX: backend */
	int foo;
} vsock_sock_t;

static uint64_t vsock_local_cid;
static const vsock_guest_ops_t *vsock_guest_ops;
static kmem_cache_t *vsock_conn_cache;

static sock_lower_handle_t vsock_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);
static vsock_sock_t * vsock_do_open(int flags);
static void vsock_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls, int flags,
    cred_t *cr);
static int vsock_accept(sock_lower_handle_t proto_handle,
    sock_lower_handle_t lproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr);
static int vsock_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
   socklen_t len, cred_t *cr);
static int vsock_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr);
static int vsock_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
   socklen_t len, sock_connid_t *id, cred_t *cr);
static int vsock_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
   socklen_t *addrlenp, cred_t *cr);
static int vsock_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr);
static int vsock_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr);
static int vsock_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
     const void *optvalp, socklen_t optlen, cred_t *cr);
static int vsock_send(sock_lower_handle_t proto_handle, mblk_t *mp,
    struct nmsghdr *msg, cred_t *cr);
static int vsock_send_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr);
static int vsock_recv_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr);
static short vsock_poll(sock_lower_handle_t proto_handle, short events,
    int anyyet, cred_t *cr);
static int vsock_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr);
static void vsock_setflowctrl(sock_lower_handle_t proto_handle);
static int vsock_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
   int mode, int32_t *rvalp, cred_t *cr);
static int vsock_close(sock_lower_handle_t, int flag, cred_t *);

static smod_reg_t sinfo = {
	.smod_version = SOCKMOD_VERSION,
	.smod_name = "vsock",
	.smod_uc_version = SOCK_UC_VERSION,
	.smod_dc_version = SOCK_DC_VERSION,
	.smod_proto_create_func = vsock_create,
};

static struct modlsockmod sockmod = {
	.sockmod_modops = &mod_sockmodops,
	.sockmod_linkinfo = "AF_VSOCK socket module",
	.sockmod_reg_info = &sinfo,
};

static struct modlinkage ml = {
	MODREV_1,
	&sockmod,
	NULL
};

static sock_downcalls_t sock_vsock_downcalls = {
	.sd_activate = vsock_activate,
	.sd_accept = vsock_accept,
	.sd_bind = vsock_bind,
	.sd_listen = vsock_listen,
	.sd_connect = vsock_connect,
	.sd_getpeername = vsock_getpeername,
	.sd_getsockname = vsock_getsockname,
	.sd_getsockopt = vsock_getsockopt,
	.sd_setsockopt = vsock_setsockopt,
	.sd_send = vsock_send,
	.sd_send_uid = vsock_send_uio,
	.sd_recv_uio = vsock_recv_uio,
	.sd_poll = vsock_poll,
	.sd_shutdown = vsock_shutdown,
	.sd_clr_flowctrl = vsock_setflowctrl,
	.sd_ioctl = vsock_ioctl,
	.sd_close = vsock_close,
};

int
_init(void)
{
	int rc;

	vsock_conn_cache = kmem_cache_create("vsock connections",
	    sizeof (vsock_sock_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	rc = mod_install(&ml);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int rc;

	kmem_cache_destroy(vsock_conn_cache);

	rc = mod_remove(&ml);
	return (rc);
}

int
vsock_attach_guest(uint64_t local_cid, const vsock_guest_ops_t *guest_ops)
{
	return (0);
}

static inline vsock_sock_t *
lhtovs(sock_lower_handle_t proto_handle)
{
	return ((vsock_sock_t *)proto_handle);
}

static sock_lower_handle_t
vsock_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	vsock_sock_t *vsock;

	if (family != AF_VSOCK || (type != SOCK_STREAM && type != SOCK_DGRAM) ||
	    proto != 0) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	*sock_downcalls = &sock_vsock_downcalls;
	*smodep = SM_CONNREQUIRED | SM_EXDATA | SM_ACCEPTSUPP;
	vsock = vsock_do_open(flags);
	*errorp = (vsock != NULL) ? 0 : ENOMEM;
	return ((sock_lower_handle_t)vsock);
}

static vsock_sock_t *
vsock_do_open(int flags)
{
	return (NULL);
}

static void
vsock_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls, int flags,
    cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
}

static int
vsock_accept(sock_lower_handle_t proto_handle,
    sock_lower_handle_t lproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (ECONNABORTED);
}

static int
vsock_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
   socklen_t len, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	
	return (EOPNOTSUPP);
}

static int
vsock_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
   socklen_t len, sock_connid_t *id, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
   socklen_t *addrlenp, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (ENOTCONN);
}

static int
vsock_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (ENOTCONN);
}

static int
vsock_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
     const void *optvalp, socklen_t optlen, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}


static int
vsock_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}


static int
vsock_send_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_recv_uio(sock_lower_handle_t proto_handle, uio_t *uiop,
    struct nmsghdr *msg, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static short
vsock_poll(sock_lower_handle_t proto_handle, short events, int anyyet,
    cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}


static int
vsock_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static void
vsock_setflowctrl(sock_lower_handle_t proto_handle)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
}

static int
vsock_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
   int mode, int32_t *rvalp, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_close(sock_lower_handle_t proto_handle, int flag, cred_t *cr)
{
	vsock_sock_t *vsock = lhtosh(proto_handle);
	return (EOPNOTSUPP);
}

static int
vsock_sock_cmp(const void *a, const void *b)
{
	const vsock_sock_t *l = a;
	const vsock_sock_t *r = b;

	if (l->vs_lcid < r->vs_lcid)
		return (-1);
	if (l->vs_lcid > r->vs_lcid)
		return (1);
	if (l->vs_rcid < r->vs_rcid)
		return (-1);
	if (l->vs_rcid > r->vs_rcid)
		return (1);
	if (l->vs_lport < r->vs_lport)
		return (-1);
	if (l->vs_lport > r->vs_rport)
		return (1);
	if (l->vs_rport < r->vs_rport)
		return (-1);
	if (l->vs_rport > r->vs_rport)
		return (1);
	return (0);
}

static uint64_t
vsock_sock_hash(const void *v)
{
	const vsock_sock_t *s = v;
	uint32_t crc;

	CRC32(crc, s->vs_lcid, sizeof (s->vs_lcid), -1U, crc32_table);
	CRC32(crc, s->vs_rcid, sizeof (s->vs_rcid), crc, crc32_table);
	CRC32(crc, s->vs_lport, sizeof (s->vs_lport), crc, crc32_table);
	CRC32(crc, s->vs_rport, sizeof (s->vs_rport), crc, crc32_table);

	return (crc);
}
