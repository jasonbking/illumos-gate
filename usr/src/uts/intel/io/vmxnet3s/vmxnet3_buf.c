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
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/ddidmareq.h>
#include "vmxnet3.h"

struct vmxnet3_bufcache {
	kmutex_t		vbc_lock;
	kcondvar_t		vbc_cv;
	int			(*vbc_ctor)(void *, void *);
	void			(*vbc_reset)(void *, void *);
	void			(*vbc_dtor)(void *, void *);
	void			*vbc_arg;
	size_t			vbc_elsize;
	uint32_t		vbc_nent;
	volatile uint32_t	vbc_nalloc;
	boolean_t		vbc_freeing;
	void			**vbc_pool;
	void			*vbc_bufs[];
};

static inline size_t
bufcache_size(uint32_t n)
{
	return (sizeof (vmxnet3_bufcache_t) + n * sizeof (void *));
}

vmxnet3_bufcache_t *
vmxnet3_bufcache_init(uint32_t nent, size_t elsize,
    int (*vb_ctor)(void *, void *), void (*vb_reset)(void *, void *),
    void (*vb_dtor)(void *, void *), void *arg, uint_t pri)
{
	vmxnet3_bufcache_t *c;

	c = kmem_zalloc(bufcache_size(nent), KM_SLEEP);
	mutex_init(&c->vbc_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	cv_init(&c->vbc_cv, NULL, CV_DRIVER, NULL);
	c->vbc_ctor = vb_ctor;
	c->vbc_reset = vb_reset;
	c->vbc_dtor = vb_dtor;
	c->vbc_arg = arg;
	c->vbc_pool = kmem_zalloc(nent * sizeof (void *), KM_SLEEP);
	c->vbc_elsize = elsize;
	c->vbc_nent = nent;

	for (uint32_t i = 0; i < nent; i++) {
		void *el = kmem_zalloc(elsize, KM_SLEEP);

		if (c->vbc_ctor(el, arg) != 0) {
			kmem_free(el, elsize);
			vmxnet3_bufcache_fini(c);
			return (NULL);
		}

		c->vbc_pool[i] = c->vbc_bufs[i] = el;
	}

	return (c);
}

void
vmxnet3_bufcache_fini(vmxnet3_bufcache_t *c)
{
	if (c == NULL)
		return;

	mutex_enter(&c->vbc_lock);
	c->vbc_freeing = B_TRUE;
	while (c->vbc_nalloc > 0)
		cv_wait(&c->vbc_cv, &c->vbc_lock);

	kmem_free(c->vbc_pool, c->vbc_nent * sizeof (void *));
	for (uint32_t i = 0; i < c->vbc_nent; i++) {
		void *el = c->vbc_bufs[i];

		c->vbc_dtor(el, c->vbc_arg);
		kmem_free(el, c->vbc_elsize);
	}

	uint32_t nent = c->vbc_nent;
	kmem_free(c, bufcache_size(nent));
}

void *
vmxnet3_bufcache_alloc(vmxnet3_bufcache_t *c)
{
	vmxnet3_dmabuf_t *buf;

	mutex_enter(&c->vbc_lock);
	if (c->vbc_nalloc == c->vbc_nent || c->vbc_freeing) {
		mutex_exit(&c->vbc_lock);
		return (NULL);
	}

	buf = c->vbc_pool[c->vbc_nalloc];
	c->vbc_pool[c->vbc_nalloc] = NULL;
	c->vbc_nalloc++;
	mutex_exit(&c->vbc_lock);

	return (buf);
}

void
vmxnet3_bufcache_free(vmxnet3_bufcache_t *c, void *buf)
{
	if (buf == NULL)
		return;

	mutex_enter(&c->vbc_lock);

	ASSERT3U(c->vbc_nalloc, >, 0);

	if (c->vbc_reset != NULL) {
		c->vbc_reset(buf, c->vbc_arg);
	}

	--c->vbc_nalloc;
	c->vbc_pool[c->vbc_nalloc] = buf;

	if (c->vbc_freeing && c->vbc_nalloc == 0)
		cv_signal(&c->vbc_cv);

	mutex_exit(&c->vbc_lock);
}
