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
 * Copyright 2026 RackTop Systems, Inc
 */

#include "ice.h"

void
ice_buf_pool_init(ice_t *ice, ice_buf_pool_t *pool, size_t sz, size_t bufsz,
    ddi_dma_attr_t *dma_attr)
{
	ddi_device_acc_attr_t	acc;
	size_t			len;
	size_t			i;

	ice_dma_acc_attr(ice, &acc);

	len = sz * sizeof (ice_dma_buffer_t);
	pool->ibp_bufs = kmem_zalloc(len, KM_SLEEP);

	len = sz * sizeof (ice_dma_buffer_t *);
	pool->ibp_free = kmem_zalloc(len, KM_SLEEP);

	pool->ibp_buflen = bufsz;
	pool->ibp_nbuf = sz;
	pool->ibp_nfree = sz;

	for (i = 0; i < sz; i++) {
		VERIFY(ice_dma_alloc(ice, &pool->ibp_bufs[i], dma_attr, &acc,
		    true, bufsz, true));
		pool->ibp_free[i] = &pool->ibp_bufs[i];
	}
}

void
ice_buf_pool_fini(ice_buf_pool_t *pool)
{
	size_t sz, i;

	sz = pool->ibp_nbuf * sizeof (ice_dma_buffer_t *);

	mutex_enter(&pool->ibp_lock);
	ASSERT3U(pool->ibp_nfree, ==, pool->ibp_nbuf);

	for (i = 0; i < pool->ibp_nbuf; i++) {
		ice_dma_free(&pool->ibp_bufs[i]);
	}

	kmem_free(pool->ibp_free, sz);
	pool->ibp_free = NULL;

	sz = pool->ibp_nbuf * sizeof (ice_dma_buffer_t);
	kmem_free(pool->ibp_bufs, sz);
	pool->ibp_bufs = NULL;

	pool->ibp_buflen = 0;
	pool->ibp_nbuf = 0;
	pool->ibp_nfree = 0;

	mutex_exit(&pool->ibp_lock);
}

ice_dma_buffer_t *
ice_buf_pool_alloc(ice_buf_pool_t *pool)
{
	ice_dma_buffer_t *buf;

	mutex_enter(&pool->ibp_lock);

	if (pool->ibp_nfree == 0) {
		mutex_exit(&pool->ibp_lock);
		return (NULL);
	}

	buf = pool->ibp_free[--pool->ibp_nfree];
	pool->ibp_free[pool->ibp_nfree] = NULL;

	mutex_exit(&pool->ibp_lock);

	return (buf);
}

void
ice_buf_pool_free(ice_buf_pool_t *pool, ice_dma_buffer_t *buf)
{
	bzero(buf->idb_va, buf->idb_len);

	mutex_enter(&pool->ibp_lock);

	ASSERT3U(pool->ibp_nfree, !=, pool->ibp_nbuf);
	pool->ibp_free[pool->ibp_nfree++] = buf;

	mutex_exit(&pool->ibp_lock);
}

size_t
ice_buf_pool_size(const ice_buf_pool_t *pool)
{
	return (pool->ibp_nbuf);
}

size_t
ice_buf_pool_nfree(const ice_buf_pool_t *pool)
{
	return (pool->ibp_nfree);
}
