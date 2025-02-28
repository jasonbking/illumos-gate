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
 * Copyright 2025 RackTop Systems, Inc.
 */

#include <inttypes.h>
#include <sys/debug.h>

#include "tpm_ddi.h"
#include "tpm20.h"
#include "tpm_tab.h"

/*
 * Note: for session contexts, the client/virtual and real id will always be
 * identical (per TAB 3.14).
 */
typedef struct tpm_tab_entry {
	uint32_t	tent_cid; /* Client (virtual) id */
	uint32_t	tent_rid; /* Real id */
	uint8_t		*tent_ctx;
	uint32_t	tent_ctxlen;
	bool		tent_loaded;
} tpm_tab_entry_t;

typedef struct tpm_tab {
	tpm_tab_entry_t	*tab_entries;
	size_t		tab_size;
	size_t		tab_alloc;
	uint32_t	tab_next_cid;
} tpm_tab_t;

int
tpm_tab_init(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;
	tpm_tab_t *tab;

	ASSERT3S(tpm->tpm_family, ==, TPM_FAMILY_2_0);

	tab = kmem_zalloc(sizeof (*tab), KM_SLEEP);
	tab->tab_next_cid = 1;
	c->tpmc_tab = tab;
	return (0);
}

void
tpm_tab_fini(tpm_client_t *c)
{
	struct tpm_tab *tab = c->tpmc_tab;

	if (tab == NULL) {
		return;
	}

	/* TODO: for each loaded handle, TPM2_FlushContext() */

	if (tab->tab_entries != NULL) {
		size_t len = tab->tab_alloc * sizeof (tpm_tab_entry_t);

		kmem_free(tab->tab_entries, len);
	}

	kmem_free(tab, sizeof (*tab));
}

uint32_t
tpm_tab_map_handle(tpm_tab_t *tab, uint32_t vobj)
{
	/*
	 * The object handle is analogous to an fd -- just an integer
	 * reference. The reason behind virtualizing object handles is
	 * for arbitrating access to the TPM. In other words, the mapping
	 * doesn't need to be constant time for any security concerns.
	 */
	for (uint_t i = 0; i < tab->tab_size; i++) {
		if (tab->tab_entries[i].tent_cid == vobj) {
			return (tab->tab_entries[i].tent_rid);
		}
	}

	return (0); /* XXX: probably needs something better */
}

#define	MAP_CHUNK 4
uint32_t
tpm_tab_new_vobj(tpm_tab_t *tab, uint32_t robj)
{
	tpm_tab_entry_t	*entry;

	if (tab->tab_size == tab->tab_alloc) {
		tpm_tab_entry_t *new_entries;
		size_t new_alloc;

		new_alloc = tab->tab_alloc + MAP_CHUNK;
		new_entries = kmem_zalloc(new_alloc *
		    sizeof (tpm_tab_entry_t), KM_SLEEP);

		bcopy(tab->tab_entries, new_entries, tab->tab_size *
		    sizeof (tpm_tab_entry_t));

		kmem_free(tab->tab_entries, tab->tab_alloc *
		    sizeof (tpm_tab_entry_t));

		tab->tab_entries = new_entries;
		tab->tab_alloc = new_alloc;
	}

	VERIFY3U(tab->tab_entries, <, tab->tab_alloc);
	entry = &tab->tab_entries[tab->tab_size++];

	entry->tent_rid = robj;

	/*
	 * XXX: This needs to be smarter -- it's possible (though unlikely)
	 * we could roll over ids and would need to look for an unused
	 * but lower numbered id.
	 */
	entry->tent_cid = tab->tab_next_cid++;

	return (entry->tent_cid);
}

bool
tpm_tab_del_obj(tpm_tab_t *tab, uint32_t cobj)
{
	uint_t i;

	for (i = 0; i < tab->tab_size; i++) {
		if (tab->tab_entries[i].tent_cid == cobj) {
			break;
		}
	}

	if (i == tab->tab_size) {
		return (false);
	}

	if (i + 1 < tab->tab_size) {
		/*
		 * Not the last entry, shift everything after the entry to
		 * delete.
		 */
		memmove(&tab->tab_entries[i], &tab->tab_entries[i + 1],
		    (tab->tab_size - i - 1) * sizeof (tpm_tab_entry_t));
	}

	/* Clear out (for clarity) what was the last entry in the list */
	bzero(&tab->tab_entries[tab->tab_size - 1],
	    sizeof (tpm_tab_entry_t));

	tab->tab_size--;
	return (true);
}

bool
tpm_tab_load_handle(tpm_t *tpm, tpm_tab_t *tab, uint32_t h)
{
	tpm_tab_entry_t	*e = NULL;

	for (uint_t i = 0; i < tab->tab_size; i++) {
		if (tab->tab_entries[i].tent_cid == h) {
			e = &tab->tab_entries[i];
			break;
		}
	}

	if (e == NULL) {
		return (false);
	}

	if (tpm->tpm_last_tab == tab && e->tent_loaded) {
		return (true);
	}

	// XXX: TPM2_LoadContext
	// XXX: Update handle mapping
	return (true);
}

bool
tpm_tab_cmd_pre(tpm_client_t *c)
{
	tpm_t		*tpm = c->tpmc_tpm;
	tpm_tab_t	*tab = c->tpmc_tab;
	tpm_cmd_t	*src, *dst;
	uint32_t	cc, attr, len, off;
	uint_t		nhdl;

	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	src = &c->tpmc_cmd;
	dst = &tpm->tpm_cmd;
	len = tpm_cmdlen(src);

	if (tab == NULL) {
		bzero(dst->tcmd_buf, sizeof (dst->tcmd_buf));
		bcopy(src->tcmd_buf, dst->tcmd_buf, len);
		return (true);
	}

	cc = tpm_cc(src);
	attr = tpm20_get_ccattr(tpm, cc);
	nhdl = TPM2_CCA_CHDL(attr);

	if (tpm->tpm_last_tab != tab && nhdl > 0) {
		;
		/* TODO: save out any loaded contexts on the current handle */
	}

	/* Make sure any handles used by the command have been loaded */
	off = TPM_HEADER_SIZE;
	for (uint_t i = 0; i < nhdl; i++) {
		uint32_t hdl;

		hdl = tpm_getbuf32(src, off);
		off += sizeof (hdl);

		if (!tpm_tab_load_handle(tpm, tab, hdl)) {
			/* XXX: error reporting */
			return (false);
		}
	}

	/* Copy over the header */
	bzero(dst->tcmd_buf, sizeof (dst->tcmd_buf));
	bcopy(src->tcmd_buf, dst->tcmd_buf, TPM_HEADER_SIZE);
	off = TPM_HEADER_SIZE;

	for (uint_t i = 0; i < nhdl; i++) {
		uint32_t src_hdl;
		uint32_t dst_hdl;

		src_hdl = tpm_getbuf32(src, off);
		dst_hdl = tpm_tab_map_handle(tab, src_hdl);
		if (dst_hdl == 0) {
			/* XXX: error */
			return (false);
		}

		BE_OUT32(&dst->tcmd_buf + off, dst_hdl);

		off += sizeof (src_hdl);
	}

	/* TODO: map other bits */
	return (true);
}
