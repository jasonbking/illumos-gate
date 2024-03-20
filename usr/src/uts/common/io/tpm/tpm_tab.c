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
 */

#include <inttypes.h>
#include <sys/debug.h>

#include "tpm_ddi.h"
#include "tpm_tab.h"

typedef struct tpm_hdl_map_entry {
	uint32_t	tme_cid; /* Client (virtual) id */
	uint32_t	tme_rid; /* Real id */
} tpm_hdl_map_entry_t;

typedef struct tpm_hdl_map {
	tpm_hdl_map_entry_t	*thm_entries;
	size_t			thm_size;
	size_t			thm_alloc;
	uint32_t		thm_next_cid;
} tpm_hdl_map_t;

struct tpm_tab {
	tpm_hdl_map_t	tt_hdl_map;
	uint8_t		*tt_session;
	size_t		tt_session_len;
};

int
tpm_tab_init(tpm_client_t *c)
{
	tpm_t *tpm = c->tpmc_tpm;
	struct tpm_tab *tab;

	ASSERT3S(tpm->tpm_family, ==, TPM_FAMILY_2_0);

	tab = kmem_zalloc(sizeof (*tab), KM_SLEEP);
	tab->tt_session = kmem_zalloc(tpm->tpm_session_size, KM_SLEEP);
	tab->tt_session_len = tpm->tpm_session_size;

	tab->tt_hdl_map.thm_next_cid = 1;
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

	if (tab->tt_session != NULL) {
		/*
		 * TPM2.0 sessions are an opaque byte stream that the TPM
		 * module is required to protect (i.e. it wraps the data
		 * using a key internal and non-exportable from the TPM)
		 * so we should not need to clear the session contents before
		 * freeing it.
		 */
		kmem_free(tab->tt_session, tab->tt_session_len);
	}

	if (tab->tt_hdl_map.thm_alloc > 0) {
		kmem_free(tab->tt_hdl_map.thm_entries,
		    tab->tt_hdl_map.thm_alloc * sizeof (tpm_hdl_map_entry_t));
	}

	kmem_free(tab, sizeof (*tab));
}

uint32_t
tpm_tab_vobj_to_real(tpm_tab_t *tab, uint32_t vobj)
{
	tpm_hdl_map_t *map = &tab->tt_hdl_map;

	/*
	 * The object handle is analogous to an fd -- just an integer
	 * reference. The reason behind virtualizing object handles is
	 * for arbitrating access to the TPM. In other words, the mapping
	 * doesn't need to be constant time for any security concerns.
	 */
	for (uint_t i = 0; i < map->thm_size; i++) {
		if (map->thm_entries[i].tme_cid == vobj) {
			return (map->thm_entries[i].tme_rid);
		}
	}

	return (0); /* XXX: probably needs something better */
}

#define	MAP_CHUNK 4
uint32_t
tpm_tab_new_vobj(tpm_tab_t *tab, uint32_t robj)
{
	tpm_hdl_map_t		*map = &tab->tt_hdl_map;
	tpm_hdl_map_entry_t	*entry;

	if (map->thm_size == map->thm_alloc) {
		tpm_hdl_map_entry_t *new_entries;
		size_t new_alloc;

		new_alloc = map->thm_alloc + MAP_CHUNK;
		new_entries = kmem_zalloc(new_alloc *
		    sizeof (tpm_hdl_map_entry_t), KM_SLEEP);

		bcopy(map->thm_entries, new_entries, map->thm_size *
		    sizeof (tpm_hdl_map_entry_t));

		kmem_free(map->thm_entries, map->thm_alloc *
		    sizeof (tpm_hdl_map_entry_t));

		map->thm_entries = new_entries;
		map->thm_alloc = new_alloc;
	}

	VERIFY3U(map->thm_entries, <, map->thm_alloc);
	entry = &map->thm_entries[map->thm_size++];

	entry->tme_rid = robj;

	/*
	 * XXX: This needs to be smarter -- it's possible (though unlikely)
	 * we could roll over ids and would need to look for an unused
	 * but lower numbered id.
	 */
	entry->tme_cid = map->thm_next_cid++;

	return (entry->tme_cid);
}

bool
tpm_tab_del_obj(tpm_tab_t *tab, uint32_t cobj)
{
	tpm_hdl_map_t *map = &tab->tt_hdl_map;
	uint_t i;

	for (i = 0; i < map->thm_size; i++) {
		if (map->thm_entries[i].tme_cid == cobj) {
			break;
		}
	}

	if (i == map->thm_size) {
		return (false);
	}

	if (i + 1 < map->thm_size) {
		/*
		 * Not the last entry, shift everything after the entry to
		 * delete.
		 */
		memmove(&map->thm_entries[i], &map->thm_entries[i + 1],
		    (map->thm_size - i - 1) * sizeof (tpm_hdl_map_entry_t));
	}

	/* Clear out (for clarity) what was the last entry in the list */
	bzero(&map->thm_entries[map->thm_size - 1],
	    sizeof (tpm_hdl_map_entry_t));

	map->thm_size--;
	return (true);
}
