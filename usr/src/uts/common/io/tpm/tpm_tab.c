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
#include <stddef.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include "tpm_ddi.h"
#include "tpm20.h"
#include "tpm_tab.h"

/*
 * The max# of handles that can appear in a command.
 * TPM Part 1 18.3
 */
#define	TPM_MAX_HANDLE	7

static tpm_tab_context_t *tab_get_context(tpm_tab_t *, tpm_client_t *,
    TPM2_HANDLE);
static void tab_delete_context(tpm_tab_t *, tpm_client_t *,
    tpm_tab_context_t *);

static TPM2_RC tab_foreach_handle(tpm_client_t *, tpm_cmd_t *, uint_t,
    TPM2_RC (*)(tpm_client_t *, TPM2_HANDLE *, uint_t, void *), void *);
static TPM2_RC tab_validate_handles(tpm_client_t *, TPM2_HANDLE *, uint_t,
    void *);
static TPM2_RC tab_map_handles(tpm_client_t *, TPM2_HANDLE *, uint_t, void *);
static TPM2_RC tab_post_flush(tpm_client_t *, TPM2_HANDLE *, uint_t, void *);
static TPM2_RC tab_post_handle(tpm_client_t *, TPM2_HANDLE *, uint_t, void *);
static TPM2_RC tab_assert_ctx_loaded(tpm_t *, tpm_tab_context_t *,
    tpm_tab_context_t **, uint_t);

static TPM2_RC tab_regap(tpm_t *);
static TPM2_RC tab_swapout_ctx(tpm_t *, TPM2_HT, tpm_tab_context_t **, uint_t);
static TPM2_RC tab_save_ctx(tpm_t *, tpm_tab_context_t *);
static TPM2_RC tab_load_ctx(tpm_t *, tpm_tab_context_t *);
static TPM2_RC tab_flush_ctx(tpm_t *, tpm_tab_context_t *);

static tpm_tab_context_t *tab_new_context(tpm_tab_t *, tpm_client_t *,
    TPM2_HANDLE);
static void tab_free_context(tpm_tab_context_t *);

static int tab_cmp_context(const void *, const void *);
static int tab_cmp_seq(const void *, const void *);

static inline TPM2_HT
handle_type(TPM2_HANDLE h)
{
	return ((TPM2_HT)(h >> 24));
}

static inline TPM2_HT
ctx_type(const tpm_tab_context_t *ctx)
{
	return (handle_type(ctx->tctx_handle));
}

static inline bool
is_session(TPM2_HANDLE h)
{
	switch (handle_type(h)) {
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		return (true);
	default:
		return (false);
	}
}

static inline bool
is_tab_managed(TPM2_HANDLE h)
{
	switch (handle_type(h)) {
	case TPM2_HT_TRANSIENT:
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		return (true);
	default:
		return (false);
	}
}

static inline TPM2_RC
tab_err(TPM2_RC rc)
{
	rc &= ~(TSS2_RC_LAYER_MASK);
	return (TSS2_RESMGR_TPM_RC_LAYER | rc);
}

static inline uint_t
tab_nhdl(tpm_t *tpm, const tpm_cmd_t *cmd)
{
	uint32_t cc, attr;

	cc = tpm_cc(cmd);
	attr = tpm20_get_ccattr(tpm, cc);
	return (TPM2_CCA_CHDL(attr));
}

static inline uint_t
tab_nhdl_resp(tpm_t *tpm, const tpm_cmd_t *cmd)
{
	uint32_t cc, attr;

	cc = tpm_cc(cmd);
	attr = tpm20_get_ccattr(tpm, cc);
	return (TPM2_CCA_RHDL(attr));
}

static inline TPM2_HANDLE
ctx_real_handle(const tpm_tab_context_t *ctx)
{
	if (is_session(ctx->tctx_handle)) {
		return (ctx->tctx_handle);
	}
	return (ctx->tobj_real_handle);
}

static inline size_t
ctx_size(const tpm_t *tpm, TPM2_HANDLE h)
{
	switch (handle_type(h)) {
	case TPM2_HT_TRANSIENT:
		return (tpm->tpm20_object_max);
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		return (tpm->tpm20_session_max);
	default:
		dev_err(tpm->tpm_dip, CE_PANIC, "%s: invalid handle type 0x%x",
		    __func__, handle_type(h));

		/* Keep gcc and smatch happy */
		return (0);
	}
}

void
tpm_tab_init(tpm_t *tpm)
{
	tpm_tab_t *tab = &tpm->tpm_tab;

	avl_create(&tab->tab_contexts, tab_cmp_context,
	    sizeof (tpm_tab_context_t), offsetof(tpm_tab_context_t, tctx_avl));

	list_create(&tab->tab_sessions, sizeof (tpm_tab_context_t),
	    offsetof(tpm_tab_context_t, tctx_list));
	tab->tab_nsessions = 0;

	list_create(&tab->tab_objects, sizeof (tpm_tab_context_t),
	    offsetof(tpm_tab_context_t, tctx_list));
	tab->tab_nobjects = 0;

	avl_create(&tab->tab_sessions_by_seq, tab_cmp_seq,
	    sizeof (tpm_tab_context_t),
	    offsetof(tpm_tab_context_t, ts_seq_avl));
}

void
tpm_tab_fini(tpm_t *tpm)
{
	tpm_tab_t	*tab = &tpm->tpm_tab;

	avl_destroy(&tab->tab_sessions_by_seq);

	list_destroy(&tab->tab_objects);
	list_destroy(&tab->tab_sessions);

	avl_destroy(&tab->tab_contexts);
}

/*
 * Prepare command for execution. Copies the command from src into
 * the TPM's command buffer mapping any handles as needed. Any swapping
 * of contexts (object or session) will also occur as needed to ensure
 * all of the handles referenced in the command (if any) are loaded
 * into the TPM.
 *
 * Any failures are returned as a TPM result (i.e. written into src).
 * Return true if the command is ready to execute, false if the
 * command should be aborted (with error written to src).
 */
bool
tpm_tab_cmd_pre(tpm_client_t *c)
{
	tpm_t			*tpm = c->tpmc_tpm;
	tpm_tab_t		*tab = &tpm->tpm_tab;
	tpm_cmd_t		*src = &c->tpmc_cmd;
	tpm_cmd_t		*dst = &tpm->tpm_cmd;
	tpm_tab_context_t	*ctx[TPM_MAX_HANDLE] = { 0 };
	uint32_t		len;
	uint_t			nhdl;
	TPM2_RC			rc;
	bool			ret = true;

	/* We should only be called from the TPM service thread */
	VERIFY3P(curthread, ==, tpm->tpm_thread);

	len = tpm_cmdlen(src);

	/*
	 * TAB only exists for TPM 2.0 devices, so non TPM 2.0 (e.g. TPM 1.2)
	 * devices are just passed along unmodified. Likewise, TPM 2.0
	 * commands that don't use any handles do not require any modification
	 * before submission, so they're also passed along unmodified.
	 */
	if (tpm->tpm_family != TPM_FAMILY_2_0 ||
	    (nhdl = tab_nhdl(tpm, src)) == 0) {
		bzero(dst->tcmd_buf, sizeof (dst->tcmd_buf));
		bcopy(dst->tcmd_buf, src->tcmd_buf, len);
		return (true);
	}

	/* If we get here, nhdl has been set to the correct # of handles */

	mutex_enter(&tab->tab_lock);

	/*
	 * Make sure any session or object handles exist for the client.
	 * This will also populate ctx with the tpm_tab_context_ts of
	 * each handle (in the position they appear in the request).
	 *
	 * For handle types that aren't managed by the TAB (e.g. NV index
	 * handles), their slots will be NULL in ctx.
	 */
	rc = tab_foreach_handle(c, src, nhdl, tab_validate_handles, ctx);
	if (rc != TPM2_RC_SUCCESS) {
		goto done;
	}

	switch (tpm_cc(src)) {
	case TPM2_CC_ContextLoad:
		// TODO
		break;
	case TPM2_CC_ContextSave:
		if (ctx[0] == NULL) {
			TPM2_HANDLE h;

			/*
			 * The TPM2_CC_ContextSave command should only
			 * have a single handle in the handle session, so
			 * we should only need to worry about ctx[0].
			 */
			VERIFY3U(nhdl, ==, 1);

			/*
			 * The handle area is immediately after the
			 * header
			 */ 
			h = tpm_getbuf32(src, TPM_HEADER_SIZE);

			/*
			 * If ctx[0] is NULL, then the handle specified
			 * is not a type that is tab managed
			 */
			VERIFY(!is_tab_managed(h));

			/*
			 * Since the handle is not one that's TAB managed,
			 * we can pass the request along to the TPM.
			 * We've used VERIFY() because if any of the
			 * above checks somehow fail, passing the handle
			 * would represent a breach of our isolation (and
			 * potentially security).
			 */
			break;
		}

		// TODO -- we need to return a custom value to
		// clients because of gap processing
		break;
	case TPM2_CC_FlushContext:
		/*
		 * This only takes a single handle, so ctx[0] should
		 * contain the handle if it's one we need to process.
		 */
		if (ctx[0] == NULL) {
			break;
		}

		/*
		 * If the context is loaded on the TPM, we need to let
		 * the command proceed. If it's a session handle, we
		 * also need to let it proceed regardless of it's been
		 * swapped out or not since we need the TPM to clean up
		 * it's internal state.
		 */
		if (ctx[0]->tctx_state == TPM_CTX_IN_TPM ||
		    is_session(ctx[0]->tctx_handle)) {
			break;
		}

		tab_delete_context(tab, c, ctx[0]);

		/* Create a success response in the client's cmd buffer */
		tpm_cmd_resp(src, TPM2_RC_SUCCESS, TPM2_ST_NO_SESSIONS);

		/* Don't need to submit anything to the TPM */
		mutex_exit(&tab->tab_lock);
		return (false);
	}

	for (uint_t i = 0; i < nhdl; i++) {
		if (ctx[i] == NULL) {
			continue;
		}

		rc = tab_assert_ctx_loaded(tpm, ctx[i], ctx, ARRAY_SIZE(ctx));
		if (rc != TPM2_RC_SUCCESS) {
			goto done;
		}
	}

	/* Copy the request into the TPM's command buffer */
	bzero(dst->tcmd_buf, sizeof (dst->tcmd_buf));
	bcopy(dst->tcmd_buf, src->tcmd_buf, len);

	/* Adjust any handles now that everthing's loaded */
	rc = tab_foreach_handle(c, dst, nhdl, tab_map_handles, ctx);

done:
	mutex_exit(&tab->tab_lock);

	if (rc != TPM2_RC_SUCCESS) {
		/* Report back any errors as a TPM2 response */
		tpm_cmd_resp(src, rc, TPM2_ST_NO_SESSIONS);
		return (false);
	}

	return (true);
}

/*
 * Post processing of command after it runs. Creates new entries for
 * new contexts and cleans up any contexts that have gone away.
 *
 * If the command needs to be retried (e.g. because of the context gap),
 * it will return false, otherwise it returns true.
 */
bool
tpm_tab_cmd_post(tpm_t *tpm, tpm_client_t *c)
{
	tpm_cmd_t		*orig = &c->tpmc_cmd;
	tpm_cmd_t		*result = &tpm->tpm_cmd;
	TPM2_HANDLE		h;
	TPM2_CC			cc;
	uint32_t		attr;
	uint_t			nhdl;
	TPM2_RC			rc = TPM2_RC_SUCCESS;

	/* We only post-process results from TPM 2.0 devices */
	if (tpm->tpm_family != TPM_FAMILY_2_0) {
		return (true);
	}

	cc = tpm_cc(orig);
	attr = tpm20_get_ccattr(tpm, cc);

	mutex_enter(&tpm->tpm_tab.tab_lock);

	/*
	 * Check for conditions where we want to have the caller
	 * retry or don't do any post processing.
	 */
	switch (tpm_cmd_rc(result)) {
	case TPM2_RC_SUCCESS:
		/* Continue post processing below */
		break;
	case TPM2_RC_CONTEXT_GAP:
		rc = tab_regap(tpm);
		if (rc == TPM2_RC_SUCCESS) {
			goto retry;
		}

		goto fail;
	case TPM2_RC_OBJECT_MEMORY:
		/* kick out an object and retry */
		rc = tab_swapout_ctx(tpm, TPM2_HT_TRANSIENT, NULL, 0);
		if (rc == TPM2_RC_SUCCESS) {
			goto retry;
		}

		goto fail;
	case TPM2_RC_SESSION_MEMORY:
		/*
		 * We don't need to distinguish between policy and
		 * hmac sessions here -- we just need to kick out any
		 * type of session we manage.
		 */
		rc = tab_swapout_ctx(tpm, TPM2_HT_HMAC_SESSION, NULL, 0);
		if (rc == TPM2_RC_SUCCESS) {
			goto retry;
		}

		goto fail;
	case TPM2_RC_MEMORY:
		/*
		 * The TPM hasn't told us if it's session or object
		 * memory that was the problem. We're just going to guess
		 * on the type to evict based on the request command. It's
		 * as good a guess as anything else.
		 */
		switch (cc) {
		case TPM2_CC_StartAuthSession:
			/*
			 * We only care about the handle type to the point
			 * where it's a session type for eviction purposes.
			 */
			rc = tab_swapout_ctx(tpm, TPM2_HT_HMAC_SESSION, NULL,
			    0);
			break;
		case TPM2_CC_Load:
		case TPM2_CC_LoadExternal:
		default:
			rc = tab_swapout_ctx(tpm, TPM2_HT_TRANSIENT, NULL, 0);
			break;
		}

		if (rc == TPM2_RC_SUCCESS) {
			goto retry;
		}

		goto fail;
	default:
		/* Anything else we leave for the caller */
		goto fail;
	}

	switch (cc) {
	case TPM2_CC_FlushContext:
		/*
		 * We passed along a flush context to the TPM. In this
		 * case, we always purge the state of the context in
		 * question.
		 */
		// TODO: get ctx tab_delete_context(&tpm->tpm_tab, c, ctx);
		break;
	case TPM2_CC_ContextSave:
		// TODO
		break;
	default:
		break;
	}

	if (TPM2_CCA_FLUSHED(attr)) {
		/*
		 * The command flushes any transient handles (i.e. objects
		 * that appeared in the request. This effectively 'frees'
		 * them, so we need to update accordingly.
		 */
		(void) tab_foreach_handle(c, orig, TPM2_CCA_CHDL(attr),
		    tab_post_flush, NULL);
	}

	/*
	 * Add any new handles returned in the result. 
 	 */
	(void) tab_foreach_handle(c, result, TPM2_CCA_RHDL(attr),
	    tab_post_handle, NULL);

	if (tpm_tag(orig) == TPM2_ST_NO_SESSIONS) {
		/* If there's no sessions, we're done */
		goto done;
	}

	// TODO -- check authorization response area and see if
	// session is done, if so, grab handle from req and free context

done:
	mutex_exit(&tpm->tpm_tab.tab_lock);
	/*
	 * Copy the result from the TPM's command buffer into the client's
	 * command buffer.
	 */
	bzero(orig, sizeof (orig->tcmd_buf));
	bcopy(orig->tcmd_buf, result->tcmd_buf, tpm_cmdlen(result));
	return (true);

retry:
	mutex_exit(&tpm->tpm_tab.tab_lock);
	return (false);

fail:
	tpm_cmd_resp(orig, rc, TPM2_ST_NO_SESSIONS);
	mutex_exit(&tpm->tpm_tab.tab_lock);

	/* These failures aren't re-tryable */
	return (true);
}

/*
 * Make sure the handle given in *hp exist on the client in preparation
 * for submission.
 */
static TPM2_RC
tab_validate_handles(tpm_client_t *c, TPM2_HANDLE *hp, uint_t n, void *arg)
{
	tpm_tab_t		*tab = &c->tpmc_tpm->tpm_tab;
	TPM2_HANDLE		h = *hp;
	tpm_tab_context_t	*ctx;
	tpm_tab_context_t	**ctxs = arg;

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	switch (handle_type(h)) {
	case TPM2_HT_TRANSIENT:
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		/* We need to validate these */
		break;
	default:
		/* Other handle types are passed verbatim to the TPM. */
		return (TPM2_RC_SUCCESS);
	}

	ctx = tab_get_context(tab, c, h);
	if (ctx == NULL) {
		TPM2_RC rc = is_session(h) ?
		    TPM2_RC_REFERENCE_S0 : TPM2_RC_REFERENCE_H0;

		/* Indicate which handle in the request was the problem */
		rc += n;
		return (tab_err(rc));
	}

	VERIFY3U(n, <, TPM_MAX_HANDLE);
	ctxs[n] = ctx;

	return (TPM2_RC_SUCCESS);
}

static TPM2_RC
tab_map_handles(tpm_client_t *c __unused, TPM2_HANDLE *hp, uint_t n, void *arg)
{
	tpm_tab_context_t **ctxs = arg;

	VERIFY3U(n, <, TPM_MAX_HANDLE);

	if (ctxs[n] == NULL || is_session(ctxs[n]->tctx_handle)) {
		/* Not a handle type we need to map */
		return (TPM2_RC_SUCCESS);
	}

	VERIFY3U(handle_type(*hp), ==, TPM2_HT_TRANSIENT);
	*hp = ctxs[n]->tobj_real_handle;

	return (TPM2_RC_SUCCESS);
}

/*
 * A TPM2 request has flushed any transient handles that appear in
 * the request. We need to remove and free them.
 */
static TPM2_RC
tab_post_flush(tpm_client_t *c, TPM2_HANDLE *hp, uint_t n, void *arg)
{
	tpm_tab_t		*tab = &c->tpmc_tpm->tpm_tab;
	tpm_tab_context_t	*ctx;

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	if (handle_type(*hp) != TPM2_HT_TRANSIENT) {
		return (TPM2_RC_SUCCESS);
	}

	ctx = tab_get_context(tab, c, *hp);

	VERIFY3S(ctx->tctx_state, ==, TPM_CTX_IN_TPM); 

	ctx->tobj_real_handle = 0;

	list_remove(&tab->tab_objects, ctx);
	tab->tab_nobjects--;

	avl_remove(&tab->tab_contexts, ctx);

	tab_free_context(ctx);

	return (TPM2_RC_SUCCESS);	
}

static TPM2_RC
tab_post_handle(tpm_client_t *c, TPM2_HANDLE *hp, uint_t n, void *arg)
{
	tpm_tab_t		*tab = &c->tpmc_tpm->tpm_tab;
	tpm_tab_context_t	*ctx = NULL;

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	if (!is_tab_managed(*hp)) {
		return (TPM2_RC_SUCCESS);
	}

	ctx = tab_new_context(tab, c, *hp);
	avl_add(&tab->tab_contexts, ctx);

	if (is_session(*hp)) {
		list_insert_head(&tab->tab_sessions, ctx);
	} else {
		*hp = ctx->tctx_handle;
		list_insert_head(&tab->tab_objects, ctx);
	}

	return (TPM2_RC_SUCCESS);
}

static TPM2_RC
tab_foreach_handle(tpm_client_t *c, tpm_cmd_t *cmd, uint_t n,
    TPM2_RC (*cb)(tpm_client_t *, TPM2_HANDLE *, uint_t, void *), void *arg)
{
	TPM2_HANDLE	h;
	uint32_t	offset;
	uint_t		i;
	TPM2_RC		rc = TPM2_RC_SUCCESS;

	/*
	 * Handles (when present) always appear immediately after the TPM
	 * header.
	 */
	offset = TPM_HEADER_SIZE;
	for (i = 0; i < n; i++) {
		h = tpm_getbuf32(cmd, offset);
		rc = cb(c, &h, i, arg);
		if (rc != TPM2_RC_SUCCESS) {
			break;
		}

		BE_OUT32(cmd->tcmd_buf + offset, h);
		offset += sizeof (h);
	}

	return (rc);
}

static TPM2_RC
tab_assert_ctx_loaded(tpm_t *tpm, tpm_tab_context_t *ctx,
    tpm_tab_context_t **preserve, uint_t npreserve)
{
	tpm_tab_t		*tab = &tpm->tpm_tab;
	list_t			*active_list;
	uint32_t		*nactive;
	TPM2_HANDLE		newh;
	TPM2_RC			rc = TPM2_RC_SUCCESS;

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	if (ctx->tctx_state == TPM_CTX_IN_TPM) {
		return (TPM2_RC_SUCCESS);
	}

	if (is_session(ctx->tctx_handle)) {
		active_list = &tab->tab_sessions;
		nactive = &tab->tab_nsessions;
	} else {
		active_list = &tab->tab_objects;
		nactive = &tab->tab_nsessions;
	}

retry:
	rc = tab_load_ctx(tpm, ctx);
	switch (rc) {
	case TPM2_RC_SUCCESS:
		break;
	case TPM2_RC_OBJECT_MEMORY:
	case TPM2_RC_MEMORY:
		/*
		 * The TPM should have enough RAM to hold at least 1
		 * object and 1 session (in reality the minimum is larger).
		 * If for some reason we cannot load the context when
		 * nothing is loaded, there's really nothing we can do
		 * but return the error.
		 */
		if (list_is_empty(active_list)) {
			return (rc);
		}

		/* Swap out the oldest object used that's still loaded */
		rc = tab_swapout_ctx(tpm, handle_type(ctx->tctx_handle),
		    preserve, npreserve);
		if (rc != TPM2_RC_SUCCESS) {
			return (rc);
		}

		goto retry;
	default:
		return (rc);
	}

	if (rc != TPM2_RC_SUCCESS) {
		return (rc);
	}

	return (TPM2_RC_SUCCESS);
}

/*
 * Choose the victim for eviction from the TPM. Any contexts found in
 * preserve are skipped (since presumably we want them loaded for the
 * command we're trying to process). If we fail for some reason, we
 * fall back to the last entry.
 */
static tpm_tab_context_t *
tab_choose_evict(tpm_t *tpm, TPM2_HT ht, tpm_tab_context_t **preserve,
    uint_t n)
{
	tpm_tab_t		*tab = &tpm->tpm_tab;
	list_t			*list = NULL;
	tpm_tab_context_t	*ctx;
	uint_t			i;

	switch (ht) {
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		list = &tab->tab_sessions;
		break;
	case TPM2_HT_TRANSIENT:
		list = &tab->tab_objects;
		break;
	default:
		dev_err(tpm->tpm_dip, CE_PANIC, "invalid handle type 0x%x", ht);
	}

	for (ctx = list_tail(list); ctx != NULL; ctx = list_prev(list, ctx)) {
		bool skip = false;

		for (i = 0; i < n; i++) {
			if (preserve[i] == NULL) {
				continue;
			}
			if (preserve[i] == ctx) {
				skip = true;
				break;
			}
		}

		if (!skip) {
			return (ctx);
		}
	}

	return (list_tail(list));
}

static TPM2_RC
tab_swapout_ctx(tpm_t *tpm, TPM2_HT ht, tpm_tab_context_t **preserve,
    uint_t npreserve)
{
	tpm_tab_t		*tab = &tpm->tpm_tab;
	tpm_tab_context_t	*ctx;
	TPM2_RC			rc;

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	ctx = tab_choose_evict(tpm, ht, preserve, npreserve);
	if (ctx == NULL) {
		return (tab_err(TPM2_RC_MEMORY));
	}

	VERIFY(list_link_active(&ctx->tctx_list));
	VERIFY3S(ctx->tctx_state, ==, TPM_CTX_IN_TPM);

	rc = tab_save_ctx(tpm, ctx);
	if (rc != TPM2_RC_SUCCESS) {
		return (rc);
	}

	return (TPM2_RC_SUCCESS);
}

/*
 * h is the handle used by the client (i.e. the virtualized handle for
 * objects).
 */
static tpm_tab_context_t *
tab_get_context(tpm_tab_t *tab, tpm_client_t *c, TPM2_HANDLE h)
{
	tpm_tab_context_t *ctx;
	tpm_tab_context_t node = {
		.tctx_client = c,
		.tctx_handle = h,
	};

	VERIFY(MUTEX_HELD(&tab->tab_lock));

	ctx = avl_find(&tab->tab_contexts, &node, NULL);
	if (ctx == NULL) {
		return (NULL);
	}

	if (ctx->tctx_state != TPM_CTX_IN_TPM) {
		return (ctx);
	}

	/* Move ctx to the front of its respective loaded list. */
	switch (handle_type(h)) {
	case TPM2_HT_TRANSIENT:
		VERIFY(list_link_active(&ctx->tctx_list));
		list_remove(&tab->tab_objects, ctx);
		list_insert_head(&tab->tab_objects, ctx);
		break;
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		VERIFY(list_link_active(&ctx->tctx_list));
		list_remove(&tab->tab_sessions, ctx);
		list_insert_head(&tab->tab_sessions, ctx);
		break;
	default:
		dev_err(c->tpmc_tpm->tpm_dip, CE_PANIC,
		    "invalid handle type 0x%x", handle_type(h));
	}

	return (ctx);
}

/*
 * Remove ctx from any lists or trees before freeing
 */
static void
tab_delete_context(tpm_tab_t *tab, tpm_client_t *c, tpm_tab_context_t *ctx)
{
	VERIFY(MUTEX_HELD(&tab->tab_lock));

	avl_remove(&tab->tab_contexts, ctx);

	switch (handle_type(ctx->tctx_handle)) {
	case TPM2_HT_POLICY_SESSION:
	case TPM2_HT_HMAC_SESSION:
		switch (ctx->tctx_state) {
		case TPM_CTX_IN_TPM:
			list_remove(&tab->tab_sessions, ctx);
			tab->tab_nsessions--;
			break;
		case TPM_CTX_IN_TAB:
		case TPM_CTX_UNLOADED:
			avl_remove(&tab->tab_sessions_by_seq, ctx);
			break;
		}
		break;
	case TPM2_HT_TRANSIENT:
		if (ctx->tctx_state == TPM_CTX_IN_TPM) {
			list_remove(&tab->tab_objects, ctx);
			tab->tab_nobjects--;
		}
		break;
	}

	tab_free_context(ctx);
}

static TPM2_RC
tab_save_ctx(tpm_t *tpm, tpm_tab_context_t *ctx)
{
	tpm_tab_t	*tab = &tpm->tpm_tab;
	tpm_cmd_t 	*cmd = &tpm->tpm_cmd;
	size_t		len, alloc;
	TPM2_RC		rc;
	int		ret = TPM2_RC_SUCCESS;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3S(ctx->tctx_state, ==, TPM_CTX_IN_TPM);

	tpm_cmd_init(cmd, TPM2_CC_ContextSave, TPM2_ST_NO_SESSIONS);
	tpm_cmd_put32(cmd, ctx_real_handle(ctx));

	ret = tpm_exec_cmd(tpm, NULL, cmd);
	if (ret != 0) {
		return (ret);
	}

	if (tpm_cmd_rc(cmd) != TPM2_RC_SUCCESS) {
		return (tab_err(tpm_cmd_rc(cmd)));
	}

	len = tpm_cmdlen(cmd) - TPM_HEADER_SIZE;
	alloc = ctx_size(tpm, ctx->tctx_handle);

	/* ptr should always be large enough to hold the results */
	VERIFY3U(len, <=, alloc);

	bzero(ctx->tctx_data, alloc);
	tpm_cmd_getbuf(cmd, TPM_HEADER_SIZE, len, ctx->tctx_data);
	ctx->tctx_datalen = len;

	if (is_session(ctx->tctx_handle)) {
		/*
		 * Saving a session handle removes most of the state
		 * from memory, but leaves just enough so that it can
		 * be loaded later. We need to update our bookkeeping to
		 * reflect this.
		 */
		list_remove(&tab->tab_sessions, ctx);
		tab->tab_nsessions--;

		avl_add(&tab->tab_sessions_by_seq, ctx);
	} else {
		/*
		 * For transient handles, we also have to issue a flush
		 * to remove the state. The TPM does not require keeping
		 * any state for transient objects before reloading them.
		 */
		tpm_cmd_init(cmd, TPM2_CC_FlushContext, TPM2_ST_NO_SESSIONS);
		tpm_cmd_put32(cmd, ctx_real_handle(ctx));

		ret = tpm_exec_cmd(tpm, NULL, cmd);
		if (ret != 0) {
			return (ret);
		}

		if (tpm_cmd_rc(cmd) != TPM2_RC_SUCCESS) {
			return (tab_err(tpm_cmd_rc(cmd)));
		}

		ctx->tobj_real_handle = 0;

		list_remove(&tab->tab_objects, ctx);
		tab->tab_nobjects--;
	}

	ctx->tctx_state = TPM_CTX_IN_TAB;
	return (TPM2_RC_SUCCESS);
}

static TPM2_RC
tab_load_ctx(tpm_t *tpm, tpm_tab_context_t *ctx)
{
	tpm_cmd_t	*cmd = &tpm->tpm_cmd;
	tpm_tab_t	*tab = &tpm->tpm_tab;
	TPM2_HANDLE	h;
	int		ret;

	VERIFY(MUTEX_HELD(&tpm->tpm_lock));
	VERIFY3S(ctx->tctx_state, !=, TPM_CTX_IN_TPM);

	tpm_cmd_init(cmd, TPM2_CC_ContextLoad, TPM2_ST_NO_SESSIONS);
	tpm_cmd_copy(cmd, ctx->tctx_data, ctx->tctx_datalen);

	ret = tpm_exec_cmd(tpm, NULL, cmd);
	if (tpm_cmd_rc(cmd) != TPM2_RC_SUCCESS) {
		/*
		 * Set the layer to indicate the error was a result of
		 * TAB/RM activity.
		 */
		return (tab_err(tpm_cmd_rc(cmd)));
	}

	/* The handle is the first item after the header */
	h = tpm_getbuf32(cmd, TPM_HEADER_SIZE);

	if (is_session(h)) {
		if (h != ctx->tctx_handle) {
			/*
			 * A very weird situation. Session handles should not
			 * change across loading and unloading. If we get here
			 * they have. It's not really clear what we can do.
			 *
			 * For now we just update the handle value and generate
			 * a warning. That should at least hopefully allow us
			 * to clean up the state when the client closes their
			 * connection.
			 *
			 * XXX: Might it be appropriate to generate an fm
			 * event for this?
			 */
			dev_err(tpm->tpm_dip, CE_WARN,
			    "loading session context resulted in a different "
			    "handle 0x%08x vs expected 0x%08x", h,
			    ctx->tctx_handle);
			ctx->tctx_handle = h;
		}

		avl_remove(&tab->tab_sessions_by_seq, ctx);

		list_insert_head(&tab->tab_sessions, ctx);
		tab->tab_nsessions++;
	} else {
		ctx->tobj_real_handle = h;
		list_insert_head(&tab->tab_objects, ctx);
		tab->tab_nobjects++;
	}

	bzero(ctx->tctx_data, ctx_size(tpm, h));
	ctx->tctx_datalen = 0;
	ctx->tctx_state = TPM_CTX_IN_TPM;

	return (TPM2_RC_SUCCESS);
}

static TPM2_RC
tab_regap(tpm_t *tpm)
{
	tpm_tab_t		*tab = &tpm->tpm_tab;
	tpm_tab_context_t	*ctx;
	TPM2_RC			rc;

	/*
	 * If we were called to regap, there has to be at least one
	 * unloaded session.
	 */
	VERIFY3U(avl_numnodes(&tab->tab_sessions_by_seq), >, 0);

	ctx = avl_last(&tab->tab_sessions_by_seq);

retry:
	/*
	 * To regap, we just load and then unload the oldest unloaded
	 * (but active) session so it's sequence number is updated.
	 */
	rc = tab_load_ctx(tpm, ctx);
	switch (rc) {
	case TPM2_RC_SUCCESS:
		rc = tab_save_ctx(tpm, ctx);
		return ((rc == TPM2_RC_SUCCESS) ? rc : tab_err(rc));
	case TPM2_RC_SESSION_MEMORY:
	case TPM2_RC_MEMORY:
		rc = tab_swapout_ctx(tpm, TPM2_HT_HMAC_SESSION, NULL, 0);
		if (rc != TPM2_RC_SUCCESS) {
			return (tab_err(rc));
		}

		/*
		 * If we run out of sessions contexts to swap out,
		 * tab_swapout_ctx() will fail, and we won't loop endlessly.
		 */
		goto retry;
	default:
		return (tab_err(rc));
	}
}

static tpm_tab_context_t *
tab_new_context(tpm_tab_t *tab, tpm_client_t *c, TPM2_HANDLE real_handle)
{
	tpm_t			*tpm = c->tpmc_tpm;
	tpm_tab_context_t	*ctx;

	VERIFY(MUTEX_HELD(&tab->tab_lock));
	VERIFY(MUTEX_HELD(&c->tpmc_lock));

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);
	ctx->tctx_data = kmem_zalloc(ctx_size(tpm, real_handle), KM_SLEEP);
	ctx->tctx_locality = c->tpmc_locality;

	switch (handle_type(real_handle)) {
	case TPM2_HT_TRANSIENT:
		/*
		 * For now, we implicitly limit the number of objects that
		 * can be created over the course of a single session to
		 * (TPM2_TRANSIENT_LAST - TPM2_TRANSIENT_FIRST) (0xfffffe --
		 * a bit over 16 million). Since every known use of the TPM
		 * currently tends use short lived sessions, this doesn't
		 * seem like it should be a problem in practice. If it is,
		 * we could look to have each client use an id space to
		 * manage the object handle values. For now, we use the
		 * simpler approach.
		 */
		ctx->tctx_handle = TPM2_TRANSIENT_FIRST + c->tpmc_next_hid++;
		if (ctx->tctx_handle > TPM2_TRANSIENT_LAST) {
			tab_free_context(ctx);
			return (NULL);
		}
		ctx->tobj_real_handle = real_handle;
		break;
	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		ctx->tctx_handle = real_handle;
		ctx->ts_client_ctx = kmem_zalloc(ctx_size(tpm, real_handle),
		    KM_SLEEP);
		break;
	default:
		dev_err(tpm->tpm_dip, CE_PANIC, "%s: invalid handle type 0x%x",
		    __func__, handle_type(real_handle));
		break;
	}

	ctx->tctx_state = TPM_CTX_IN_TPM;
	return (ctx);
}

static void
tab_free_context(tpm_tab_context_t *ctx)
{
	tpm_t		*tpm = ctx->tctx_client->tpmc_tpm;
	tpm_tab_t	*tab = &tpm->tpm_tab;
	size_t		size;

	VERIFY(!list_link_active(&ctx->tctx_list));

	/*
	 * We can use the 'virtual' handle to determine the size
	 * since all handles encode the type in the upper 8 bits
	 */
	size = ctx_size(tpm, ctx->tctx_handle);

	bzero(ctx->tctx_data, size);
	kmem_free(ctx->tctx_data, size);

	VERIFY(ctx->tctx_state != TPM_CTX_IN_TPM);

	if (is_session(ctx->tctx_handle)) {
		bzero(ctx->ts_client_ctx, size);
		kmem_free(ctx->ts_client_ctx, size);
	}

	kmem_free(ctx, sizeof (*ctx));
}

static int
tab_cmp_context(const void *a, const void *b)
{
	const tpm_tab_context_t *l = a;
	const tpm_tab_context_t *r = b;
	int			ret;

	if (l->tctx_client->tpmc_minor < r->tctx_client->tpmc_minor) {
		return (-1);
	}
	if (l->tctx_client->tpmc_minor > r->tctx_client->tpmc_minor) {
		return (1);
	}

	if (l->tctx_handle < r->tctx_handle) {
		return (-1);
	}
	if (l->tctx_handle > r->tctx_handle) {
		return (1);
	}

	return (0);
}

static int
tab_cmp_seq(const void *a, const void *b)
{
	const tpm_tab_context_t *l = a;
	const tpm_tab_context_t *r = b;
	uint64_t		l_seq;
	uint64_t		r_seq;

	/*
	 * We should only have session contexts that have been saved off
	 * the TPM. We verify these when inserting, so we just assert them
	 * here.
	 */
	ASSERT(is_session(l->tctx_handle));
	ASSERT3S(l->tctx_state, !=, TPM_CTX_IN_TPM);
	ASSERT(is_session(r->tctx_handle));
	ASSERT3S(r->tctx_state, !=, TPM_CTX_IN_TPM);

	/*
	 * And they should have enough saved data for at least the
	 * sequence value.
	 */
	VERIFY3U(l->tctx_datalen, >, sizeof (l_seq));
	VERIFY3U(r->tctx_datalen, >, sizeof (r_seq));

	l_seq = BE_IN64(l->tctx_data);
	r_seq = BE_IN64(r->tctx_data);

	if (l_seq < r_seq) {
		return (-1);
	}
	if (l_seq > r_seq) {
		return (1);
	}
	return (0);
}	
