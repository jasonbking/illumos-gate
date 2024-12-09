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
 * Copyright 2026 Jason King
 */

/*
 * Client side of the lldpd door protocol (see lldp_door.h).
 */

#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <liblldp.h>

#include "lldp_door.h"

/* Initial size (in entries) of the array returned by lldp_get_neighbors() */
#define	NBRS_CHUNK	16

static int
lldp_door_open(int *fdp)
{
	const char *path = getenv(LLDP_DOOR_ENV);
	int fd;

	if (path == NULL)
		path = LLDP_DOOR_PATH;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno);

	*fdp = fd;
	return (0);
}

/*
 * Issue a single request. On success, *dap describes the reply. If the
 * reply didn't fit in the caller's buffer, the door framework will have
 * mapped a new buffer (dap->rbuf != rbuf), which the caller must munmap().
 */
static int
lldp_door_call(int fd, lldp_door_req_t *req, char *rbuf, size_t rsize,
    door_arg_t *dap)
{
	for (;;) {
		(void) memset(dap, '\0', sizeof (*dap));
		dap->data_ptr = (char *)req;
		dap->data_size = sizeof (*req);
		dap->rbuf = rbuf;
		dap->rsize = rsize;

		if (door_call(fd, dap) == 0)
			return (0);

		if (errno != EINTR)
			return (errno);
	}
}

static int
nbrs_append(lldp_neighbor_t **nbrsp, uint_t *nump, uint_t *allocp,
    const lldp_door_nbr_t *rec, const uint8_t *pdu)
{
	lldp_neighbor_t *n;

	if (*nump == *allocp) {
		uint_t newalloc = (*allocp == 0) ? NBRS_CHUNK : *allocp * 2;
		lldp_neighbor_t *newn;

		if (newalloc < *allocp)
			return (EOVERFLOW);

		newn = recallocarray(*nbrsp, *allocp, newalloc,
		    sizeof (lldp_neighbor_t));
		if (newn == NULL)
			return (errno);

		*nbrsp = newn;
		*allocp = newalloc;
	}

	n = &(*nbrsp)[*nump];
	(void) memset(n, '\0', sizeof (*n));

	(void) memcpy(n->ln_link, rec->ldn_link, sizeof (n->ln_link));
	n->ln_link[sizeof (n->ln_link) - 1] = '\0';
	n->ln_ttl = rec->ldn_ttl;
	n->ln_pdu_len = rec->ldn_pdu_len;

	if (n->ln_pdu_len > 0) {
		n->ln_pdu = malloc(n->ln_pdu_len);
		if (n->ln_pdu == NULL)
			return (errno);
		(void) memcpy(n->ln_pdu, pdu, n->ln_pdu_len);
	}

	(*nump)++;
	return (0);
}

/*
 * Validate and consume a single page of neighbors. On success, *morep is
 * set if there are additional pages, and *nextp to the cursor to use for
 * the next request.
 */
static int
process_reply(const char *data, size_t len, lldp_neighbor_t **nbrsp,
    uint_t *nump, uint_t *allocp, bool *morep, lldp_door_cursor_t *nextp)
{
	lldp_door_reply_t	rep;
	size_t			off;
	int			ret;

	if (data == NULL || len < sizeof (rep))
		return (EPROTO);

	/* Copy out headers, so we don't depend on the reply's alignment */
	(void) memcpy(&rep, data, sizeof (rep));

	if (rep.ldrp_version != LLDP_DOOR_VERSION)
		return (EPROTO);
	if (rep.ldrp_error != 0)
		return (rep.ldrp_error);

	off = LLDP_DOOR_REC_OFF;
	for (uint32_t i = 0; i < rep.ldrp_count; i++) {
		lldp_door_nbr_t rec;

		if (off > len || len - off < sizeof (rec))
			return (EPROTO);

		(void) memcpy(&rec, data + off, sizeof (rec));

		if (rec.ldn_reclen < LLDP_DOOR_NBR_RECLEN(rec.ldn_pdu_len) ||
		    rec.ldn_reclen > len - off)
			return (EPROTO);

		ret = nbrs_append(nbrsp, nump, allocp, &rec,
		    (const uint8_t *)data + off + sizeof (rec));
		if (ret != 0)
			return (ret);

		off += rec.ldn_reclen;
	}

	*morep = (rep.ldrp_flags & LLDP_DOOR_F_MORE) != 0;

	/*
	 * A page that claims there's more data but returned nothing would
	 * have us loop forever.
	 */
	if (*morep && rep.ldrp_count == 0)
		return (EPROTO);

	*nextp = rep.ldrp_next;
	return (0);
}

int
lldp_get_neighbors(const char *link, lldp_neighbor_t **nbrsp, uint_t *nump)
{
	lldp_door_req_t		req = { 0 };
	lldp_neighbor_t		*nbrs = NULL;
	uint_t			num = 0;
	uint_t			alloc = 0;
	char			*rbuf = NULL;
	int			fd = -1;
	int			ret;
	bool			more;

	if (nbrsp == NULL || nump == NULL)
		return (EINVAL);

	req.ldrq_version = LLDP_DOOR_VERSION;
	req.ldrq_cmd = LLDP_DOOR_CMD_NEIGHBORS;
	if (link != NULL &&
	    strlcpy(req.ldrq_link, link, sizeof (req.ldrq_link)) >=
	    sizeof (req.ldrq_link)) {
		return (ENAMETOOLONG);
	}

	rbuf = malloc(LLDP_DOOR_REPLY_MAX);
	if (rbuf == NULL)
		return (errno);

	if ((ret = lldp_door_open(&fd)) != 0)
		goto done;

	do {
		door_arg_t da;

		more = false;

		ret = lldp_door_call(fd, &req, rbuf, LLDP_DOOR_REPLY_MAX, &da);
		if (ret != 0)
			goto done;

		ret = process_reply(da.data_ptr, da.data_size, &nbrs, &num,
		    &alloc, &more, &req.ldrq_cursor);

		if (da.rbuf != rbuf)
			(void) munmap(da.rbuf, da.rsize);

		if (ret != 0)
			goto done;
	} while (more);

done:
	if (fd >= 0)
		(void) close(fd);
	free(rbuf);

	if (ret != 0) {
		lldp_neighbors_free(nbrs, num);
		return (ret);
	}

	*nbrsp = nbrs;
	*nump = num;
	return (0);
}

void
lldp_neighbors_free(lldp_neighbor_t *nbrs, uint_t num)
{
	if (nbrs == NULL)
		return;

	for (uint_t i = 0; i < num; i++)
		free(nbrs[i].ln_pdu);
	free(nbrs);
}
