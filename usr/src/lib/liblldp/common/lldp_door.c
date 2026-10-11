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

/* Initial size (in entries) of the arrays we return */
#define	ARRAY_CHUNK	16

/*
 * Consumes the ldrp_count records (in data, of len bytes) of a single reply
 * page. Returns 0 or an errno value.
 */
typedef int (*lldp_door_page_f)(const char *data, size_t len,
    uint32_t count, void *arg);

static int
lldp_door_open(int *fdp)
{
	const char *path = getenv(LLDP_DOOR_ENV);
	int fd;

	if (path == NULL)
		path = LLDP_DOOR_PATH;

	/*
	 * If there's no door file, lldpd isn't running. Report that as
	 * ECONNREFUSED, since ENOENT means there's no such agent.
	 */
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return ((errno == ENOENT) ? ECONNREFUSED : errno);

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

		/*
		 * EBADF: the file isn't (or is no longer) a door, i.e.
		 * lldpd exited without removing it.
		 */
		if (errno == EBADF)
			return (ECONNREFUSED);
		if (errno != EINTR)
			return (errno);
	}
}

/*
 * Make room for one more entry (each of size bytes) in the array *arrp,
 * which holds *nump entries and has room for *allocp.
 */
static int
array_grow(void *arrp, uint_t *nump, uint_t *allocp, size_t size)
{
	void **ap = arrp;
	uint_t newalloc;
	void *newa;

	if (*nump < *allocp)
		return (0);

	newalloc = (*allocp == 0) ? ARRAY_CHUNK : *allocp * 2;
	if (newalloc < *allocp)
		return (EOVERFLOW);

	newa = recallocarray(*ap, *allocp, newalloc, size);
	if (newa == NULL)
		return (errno);

	*ap = newa;
	*allocp = newalloc;
	return (0);
}

/*
 * Validate the header of a single reply page, and hand its records to
 * the page function. On success, *morep is set if there are additional
 * pages, and *nextp to the cursor to use for the next request.
 */
static int
process_reply(const char *data, size_t len, lldp_door_page_f func,
    void *arg, bool *morep, lldp_door_cursor_t *nextp)
{
	lldp_door_reply_t	rep;
	int			ret;

	if (data == NULL || len < sizeof (rep))
		return (EPROTO);

	/* Copy out headers, so we don't depend on the reply's alignment */
	(void) memcpy(&rep, data, sizeof (rep));

	if (rep.ldrp_version != LLDP_DOOR_VERSION)
		return (EPROTO);
	if (rep.ldrp_error != 0)
		return (rep.ldrp_error);
	if (len < LLDP_DOOR_REC_OFF)
		return (EPROTO);

	ret = func(data + LLDP_DOOR_REC_OFF, len - LLDP_DOOR_REC_OFF,
	    rep.ldrp_count, arg);
	if (ret != 0)
		return (ret);

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

/*
 * Issue cmd (for link, or all agents if NULL), following the cursor until
 * every page has been passed to func.
 */
static int
lldp_door_request(lldp_door_cmd_t cmd, const char *link,
    lldp_door_page_f func, void *arg)
{
	lldp_door_req_t		req = { 0 };
	char			*rbuf = NULL;
	int			fd = -1;
	int			ret;
	bool			more;

	req.ldrq_version = LLDP_DOOR_VERSION;
	req.ldrq_cmd = cmd;
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

		ret = process_reply(da.data_ptr, da.data_size, func, arg,
		    &more, &req.ldrq_cursor);

		if (da.rbuf != rbuf)
			(void) munmap(da.rbuf, da.rsize);
	} while (ret == 0 && more);

done:
	if (fd >= 0)
		(void) close(fd);
	free(rbuf);
	return (ret);
}

typedef struct nbrs_arg {
	lldp_neighbor_t	*na_nbrs;
	uint_t		na_num;
	uint_t		na_alloc;
} nbrs_arg_t;

static int
nbrs_append(nbrs_arg_t *na, const lldp_door_nbr_t *rec, const char *pdu)
{
	lldp_neighbor_t *n;
	int ret;

	ret = array_grow(&na->na_nbrs, &na->na_num, &na->na_alloc,
	    sizeof (lldp_neighbor_t));
	if (ret != 0)
		return (ret);

	n = &na->na_nbrs[na->na_num];
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

	na->na_num++;
	return (0);
}

static int
nbrs_page(const char *data, size_t len, uint32_t count, void *arg)
{
	size_t off = 0;
	int ret;

	for (uint32_t i = 0; i < count; i++) {
		lldp_door_nbr_t rec;

		if (off > len || len - off < sizeof (rec))
			return (EPROTO);

		(void) memcpy(&rec, data + off, sizeof (rec));

		if (rec.ldn_reclen < LLDP_DOOR_NBR_RECLEN(rec.ldn_pdu_len) ||
		    rec.ldn_reclen > len - off)
			return (EPROTO);

		ret = nbrs_append(arg, &rec, data + off + sizeof (rec));
		if (ret != 0)
			return (ret);

		off += rec.ldn_reclen;
	}

	return (0);
}

int
lldp_get_neighbors(const char *link, lldp_neighbor_t **nbrsp, uint_t *nump)
{
	nbrs_arg_t	na = { 0 };
	int		ret;

	if (nbrsp == NULL || nump == NULL)
		return (EINVAL);

	ret = lldp_door_request(LLDP_DOOR_CMD_NEIGHBORS, link, nbrs_page, &na);
	if (ret != 0) {
		lldp_neighbors_free(na.na_nbrs, na.na_num);
		return (ret);
	}

	*nbrsp = na.na_nbrs;
	*nump = na.na_num;
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

typedef struct stats_arg {
	lldp_stats_t	*sa_stats;
	uint_t		sa_num;
	uint_t		sa_alloc;
} stats_arg_t;

static int
stats_page(const char *data, size_t len, uint32_t count, void *arg)
{
	stats_arg_t *sa = arg;
	int ret;

	if (count > len / sizeof (lldp_door_stats_t))
		return (EPROTO);

	for (uint32_t i = 0; i < count; i++) {
		lldp_door_stats_t rec;
		lldp_stats_t *s;

		(void) memcpy(&rec, data + i * sizeof (rec), sizeof (rec));

		ret = array_grow(&sa->sa_stats, &sa->sa_num, &sa->sa_alloc,
		    sizeof (lldp_stats_t));
		if (ret != 0)
			return (ret);

		s = &sa->sa_stats[sa->sa_num++];
		(void) memset(s, '\0', sizeof (*s));
		(void) memcpy(s->ls_link, rec.lds_link, sizeof (s->ls_link));
		s->ls_link[sizeof (s->ls_link) - 1] = '\0';
		s->ls_stats = rec.lds_stats;
	}

	return (0);
}

int
lldp_get_stats(const char *link, lldp_stats_t **statsp, uint_t *nump)
{
	stats_arg_t	sa = { 0 };
	int		ret;

	if (statsp == NULL || nump == NULL)
		return (EINVAL);

	ret = lldp_door_request(LLDP_DOOR_CMD_STATS, link, stats_page, &sa);
	if (ret != 0) {
		lldp_stats_free(sa.sa_stats, sa.sa_num);
		return (ret);
	}

	*statsp = sa.sa_stats;
	*nump = sa.sa_num;
	return (0);
}

void
lldp_stats_free(lldp_stats_t *stats, uint_t num __unused)
{
	free(stats);
}
