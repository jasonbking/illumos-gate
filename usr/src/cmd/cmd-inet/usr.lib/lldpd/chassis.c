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
 * The system's Chassis ID.
 *
 * Neighbors identify the information we send by our chassis id (and each
 * agent's port id), so it should be unique, and stable for as long as
 * possible. Where it comes from is set by the chassis_id_type property
 * (see lldpd.xml):
 *
 *	topo	topo's chassis-id (from SMBIOS, or the PROM on SPARC)
 *	uuid	The SMBIOS system UUID
 *	serial	An SMBIOS serial number (system, then chassis, then
 *		baseboard)
 *	macaddr	The lowest primary MAC address of the physical Ethernet
 *		links (preferring universally administered addresses)
 *	hostid	The hostid, as hostid(1) prints it
 *	local	The chassis_id property
 *	auto	The first of topo, uuid, serial, macaddr, and hostid that's
 *		available (the default)
 *
 * macaddr is sent with the MAC address subtype; everything else is locally
 * assigned. Firmware is often shipped with placeholder values ("To Be
 * Filled By O.E.M.", an all-zero UUID, ...); those are treated as missing.
 *
 * The candidates are gathered once, at startup (when topo is walked), so
 * the chassis id only changes if the configuration does -- not, for
 * example, because a NIC with a lower MAC address was added later.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/ethernet.h>
#include <sys/smbios.h>
#include <sys/sysmacros.h>
#include <libdladm.h>
#include <libdllink.h>

#include "chassis.h"
#include "log.h"

typedef struct chassis_cand {
	bool			cc_valid;
	lldp_chassis_type_t	cc_type;
	uint8_t			cc_id[LLDP_CHASSIS_MAX];
	uint8_t			cc_len;
	const char		*cc_why;	/* If !cc_valid */
} chassis_cand_t;

/* Indexed by lldp_chassis_id_src_t (AUTO and LOCAL are unused) */
static chassis_cand_t chassis_cands[LLDP_CHASSIS_ID_SRC_LOCAL + 1] = {
	[LLDP_CHASSIS_ID_SRC_TOPO] = { .cc_why = "topo has no chassis-id" },
	[LLDP_CHASSIS_ID_SRC_UUID] = { .cc_why = "SMBIOS is unavailable" },
	[LLDP_CHASSIS_ID_SRC_SERIAL] = { .cc_why = "SMBIOS is unavailable" },
	[LLDP_CHASSIS_ID_SRC_MACADDR] = {
	    .cc_why = "no physical Ethernet links" },
	[LLDP_CHASSIS_ID_SRC_HOSTID] = { .cc_why = "no hostid" },
};

/* The order sources are tried for chassis_id_type auto */
static const lldp_chassis_id_src_t chassis_auto_order[] = {
	LLDP_CHASSIS_ID_SRC_TOPO,
	LLDP_CHASSIS_ID_SRC_UUID,
	LLDP_CHASSIS_ID_SRC_SERIAL,
	LLDP_CHASSIS_ID_SRC_MACADDR,
	LLDP_CHASSIS_ID_SRC_HOSTID,
};

/*
 * Values firmware commonly uses instead of a real serial number, compared
 * ignoring case (and leading and trailing whitespace).
 */
static const char *chassis_junk[] = {
	"to be filled by o.e.m.",
	"to be filled by oem",
	"default string",
	"system serial number",
	"chassis serial number",
	"base board serial number",
	"serial number",
	"not available",
	"not specified",
	"not applicable",
	"none",
	"n/a",
	"na",
	"oem",
	"invalid",
	"unknown",
	"0123456789",
	"123456789",
	"1234567890",
};

/*
 * Copy s, trimmed of leading and trailing whitespace, to buf. Returns the
 * length.
 */
static size_t
str_trim(const char *s, char *buf, size_t buflen)
{
	size_t len;

	while (isspace((uchar_t)*s))
		s++;
	len = strlen(s);
	while (len > 0 && isspace((uchar_t)s[len - 1]))
		len--;
	len = MIN(len, buflen - 1);
	(void) memcpy(buf, s, len);
	buf[len] = '\0';
	return (len);
}

/*
 * Is s missing, or a placeholder rather than a real identifier: empty,
 * a known placeholder, or a single repeated character ("00000000",
 * "XXXXXXXX", "........")?
 */
bool
chassis_str_junk(const char *s)
{
	char	buf[LLDP_CHASSIS_MAX + 1];
	size_t	len;
	bool	same = true;

	if (s == NULL)
		return (true);

	len = str_trim(s, buf, sizeof (buf));
	if (len == 0)
		return (true);

	for (size_t i = 0; i < ARRAY_SIZE(chassis_junk); i++) {
		if (strcasecmp(buf, chassis_junk[i]) == 0)
			return (true);
	}

	for (size_t i = 1; i < len; i++) {
		if (buf[i] != buf[0]) {
			same = false;
			break;
		}
	}
	return (same && len > 1);
}

/*
 * Is a (16 byte) SMBIOS UUID a placeholder: all one value (e.g. all zero
 * or all 0xff), or the 03000200-0400-0500-0006-000700080009 that several
 * vendors' firmware ships with?
 */
bool
chassis_uuid_junk(const uint8_t *u)
{
	static const uint8_t seq[16] = {
		0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
		0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09
	};
	bool same = true;

	for (uint_t i = 1; i < 16; i++) {
		if (u[i] != u[0]) {
			same = false;
			break;
		}
	}
	return (same || memcmp(u, seq, sizeof (seq)) == 0);
}

static void
cand_set(lldp_chassis_id_src_t src, lldp_chassis_type_t type,
    const void *id, size_t len)
{
	chassis_cand_t *cc = &chassis_cands[src];

	cc->cc_valid = true;
	cc->cc_type = type;
	cc->cc_len = MIN(len, sizeof (cc->cc_id));
	(void) memcpy(cc->cc_id, id, cc->cc_len);
	cc->cc_why = NULL;
}

/* A string candidate, if it isn't a placeholder */
static bool
cand_set_str(lldp_chassis_id_src_t src, const char *s)
{
	char buf[LLDP_CHASSIS_MAX + 1];

	if (chassis_str_junk(s))
		return (false);

	cand_set(src, LLDP_CHASSIS_LOCAL, buf, str_trim(s, buf, sizeof (buf)));
	return (true);
}

/*
 * topo's chassis-id (from the root of the hc scheme), if it has one. On
 * x86, this is (normally) the SMBIOS system serial number.
 */
void
chassis_set_topo(const char *csn)
{
	if (csn == NULL)
		return;

	if (!cand_set_str(LLDP_CHASSIS_ID_SRC_TOPO, csn)) {
		chassis_cands[LLDP_CHASSIS_ID_SRC_TOPO].cc_why =
		    "topo's chassis-id is a placeholder";
	}
}

/*
 * The SMBIOS system UUID. Since SMBIOS 2.6, the first three fields are
 * little-endian (before, they were generally treated as big-endian, as in
 * RFC 4122); we format it as dmidecode and smbios(8)'s 'endian-corrected'
 * UUID do, so it matches what other tools show.
 */
static void
chassis_smbios_uuid(smbios_hdl_t *shp)
{
	chassis_cand_t		*cc = &chassis_cands[LLDP_CHASSIS_ID_SRC_UUID];
	smbios_system_t		sys;
	smbios_version_t	v;
	const uint8_t		*u;
	char			buf[37];
	bool			le;

	if (smbios_info_system(shp, &sys) == -1 || sys.smbs_uuid == NULL ||
	    sys.smbs_uuidlen < 16) {
		cc->cc_why = "SMBIOS has no system UUID";
		return;
	}

	u = sys.smbs_uuid;
	if (chassis_uuid_junk(u)) {
		cc->cc_why = "the SMBIOS system UUID is a placeholder";
		return;
	}

	smbios_info_smbios_version(shp, &v);
	le = v.smbv_major > 2 || (v.smbv_major == 2 && v.smbv_minor >= 6);

	(void) snprintf(buf, sizeof (buf),
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x",
	    u[le ? 3 : 0], u[le ? 2 : 1], u[le ? 1 : 2], u[le ? 0 : 3],
	    u[le ? 5 : 4], u[le ? 4 : 5], u[le ? 7 : 6], u[le ? 6 : 7],
	    u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);

	cand_set(LLDP_CHASSIS_ID_SRC_UUID, LLDP_CHASSIS_LOCAL, buf,
	    strlen(buf));
}

/* The first SMBIOS serial number that isn't a placeholder */
static void
chassis_smbios_serial(smbios_hdl_t *shp)
{
	static const uint_t types[] = {
		SMB_TYPE_SYSTEM, SMB_TYPE_CHASSIS, SMB_TYPE_BASEBOARD
	};

	for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
		smbios_struct_t	st;
		smbios_info_t	info;

		if (smbios_lookup_type(shp, types[i], &st) == -1 ||
		    smbios_info_common(shp, st.smbstr_id, &info) == -1) {
			continue;
		}
		if (cand_set_str(LLDP_CHASSIS_ID_SRC_SERIAL, info.smbi_serial))
			return;
	}

	chassis_cands[LLDP_CHASSIS_ID_SRC_SERIAL].cc_why =
	    "SMBIOS has no serial number (or only placeholders)";
}

typedef struct mac_walk {
	uint8_t		mw_addr[ETHERADDRL];
	size_t		mw_len;
	bool		mw_found;
} mac_walk_t;

/* Universally administered addresses sort before local ones */
static int
mac_cmp(const uint8_t *a, const uint8_t *b, size_t len)
{
	bool la = (a[0] & 0x02) != 0, lb = (b[0] & 0x02) != 0;

	if (la != lb)
		return (la ? 1 : -1);
	return (memcmp(a, b, len));
}

static boolean_t
mac_walk_addr(void *arg, dladm_macaddr_attr_t *attr)
{
	static const uint8_t zero[ETHERADDRL] = { 0 };
	mac_walk_t *mw = arg;

	/* Slot 0 is the link's primary address; the rest are extra slots */
	if (attr->ma_slot != 0)
		return (B_TRUE);

	if (attr->ma_addrlen != ETHERADDRL ||
	    memcmp(attr->ma_addr, zero, ETHERADDRL) == 0 ||
	    (attr->ma_addr[0] & 0x01) != 0) {
		return (B_FALSE);
	}

	if (!mw->mw_found ||
	    mac_cmp(attr->ma_addr, mw->mw_addr, ETHERADDRL) < 0) {
		(void) memcpy(mw->mw_addr, attr->ma_addr, ETHERADDRL);
		mw->mw_len = ETHERADDRL;
		mw->mw_found = true;
	}
	return (B_FALSE);
}

static int
mac_walk_link(dladm_handle_t dlh, datalink_id_t linkid, void *arg)
{
	(void) dladm_walk_macaddr(dlh, linkid, arg, mac_walk_addr);
	return (DLADM_WALK_CONTINUE);
}

static void
chassis_macaddr(dladm_handle_t dlh)
{
	mac_walk_t mw = { 0 };

	if (dlh == NULL)
		return;

	(void) dladm_walk_datalink_id(mac_walk_link, dlh, &mw,
	    DATALINK_CLASS_PHYS, DL_ETHER, DLADM_OPT_ACTIVE);
	if (mw.mw_found) {
		cand_set(LLDP_CHASSIS_ID_SRC_MACADDR, LLDP_CHASSIS_MACADDR,
		    mw.mw_addr, mw.mw_len);
	}
}

static void
chassis_hostid(void)
{
	long	id = gethostid();
	char	buf[32];

	if (id == 0 || id == -1)
		return;

	/* As hostid(1) prints it */
	(void) snprintf(buf, sizeof (buf), "%08lx", (ulong_t)id & 0xffffffffUL);
	cand_set(LLDP_CHASSIS_ID_SRC_HOSTID, LLDP_CHASSIS_LOCAL, buf,
	    strlen(buf));
}

static void
chassis_log_cand(struct log *l, lldp_chassis_id_src_t src)
{
	const chassis_cand_t	*cc = &chassis_cands[src];
	lldp_chassis_t		c = { 0 };
	char			buf[LLDP_CHASSIS_MAX * 4 + 1];

	if (!cc->cc_valid) {
		log_debug(l, "chassis id source unavailable",
		    LOG_T_STRING, "chassis_id_type",
		    lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE, src),
		    LOG_T_STRING, "reason", cc->cc_why,
		    LOG_T_END);
		return;
	}

	c.llc_type = cc->cc_type;
	c.llc_len = cc->cc_len;
	(void) memcpy(c.llc_id, cc->cc_id, cc->cc_len);
	(void) lldp_chassis_str(&c, buf, sizeof (buf));
	log_debug(l, "chassis id source",
	    LOG_T_STRING, "chassis_id_type",
	    lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE, src),
	    LOG_T_STRING, "chassis_id", buf,
	    LOG_T_END);
}

/*
 * Gather the candidates other than topo's (see chassis_set_topo()). Called
 * once, at startup, while we still have our privileges.
 */
void
chassis_init(struct log *l, dladm_handle_t dlh)
{
	smbios_hdl_t	*shp;
	int		err;

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, &err)) != NULL) {
		chassis_smbios_uuid(shp);
		chassis_smbios_serial(shp);
		smbios_close(shp);
	} else {
		log_debug(l, "failed to open SMBIOS",
		    LOG_T_STRING, "errmsg", smbios_errmsg(err),
		    LOG_T_END);
	}

	chassis_macaddr(dlh);
	chassis_hostid();

	for (size_t i = 0; i < ARRAY_SIZE(chassis_auto_order); i++)
		chassis_log_cand(l, chassis_auto_order[i]);
}

static void
chassis_use(lldp_chassis_t *c, const chassis_cand_t *cc)
{
	(void) memset(c, '\0', sizeof (*c));
	c->llc_type = cc->cc_type;
	c->llc_len = cc->cc_len;
	(void) memcpy(c->llc_id, cc->cc_id, cc->cc_len);
}

/*
 * Choose the chassis id for chassis_id_type want (and, for local, the
 * chassis_id property local), and set c to it. If want isn't available, we
 * fall back to auto. Returns the source used.
 */
lldp_chassis_id_src_t
chassis_select(struct log *l, lldp_chassis_id_src_t want, const char *local,
    lldp_chassis_t *c)
{
	const char *why;

	switch (want) {
	case LLDP_CHASSIS_ID_SRC_AUTO:
		break;

	case LLDP_CHASSIS_ID_SRC_LOCAL: {
		char	buf[LLDP_CHASSIS_MAX + 1];
		size_t	len = 0;

		if (local != NULL)
			len = str_trim(local, buf, sizeof (buf));
		if (len > 0) {
			(void) memset(c, '\0', sizeof (*c));
			c->llc_type = LLDP_CHASSIS_LOCAL;
			c->llc_len = len;
			(void) memcpy(c->llc_id, buf, len);
			return (want);
		}

		log_warn(l, "chassis_id_type is local, but chassis_id isn't "
		    "set; using auto", LOG_T_END);
		break;
	}

	case LLDP_CHASSIS_ID_SRC_TOPO:
	case LLDP_CHASSIS_ID_SRC_UUID:
	case LLDP_CHASSIS_ID_SRC_SERIAL:
	case LLDP_CHASSIS_ID_SRC_MACADDR:
	case LLDP_CHASSIS_ID_SRC_HOSTID:
		if (chassis_cands[want].cc_valid) {
			chassis_use(c, &chassis_cands[want]);
			return (want);
		}

		why = chassis_cands[want].cc_why;
		log_warn(l, "chassis id type unavailable; using auto",
		    LOG_T_STRING, "chassis_id_type",
		    lldp_prop_name(LLDP_PROP_CHASSIS_ID_TYPE, want),
		    LOG_T_STRING, "reason", (why != NULL) ? why : "",
		    LOG_T_END);
		break;

	default:
		log_warn(l, "invalid chassis id type; using auto",
		    LOG_T_UINT32, "chassis_id_type", (uint32_t)want,
		    LOG_T_END);
		break;
	}

	for (size_t i = 0; i < ARRAY_SIZE(chassis_auto_order); i++) {
		lldp_chassis_id_src_t src = chassis_auto_order[i];

		if (chassis_cands[src].cc_valid) {
			chassis_use(c, &chassis_cands[src]);
			return (src);
		}
	}

	/*
	 * Nothing at all (no hostid, even): the best we can do is the
	 * hostname, which at least distinguishes us from our neighbors. It's
	 * reported as locally configured.
	 */
	char host[MAXHOSTNAMELEN] = { 0 };

	(void) gethostname(host, sizeof (host));
	log_warn(l, "no chassis id source available; using the hostname",
	    LOG_T_STRING, "hostname", host,
	    LOG_T_END);

	(void) memset(c, '\0', sizeof (*c));
	c->llc_type = LLDP_CHASSIS_LOCAL;
	c->llc_len = MIN(strlen(host), sizeof (c->llc_id));
	(void) memcpy(c->llc_id, host, c->llc_len);
	return (LLDP_CHASSIS_ID_SRC_LOCAL);
}
