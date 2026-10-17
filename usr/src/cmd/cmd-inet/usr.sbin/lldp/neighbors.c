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
 * lldp show-neighbors [-w] [-v | -x | [-p] -o field[,...]] [link]
 *
 * Shows the neighbors lldpd has learned on each link, in one of three
 * forms:
 *
 *	(default)	One line per neighbor (via libofmt, so -o and -p work as
 *			for the other datalink tools).
 *	-v		Every TLV of each neighbor's LLDPDU, decoded.
 *	-x		Each TLV of each neighbor's LLDPDU, in hex.
 *
 * With -w, they're shown again (in the same form) whenever they change.
 *
 * Everything in an LLDPDU comes from the network, so every string from a
 * PDU is displayed via liblldp, which escapes anything that isn't
 * printable (lldp_str_print() and friends).
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

#include "lldp.h"

/* A neighbor, with its PDU decoded */
typedef struct nbr {
	const lldp_neighbor_t	*n_nb;
	lldp_pdu_t		*n_pdu;	/* NULL if it couldn't be parsed */
	char			n_link[MAXLINKNAMELEN];	/* Datalink name */
} nbr_t;

/* Large enough for any string from a PDU, escaped (4 bytes per byte) */
#define	STRBUF_LEN	(4 * 512 + 1)

/* In the default (summary) view, only the host part of the system name */
static bool short_sysname;

static void
str_print(const lldp_str_t *s, char *buf, size_t buflen, uint_t flags)
{
	(void) lldp_str_print(s, buf, buflen, flags);
}

/* Write len bytes as hex ("00 0f 04") */
static void
hex_print(const uint8_t *v, size_t len, char *buf, size_t buflen)
{
	size_t off = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (size_t i = 0; i < len && off < buflen; i++) {
		int n = snprintf(buf + off, buflen - off, "%s%02x",
		    (i > 0) ? " " : "", v[i]);
		if (n < 0)
			break;
		off += n;
	}
}

/*
 * The enabled capabilities, as letters (the key is in 'lldp help', and
 * lldp(8)).
 */
static const struct {
	lldp_cap_t	cl_cap;
	char		cl_letter;
} cap_letters[] = {
	{ LLDP_CAP_MAC_BRIDGE,	'B' },
	{ LLDP_CAP_ROUTER,	'R' },
	{ LLDP_CAP_AP,		'W' },
	{ LLDP_CAP_PHONE,	'T' },
	{ LLDP_CAP_DOCSIS,	'D' },
	{ LLDP_CAP_STATION,	'S' },
	{ LLDP_CAP_REPEATER,	'r' },
	{ LLDP_CAP_OTHER,	'O' },
	{ LLDP_CAP_CVLAN,	'C' },
	{ LLDP_CAP_SVLAN,	's' },
	{ LLDP_CAP_TPMR,	't' },
};

static void
caps_letters(lldp_cap_t caps, char *buf, size_t buflen)
{
	size_t n = 0;

	for (size_t i = 0; i < ARRAY_SIZE(cap_letters) && n + 1 < buflen;
	    i++) {
		if (caps & cap_letters[i].cl_cap)
			buf[n++] = cap_letters[i].cl_letter;
	}
	if (buflen > 0)
		buf[n] = '\0';
}

/*
 * The host part of a system name that looks like a domain name (e.g.
 * 'sw1' for 'sw1.example.com'); anything else is left alone.
 */
static void
short_name(char *name)
{
	char *dot = NULL;

	for (char *p = name; *p != '\0'; p++) {
		if (!isalnum((unsigned char)*p) && *p != '-' && *p != '.')
			return;
		if (*p == '.' && dot == NULL)
			dot = p;
	}

	if (dot != NULL && dot != name)
		*dot = '\0';
}

static void
mgmt_list(const lldp_pdu_t *pdu, char *buf, size_t buflen)
{
	size_t off = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (uint_t i = 0; i < pdu->lp_nmgmt && off + 1 < buflen; i++) {
		if (i > 0)
			buf[off++] = ',';
		off += lldp_mgmt_addr_str(&pdu->lp_mgmt[i], buf + off,
		    buflen - off);
		off = MIN(off, buflen - 1);
	}
}

static void
vlan_list(const lldp_pdu_t *pdu, char *buf, size_t buflen)
{
	size_t off = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (uint_t i = 0; i < pdu->lp_nvlan_names && off < buflen; i++) {
		int n = snprintf(buf + off, buflen - off, "%s%u",
		    (i > 0) ? "," : "", pdu->lp_vlan_names[i].lvn_vid);
		if (n < 0)
			break;
		off += n;
	}
}

/*
 * The fields of the default view. Field names (like subcommand names) are
 * not translated.
 */
typedef enum nbr_field {
	NF_LINK,
	NF_DEVICE,
	NF_SYSNAME,
	NF_CHASSIS,
	NF_CHASSIS_TYPE,
	NF_PORT,
	NF_PORT_TYPE,
	NF_PORTDESC,
	NF_SYSDESC,
	NF_CAPS,
	NF_SYSCAPS,
	NF_ENABLED_CAPS,
	NF_MGMTADDR,
	NF_TTL,
	NF_EXPIRES,
	NF_PVID,
	NF_VLANS,
	NF_MAX_FRAME,
	NF_MAU,
} nbr_field_t;

#define	NBR_DEFAULT_FIELDS	"link,sysname,chassis,port,caps,expires"

static boolean_t
nbr_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const nbr_t		*n = arg->ofmt_cbarg;
	const lldp_pdu_t	*pdu = n->n_pdu;
	const char		*s;
	char			t[LLDP_TYPESTR_LEN];

	buf[0] = '\0';

	switch (arg->ofmt_id) {
	case NF_LINK:
		(void) strlcpy(buf, n->n_link, buflen);
		return (B_TRUE);
	case NF_DEVICE:
		(void) strlcpy(buf, n->n_nb->ln_link, buflen);
		return (B_TRUE);
	case NF_EXPIRES:
		(void) snprintf(buf, buflen, "%u", n->n_nb->ln_ttl);
		return (B_TRUE);
	default:
		break;
	}

	/* Everything else comes from the PDU; an unparsable one shows '--' */
	if (pdu == NULL)
		return (B_TRUE);

	switch (arg->ofmt_id) {
	case NF_SYSNAME:
		if (pdu->lp_present & LLDP_PDU_SYS_NAME) {
			str_print(&pdu->lp_sys_name, buf, buflen, 0);
			if (short_sysname)
				short_name(buf);
		}
		break;
	case NF_CHASSIS:
		(void) lldp_chassis_str(&pdu->lp_chassis, buf, buflen);
		break;
	case NF_CHASSIS_TYPE:
		(void) strlcpy(buf, lldp_chassis_typestr(
		    pdu->lp_chassis.llc_type, t, sizeof (t)), buflen);
		break;
	case NF_PORT:
		(void) lldp_port_str(&pdu->lp_port, buf, buflen);
		break;
	case NF_PORT_TYPE:
		(void) strlcpy(buf, lldp_port_typestr(pdu->lp_port.llp_type,
		    t, sizeof (t)), buflen);
		break;
	case NF_PORTDESC:
		if (pdu->lp_present & LLDP_PDU_PORT_DESC)
			str_print(&pdu->lp_port_desc, buf, buflen, 0);
		break;
	case NF_SYSDESC:
		if (pdu->lp_present & LLDP_PDU_SYS_DESC)
			str_print(&pdu->lp_sys_desc, buf, buflen, 0);
		break;
	case NF_CAPS:
		if (pdu->lp_present & LLDP_PDU_SYS_CAP)
			caps_letters(pdu->lp_en_caps, buf, buflen);
		break;
	case NF_SYSCAPS:
		if (pdu->lp_present & LLDP_PDU_SYS_CAP)
			(void) lldp_caps_str(pdu->lp_sys_caps, buf, buflen);
		break;
	case NF_ENABLED_CAPS:
		if (pdu->lp_present & LLDP_PDU_SYS_CAP)
			(void) lldp_caps_str(pdu->lp_en_caps, buf, buflen);
		break;
	case NF_MGMTADDR:
		mgmt_list(pdu, buf, buflen);
		break;
	case NF_TTL:
		(void) snprintf(buf, buflen, "%u", pdu->lp_ttl);
		break;
	case NF_PVID:
		if (pdu->lp_present & LLDP_PDU_PVID)
			(void) snprintf(buf, buflen, "%u", pdu->lp_pvid);
		break;
	case NF_VLANS:
		vlan_list(pdu, buf, buflen);
		break;
	case NF_MAX_FRAME:
		if (pdu->lp_present & LLDP_PDU_MAX_FRAME)
			(void) snprintf(buf, buflen, "%u", pdu->lp_max_frame);
		break;
	case NF_MAU:
		if ((pdu->lp_present & LLDP_PDU_PHYCFG) == 0)
			break;
		if ((s = lldp_mau_str(pdu->lp_phycfg.lpc_mau, NULL)) != NULL)
			(void) strlcpy(buf, s, buflen);
		else if (pdu->lp_phycfg.lpc_mau != LLDP_MAU_UNKNOWN)
			(void) snprintf(buf, buflen, "%u",
			    pdu->lp_phycfg.lpc_mau);
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const ofmt_field_t nbr_fields[] = {
	{ "LINK",		10,	NF_LINK,		nbr_ofmt_cb },
	{ "DEVICE",		10,	NF_DEVICE,		nbr_ofmt_cb },
	{ "SYSNAME",		18,	NF_SYSNAME,		nbr_ofmt_cb },
	{ "CHASSIS",		19,	NF_CHASSIS,		nbr_ofmt_cb },
	{ "CHASSIS-TYPE",	13,	NF_CHASSIS_TYPE,	nbr_ofmt_cb },
	{ "PORT",		14,	NF_PORT,		nbr_ofmt_cb },
	{ "PORT-TYPE",		11,	NF_PORT_TYPE,		nbr_ofmt_cb },
	{ "PORTDESC",		24,	NF_PORTDESC,		nbr_ofmt_cb },
	{ "SYSDESC",		32,	NF_SYSDESC,		nbr_ofmt_cb },
	{ "CAPS",		6,	NF_CAPS,		nbr_ofmt_cb },
	{ "SYSCAPS",		20,	NF_SYSCAPS,		nbr_ofmt_cb },
	{ "ENABLED-CAPS",	20,	NF_ENABLED_CAPS,	nbr_ofmt_cb },
	{ "MGMTADDR",		24,	NF_MGMTADDR,		nbr_ofmt_cb },
	{ "TTL",		6,	NF_TTL,			nbr_ofmt_cb },
	{ "EXPIRES",		8,	NF_EXPIRES,		nbr_ofmt_cb },
	{ "PVID",		6,	NF_PVID,		nbr_ofmt_cb },
	{ "VLANS",		16,	NF_VLANS,		nbr_ofmt_cb },
	{ "MAX-FRAME",		10,	NF_MAX_FRAME,		nbr_ofmt_cb },
	{ "MAU",		15,	NF_MAU,			nbr_ofmt_cb },
	{ NULL,			0,	0,			NULL }
};

/*
 * Decode a BER encoded OID (as in a management address TLV) into dotted
 * form. Returns false if it's malformed.
 */
static bool
oid_print(const uint8_t *oid, size_t len, char *buf, size_t buflen)
{
	size_t		off = 0;
	uint64_t	v = 0;
	bool		first = true;

	if (len == 0 || buflen == 0)
		return (false);
	buf[0] = '\0';

	for (size_t i = 0; i < len; i++) {
		if (v > (UINT32_MAX >> 7))
			return (false);
		v = (v << 7) | (oid[i] & 0x7f);
		if (oid[i] & 0x80)
			continue;

		int n;
		if (first) {
			uint64_t x = MIN(v / 40, 2);

			n = snprintf(buf + off, buflen - off, "%" PRIu64
			    ".%" PRIu64, x, v - 40 * x);
			first = false;
		} else {
			n = snprintf(buf + off, buflen - off, ".%" PRIu64, v);
		}
		if (n < 0 || (size_t)n >= buflen - off)
			return (false);
		off += n;
		v = 0;
	}

	/* The last byte must end a subidentifier */
	return ((oid[len - 1] & 0x80) == 0);
}

/* The OUI of an organizationally specific TLV, with its name if known */
static void
oui_print(uint32_t oui, char *buf, size_t buflen)
{
	const char *name = lldp_oui_str(oui);

	(void) snprintf(buf, buflen, "%02x:%02x:%02x%s%s%s",
	    (oui >> 16) & 0xff, (oui >> 8) & 0xff, oui & 0xff,
	    (name != NULL) ? " (" : "", (name != NULL) ? name : "",
	    (name != NULL) ? ")" : "");
}

static void
verbose_8021(const lldp_pdu_t *pdu)
{
	char buf[STRBUF_LEN], s[STRBUF_LEN];

	if ((pdu->lp_present & (LLDP_PDU_PVID | LLDP_PDU_MGMT_VID |
	    LLDP_PDU_AGGR)) == 0 && pdu->lp_nppvid == 0 &&
	    pdu->lp_nvlan_names == 0 && pdu->lp_nproto == 0) {
		return;
	}

	vsection(TOP_INDENT, "IEEE 802.1");

	if (pdu->lp_present & LLDP_PDU_PVID) {
		(void) snprintf(buf, sizeof (buf), "%u", pdu->lp_pvid);
		vline(SUB_INDENT, gettext("Port VLAN ID"), buf);
	}

	for (uint_t i = 0; i < pdu->lp_nppvid; i++) {
		const lldp_ppvid_t *pv = &pdu->lp_ppvid[i];

		(void) snprintf(buf, sizeof (buf), "%u (%s, %s)",
		    pv->lpv_ppvid,
		    (pv->lpv_flags & LLDP_PPVID_SUP) ? gettext("supported") :
		    gettext("not supported"),
		    (pv->lpv_flags & LLDP_PPVID_EN) ? gettext("enabled") :
		    gettext("disabled"));
		vline(SUB_INDENT, (i == 0) ? gettext("Protocol VLAN") : NULL,
		    buf);
	}

	for (uint_t i = 0; i < pdu->lp_nvlan_names; i++) {
		const lldp_vlan_name_t *vn = &pdu->lp_vlan_names[i];

		str_print(&vn->lvn_name, s, sizeof (s), 0);
		(void) snprintf(buf, sizeof (buf), "%u %s", vn->lvn_vid, s);
		vline(SUB_INDENT, (i == 0) ? gettext("VLAN names") : NULL,
		    buf);
	}

	for (uint_t i = 0; i < pdu->lp_nproto; i++) {
		hex_print(pdu->lp_proto[i].ls_data, pdu->lp_proto[i].ls_len,
		    buf, sizeof (buf));
		vline(SUB_INDENT, (i == 0) ? gettext("Protocol ID") : NULL,
		    buf);
	}

	if (pdu->lp_present & LLDP_PDU_MGMT_VID) {
		(void) snprintf(buf, sizeof (buf), "%u", pdu->lp_mgmt_vid);
		vline(SUB_INDENT, gettext("Management VID"), buf);
	}

	if (pdu->lp_present & LLDP_PDU_AGGR) {
		const lldp_link_aggr_t *la = &pdu->lp_aggr;

		if (la->lla_status & LLDP_LINK_AGGR_STATUS) {
			(void) snprintf(buf, sizeof (buf),
			    gettext("aggregated, port %u"), la->lla_portid);
		} else {
			(void) strlcpy(buf,
			    (la->lla_status & LLDP_LINK_AGGR_CAP) ?
			    gettext("capable, not aggregated") :
			    gettext("not capable"), sizeof (buf));
		}
		vline(SUB_INDENT, gettext("Link aggregation"), buf);
	}
}

static void
verbose_8023(const lldp_pdu_t *pdu)
{
	char		buf[STRBUF_LEN];
	const char	*mau, *mode;
	lldp_mau_mode_t	m;

	if ((pdu->lp_present & (LLDP_PDU_PHYCFG | LLDP_PDU_POWER_MDI |
	    LLDP_PDU_MAX_FRAME)) == 0) {
		return;
	}

	vsection(TOP_INDENT, "IEEE 802.3");

	if (pdu->lp_present & LLDP_PDU_PHYCFG) {
		const lldp_phycfg_t *pc = &pdu->lp_phycfg;

		if (pc->lpc_autoneg & LLDP_AUTONEG_SUP) {
			vline(SUB_INDENT, gettext("Auto-negotiation"),
			    (pc->lpc_autoneg & LLDP_AUTONEG_EN) ?
			    gettext("supported, enabled") :
			    gettext("supported, disabled"));
			(void) lldp_autoneg_caps_str(pc->lpc_adv, buf,
			    sizeof (buf));
			vline(SUB_INDENT, gettext("Advertised"), buf);
		} else {
			vline(SUB_INDENT, gettext("Auto-negotiation"),
			    gettext("not supported"));
		}

		mau = lldp_mau_str(pc->lpc_mau, &m);
		mode = lldp_mau_mode_str(m);
		if (mau == NULL) {
			(void) snprintf(buf, sizeof (buf),
			    gettext("unknown (%u)"), pc->lpc_mau);
		} else if (mode != NULL) {
			(void) snprintf(buf, sizeof (buf), "%s (%s)", mau,
			    mode);
		} else {
			(void) strlcpy(buf, mau, sizeof (buf));
		}
		vline(SUB_INDENT, gettext("Operational MAU"), buf);
	}

	if (pdu->lp_present & LLDP_PDU_POWER_MDI) {
		const lldp_power_mdi_t *pm = &pdu->lp_power;

		/*
		 * MDI power support: bit 0 is the port class (PSE or PD),
		 * bit 1 PSE MDI power support, bit 2 PSE MDI power state,
		 * bit 3 PSE pairs control ability. The power class is
		 * sent as the class plus one.
		 */
		(void) snprintf(buf, sizeof (buf), "%s%s%s, %s, %s %d",
		    (pm->lpm_support & 0x01) ? "PSE" : "PD",
		    (pm->lpm_support & 0x02) ? gettext(", supported") : "",
		    (pm->lpm_support & 0x04) ? gettext(", enabled") : "",
		    (pm->lpm_pair == 1) ? gettext("signal pairs") :
		    (pm->lpm_pair == 2) ? gettext("spare pairs") :
		    gettext("unknown pairs"),
		    gettext("class"), (int)pm->lpm_class - 1);
		vline(SUB_INDENT, gettext("Power via MDI"), buf);
	}

	if (pdu->lp_present & LLDP_PDU_MAX_FRAME) {
		(void) snprintf(buf, sizeof (buf), "%u", pdu->lp_max_frame);
		vline(SUB_INDENT, gettext("Maximum frame"), buf);
	}
}

/* A TLV that wasn't decoded (or was malformed) */
static void
tlv_line(const lldp_tlv_t *t, bool bad, bool first, const char *label)
{
	char	buf[STRBUF_LEN], hex[STRBUF_LEN], oui[64];

	if (t->lt_org) {
		hex_print(t->lt_info, t->lt_infolen, hex, sizeof (hex));
		oui_print(t->lt_oui, oui, sizeof (oui));
		(void) snprintf(buf, sizeof (buf),
		    gettext("OUI %s, subtype %u%s%s"), oui, t->lt_subtype,
		    (t->lt_infolen > 0) ? ": " : "", hex);
	} else {
		hex_print(t->lt_value, t->lt_len, hex, sizeof (hex));
		(void) snprintf(buf, sizeof (buf),
		    gettext("type %u (%s)%s%s"), t->lt_type,
		    lldp_tlv_type_str(t->lt_type), (t->lt_len > 0) ? ": " : "",
		    hex);
	}

	if (bad) {
		char lbuf[STRBUF_LEN];

		(void) snprintf(lbuf, sizeof (lbuf), gettext("%s (length %u)"),
		    buf, t->lt_len);
		vline(TOP_INDENT, first ? label : NULL, lbuf);
	} else {
		vline(TOP_INDENT, first ? label : NULL, buf);
	}
}

static void
nbr_header(const nbr_t *n, const char *extra)
{
	if (strcmp(n->n_link, n->n_nb->ln_link) != 0) {
		(void) printf("%s (%s)%s%s\n", n->n_link, n->n_nb->ln_link,
		    (extra != NULL) ? ": " : "", (extra != NULL) ? extra : "");
	} else {
		(void) printf("%s%s%s\n", n->n_link,
		    (extra != NULL) ? ": " : "", (extra != NULL) ? extra : "");
	}
}

static void
nbr_print_verbose(const nbr_t *n)
{
	const lldp_pdu_t	*pdu = n->n_pdu;
	char			buf[STRBUF_LEN], s[STRBUF_LEN], t[64];

	if (pdu == NULL) {
		nbr_header(n, NULL);
		vline(TOP_INDENT, gettext("Error"), gettext("malformed LLDPDU "
		    "(invalid Chassis ID, Port ID, or TTL TLV); "
		    "see 'show-neighbors -x'"));
		return;
	}

	if (pdu->lp_present & LLDP_PDU_SYS_NAME) {
		str_print(&pdu->lp_sys_name, s, sizeof (s), 0);
		nbr_header(n, s);
	} else {
		nbr_header(n, NULL);
	}

	(void) lldp_chassis_str(&pdu->lp_chassis, s, sizeof (s));
	(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
	    lldp_chassis_typedesc(pdu->lp_chassis.llc_type, t, sizeof (t)));
	vline(TOP_INDENT, gettext("Chassis ID"), buf);

	(void) lldp_port_str(&pdu->lp_port, s, sizeof (s));
	(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
	    lldp_port_typedesc(pdu->lp_port.llp_type, t, sizeof (t)));
	vline(TOP_INDENT, gettext("Port ID"), buf);

	if (pdu->lp_present & LLDP_PDU_PORT_DESC) {
		str_print(&pdu->lp_port_desc, s, sizeof (s), 0);
		vline(TOP_INDENT, gettext("Port description"), s);
	}

	(void) snprintf(buf, sizeof (buf), gettext("%u (expires in %us)"),
	    pdu->lp_ttl, n->n_nb->ln_ttl);
	vline(TOP_INDENT, "TTL", buf);

	if (pdu->lp_present & LLDP_PDU_SYS_NAME) {
		str_print(&pdu->lp_sys_name, s, sizeof (s), 0);
		vline(TOP_INDENT, gettext("System name"), s);
	}

	if (pdu->lp_present & LLDP_PDU_SYS_DESC) {
		str_print(&pdu->lp_sys_desc, s, sizeof (s),
		    LLDP_STR_MULTILINE);
		vline(TOP_INDENT, gettext("System description"), s);
	}

	if (pdu->lp_present & LLDP_PDU_SYS_CAP) {
		char en[256];

		(void) lldp_caps_str(pdu->lp_sys_caps, s, sizeof (s));
		(void) lldp_caps_str(pdu->lp_en_caps, en, sizeof (en));
		(void) snprintf(buf, sizeof (buf), gettext("%s (enabled: %s)"),
		    s, en);
		vline(TOP_INDENT, gettext("Capabilities"), buf);
	}

	for (uint_t i = 0; i < pdu->lp_nmgmt; i++) {
		const lldp_mgmt_addr_t *ma = &pdu->lp_mgmt[i];
		const char *label = (i == 0) ?
		    gettext("Management address") : NULL;

		(void) lldp_mgmt_addr_str(ma, s, sizeof (s));
		if (ma->lma_iftype == LLDP_MGMT_IFINDEX ||
		    ma->lma_iftype == LLDP_MGMT_SYSPORT) {
			(void) snprintf(buf, sizeof (buf), "%s (%s, %s %u)", s,
			    lldp_mgmt_af_str(ma->lma_af, t, sizeof (t)),
			    lldp_mgmt_iftype_str(ma->lma_iftype),
			    ma->lma_ifnum);
		} else {
			(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
			    lldp_mgmt_af_str(ma->lma_af, t, sizeof (t)));
		}
		vline(TOP_INDENT, label, buf);

		if (ma->lma_oidlen > 0) {
			char oid[STRBUF_LEN];

			if (!oid_print(ma->lma_oid, ma->lma_oidlen, oid,
			    sizeof (oid))) {
				hex_print(ma->lma_oid, ma->lma_oidlen, oid,
				    sizeof (oid));
			}
			(void) snprintf(buf, sizeof (buf), "OID %s", oid);
			vline(TOP_INDENT, NULL, buf);
		}
	}

	verbose_8021(pdu);
	verbose_8023(pdu);

	for (uint_t i = 0; i < pdu->lp_nother; i++) {
		tlv_line(&pdu->lp_other[i], false, i == 0,
		    gettext("Other TLVs"));
	}

	for (uint_t i = 0; i < pdu->lp_nbad; i++) {
		tlv_line(&pdu->lp_bad[i], true, i == 0,
		    gettext("Malformed TLVs"));
	}

	if (pdu->lp_flags & LLDP_PDU_F_TRUNCATED)
		vline(TOP_INDENT, gettext("Warning"),
		    gettext("LLDPDU is truncated"));
	if (pdu->lp_flags & LLDP_PDU_F_NO_END)
		vline(TOP_INDENT, gettext("Warning"),
		    gettext("LLDPDU has no End TLV"));
	if (pdu->lp_flags & LLDP_PDU_F_TRAILING)
		vline(TOP_INDENT, gettext("Warning"),
		    gettext("data after the End TLV"));
}

/*
 * -x output: each TLV's type, name, length, and value in hex, 12 bytes per
 * line (which keeps the lines within 80 columns).
 */
#define	HEX_PER_LINE	12
#define	NAME_WIDTH	25
/* Where the hex starts: indent, type (3), name, and length (4) */
#define	HEX_COL		(TOP_INDENT + 3 + 2 + NAME_WIDTH + 1 + 4 + 2)

static void
hex_lines(const uint8_t *v, size_t len, int col)
{
	char buf[HEX_PER_LINE * 3 + 1];

	if (len == 0) {
		(void) putchar('\n');
		return;
	}

	for (size_t off = 0; off < len; off += HEX_PER_LINE) {
		hex_print(v + off, MIN(len - off, HEX_PER_LINE), buf,
		    sizeof (buf));
		(void) printf("%*s%s\n", (off == 0) ? 2 : col, "", buf);
	}
}

static void
nbr_print_raw(const nbr_t *n)
{
	const lldp_neighbor_t	*nb = n->n_nb;
	lldp_tlv_iter_t		it;
	lldp_tlv_t		t;
	char			buf[128], oui[64];
	int			ret;

	(void) snprintf(buf, sizeof (buf), gettext("%zu bytes, expires in %us"),
	    nb->ln_pdu_len, nb->ln_ttl);
	nbr_header(n, buf);

	lldp_tlv_iter_init(&it, nb->ln_pdu, nb->ln_pdu_len);
	while ((ret = lldp_tlv_iter_next(&it, &t)) == 1) {
		const char *name = lldp_tlv_type_str(t.lt_type);

		if (t.lt_org) {
			oui_print(t.lt_oui, oui, sizeof (oui));
			(void) snprintf(buf, sizeof (buf), "%s/%u", oui,
			    t.lt_subtype);
			name = buf;
		}

		(void) printf("%*s%3u  %-*s %4u", TOP_INDENT, "",
		    t.lt_type, NAME_WIDTH, name, t.lt_len);
		hex_lines(t.lt_value, t.lt_len, HEX_COL);
	}

	if (ret < 0) {
		size_t left = nb->ln_pdu_len - it.lti_off;

		(void) printf("%*s", TOP_INDENT, "");
		(void) printf(gettext("truncated TLV at offset %zu:"),
		    it.lti_off);
		(void) putchar('\n');
		(void) printf("%*s", HEX_COL - 2, "");
		hex_lines(nb->ln_pdu + it.lti_off, left, HEX_COL);
	} else if (it.lti_noend) {
		(void) printf("%*s%s\n", TOP_INDENT, "", gettext("no End TLV"));
	} else if (it.lti_off < nb->ln_pdu_len) {
		(void) printf("%*s", TOP_INDENT, "");
		(void) printf(gettext("%zu bytes after the End TLV"),
		    nb->ln_pdu_len - it.lti_off);
		(void) putchar('\n');
	}
}

/* How to show the neighbors */
typedef struct nbr_view {
	lldp_ofmt_opts_t	nv_opts;	/* Default view */
	bool			nv_verbose;	/* -v */
	bool			nv_raw;		/* -x */
} nbr_view_t;

/* Have the neighbors (other than how long until they expire) changed? */
static bool
nbrs_differ(const lldp_neighbor_t *a, uint_t na, const lldp_neighbor_t *b,
    uint_t nb)
{
	if (na != nb)
		return (true);

	for (uint_t i = 0; i < na; i++) {
		if (strcmp(a[i].ln_link, b[i].ln_link) != 0 ||
		    a[i].ln_pdu_len != b[i].ln_pdu_len ||
		    memcmp(a[i].ln_pdu, b[i].ln_pdu, a[i].ln_pdu_len) != 0) {
			return (true);
		}
	}
	return (false);
}

static void
nbrs_print(const nbr_view_t *v, lldp_neighbor_t *nbrs, uint_t n)
{
	ofmt_handle_t	ofmt = NULL;
	nbr_t		*ns;
	int		ret;

	/* A new handle each time, so a table is printed with its header */
	if (!v->nv_verbose && !v->nv_raw)
		ofmt = lldp_ofmt_open(&v->nv_opts, nbr_fields, 0);

	if ((ns = calloc(MAX(n, 1), sizeof (nbr_t))) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));

	for (uint_t i = 0; i < n; i++) {
		ns[i].n_nb = &nbrs[i];
		link_name(nbrs[i].ln_link, ns[i].n_link, sizeof (ns[i].n_link));

		/* The raw view doesn't need it decoded */
		if (v->nv_raw)
			continue;

		ret = lldp_pdu_parse(nbrs[i].ln_pdu, nbrs[i].ln_pdu_len,
		    &ns[i].n_pdu);
		if (ret == ENOMEM) {
			errx(EXIT_FAILURE, gettext("failed to allocate "
			    "memory"));
		}
		/* Otherwise (EBADMSG), the neighbor is shown as malformed */
	}

	for (uint_t i = 0; i < n; i++) {
		if (v->nv_verbose) {
			if (i > 0)
				(void) putchar('\n');
			nbr_print_verbose(&ns[i]);
		} else if (v->nv_raw) {
			if (i > 0)
				(void) putchar('\n');
			nbr_print_raw(&ns[i]);
		} else {
			ofmt_print(ofmt, &ns[i]);
		}
	}

	if (ofmt != NULL)
		ofmt_close(ofmt);
	for (uint_t i = 0; i < n; i++)
		lldp_pdu_free(ns[i].n_pdu);
	free(ns);
}

/*
 * -w: show the neighbors again whenever they change, until interrupted (or
 * lldpd goes away). With a link, only changes to its neighbors count.
 * Except in parsable mode, each update starts with the time.
 */
static int
nbrs_watch(const char *link, const nbr_view_t *v, lldp_neighbor_t *nbrs,
    uint_t n)
{
	uint32_t	gen = 0;
	bool		missing = false;
	int		ret;

	if ((ret = lldp_wait_change(&gen, 0)) != 0) {
		lldp_warn(ret, NULL, gettext("neighbor changes"));
		lldp_neighbors_free(nbrs, n);
		return (EXIT_FAILURE);
	}

	for (;;) {
		lldp_neighbor_t	*cur = NULL;
		uint_t		cn = 0;
		uint32_t	prev = gen;

		(void) fflush(stdout);

		ret = lldp_wait_change(&gen, LLDP_WAIT_MAX);
		if (ret != 0) {
			lldp_warn(ret, NULL, gettext("neighbor changes"));
			break;
		}
		if (gen == prev)
			continue;	/* Timed out; wait again */

		ret = lldp_get_neighbors(link, &cur, &cn);
		if (ret == ENOENT && link != NULL) {
			/* The link's agent went away (it may come back) */
			if (!missing)
				lldp_warn(ret, link, NULL);
			missing = true;
			lldp_neighbors_free(nbrs, n);
			nbrs = NULL;
			n = 0;
			continue;
		}
		if (ret != 0) {
			lldp_warn(ret, link, gettext("neighbors"));
			break;
		}

		if (!missing && !nbrs_differ(nbrs, n, cur, cn)) {
			lldp_neighbors_free(cur, cn);
			continue;
		}
		missing = false;

		if (!v->nv_opts.loo_parsable) {
			char		when[64];
			time_t		now = time(NULL);
			struct tm	tm;

			(void) strftime(when, sizeof (when), "%F %T",
			    localtime_r(&now, &tm));
			(void) printf("\n%s\n", when);
		}
		nbrs_print(v, cur, cn);

		lldp_neighbors_free(nbrs, n);
		nbrs = cur;
		n = cn;
	}

	lldp_neighbors_free(nbrs, n);
	return (EXIT_FAILURE);
}

int
do_show_neighbors(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-neighbors");
	nbr_view_t		v = { 0 };
	lldp_ofmt_opts_t	*opts = &v.nv_opts;
	bool			watch = false;
	const char		*link = NULL;
	lldp_neighbor_t		*nbrs = NULL;
	uint_t			n = 0;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":po:vwx")) != -1) {
		switch (c) {
		case 'p':
			opts->loo_parsable = true;
			break;
		case 'o':
			opts->loo_fields = optarg;
			break;
		case 'v':
			v.nv_verbose = true;
			break;
		case 'w':
			watch = true;
			break;
		case 'x':
			v.nv_raw = true;
			break;
		case ':':
			warnx(gettext("option -%c requires an argument"),
			    optopt);
			cmd_usage(cmd);
		case '?':
			warnx(gettext("unknown option -%c"), optopt);
			cmd_usage(cmd);
		}
	}

	if (v.nv_verbose && v.nv_raw) {
		warnx(gettext("-v and -x can't be used together"));
		cmd_usage(cmd);
	}
	if ((v.nv_verbose || v.nv_raw) &&
	    (opts->loo_parsable || opts->loo_fields)) {
		warnx(gettext("-%c can't be used with -p or -o"),
		    v.nv_verbose ? 'v' : 'x');
		cmd_usage(cmd);
	}

	if (argc - optind > 1) {
		warnx(gettext("only one link may be given"));
		cmd_usage(cmd);
	}
	if (argc - optind == 1)
		link = argv[optind];

	/* Check the options before talking to lldpd */
	if (!v.nv_verbose && !v.nv_raw) {
		if (opts->loo_fields == NULL && !opts->loo_parsable) {
			opts->loo_fields = NBR_DEFAULT_FIELDS;
			short_sysname = true;
		}
		ofmt_close(lldp_ofmt_open(opts, nbr_fields, 0));
	}
	if (v.nv_verbose)
		vline_init();

	ret = lldp_get_neighbors(link, &nbrs, &n);
	if (ret != 0) {
		lldp_warn(ret, link, gettext("neighbors"));
		return (EXIT_FAILURE);
	}

	nbrs_print(&v, nbrs, n);

	if (watch)
		return (nbrs_watch(link, &v, nbrs, n));

	lldp_neighbors_free(nbrs, n);
	return (EXIT_SUCCESS);
}
