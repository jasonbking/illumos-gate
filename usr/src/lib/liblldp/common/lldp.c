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

#include <libintl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libcustr.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <liblldp.h>

/*
 * IANA Address Family Numbers
 * (https://www.iana.org/assignments/address-family-numbers), as used in the
 * first byte of network address chassis and port ids. These unfortuantely
 * are different from our AF_xxx values.
 */
#define	IANA_AF_IPV4	1
#define	IANA_AF_IPV6	2
#define	IANA_AF_802	6	/* IEEE 802 (incl. Ethernet) MAC address */

#define	LLDP_MACADDR_LEN	6

const uint8_t lldp_oui_8023[3] = { 0x00, 0x12, 0x0f };

/*
 * Write v as hex bytes separated by sep into buf. Like snprintf(), the
 * output is truncated (but always NUL-terminated, if buflen > 0) if buf is
 * too small, and the return value is the length of the full string
 * (excluding the terminating NUL).
 */
static size_t
lldp_hex_str(const uint8_t *v, size_t vlen, char *buf, size_t buflen,
    const char *sep)
{
	size_t total, off = 0;

	total = vlen * 2;
	if (vlen > 1)
		total += (vlen - 1) * strlen(sep);

	if (buflen == 0)
		return (total);

	buf[0] = '\0';

	for (size_t i = 0; i < vlen; i++) {
		int n;

		n = snprintf(buf + off, buflen - off, "%02x%s", v[i],
		    (i + 1 < vlen) ? sep : "");
		if (n < 0)
			break;

		/* Out of space; buf has been truncated and terminated */
		if ((size_t)n >= buflen - off)
			break;

		off += n;
	}

	return (total);
}

/*
 * Write a (not necessarily NUL-terminated) text id into buf, with
 * snprintf() semantics. It came from the network, so anything that isn't
 * printable is escaped (see lldp_str_print()).
 */
static size_t
lldp_text_str(const uint8_t *v, size_t vlen, char *buf, size_t buflen)
{
	lldp_str_t s = {
		.ls_data = v,
		.ls_len = (uint16_t)MIN(vlen, UINT16_MAX),
	};

	return (lldp_str_print(&s, buf, buflen, 0));
}

/*
 * The names of lldpd's SMF property values (see lldp_prop_val()).
 */
typedef struct prop_name {
	const char	*pn_name;
	uint_t		pn_val;
} prop_name_t;

/* As lldpd's log_level_t */
static const prop_name_t log_level_names[] = {
	{ "trace",	10 },
	{ "debug",	20 },
	{ "info",	30 },
	{ "warn",	40 },
	{ "error",	50 },
	{ "fatal",	60 },
	{ NULL,		0 }
};

static const prop_name_t chassis_id_src_names[] = {
	{ "auto",	LLDP_CHASSIS_ID_SRC_AUTO },
	{ "topo",	LLDP_CHASSIS_ID_SRC_TOPO },
	{ "uuid",	LLDP_CHASSIS_ID_SRC_UUID },
	{ "serial",	LLDP_CHASSIS_ID_SRC_SERIAL },
	{ "macaddr",	LLDP_CHASSIS_ID_SRC_MACADDR },
	{ "hostid",	LLDP_CHASSIS_ID_SRC_HOSTID },
	{ "local",	LLDP_CHASSIS_ID_SRC_LOCAL },
	{ NULL,		0 }
};

static const prop_name_t admin_status_names[] = {
	{ "disabled",	LLDP_LINK_DISABLED },
	{ "tx",		LLDP_LINK_TX },
	{ "rx",		LLDP_LINK_RX },
	{ "txrx",	LLDP_LINK_TXRX },
	{ NULL,		0 }
};

static const prop_name_t port_id_src_names[] = {
	{ "ifname",	LLDP_PORT_ID_SRC_IFNAME },
	{ "hwname",	LLDP_PORT_ID_SRC_HWNAME },
	{ "macaddr",	LLDP_PORT_ID_SRC_MACADDR },
	{ "label",	LLDP_PORT_ID_SRC_LABEL },
	{ "local",	LLDP_PORT_ID_SRC_LOCAL },
	{ NULL,		0 }
};

static const prop_name_t tx_tlv_names[] = {
	{ "port-desc",	LLDP_TX_PORTDESC },
	{ "sys-name",	LLDP_TX_SYSNAME },
	{ "sys-desc",	LLDP_TX_SYSDESC },
	{ "sys-cap",	LLDP_TX_SYSCAP },
	{ "mgmt-addr",	LLDP_TX_MGMTADDR },
	{ NULL,		0 }
};

static const prop_name_t tx_8021_tlv_names[] = {
	{ "native-vlan",	LLDP_TX_X1_NATIVE_VLAN },
	{ "vlans",		LLDP_TX_X1_VLANS },
	{ "vlan-name",		LLDP_TX_X1_VLAN_NAME },
	{ "mgmt-vlan",		LLDP_TX_X2_MGMT_VLAN },
	{ NULL,			0 }
};

static const prop_name_t tx_8023_tlv_names[] = {
	{ "phy-cfg",	LLDP_TX_X3_PHYCFG },
	{ "mtu",	LLDP_TX_X3_MTU },
	{ NULL,		0 }
};

static const prop_name_t *
prop_names(lldp_prop_t prop)
{
	switch (prop) {
	case LLDP_PROP_LOG_LEVEL:
		return (log_level_names);
	case LLDP_PROP_CHASSIS_ID_TYPE:
		return (chassis_id_src_names);
	case LLDP_PROP_ADMIN_STATUS:
		return (admin_status_names);
	case LLDP_PROP_PORT_ID_TYPE:
		return (port_id_src_names);
	case LLDP_PROP_TX_TLVS:
		return (tx_tlv_names);
	case LLDP_PROP_TX_8021_TLVS:
		return (tx_8021_tlv_names);
	case LLDP_PROP_TX_8023_TLVS:
		return (tx_8023_tlv_names);
	default:
		return (NULL);
	}
}

bool
lldp_prop_val(lldp_prop_t prop, const char *name, uint_t *vp)
{
	const prop_name_t *pn = prop_names(prop);

	for (; pn != NULL && pn->pn_name != NULL; pn++) {
		if (strcmp(pn->pn_name, name) == 0) {
			*vp = pn->pn_val;
			return (true);
		}
	}
	return (false);
}

const char *
lldp_prop_name(lldp_prop_t prop, uint_t val)
{
	const prop_name_t *pn = prop_names(prop);

	for (; pn != NULL && pn->pn_name != NULL; pn++) {
		if (pn->pn_val == val)
			return (pn->pn_name);
	}
	return ("unknown");
}

size_t
lldp_prop_flags_str(lldp_prop_t prop, uint_t flags, char *buf, size_t buflen)
{
	const prop_name_t	*pn = prop_names(prop);
	size_t			len = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (; pn != NULL && pn->pn_name != NULL; pn++) {
		if ((flags & pn->pn_val) == 0)
			continue;
		if (len > 0)
			len = strlcat(buf, ",", buflen);
		len = strlcat(buf, pn->pn_name, buflen);
	}

	if (len == 0)
		len = strlcpy(buf, "none", buflen);
	return (len);
}

size_t
lldp_prop_names_str(lldp_prop_t prop, char *buf, size_t buflen)
{
	const prop_name_t	*pn = prop_names(prop);
	size_t			len = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (; pn != NULL && pn->pn_name != NULL; pn++) {
		if (len > 0)
			len = strlcat(buf, ",", buflen);
		len = strlcat(buf, pn->pn_name, buflen);
	}
	return (len);
}

/*
 * lldpd's SMF properties. The defaults and ranges of the agent properties
 * are those given in IEEE 802.1AB-2016 (and the LLDP-V2-MIB).
 */
#define	PI_SYS(_name, _pg)	\
	.lpi_name = (_name), .lpi_flags = LLDP_PI_SYSTEM, .lpi_pg = (_pg)
#define	PI_AGENT(_name)		\
	.lpi_name = (_name), .lpi_flags = LLDP_PI_AGENT
#define	PI_COUNT(_def, _min, _max)	\
	.lpi_type = LLDP_PT_COUNT, .lpi_def = (_def), .lpi_min = (_min), \
	.lpi_max = (_max)
#define	PI_ENUM(_names, _def)	\
	.lpi_type = LLDP_PT_ENUM, .lpi_names = (_names), .lpi_def = (_def)
#define	PI_FLAGS(_names, _def)	\
	.lpi_type = LLDP_PT_FLAGS, .lpi_names = (_names), .lpi_def = (_def)
#define	PI_STRING(_max, _derived)	\
	.lpi_type = LLDP_PT_STRING, .lpi_max = (_max), .lpi_derived = (_derived)

static const lldp_propinfo_t propinfo[] = {
	/* System */
	{ PI_SYS("log_level", LLDP_PG_DAEMON),
	    PI_ENUM(LLDP_PROP_LOG_LEVEL, 30) },
	{ PI_SYS("sysname", LLDP_PG_CONFIG),
	    PI_STRING(LLDP_SYS_NAME_MAX, "the hostname") },
	{ PI_SYS("sysdesc", LLDP_PG_CONFIG),
	    PI_STRING(LLDP_SYS_DESC_MAX, "from uname") },
	{ PI_SYS("chassis_id_type", LLDP_PG_CONFIG),
	    PI_ENUM(LLDP_PROP_CHASSIS_ID_TYPE, LLDP_CHASSIS_ID_SRC_AUTO) },
	{ PI_SYS("chassis_id", LLDP_PG_CONFIG),
	    PI_STRING(LLDP_CHASSIS_MAX, NULL) },

	/* Agents */
	{ PI_AGENT("admin_status"),
	    PI_ENUM(LLDP_PROP_ADMIN_STATUS, LLDP_LINK_TXRX) },
	{ PI_AGENT("port_id_type"),
	    PI_ENUM(LLDP_PROP_PORT_ID_TYPE, LLDP_PORT_ID_SRC_IFNAME) },
	{ .lpi_name = "port_id", .lpi_flags = LLDP_PI_AGENT | LLDP_PI_LINK_ONLY,
	    PI_STRING(LLDP_PORT_MAX, NULL) },
	{ PI_AGENT("port_desc"),
	    PI_STRING(LLDP_PORT_DESC_MAX, "derived from the port") },
	{ PI_AGENT("tx_tlvs"),
	    PI_FLAGS(LLDP_PROP_TX_TLVS, LLDP_TX_PORTDESC | LLDP_TX_SYSNAME |
	    LLDP_TX_SYSDESC | LLDP_TX_SYSCAP) },
	{ PI_AGENT("tx_8021_tlvs"), PI_FLAGS(LLDP_PROP_TX_8021_TLVS, 0) },
	{ PI_AGENT("tx_8023_tlvs"), PI_FLAGS(LLDP_PROP_TX_8023_TLVS, 0) },
	{ PI_AGENT("tx_interval"), PI_COUNT(30, 1, 3600) },
	{ PI_AGENT("tx_hold_multiplier"), PI_COUNT(4, 2, 10) },
	{ PI_AGENT("reinit_delay"), PI_COUNT(2, 1, 10) },
	{ PI_AGENT("tx_credit_max"), PI_COUNT(5, 1, 10) },
	{ PI_AGENT("tx_fast_interval"), PI_COUNT(1, 1, 3600) },
	{ PI_AGENT("tx_fast_init"), PI_COUNT(4, 1, 8) },
	{ PI_AGENT("neighbor_max"), PI_COUNT(32, 1, UINT16_MAX) },
	{ PI_AGENT("notify"), .lpi_type = LLDP_PT_BOOLEAN, .lpi_def = 1 },
	/* lldpV2NotificationInterval */
	{ PI_AGENT("notification_interval"), PI_COUNT(30, 1, 3600) },
};

#undef	PI_SYS
#undef	PI_AGENT
#undef	PI_COUNT
#undef	PI_ENUM
#undef	PI_FLAGS
#undef	PI_STRING

const lldp_propinfo_t *
lldp_propinfo(const char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(propinfo); i++) {
		if (strcmp(propinfo[i].lpi_name, name) == 0)
			return (&propinfo[i]);
	}
	return (NULL);
}

const lldp_propinfo_t *
lldp_propinfo_iter(uint_t i)
{
	return ((i < ARRAY_SIZE(propinfo)) ? &propinfo[i] : NULL);
}

size_t
lldp_propinfo_default_str(const lldp_propinfo_t *pi, char *buf, size_t buflen)
{
	switch (pi->lpi_type) {
	case LLDP_PT_COUNT:
		return (snprintf(buf, buflen, "%u", pi->lpi_def));
	case LLDP_PT_BOOLEAN:
		return (strlcpy(buf, pi->lpi_def ? "true" : "false", buflen));
	case LLDP_PT_ENUM:
		return (strlcpy(buf, lldp_prop_name(pi->lpi_names, pi->lpi_def),
		    buflen));
	case LLDP_PT_FLAGS:
		return (lldp_prop_flags_str(pi->lpi_names, pi->lpi_def, buf,
		    buflen));
	case LLDP_PT_STRING:
	default:
		if (pi->lpi_derived == NULL)
			return (strlcpy(buf, "", buflen));
		return (snprintf(buf, buflen, "(%s)", pi->lpi_derived));
	}
}

const char *
lldp_admin_status_str(lldp_admin_status_t s)
{
	return (lldp_prop_name(LLDP_PROP_ADMIN_STATUS, s));
}

const char *
lldp_agent_state_str(lldp_agent_state_t s)
{
	switch (s) {
	case LLDP_AGENT_DISABLED:
		return ("disabled");
	case LLDP_AGENT_OFFLINE:
		return ("offline");
	case LLDP_AGENT_FAILED:
		return ("failed");
	case LLDP_AGENT_DOWN:
		return ("down");
	case LLDP_AGENT_CHANGING:
		return ("changing");
	case LLDP_AGENT_ACTIVE:
		return ("active");
	default:
		return ("unknown");
	}
}

/*
 * Chassis ID and Port ID subtypes have two names: a short token (as used in
 * parsable output and logs) and a (localized) description for people. Both
 * are set here so they stay in sync. Returns false for an unknown subtype.
 */
static bool
chassis_type_names(lldp_chassis_type_t t, const char **token,
    const char **desc)
{
	switch (t) {
	case LLDP_CHASSIS_COMPONENT:
		*token = "component";
		*desc = dgettext(TEXT_DOMAIN, "chassis component");
		return (true);
	case LLDP_CHASSIS_IFALIAS:
		*token = "ifAlias";
		*desc = dgettext(TEXT_DOMAIN, "interface alias");
		return (true);
	case LLDP_CHASSIS_PORT:
		*token = "port";
		*desc = dgettext(TEXT_DOMAIN, "port component");
		return (true);
	case LLDP_CHASSIS_MACADDR:
		*token = "macaddr";
		*desc = dgettext(TEXT_DOMAIN, "MAC address");
		return (true);
	case LLDP_CHASSIS_NETADDR:
		*token = "netaddr";
		*desc = dgettext(TEXT_DOMAIN, "network address");
		return (true);
	case LLDP_CHASSIS_IFNAME:
		*token = "ifName";
		*desc = dgettext(TEXT_DOMAIN, "interface name");
		return (true);
	case LLDP_CHASSIS_LOCAL:
		*token = "local";
		*desc = dgettext(TEXT_DOMAIN, "locally assigned");
		return (true);
	default:
		return (false);
	}
}

static bool
port_type_names(lldp_port_type_t t, const char **token, const char **desc)
{
	switch (t) {
	case LLDP_PORT_IFALIAS:
		*token = "ifAlias";
		*desc = dgettext(TEXT_DOMAIN, "interface alias");
		return (true);
	case LLDP_PORT_COMPONENT:
		*token = "component";
		*desc = dgettext(TEXT_DOMAIN, "port component");
		return (true);
	case LLDP_PORT_MACADDR:
		*token = "macaddr";
		*desc = dgettext(TEXT_DOMAIN, "MAC address");
		return (true);
	case LLDP_PORT_NETADDR:
		*token = "netaddr";
		*desc = dgettext(TEXT_DOMAIN, "network address");
		return (true);
	case LLDP_PORT_IFNAME:
		*token = "ifName";
		*desc = dgettext(TEXT_DOMAIN, "interface name");
		return (true);
	case LLDP_PORT_CIRCUIT_ID:
		*token = "circuitId";
		*desc = dgettext(TEXT_DOMAIN, "agent circuit ID");
		return (true);
	case LLDP_PORT_LOCAL:
		*token = "local";
		*desc = dgettext(TEXT_DOMAIN, "locally assigned");
		return (true);
	default:
		return (false);
	}
}

/* An unknown (reserved) subtype's token is its number */
const char *
lldp_chassis_typestr(lldp_chassis_type_t t, char *buf, size_t buflen)
{
	const char *token, *desc;

	if (chassis_type_names(t, &token, &desc))
		return (token);
	(void) snprintf(buf, buflen, "%u", t);
	return (buf);
}

const char *
lldp_chassis_typedesc(lldp_chassis_type_t t, char *buf, size_t buflen)
{
	const char *token, *desc;

	if (chassis_type_names(t, &token, &desc))
		return (desc);
	(void) snprintf(buf, buflen, dgettext(TEXT_DOMAIN, "subtype %u"), t);
	return (buf);
}

const char *
lldp_port_typestr(lldp_port_type_t t, char *buf, size_t buflen)
{
	const char *token, *desc;

	if (port_type_names(t, &token, &desc))
		return (token);
	(void) snprintf(buf, buflen, "%u", t);
	return (buf);
}

const char *
lldp_port_typedesc(lldp_port_type_t t, char *buf, size_t buflen)
{
	const char *token, *desc;

	if (port_type_names(t, &token, &desc))
		return (desc);
	(void) snprintf(buf, buflen, dgettext(TEXT_DOMAIN, "subtype %u"), t);
	return (buf);
}

/* The IANA address family of a management (or network) address */
const char *
lldp_mgmt_af_str(uint8_t af, char *buf, size_t buflen)
{
	switch (af) {
	case IANA_AF_IPV4:
		return ("IPv4");
	case IANA_AF_IPV6:
		return ("IPv6");
	case IANA_AF_802:
		return (dgettext(TEXT_DOMAIN, "MAC"));
	default:
		(void) snprintf(buf, buflen,
		    dgettext(TEXT_DOMAIN, "address family %u"), af);
		return (buf);
	}
}

const char *
lldp_cap_str(lldp_cap_t t)
{
	switch (t) {
	case LLDP_CAP_NONE:
		return (NULL);
	case LLDP_CAP_OTHER:
		return ("other");
	case LLDP_CAP_REPEATER:
		return ("repeater");
	case LLDP_CAP_MAC_BRIDGE:
		return ("bridge");
	case LLDP_CAP_AP:
		return ("ap");
	case LLDP_CAP_ROUTER:
		return ("router");
	case LLDP_CAP_PHONE:
		return ("phone");
	case LLDP_CAP_DOCSIS:
		return ("docsis");
	case LLDP_CAP_STATION:
		return ("station");
	case LLDP_CAP_CVLAN:
		return ("cvlan");
	case LLDP_CAP_SVLAN:
		return ("svlan");
	case LLDP_CAP_TPMR:
		return ("tpmr");
	default:
		return ("unknown");
	}
}

static bool
lldp_is_printable(const uint8_t *v, size_t vlen)
{
	for (size_t i = 0; i < vlen; i++) {
		/* Printable ASCII, independent of the current locale */
		if (v[i] < 0x20 || v[i] > 0x7e)
			return (false);
	}
	return (true);
}

/*
 * A network address id is a one byte IANA address family number followed by
 * the address. IPv4, IPv6, and IEEE 802 (MAC) addresses are decoded; any
 * other family, or an address whose length doesn't match its family, is
 * written as hex (including the address family byte).
 */
static size_t
lldp_netaddr_str(const uint8_t *v, size_t vlen, char *buf, size_t buflen)
{
	char		addr[INET6_ADDRSTRLEN];
	const uint8_t	*a;
	size_t		alen;
	int		n;

	if (vlen < 1)
		return (lldp_hex_str(v, vlen, buf, buflen, ""));

	a = v + 1;
	alen = vlen - 1;

	switch (v[0]) {
	case IANA_AF_IPV4: {
		struct in_addr in4;

		if (alen != sizeof (in4))
			break;

		/* Copy out; the id isn't necessarily aligned */
		(void) memcpy(&in4, a, sizeof (in4));
		if (inet_ntop(AF_INET, &in4, addr, sizeof (addr)) == NULL)
			break;

		n = snprintf(buf, buflen, "%s", addr);
		return ((n < 0) ? 0 : (size_t)n);
	}
	case IANA_AF_IPV6: {
		struct in6_addr in6;

		if (alen != sizeof (in6))
			break;

		(void) memcpy(&in6, a, sizeof (in6));
		if (inet_ntop(AF_INET6, &in6, addr, sizeof (addr)) == NULL)
			break;

		n = snprintf(buf, buflen, "%s", addr);
		return ((n < 0) ? 0 : (size_t)n);
	}
	case IANA_AF_802:
		if (alen != LLDP_MACADDR_LEN)
			break;
		return (lldp_hex_str(a, alen, buf, buflen, ":"));
	default:
		break;
	}

	return (lldp_hex_str(v, vlen, buf, buflen, ""));
}

/*
 * An agent circuit id (RFC 3046) is opaque; in practice it's either a
 * printable string or packed binary. Treat it as a string if every byte is
 * printable ASCII (ignoring any trailing NUL padding), otherwise write it as
 * hex.
 */
static size_t
lldp_circuit_id_str(const uint8_t *v, size_t vlen, char *buf, size_t buflen)
{
	size_t len = vlen;

	while (len > 0 && v[len - 1] == '\0')
		len--;

	if (len > 0 && lldp_is_printable(v, len))
		return (lldp_text_str(v, len, buf, buflen));

	return (lldp_hex_str(v, vlen, buf, buflen, ""));
}

/*
 * Write a printable form of a chassis id into buf. Like snprintf(), the
 * output is truncated (but NUL-terminated, if buflen > 0) if buf is too
 * small, and the return value is the length of the full string (excluding
 * the terminating NUL).
 */
size_t
lldp_chassis_str(const lldp_chassis_t *c, char *buf, size_t buflen)
{
	size_t len = MIN(c->llc_len, sizeof (c->llc_id));

	switch (c->llc_type) {
	case LLDP_CHASSIS_COMPONENT:
	case LLDP_CHASSIS_IFALIAS:
	case LLDP_CHASSIS_PORT:
	case LLDP_CHASSIS_IFNAME:
	case LLDP_CHASSIS_LOCAL:
		return (lldp_text_str(c->llc_id, len, buf, buflen));
	case LLDP_CHASSIS_MACADDR:
		return (lldp_hex_str(c->llc_id, len, buf, buflen, ":"));
	case LLDP_CHASSIS_NETADDR:
		return (lldp_netaddr_str(c->llc_id, len, buf, buflen));
	default:
		return (lldp_hex_str(c->llc_id, len, buf, buflen, ""));
	}
}

/*
 * Write a printable form of a port id into buf, with the same semantics as
 * lldp_chassis_str().
 */
size_t
lldp_port_str(const lldp_port_t *p, char *buf, size_t buflen)
{
	size_t len = MIN(p->llp_len, sizeof (p->llp_id));

	switch (p->llp_type) {
	case LLDP_PORT_IFALIAS:
	case LLDP_PORT_COMPONENT:
	case LLDP_PORT_IFNAME:
	case LLDP_PORT_LOCAL:
		return (lldp_text_str(p->llp_id, len, buf, buflen));
	case LLDP_PORT_MACADDR:
		return (lldp_hex_str(p->llp_id, len, buf, buflen, ":"));
	case LLDP_PORT_NETADDR:
		return (lldp_netaddr_str(p->llp_id, len, buf, buflen));
	case LLDP_PORT_CIRCUIT_ID:
		return (lldp_circuit_id_str(p->llp_id, len, buf, buflen));
	default:
		return (lldp_hex_str(p->llp_id, len, buf, buflen, ""));
	}
}

/*
 * Append to buf (with total output so far of off bytes) with snprintf()
 * semantics, returning the length of the appended string (whether or not it
 * fit).
 */
static size_t
lldp_append(char *buf, size_t buflen, size_t off, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	va_start(ap, fmt);
	if (off < buflen)
		n = vsnprintf(buf + off, buflen - off, fmt, ap);
	else
		n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	return ((n < 0) ? 0 : (size_t)n);
}

/*
 * Write a comma separated list of the capabilities in caps (e.g.
 * "bridge,router") into buf. Any bits without a defined capability are
 * appended as a single hex value (e.g. "router,0x800"), and an empty set is
 * written as "none". Like snprintf(), the output is truncated (but
 * NUL-terminated, if buflen > 0) if buf is too small, and the return value
 * is the length of the full string (excluding the terminating NUL).
 */
size_t
lldp_caps_str(lldp_cap_t caps, char *buf, size_t buflen)
{
	uint32_t	bits = (uint32_t)caps;
	uint32_t	unknown = 0;
	size_t		total = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (uint_t i = 0; i < 32; i++) {
		uint32_t bit = 1U << i;

		if ((bits & bit) == 0)
			continue;

		if (bit > LLDP_CAP_TPMR) {
			unknown |= bit;
			continue;
		}

		total += lldp_append(buf, buflen, total, "%s%s",
		    (total > 0) ? "," : "", lldp_cap_str((lldp_cap_t)bit));
	}

	if (unknown != 0) {
		total += lldp_append(buf, buflen, total, "%s0x%x",
		    (total > 0) ? "," : "", unknown);
	}

	if (total == 0)
		total = lldp_append(buf, buflen, 0, "none");

	return (total);
}

const char *
lldp_tlv_type_str(lldp_tlv_type_t type)
{
	switch (type) {
	case LLDP_TLV_END:
		return ("End");
	case LLDP_TLV_CHASSIS_ID:
		return ("Chassis ID");
	case LLDP_TLV_PORT_ID:
		return ("Port ID");
	case LLDP_TLV_TTL:
		return ("TTL");
	case LLDP_TLV_PORT_DESC:
		return ("Port Description");
	case LLDP_TLV_SYS_NAME:
		return ("System Name");
	case LLDP_TLV_SYS_DESC:
		return ("System Description");
	case LLDP_TLV_SYS_CAP:
		return ("System Capabilities");
	case LLDP_TLV_MGMT_ADDR:
		return ("Management Address");
	case LLDP_TLV_ORG_SPEC:
		return ("Organizationally Specific");
	default:
		return ("Reserved");
	}
}

/*
 * Write a printable form of a string from a TLV; see liblldp.h.
 */
size_t
lldp_str_print(const lldp_str_t *s, char *buf, size_t buflen, uint_t flags)
{
	const uint8_t	*v = s->ls_data;
	size_t		len = s->ls_len;
	size_t		total = 0;

	if (buflen > 0)
		buf[0] = '\0';

	/* Some implementations pad with NULs or whitespace */
	while (len > 0 && (v[len - 1] == '\0' || v[len - 1] == ' ' ||
	    v[len - 1] == '\t' || v[len - 1] == '\r' || v[len - 1] == '\n')) {
		len--;
	}

	for (size_t i = 0; i < len; i++) {
		uint8_t c = v[i];

		/* CR LF is a single line break */
		if (c == '\r' && i + 1 < len && v[i + 1] == '\n')
			continue;

		if (c == '\n' || c == '\r') {
			total += lldp_append(buf, buflen, total, "%s",
			    (flags & LLDP_STR_MULTILINE) ? "\n" : " ");
		} else if (c == '\t') {
			total += lldp_append(buf, buflen, total, " ");
		} else if (c == '\\') {
			total += lldp_append(buf, buflen, total, "\\\\");
		} else if (c < 0x20 || c > 0x7e) {
			/* Includes all non-ASCII bytes, and DEL */
			total += lldp_append(buf, buflen, total, "\\x%02x", c);
		} else {
			total += lldp_append(buf, buflen, total, "%c", c);
		}
	}

	return (total);
}

size_t
lldp_mgmt_addr_str(const lldp_mgmt_addr_t *ma, char *buf, size_t buflen)
{
	uint8_t	v[1 + LLDP_MGMT_ADDR_MAX];
	size_t	alen = MIN(ma->lma_addrlen, LLDP_MGMT_ADDR_MAX);

	/* Same encoding as a network address chassis/port id */
	v[0] = ma->lma_af;
	(void) memcpy(v + 1, ma->lma_addr, alen);
	return (lldp_netaddr_str(v, 1 + alen, buf, buflen));
}

const char *
lldp_mgmt_iftype_str(lldp_mgmt_ifnum_t t)
{
	switch (t) {
	case LLDP_MGMT_UNKNOWN:
		return ("unknown");
	case LLDP_MGMT_IFINDEX:
		return ("ifIndex");
	case LLDP_MGMT_SYSPORT:
		return ("system port");
	default:
		return ("unknown");
	}
}

/*
 * RFC 4836 ifMauAutoNegCapAdvertisedBits, by bit number. The media names
 * match lldp_mau_str(), with the duplex as HD/FD.
 */
static const char *autoneg_cap_names[16] = {
	"other",		/* bOther */
	"10BASE-T HD",		/* b10baseT */
	"10BASE-T FD",		/* b10baseTFD */
	"100BASE-T4",		/* b100baseT4 */
	"100BASE-TX HD",	/* b100baseTX */
	"100BASE-TX FD",	/* b100baseTXFD */
	"100BASE-T2 HD",	/* b100baseT2 */
	"100BASE-T2 FD",	/* b100baseT2FD */
	"PAUSE",		/* bFdxPause */
	"asym PAUSE",		/* bFdxAPause */
	"sym PAUSE",		/* bFdxSPause */
	"asym+sym PAUSE",	/* bFdxBPause */
	"1000BASE-X HD",	/* b1000baseX */
	"1000BASE-X FD",	/* b1000baseXFD */
	"1000BASE-T HD",	/* b1000baseT */
	"1000BASE-T FD",	/* b1000baseTFD */
};

size_t
lldp_autoneg_caps_str(uint16_t adv, char *buf, size_t buflen)
{
	size_t total = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (uint_t i = 0; i < ARRAY_SIZE(autoneg_cap_names); i++) {
		if ((adv & LLDP_AUTONEG_CAP(i)) == 0)
			continue;
		total += lldp_append(buf, buflen, total, "%s%s",
		    (total > 0) ? "," : "", autoneg_cap_names[i]);
	}

	if (total == 0)
		total = lldp_append(buf, buflen, 0, "none");

	return (total);
}

const char *
lldp_oui_str(uint32_t oui)
{
	switch (oui) {
	case LLDP_OUI_8021:
		return ("IEEE 802.1");
	case LLDP_OUI_8023:
		return ("IEEE 802.3");
	case LLDP_OUI_TIA:
		return ("TIA TR-41");
	default:
		return (NULL);
	}
}
