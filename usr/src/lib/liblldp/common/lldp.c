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

#include <stdarg.h>
#include <stdbool.h>
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
 * snprintf() semantics.
 */
static size_t
lldp_text_str(const uint8_t *v, size_t vlen, char *buf, size_t buflen)
{
	int n;

	n = snprintf(buf, buflen, "%.*s", (int)vlen, (const char *)v);
	return ((n < 0) ? 0 : (size_t)n);
}

const char *
lldp_admin_status_str(lldp_admin_status_t s)
{
	switch (s) {
	case LLDP_LINK_DISABLED:
		return ("disabled");
	case LLDP_LINK_TX:
		return ("tx");
	case LLDP_LINK_RX:
		return ("rx");
	case LLDP_LINK_TXRX:
		return ("txrx");
	default:
		return ("unknown");
	}
}

const char *
lldp_chassis_typestr(lldp_chassis_type_t t)
{
	switch (t) {
	case LLDP_CHASSIS_COMPONENT:
		return ("component");
	case LLDP_CHASSIS_IFALIAS:
		return ("ifAlias");
	case LLDP_CHASSIS_PORT:
		return ("port");
	case LLDP_CHASSIS_MACADDR:
		return ("macaddr");
	case LLDP_CHASSIS_NETADDR:
		return ("netaddr");
	case LLDP_CHASSIS_IFNAME:
		return ("ifName");
	case LLDP_CHASSIS_LOCAL:
		return ("local");
	default:
		return ("unknown");
	}
}

const char *
lldp_port_typestr(lldp_port_type_t t)
{
	switch (t) {
	case LLDP_PORT_IFALIAS:
		return ("ifAlias");
	case LLDP_PORT_COMPONENT:
		return ("component");
	case LLDP_PORT_MACADDR:
		return ("macaddr");
	case LLDP_PORT_NETADDR:
		return ("netaddr");
	case LLDP_PORT_IFNAME:
		return ("ifName");
	case LLDP_PORT_CIRCUIT_ID:
		return ("circuitId");
	case LLDP_PORT_LOCAL:
		return ("local");
	default:
		return ("unknown");
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
		return ("Chassis Id");
	case LLDP_TLV_PORT_ID:
		return ("Port Id");
	case LLDP_TLV_TTL:
		return ("ttl");
	case LLDP_TLV_PORT_DESC:
		return ("Port Description");
	case LLDP_TLV_SYS_NAME:
		return ("System Name");
	case LLDP_TLV_SYS_DESC:
		return ("System description");
	case LLDP_TLV_SYS_CAP:
		return ("System capabilities");
	case LLDP_TLV_MGMT_ADDR:
		return ("Management addresses");
	case LLDP_TLV_ORG_SPEC:
		return ("Organization specific");
	default:
		return ("Unknown");
	}
}
