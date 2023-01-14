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
 * Copyright 2022 Jason King
 */

#include <libcustr.h>
#include <liblldp.h>

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

size_t
lldp_chassis_str(const lldp_chassis_t *c, char *buf, size_t buflen)
{
	return (0);
}

size_t
lldp_port_str(const lldp_port_t *p, char *buf, size_t buflen)
{
	return (0);
}

size_t
lldp_caps_str(lldp_cap_t caps, char *buf, size_t buflen)
{
	return (0);
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
