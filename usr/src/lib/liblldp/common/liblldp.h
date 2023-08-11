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

#ifndef _LIBLLDP_H
#define	_LIBLLDP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum lldp_tlv_type {
	LLDP_TLV_END =		0,
	LLDP_TLV_CHASSIS_ID =	1,
	LLDP_TLV_PORT_ID =	2,
	LLDP_TLV_TTL =		3,
	LLDP_TLV_PORT_DESC =	4,
	LLDP_TLV_SYS_NAME =	5,
	LLDP_TLV_SYS_DESC = 	6,
	LLDP_TLV_SYS_CAP =	7,
	LLDP_TLV_MGMT_ADDR =	8,
	LLDP_TLV_ORG_SPEC =	127,
} lldp_tlv_type_t;
#define	LLDP_TLV_MAX		LLDP_TLV_ORG_SPEC

typedef enum lldp_admin_status {
	LLDP_LINK_DISABLED =	0,
	LLDP_LINK_TX =		1,
	LLDP_LINK_RX =		2,
	LLDP_LINK_TXRX =	3,
} lldp_admin_status_t;

typedef enum lldp_chassis_type {
	LLDP_CHASSIS_COMPONENT =	1,
	LLDP_CHASSIS_IFALIAS =		2,
	LLDP_CHASSIS_PORT =		3,
	LLDP_CHASSIS_MACADDR =		4,
	LLDP_CHASSIS_NETADDR =		5,
	LLDP_CHASSIS_IFNAME =		6,
	LLDP_CHASSIS_LOCAL =		7,
} lldp_chassis_type_t;

#define	LLDP_CHASSIS_MAX	255
typedef struct lldp_chassis {
	lldp_chassis_type_t	llc_type;
	uint8_t			llc_id[LLDP_CHASSIS_MAX];
	uint8_t			llc_len;
} lldp_chassis_t;

typedef enum lldp_port_type {
	LLDP_PORT_IFALIAS =	1,
	LLDP_PORT_COMPONENT =	2,
	LLDP_PORT_MACADDR =	3,
	LLDP_PORT_NETADDR =	4,
	LLDP_PORT_IFNAME =	5,
	LLDP_PORT_CIRCUIT_ID =	6,
	LLDP_PORT_LOCAL =	7,
} lldp_port_type_t;

#define	LLDP_PORT_MAX		255
typedef struct lldp_port {
	lldp_port_type_t	llp_type;
	uint8_t			llp_id[LLDP_PORT_MAX];
	uint8_t			llp_len;
} lldp_port_t;

/*
 * These reflect the sizes on the wire, which do not include any terminating
 * NULs (which are not sent over the wire).
 */
#define	LLDP_PORT_DESC_MAX	255
#define	LLDP_SYS_NAME_MAX	255
#define	LLDP_SYS_DESC_MAX	255
#define	LLDP_MGMR_ADDR_MAX	31

typedef enum lldp_cap {
	LLDP_CAP_NONE =		0,
	LLDP_CAP_OTHER =	(1 << 0),
	LLDP_CAP_REPEATER =	(1 << 1),
	LLDP_CAP_MAC_BRIDGE =	(1 << 2),
	LLDP_CAP_AP =		(1 << 3),
	LLDP_CAP_ROUTER =	(1 << 4),
	LLDP_CAP_PHONE =	(1 << 5),
	LLDP_CAP_DOCSIS =	(1 << 6),
	LLDP_CAP_STATION =	(1 << 7),
	LLDP_CAP_CVLAN =	(1 << 8),
	LLDP_CAP_SVLAN =	(1 << 9),
	LLDP_CAP_TPMR =		(1 << 10),
} lldp_cap_t;

typedef enum lldp_mgmt_ifnum {
	LLDP_MGMT_UNKNOWN =	1,
	LLDP_MGMT_IFINDEX =	2,
	LLDP_MGMT_SYSPORT =	3,
} lldp_mgmt_ifnum_t;

typedef enum lldp_vlan {
	LLDP_VLAN_NONE =	0,
	LLDP_VLAN_SUP =		(1 << 0),
	LLDP_VLAN_EN =		(1 << 1),
} lldp_vlan_t;

typedef enum lldp_aggr {
	LLDP_AGGR_NONE =	0,
	LLDP_AGGR_SUP =		(1 << 0),
	LLDP_AGGR_EN =		(1 << 1),
} lldp_aggr_t;

/*
 * The core TLVs that can optionally be sent. Chassis ID and Port ID are always
 * required and cannot be disabled (thus are omitted from this list).
 */
typedef enum lldp_tx_core_tlv {
	LLDP_TX_NONE =		0,
	LLDP_TX_PORTDESC =	(1 << 0),
	LLDP_TX_SYSNAME =	(1 << 1),
	LLDP_TX_SYSDESC =	(1 << 2),
	LLDP_TX_SYSCAP =	(1 << 3),
	LLDP_TX_MGMTADDR =	(1 << 4),
} lldp_tx_core_tlv_t;

typedef enum lldp_tx_8021_tlv {
	LLDP_TX_X1_NONE =		0,
	LLDP_TX_X1_NATIVE_VLAN =	(1 << 0),
	LLDP_TX_X1_VLANS =		(1 << 1),
	LLDP_TX_X1_VLAN_NAME =		(1 << 2),
	LLDP_TX_X2_MGMT_VLAN =		(1 << 3),
} lldp_tx_8021_tlv_t;

extern const uint8_t lldp_oui_8023[3];

typedef enum lldp_8023_type {
	LLDP_8023_PHYCFG =		1,
	LLDP_8023_POWER_MDI =		2,
	LLDP_8023_AGGR =		3,	/* deprecated */
	LLDP_8023_MTU =			4,
	LLDP_8023_EEE =			5,
	LLDP_8023_EEE_FAST_WAKE =	6,
	LLDP_8023_ADDTL =		7,
	LLDP_8023_POWER_MEASURE =	8,
} lldp_8023_type_t;

typedef enum lldp_tx_8023_tlv {
	LLDP_TX_X3_PHYCFG =		(1 << 0),
	LLDP_TX_X3_MTU =		(1 << 1),
} lldp_tx_8023_tlv_t;

typedef struct lldp_config {
	lldp_chassis_t	lcfg_chassis;
	char		*lcfg_sysname;
	char		*lcfg_sysdesc;
	uint16_t	lcfg_syscap;
	uint16_t	lcfg_encap;
	/*
	 * For the management addresses, we currently only support sending
	 * IPv4/IPv6 addresses. We keep a NULL terminated list of IP interface
	 * names that we use to obtain the management address to send.
	 */
	char		**lcfg_mgmt_if;
} lldp_config_t;

typedef struct lldp_agent_config {
	lldp_admin_status_t	lac_status;
	lldp_port_t		lac_port;
	char			*lac_portdesc;
	lldp_tx_core_tlv_t	lac_core_tlvs;
	lldp_tx_8021_tlv_t	lac_8021_tlvs;
	lldp_tx_8023_tlv_t	lac_8023_tlvs;
} lldp_agent_config_t;

typedef struct lldp_agent_stats {
	uint64_t	las_ageouts;
	uint64_t	las_discarded;
	uint64_t	las_in_errors;
	uint64_t	las_in_frames;
	uint64_t	las_out_frames;
	uint64_t	las_discarded_tlvs;
	uint64_t	las_unknown_tlvs;
	uint64_t	las_length_errs;
} lldp_agent_stats_t;

const char *lldp_tlv_type_str(lldp_tlv_type_t);
const char *lldp_admin_status_str(lldp_admin_status_t);
const char *lldp_chassis_typestr(lldp_chassis_type_t);
const char *lldp_port_typestr(lldp_port_type_t);
/* Note only one cap may be set for this */
const char *lldp_cap_str(lldp_cap_t);

size_t lldp_chassis_str(const lldp_chassis_t *, char *, size_t);
size_t lldp_port_str(const lldp_port_t *, char *, size_t);
size_t lldp_caps_str(lldp_cap_t, char *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBLLDP_H */
