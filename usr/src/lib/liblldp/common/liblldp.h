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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mac_ether.h>
#include <stdbool.h>

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
#define	LLDP_MGMT_ADDR_MAX	31	/* Management address (w/o family) */
#define	LLDP_MGMT_OID_MAX	128	/* Management address object id */

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

/* OUIs of organizationally specific TLVs (as a 24-bit value) */
#define	LLDP_OUI_8021	0x0080c2	/* IEEE 802.1 */
#define	LLDP_OUI_8023	0x00120f	/* IEEE 802.3 */
#define	LLDP_OUI_TIA	0x0012bb	/* TIA TR-41 (LLDP-MED) */

/* IEEE 802.1 organizationally specific TLVs (802.1Q Annex D) */
typedef enum lldp_8021_type {
	LLDP_8021_PVID =		1,	/* Port VLAN ID */
	LLDP_8021_PPVID =		2,	/* Port and protocol VLAN ID */
	LLDP_8021_VLAN_NAME =		3,
	LLDP_8021_PROTO_ID =		4,	/* Protocol identity */
	LLDP_8021_VID_USAGE =		5,	/* VID usage digest */
	LLDP_8021_MGMT_VID =		6,	/* Management VID */
	LLDP_8021_AGGR =		7,	/* Link aggregation */
} lldp_8021_type_t;

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

/*
 * Per-agent counters, following the LLDP-V2-MIB statistics (802.1AB-2016
 * 9.2.6.2 and 11.5). They count from when lldpd created the agent.
 */
typedef struct lldp_agent_stats {
	uint64_t	las_ageouts;	/* Neighbors whose info aged out */
	uint64_t	las_discarded;	/* Received frames discarded */
	uint64_t	las_in_errors;	/* Received frames in error */
	uint64_t	las_in_frames;	/* Valid LLDPDUs received */
	uint64_t	las_out_frames;	/* LLDPDUs sent (incl. shutdown) */
	uint64_t	las_discarded_tlvs; /* TLVs discarded from valid PDUs */
	uint64_t	las_unknown_tlvs; /* TLVs with a reserved type */
	uint64_t	las_length_errs; /* TX TLVs that didn't fit the PDU */
	uint64_t	las_rem_drops;	/* New neighbors dropped (too many) */
} lldp_agent_stats_t;

/*
 * A neighbor of one of lldpd's agents, as returned by lldp_get_neighbors().
 */
typedef struct lldp_neighbor {
	char		ln_link[MAXLINKNAMELEN];	/* Agent's hw link */
	uint16_t	ln_ttl;		/* Seconds until the info ages out */
	size_t		ln_pdu_len;
	uint8_t		*ln_pdu;	/* The LLDPDU, exactly as received */
} lldp_neighbor_t;

/*
 * Retrieve the current neighbors of the agent for the given link, or of all
 * agents if link is NULL. The link may be given by its hardware name (e.g.
 * 'igb0') or, if it has been renamed, its datalink name; ln_link is always
 * the hardware name. On success, returns 0 and sets
 * *nbrsp to an array of *nump neighbors, which must be freed with
 * lldp_neighbors_free(). On failure, returns an errno value: ENOENT if
 * there's no agent for link, ECONNREFUSED if lldpd isn't running.
 */
int lldp_get_neighbors(const char *, lldp_neighbor_t **, uint_t *);
void lldp_neighbors_free(lldp_neighbor_t *, uint_t);

/*
 * The statistics of one of lldpd's agents, as returned by lldp_get_stats().
 */
typedef struct lldp_stats {
	char			ls_link[MAXLINKNAMELEN]; /* Agent's hw link */
	uint32_t		ls_linkid;	/* Its datalink id */
	lldp_agent_stats_t	ls_stats;
} lldp_stats_t;

/*
 * Retrieve the statistics of the agent for the given link (by hardware or
 * datalink name, as with lldp_get_neighbors()), or of every agent if link
 * is NULL, ordered by ls_link. On success, returns 0 and sets *statsp to
 * an array of *nump entries, which must be freed with lldp_stats_free().
 * On failure, returns an errno value (as for lldp_get_neighbors()).
 */
int lldp_get_stats(const char *, lldp_stats_t **, uint_t *);
void lldp_stats_free(lldp_stats_t *, uint_t);

/*
 * For the lldp RCM module: tell lldpd that the link with the given datalink
 * id is being offlined (lldpd releases it), that the offline has been
 * undone or the link is back online (lldpd reopens it), or that it has been
 * removed (lldpd destroys its agent). Returns 0 on success, or an errno
 * value: ENOENT if lldpd has no agent for the link, ECONNREFUSED if lldpd
 * isn't running, EPERM if the caller lacks {PRIV_SYS_DL_CONFIG}.
 */
typedef enum lldp_link_event {
	LLDP_LINK_EV_OFFLINE = 1,
	LLDP_LINK_EV_ONLINE,
	LLDP_LINK_EV_REMOVE,
} lldp_link_event_t;

int lldp_link_notify(lldp_link_event_t, uint32_t);

const char *lldp_tlv_type_str(lldp_tlv_type_t);

/*
 * The IANA dot3MauType value (the final arc of its OID) corresponding to a
 * mac_ether_media_t, or LLDP_MAU_UNKNOWN if there isn't one. Where IANA
 * has separate half/full duplex types, the full duplex type is returned.
 */
#define	LLDP_MAU_UNKNOWN	0
uint16_t lldp_ether_media_to_mau(mac_ether_media_t);
const char *lldp_admin_status_str(lldp_admin_status_t);
const char *lldp_chassis_typestr(lldp_chassis_type_t);
const char *lldp_port_typestr(lldp_port_type_t);
/* Note only one cap may be set for this */
const char *lldp_cap_str(lldp_cap_t);

size_t lldp_chassis_str(const lldp_chassis_t *, char *, size_t);
size_t lldp_port_str(const lldp_port_t *, char *, size_t);
size_t lldp_caps_str(lldp_cap_t, char *, size_t);

/*
 * Parsing LLDPDUs (e.g. as returned by lldp_get_neighbors()).
 */

/*
 * A TLV of an LLDPDU. lt_value (lt_len bytes) points into the PDU. For an
 * organizationally specific TLV with a complete header (lt_org), lt_oui and
 * lt_subtype are split out, and lt_info (lt_infolen bytes) is the rest of
 * the value (the information string).
 */
typedef struct lldp_tlv {
	uint8_t		lt_type;	/* lldp_tlv_type_t (0-127) */
	uint16_t	lt_len;
	size_t		lt_off;		/* Offset of the TLV in the PDU */
	const uint8_t	*lt_value;
	bool		lt_org;
	uint32_t	lt_oui;
	uint8_t		lt_subtype;
	uint16_t	lt_infolen;
	const uint8_t	*lt_info;
} lldp_tlv_t;

/*
 * Iterate over the TLVs of a PDU. lldp_tlv_iter_next() returns 1 and fills
 * in the next TLV (including the End TLV), 0 when there are no more (after
 * the End TLV, or at the end of the data if there isn't one; lti_noend is
 * then set), or -1 if the next TLV is truncated (its header or value runs
 * past the end of the data; lti_off is its offset). The data must remain
 * valid while the TLVs are in use.
 */
typedef struct lldp_tlv_iter {
	const uint8_t	*lti_pdu;
	size_t		lti_len;
	size_t		lti_off;
	bool		lti_done;
	bool		lti_noend;
} lldp_tlv_iter_t;

void lldp_tlv_iter_init(lldp_tlv_iter_t *, const void *, size_t);
int lldp_tlv_iter_next(lldp_tlv_iter_t *, lldp_tlv_t *);

/*
 * A string from a TLV, exactly as received: it isn't NUL-terminated and
 * can contain anything. Use lldp_str_print() to display it.
 */
typedef struct lldp_str {
	const uint8_t	*ls_data;
	uint16_t	ls_len;
} lldp_str_t;

typedef struct lldp_mgmt_addr {
	uint8_t			lma_af;		/* IANA address family */
	uint8_t			lma_addrlen;
	uint8_t			lma_addr[LLDP_MGMT_ADDR_MAX];
	lldp_mgmt_ifnum_t	lma_iftype;	/* As received (may be 0) */
	uint32_t		lma_ifnum;
	uint8_t			lma_oidlen;	/* ASN.1 BER encoded OID */
	const uint8_t		*lma_oid;
} lldp_mgmt_addr_t;

/* lpv_flags */
#define	LLDP_PPVID_SUP		0x02	/* Port and protocol VLAN supported */
#define	LLDP_PPVID_EN		0x04	/* ... and enabled */

typedef struct lldp_ppvid {
	uint8_t		lpv_flags;
	uint16_t	lpv_ppvid;
} lldp_ppvid_t;

typedef struct lldp_vlan_name {
	uint16_t	lvn_vid;
	lldp_str_t	lvn_name;
} lldp_vlan_name_t;

/* lla_status (bits 2-3 are the 802.1AX-2014 aggregation port type) */
#define	LLDP_LINK_AGGR_CAP	0x01	/* Aggregation capability */
#define	LLDP_LINK_AGGR_STATUS	0x02	/* Currently aggregated */
#define	LLDP_LINK_AGGR_PORT_TYPE(s)	(((s) >> 2) & 0x3)

typedef struct lldp_link_aggr {
	uint8_t		lla_status;
	uint32_t	lla_portid;	/* Aggregated port id (ifIndex) */
} lldp_link_aggr_t;

/* lpc_autoneg */
#define	LLDP_AUTONEG_SUP	0x01
#define	LLDP_AUTONEG_EN		0x02

/*
 * lpc_adv is RFC 4836 ifMauAutoNegCapAdvertisedBits, with bit 0 (bOther)
 * as the most significant bit of the 16-bit field.
 */
#define	LLDP_AUTONEG_CAP(n)	((uint16_t)(0x8000 >> (n)))

typedef struct lldp_phycfg {
	uint8_t		lpc_autoneg;
	uint16_t	lpc_adv;
	uint16_t	lpc_mau;	/* dot3MauType; see lldp_mau_str() */
} lldp_phycfg_t;

typedef struct lldp_power_mdi {
	uint8_t		lpm_support;	/* MDI power support */
	uint8_t		lpm_pair;	/* PSE power pair */
	uint8_t		lpm_class;	/* Power class */
} lldp_power_mdi_t;

/* lp_present: which of the single-valued optional TLVs were received */
#define	LLDP_PDU_PORT_DESC	(1U << 0)
#define	LLDP_PDU_SYS_NAME	(1U << 1)
#define	LLDP_PDU_SYS_DESC	(1U << 2)
#define	LLDP_PDU_SYS_CAP	(1U << 3)
#define	LLDP_PDU_PVID		(1U << 4)
#define	LLDP_PDU_MGMT_VID	(1U << 5)
#define	LLDP_PDU_AGGR		(1U << 6)
#define	LLDP_PDU_PHYCFG		(1U << 7)
#define	LLDP_PDU_POWER_MDI	(1U << 8)
#define	LLDP_PDU_MAX_FRAME	(1U << 9)

/* lp_flags: problems with the PDU as a whole */
#define	LLDP_PDU_F_NO_END	(1U << 0)	/* No End TLV */
#define	LLDP_PDU_F_TRUNCATED	(1U << 1)	/* A TLV ran past the end */
#define	LLDP_PDU_F_TRAILING	(1U << 2)	/* Data after the End TLV */

/*
 * A decoded LLDPDU. Everything points into lp_pdu, a copy of the PDU.
 *
 * TLVs that aren't decoded (reserved TLV types, and organizationally
 * specific TLVs with an OUI or subtype that isn't decoded) are in lp_other.
 * TLVs that are malformed (e.g. the wrong length), or that appear more than
 * once when they mustn't (only the first is used), are in lp_bad.
 */
typedef struct lldp_pdu {
	uint32_t		lp_present;
	uint32_t		lp_flags;

	lldp_chassis_t		lp_chassis;
	lldp_port_t		lp_port;
	uint16_t		lp_ttl;
	lldp_str_t		lp_port_desc;
	lldp_str_t		lp_sys_name;
	lldp_str_t		lp_sys_desc;
	lldp_cap_t		lp_sys_caps;
	lldp_cap_t		lp_en_caps;
	uint_t			lp_nmgmt;
	lldp_mgmt_addr_t	*lp_mgmt;

	/* IEEE 802.1 */
	uint16_t		lp_pvid;
	uint16_t		lp_mgmt_vid;
	uint_t			lp_nppvid;
	lldp_ppvid_t		*lp_ppvid;
	uint_t			lp_nvlan_names;
	lldp_vlan_name_t	*lp_vlan_names;
	uint_t			lp_nproto;
	lldp_str_t		*lp_proto;	/* Protocol identities */
	lldp_link_aggr_t	lp_aggr;	/* Also 802.3 (deprecated) */

	/* IEEE 802.3 */
	lldp_phycfg_t		lp_phycfg;
	lldp_power_mdi_t	lp_power;
	uint16_t		lp_max_frame;

	uint_t			lp_nother;
	lldp_tlv_t		*lp_other;
	uint_t			lp_nbad;
	lldp_tlv_t		*lp_bad;

	size_t			lp_pdulen;
	uint8_t			*lp_pdu;
} lldp_pdu_t;

/*
 * Parse an LLDPDU (starting with its Chassis ID TLV, e.g. ln_pdu). On
 * success, returns 0 and sets *pdup, which must be freed with
 * lldp_pdu_free(). Fails with EBADMSG if the PDU doesn't start with valid
 * Chassis ID, Port ID, and TTL TLVs; problems elsewhere in the PDU don't
 * cause a failure, but are recorded (lp_bad, lp_flags).
 */
int lldp_pdu_parse(const void *, size_t, lldp_pdu_t **);
void lldp_pdu_free(lldp_pdu_t *);

/*
 * Write a printable form of a string from a TLV into buf, with snprintf()
 * semantics: bytes that aren't printable ASCII (and backslashes) are
 * written as C-style escapes (e.g. '\x1b'), so the result is always safe
 * to display; trailing NULs and whitespace are dropped. With
 * LLDP_STR_MULTILINE, line breaks are kept (as '\n'); otherwise each is
 * written as a space.
 */
#define	LLDP_STR_MULTILINE	0x1
size_t lldp_str_print(const lldp_str_t *, char *, size_t, uint_t);

/* The management address (e.g. "192.0.2.1"), with snprintf() semantics */
size_t lldp_mgmt_addr_str(const lldp_mgmt_addr_t *, char *, size_t);
const char *lldp_mgmt_iftype_str(lldp_mgmt_ifnum_t);

/*
 * The advertised auto-negotiation capabilities (lpc_adv) as a comma
 * separated list (e.g. "1000BASE-T FD,100BASE-TX FD"), with snprintf()
 * semantics. An empty set is written as "none".
 */
size_t lldp_autoneg_caps_str(uint16_t, char *, size_t);

/* The name of a well-known OUI (e.g. "IEEE 802.3"), or NULL */
const char *lldp_oui_str(uint32_t);

/*
 * The name of a dot3MauType (e.g. "1000BASE-T"), or NULL if it isn't known.
 * If the MAU type specifies the duplex mode, it's returned via the second
 * argument (if non-NULL).
 */
typedef enum lldp_mau_mode {
	LLDP_MAU_MODE_UNSPECIFIED = 0,
	LLDP_MAU_MODE_HALF,
	LLDP_MAU_MODE_FULL,
	LLDP_MAU_MODE_MULTIDROP,
} lldp_mau_mode_t;

const char *lldp_mau_str(uint16_t, lldp_mau_mode_t *);
const char *lldp_mau_mode_str(lldp_mau_mode_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBLLDP_H */
