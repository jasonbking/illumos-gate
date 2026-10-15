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
 * Parsing of LLDPDUs (IEEE 802.1AB-2016 clause 8, the IEEE 802.1 TLVs of
 * IEEE 802.1Q-2018 Annex D, and the IEEE 802.3 TLVs of IEEE 802.3-2022
 * clause 79).
 *
 * A PDU comes from the network, so nothing about it is trusted: every
 * length is checked against what's actually present before it's used. A
 * malformed TLV is recorded (in lp_bad) and skipped, so a single bad TLV
 * doesn't hide the rest of the PDU; only the mandatory TLVs (Chassis ID,
 * Port ID, and TTL, which must come first, in that order) are required to
 * be valid.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

#define	TLV_HDR_LEN	2
#define	ORG_HDR_LEN	4	/* OUI (3) + subtype (1) */

/* The lengths (of the TLV value) 802.1AB allows for the basic TLVs */
#define	ID_LEN_MIN	2	/* Subtype + at least 1 byte of id */
#define	ID_LEN_MAX	256	/* Subtype + up to 255 bytes of id */
#define	TTL_LEN		2
#define	STR_LEN_MAX	255
#define	SYS_CAP_LEN	4
#define	MGMT_LEN_MIN	9
#define	MGMT_LEN_MAX	167

static uint16_t
get16(const uint8_t *p)
{
	return ((uint16_t)((p[0] << 8) | p[1]));
}

static uint32_t
get32(const uint8_t *p)
{
	return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

void
lldp_tlv_iter_init(lldp_tlv_iter_t *it, const void *pdu, size_t len)
{
	(void) memset(it, '\0', sizeof (*it));
	it->lti_pdu = pdu;
	it->lti_len = (pdu == NULL) ? 0 : len;
}

int
lldp_tlv_iter_next(lldp_tlv_iter_t *it, lldp_tlv_t *tlv)
{
	const uint8_t	*p;
	size_t		left;

	if (it->lti_done)
		return (0);

	left = it->lti_len - it->lti_off;
	if (left == 0) {
		it->lti_done = true;
		it->lti_noend = true;
		return (0);
	}

	if (left < TLV_HDR_LEN)
		return (-1);

	p = it->lti_pdu + it->lti_off;
	(void) memset(tlv, '\0', sizeof (*tlv));
	tlv->lt_type = p[0] >> 1;
	tlv->lt_len = ((p[0] & 0x1) << 8) | p[1];
	tlv->lt_off = it->lti_off;
	tlv->lt_value = p + TLV_HDR_LEN;

	if (tlv->lt_len > left - TLV_HDR_LEN)
		return (-1);

	if (tlv->lt_type == LLDP_TLV_ORG_SPEC && tlv->lt_len >= ORG_HDR_LEN) {
		tlv->lt_org = true;
		tlv->lt_oui = ((uint32_t)tlv->lt_value[0] << 16) |
		    ((uint32_t)tlv->lt_value[1] << 8) | tlv->lt_value[2];
		tlv->lt_subtype = tlv->lt_value[3];
		tlv->lt_info = tlv->lt_value + ORG_HDR_LEN;
		tlv->lt_infolen = tlv->lt_len - ORG_HDR_LEN;
	}

	it->lti_off += TLV_HDR_LEN + tlv->lt_len;
	if (tlv->lt_type == LLDP_TLV_END)
		it->lti_done = true;

	return (1);
}

/*
 * Append an element (of size bytes) to the array *arrp of *nump elements,
 * growing it as needed. Returns false if out of memory.
 */
static bool
append(void *arrp, uint_t *nump, size_t size, const void *elem)
{
	void		**ap = arrp;
	uint_t		n = *nump;
	uint8_t		*a;

	/* Grow by doubling, starting at 4 */
	if (n == 0 || (n >= 4 && (n & (n - 1)) == 0)) {
		uint_t newn = (n == 0) ? 4 : n * 2;

		if ((a = reallocarray(*ap, newn, size)) == NULL)
			return (false);
		*ap = a;
	}

	a = *ap;
	(void) memcpy(a + n * size, elem, size);
	*nump = n + 1;
	return (true);
}

static bool
add_tlv(lldp_tlv_t **listp, uint_t *nump, const lldp_tlv_t *tlv)
{
	return (append(listp, nump, sizeof (lldp_tlv_t), tlv));
}

/*
 * If the single-valued TLV flag is already present, the TLV is a duplicate.
 * Otherwise mark it present.
 */
static bool
first(lldp_pdu_t *pdu, uint32_t flag)
{
	if (pdu->lp_present & flag)
		return (false);
	pdu->lp_present |= flag;
	return (true);
}

static void
set_str(lldp_str_t *s, const uint8_t *data, size_t len)
{
	s->ls_data = data;
	s->ls_len = (uint16_t)len;
}

/* Returns 0, or -1 if the TLV is malformed, or ENOMEM */
static int
parse_mgmt(lldp_pdu_t *pdu, const lldp_tlv_t *tlv)
{
	const uint8_t		*v = tlv->lt_value;
	size_t			len = tlv->lt_len;
	lldp_mgmt_addr_t	ma = { 0 };
	size_t			slen, off;

	if (len < MGMT_LEN_MIN || len > MGMT_LEN_MAX)
		return (-1);

	/* String length: address subtype (1) + address (1-31) */
	slen = v[0];
	if (slen < 2 || slen > LLDP_MGMT_ADDR_MAX + 1)
		return (-1);

	/* String length byte + string + interface subtype + number + OID len */
	if (1 + slen + 1 + 4 + 1 > len)
		return (-1);

	ma.lma_af = v[1];
	ma.lma_addrlen = (uint8_t)(slen - 1);
	(void) memcpy(ma.lma_addr, v + 2, ma.lma_addrlen);

	off = 1 + slen;
	ma.lma_iftype = (lldp_mgmt_ifnum_t)v[off];
	ma.lma_ifnum = get32(v + off + 1);
	off += 5;

	ma.lma_oidlen = v[off++];
	if (ma.lma_oidlen > LLDP_MGMT_OID_MAX || off + ma.lma_oidlen != len)
		return (-1);
	ma.lma_oid = (ma.lma_oidlen > 0) ? v + off : NULL;

	if (!append(&pdu->lp_mgmt, &pdu->lp_nmgmt, sizeof (ma), &ma))
		return (ENOMEM);
	return (0);
}

/* As parse_mgmt(); returns 1 if the subtype isn't one we decode */
static int
parse_8021(lldp_pdu_t *pdu, const lldp_tlv_t *tlv)
{
	const uint8_t	*v = tlv->lt_info;
	size_t		len = tlv->lt_infolen;

	switch (tlv->lt_subtype) {
	case LLDP_8021_PVID:
		if (len != 2)
			return (-1);
		if (!first(pdu, LLDP_PDU_PVID))
			return (-1);
		pdu->lp_pvid = get16(v);
		return (0);

	case LLDP_8021_PPVID: {
		lldp_ppvid_t pv;

		if (len != 3)
			return (-1);
		pv.lpv_flags = v[0];
		pv.lpv_ppvid = get16(v + 1);
		if (!append(&pdu->lp_ppvid, &pdu->lp_nppvid, sizeof (pv), &pv))
			return (ENOMEM);
		return (0);
	}

	case LLDP_8021_VLAN_NAME: {
		lldp_vlan_name_t vn;

		/* VID (2) + name length (1) + name (0-32) */
		if (len < 3 || v[2] > 32 || len != 3 + (size_t)v[2])
			return (-1);
		vn.lvn_vid = get16(v);
		set_str(&vn.lvn_name, v + 3, v[2]);
		if (!append(&pdu->lp_vlan_names, &pdu->lp_nvlan_names,
		    sizeof (vn), &vn)) {
			return (ENOMEM);
		}
		return (0);
	}

	case LLDP_8021_PROTO_ID: {
		lldp_str_t ps;

		/* Length (1) + protocol identity (0-255) */
		if (len < 1 || len != 1 + (size_t)v[0])
			return (-1);
		set_str(&ps, v + 1, v[0]);
		if (!append(&pdu->lp_proto, &pdu->lp_nproto, sizeof (ps), &ps))
			return (ENOMEM);
		return (0);
	}

	case LLDP_8021_MGMT_VID:
		if (len != 2)
			return (-1);
		if (!first(pdu, LLDP_PDU_MGMT_VID))
			return (-1);
		pdu->lp_mgmt_vid = get16(v);
		return (0);

	case LLDP_8021_AGGR:
		if (len != 5)
			return (-1);
		if (!first(pdu, LLDP_PDU_AGGR))
			return (-1);
		pdu->lp_aggr.lla_status = v[0];
		pdu->lp_aggr.lla_portid = get32(v + 1);
		return (0);

	default:
		return (1);
	}
}

static int
parse_8023(lldp_pdu_t *pdu, const lldp_tlv_t *tlv)
{
	const uint8_t	*v = tlv->lt_info;
	size_t		len = tlv->lt_infolen;

	switch (tlv->lt_subtype) {
	case LLDP_8023_PHYCFG:
		if (len != 5)
			return (-1);
		if (!first(pdu, LLDP_PDU_PHYCFG))
			return (-1);
		pdu->lp_phycfg.lpc_autoneg = v[0];
		pdu->lp_phycfg.lpc_adv = get16(v + 1);
		pdu->lp_phycfg.lpc_mau = get16(v + 3);
		return (0);

	case LLDP_8023_POWER_MDI:
		/*
		 * The basic fields are 3 bytes; later revisions of 802.3
		 * extend the TLV (the extensions aren't decoded).
		 */
		if (len < 3)
			return (-1);
		if (!first(pdu, LLDP_PDU_POWER_MDI))
			return (-1);
		pdu->lp_power.lpm_support = v[0];
		pdu->lp_power.lpm_pair = v[1];
		pdu->lp_power.lpm_class = v[2];
		return (0);

	case LLDP_8023_AGGR:
		/* Deprecated in favor of the 802.1 version; same contents */
		if (len != 5)
			return (-1);
		if (!first(pdu, LLDP_PDU_AGGR))
			return (-1);
		pdu->lp_aggr.lla_status = v[0];
		pdu->lp_aggr.lla_portid = get32(v + 1);
		return (0);

	case LLDP_8023_MTU:
		if (len != 2)
			return (-1);
		if (!first(pdu, LLDP_PDU_MAX_FRAME))
			return (-1);
		pdu->lp_max_frame = get16(v);
		return (0);

	default:
		return (1);
	}
}

/*
 * Decode an optional TLV. Returns 0 if it was decoded, 1 if it isn't one we
 * decode, -1 if it's malformed (or an unexpected duplicate), or ENOMEM.
 */
static int
parse_tlv(lldp_pdu_t *pdu, const lldp_tlv_t *tlv)
{
	const uint8_t	*v = tlv->lt_value;
	size_t		len = tlv->lt_len;

	switch (tlv->lt_type) {
	case LLDP_TLV_CHASSIS_ID:
	case LLDP_TLV_PORT_ID:
	case LLDP_TLV_TTL:
		/* Only allowed once, at the start */
		return (-1);

	case LLDP_TLV_PORT_DESC:
		if (len > STR_LEN_MAX || !first(pdu, LLDP_PDU_PORT_DESC))
			return (-1);
		set_str(&pdu->lp_port_desc, v, len);
		return (0);

	case LLDP_TLV_SYS_NAME:
		if (len > STR_LEN_MAX || !first(pdu, LLDP_PDU_SYS_NAME))
			return (-1);
		set_str(&pdu->lp_sys_name, v, len);
		return (0);

	case LLDP_TLV_SYS_DESC:
		if (len > STR_LEN_MAX || !first(pdu, LLDP_PDU_SYS_DESC))
			return (-1);
		set_str(&pdu->lp_sys_desc, v, len);
		return (0);

	case LLDP_TLV_SYS_CAP:
		if (len != SYS_CAP_LEN || !first(pdu, LLDP_PDU_SYS_CAP))
			return (-1);
		pdu->lp_sys_caps = (lldp_cap_t)get16(v);
		pdu->lp_en_caps = (lldp_cap_t)get16(v + 2);
		return (0);

	case LLDP_TLV_MGMT_ADDR:
		return (parse_mgmt(pdu, tlv));

	case LLDP_TLV_ORG_SPEC:
		if (!tlv->lt_org)
			return (-1);
		switch (tlv->lt_oui) {
		case LLDP_OUI_8021:
			return (parse_8021(pdu, tlv));
		case LLDP_OUI_8023:
			return (parse_8023(pdu, tlv));
		default:
			return (1);
		}

	default:
		/* Reserved types */
		return (1);
	}
}

/*
 * Read one of the mandatory TLVs, which must be of the given type, with a
 * value length in [min, max].
 */
static bool
get_mandatory(lldp_tlv_iter_t *it, uint8_t type, size_t min, size_t max,
    lldp_tlv_t *tlv)
{
	if (lldp_tlv_iter_next(it, tlv) != 1)
		return (false);
	return (tlv->lt_type == type && tlv->lt_len >= min &&
	    tlv->lt_len <= max);
}

int
lldp_pdu_parse(const void *data, size_t len, lldp_pdu_t **pdup)
{
	lldp_pdu_t	*pdu;
	lldp_tlv_iter_t	it;
	lldp_tlv_t	tlv;
	int		ret;

	if (data == NULL || pdup == NULL)
		return (EINVAL);

	if ((pdu = calloc(1, sizeof (*pdu))) == NULL)
		return (ENOMEM);

	/* Everything we return points into our own copy of the PDU */
	if (len > 0 && (pdu->lp_pdu = malloc(len)) == NULL) {
		free(pdu);
		return (ENOMEM);
	}
	if (len > 0)
		(void) memcpy(pdu->lp_pdu, data, len);
	pdu->lp_pdulen = len;

	lldp_tlv_iter_init(&it, pdu->lp_pdu, len);

	if (!get_mandatory(&it, LLDP_TLV_CHASSIS_ID, ID_LEN_MIN, ID_LEN_MAX,
	    &tlv)) {
		goto badmsg;
	}
	pdu->lp_chassis.llc_type = (lldp_chassis_type_t)tlv.lt_value[0];
	pdu->lp_chassis.llc_len = (uint8_t)(tlv.lt_len - 1);
	(void) memcpy(pdu->lp_chassis.llc_id, tlv.lt_value + 1,
	    pdu->lp_chassis.llc_len);

	if (!get_mandatory(&it, LLDP_TLV_PORT_ID, ID_LEN_MIN, ID_LEN_MAX,
	    &tlv)) {
		goto badmsg;
	}
	pdu->lp_port.llp_type = (lldp_port_type_t)tlv.lt_value[0];
	pdu->lp_port.llp_len = (uint8_t)(tlv.lt_len - 1);
	(void) memcpy(pdu->lp_port.llp_id, tlv.lt_value + 1,
	    pdu->lp_port.llp_len);

	/* Any octets of the TTL beyond the first two are ignored */
	if (!get_mandatory(&it, LLDP_TLV_TTL, TTL_LEN, SIZE_MAX, &tlv))
		goto badmsg;
	pdu->lp_ttl = get16(tlv.lt_value);

	while ((ret = lldp_tlv_iter_next(&it, &tlv)) == 1) {
		if (tlv.lt_type == LLDP_TLV_END) {
			if (tlv.lt_len != 0 &&
			    !add_tlv(&pdu->lp_bad, &pdu->lp_nbad, &tlv))
				goto nomem;
			break;
		}

		switch (parse_tlv(pdu, &tlv)) {
		case 0:
			break;
		case 1:
			if (!add_tlv(&pdu->lp_other, &pdu->lp_nother, &tlv))
				goto nomem;
			break;
		case -1:
			if (!add_tlv(&pdu->lp_bad, &pdu->lp_nbad, &tlv))
				goto nomem;
			break;
		default:
			goto nomem;
		}
	}

	if (ret < 0)
		pdu->lp_flags |= LLDP_PDU_F_TRUNCATED;
	else if (it.lti_noend)
		pdu->lp_flags |= LLDP_PDU_F_NO_END;
	else if (it.lti_off < len)
		pdu->lp_flags |= LLDP_PDU_F_TRAILING;

	*pdup = pdu;
	return (0);

badmsg:
	lldp_pdu_free(pdu);
	return (EBADMSG);

nomem:
	lldp_pdu_free(pdu);
	return (ENOMEM);
}

void
lldp_pdu_free(lldp_pdu_t *pdu)
{
	if (pdu == NULL)
		return;

	free(pdu->lp_mgmt);
	free(pdu->lp_ppvid);
	free(pdu->lp_vlan_names);
	free(pdu->lp_proto);
	free(pdu->lp_other);
	free(pdu->lp_bad);
	free(pdu->lp_pdu);
	free(pdu);
}
