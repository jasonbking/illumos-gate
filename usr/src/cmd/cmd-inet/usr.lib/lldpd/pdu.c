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

#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <liblldp.h>
#include <string.h>

#include "agent.h"
#include "buf.h"
#include "lldpd.h"
#include "log.h"
#include "neighbor.h"
#include "pdu.h"
#include "tlv.h"

/*
 * The number of 'standard' TLV types
 */
#define	TLV_NUM_STANDARD 9
#define	TLV_LEN_MAX	(0x1ff)

static inline lldp_tlv_type_t
tlv_type(uint16_t tlv)
{
	return (tlv >> 9);
}

static inline uint16_t
tlv_len(uint16_t tlv)
{
	return (tlv & TLV_LEN_MAX);
}

static bool get_tlv(log_t *, buf_t *, tlv_t *);
static bool get_tlv_expect(log_t *, buf_t *, lldp_tlv_type_t, tlv_t *);

static bool write_end(buf_t *);
static bool write_chassis_id(buf_t *);
static bool write_port_id(agent_t *, buf_t *);
static bool write_ttl(buf_t *, uint16_t);

static bool write_portdesc(agent_t *, buf_t *);
static bool write_sysname(agent_t *, buf_t *);
static bool write_sysdesc(agent_t *, buf_t *);
static bool write_syscap(agent_t *, buf_t *);
static bool write_mgmtaddr(agent_t *, buf_t *);

static bool write_native_vlan(agent_t *, buf_t *);
static bool write_vlans(agent_t *, buf_t *);
static bool write_vlan_name(agent_t *, buf_t *);
static bool write_mgmt_vlan(agent_t *, buf_t *);

static bool write_phycfg(agent_t *, buf_t *);
static bool write_power(agent_t *, buf_t *);
static bool write_aggr(agent_t *, buf_t *);
static bool write_mtu(agent_t *, buf_t *);

typedef struct tlv_tbl {
	uint_t	tlv;
	bool	(*write)(agent_t *, buf_t *);
} tlv_tbl_t;

static void write_tlv_table(tlv_tbl_t *, uint_t, uint_t, agent_t *, buf_t *);

static tlv_tbl_t tlv_tbl[] = {
	{ LLDP_TX_PORTDESC, write_portdesc },
	{ LLDP_TX_SYSNAME, write_sysname },
	{ LLDP_TX_SYSDESC, write_sysdesc },
	{ LLDP_TX_SYSCAP, write_syscap },
	{ LLDP_TX_MGMTADDR, write_mgmtaddr },
};

static tlv_tbl_t tlv_8021_tlv_tbl[] = {
	{ LLDP_TX_X1_NATIVE_VLAN, write_native_vlan },
	{ LLDP_TX_X1_VLANS, write_vlans },
	{ LLDP_TX_X1_VLAN_NAME, write_vlan_name },
	{ LLDP_TX_X2_MGMT_VLAN, write_mgmt_vlan },
};

static tlv_tbl_t tlv_8023_tlv_tbl[] = {
	{ LLDP_TX_X3_PHYCFG, write_phycfg },
	{ LLDP_TX_X3_POWER, write_power },
	{ LLDP_TX_X3_AGGR, write_aggr },
	{ LLDP_TX_X3_MTU, write_mtu },
};

/*
 * Which standard TLVs can only appear more than once in a PDU. This excludes
 * LLDP_TLV_ORG_SPEC since that is handled specially.
 */
static lldp_tlv_type_t tlv_multi[] = {
	LLDP_TLV_MGMT_ADDR,
};

static inline uint16_t
make_tlv(lldp_tlv_type_t type, uint16_t len)
{
	VERIFY3U(type, <=, LLDP_TLV_MAX);
	VERIFY3U(len, <=, TLV_LEN_MAX);
	return ((uint16_t)type << 9 | len);
}

void
make_pdu(agent_t *a, buf_t *buf)
{
	agent_cfg_t *cfg;
	buf_t w = *buf;
	buf_t tlv_w;

	mutex_enter(&lldp_config_lock);
	mutex_enter(&a->a_lock);

	cfg = &a->a_cfg;

	/* We should always have enough space for the mandatory TLVs */
	VERIFY(write_chassis_id(&w));
	VERIFY(write_port_id(a, &w));
	VERIFY(write_ttl(&w, a->a_tx.tx_ttl));

	/* When writing TLVs, guarantee space for the final END TLV */
	VERIFY(buf_take(&w, buf_len(&w) - 2, &tlv_w));

	write_tlv_table(tlv_tbl, ARRAY_SIZE(tlv_tbl), cfg->ac_tx_tlvs, a,
	    &tlv_w);
	write_tlv_table(tlv_8021_tlv_tbl, ARRAY_SIZE(tlv_8021_tlv_tbl),
	    cfg->ac_tx_8021_tlvs, a, &tlv_w);
	write_tlv_table(tlv_8023_tlv_tbl, ARRAY_SIZE(tlv_8023_tlv_tbl),
	    cfg->ac_tx_8023_tlvs, a, &tlv_w);

	/* Skip past all the TLVs written so far */
	VERIFY(buf_skip(&w, buf_len(&w) - buf_len(&tlv_w)));

	/* Write out the END TLV. We guaranteed space for this above */
	VERIFY(write_end(&w));

	/* Make buf reflect the amount of data written */
	VERIFY(buf_truncate(buf, buf_len(buf) - buf_len(&w)));
}

void
make_shutdown_pdu(agent_t *a, buf_t *buf)
{
	buf_t w = *buf;

	mutex_enter(&lldp_config_lock);
	mutex_enter(&a->a_lock);

	/* We should always have enough space for a shutdown PDU */
	VERIFY(write_chassis_id(&w));
	VERIFY(write_port_id(a, &w));
	VERIFY(write_ttl(&w, 0));
	VERIFY(write_end(&w));

	mutex_exit(&a->a_lock);
	mutex_exit(&lldp_config_lock);

	/* Set written length in buf */
	VERIFY(buf_truncate(buf, buf_len(buf) - buf_len(&w)));
}

bool
process_pdu(log_t *log, buf_t *raw, neighbor_t **np)
{
	neighbor_t	*nb = NULL;
	buf_t		buf = { 0 };
	tlv_t		chassis = { 0 };
	tlv_t		port = { 0 };
	tlv_t		ttl = { 0 };
	uint8_t		pdu_count[TLV_NUM_STANDARD] = { 0 };
	bool		ret = true;

	TRACE_ENTER(log);

	*np = NULL;

	nb = neighbor_new();
	if (nb == NULL) {
		log_warn(log, "failed to allocate new neighbor", LOG_T_END);
		TRACE_RETURN(log);
		return (false);
	}

	(void) memcpy(nb->nb_pdu, buf_ptr(raw), buf_len(raw));
	nb->nb_pdu_len = buf_len(raw);

	buf_init(&buf, nb->nb_pdu, nb->nb_pdu_len);

	/*
	 * 802.1AB 8.2 -- The first three PDUs must be (in order):
	 * chassis id, port id, and ttl.
	 */
	if (!get_tlv_expect(log, &buf, LLDP_TLV_CHASSIS_ID, &chassis)) {
		ret = false;
		goto done;
	}
	if (buf_len(&chassis.tlv_buf) < 2 ||
	    buf_len(&chassis.tlv_buf) > LLDP_CHASSIS_MAX) {
		log_warn(log, "Chassis ID PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&chassis.tlv_buf),
		    LOG_T_END);
		ret = false;
		goto done;
	}
	pdu_count[LLDP_TLV_CHASSIS_ID]++;

	if (!get_tlv_expect(log, &buf, LLDP_TLV_PORT_ID, &port)) {
		ret = false;
		goto done;
	}
	if (buf_len(&port.tlv_buf) < 2 ||
	    buf_len(&port.tlv_buf) > LLDP_PORT_MAX) {
		log_warn(log, "Port ID PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&port.tlv_buf),
		    LOG_T_END);
		ret = false;
		goto done;
	}
	pdu_count[LLDP_TLV_PORT_ID]++;

	if (!get_tlv_expect(log, &buf, LLDP_TLV_TTL, &ttl)) {
		ret = false;
		goto done;
	}
	if (buf_len(&ttl.tlv_buf) < 2) {
		log_warn(log, "TTL PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&ttl.tlv_buf),
		    LOG_T_END);
		ret = false;
		goto done;
	}
	pdu_count[LLDP_TLV_TTL]++;

	while (buf_len(&buf) > 0) {
		tlv_t tlv = { 0 };

		if (!get_tlv(log, &buf, &tlv)) {
			log_warn(log, "failed to read TLV pair; "
			    "PDU is truncated",
			    LOG_T_END);
			ret = false;
			goto done;
		}

		if (tlv.tlv_type == LLDP_TLV_END) {
			pdu_count[LLDP_TLV_END]++;
			break;
		}

		if (tlv.tlv_type == LLDP_TLV_ORG_SPEC) {
			/*
			 * Verify there's at least 4 bytes in the TLV for
			 * OUI (3) + subtype (1).
			 */
			if (buf_len(&tlv.tlv_buf) < 4) {
				log_warn(log, "Org specific PDU does not "
				     "required header",
				     LOG_T_UINT32, "len", buf_len(&tlv.tlv_buf),
				     LOG_T_END);
				continue;
			}

			if (!tlv_list_add(&nb->nb_org_tlvs, &tlv)) {
				ret = false;
				goto done;
			}

			pdu_count[LLDP_TLV_ORG_SPEC]++;
		} else if (tlv.tlv_type < TLV_NUM_STANDARD) {
			bool ok = false;

			if (pdu_count[tlv.tlv_type] > 1) {
				for (uint_t i = 0; i < ARRAY_SIZE(tlv_multi);
				    i++) {
					if (tlv_multi[i] == tlv.tlv_type) {
						ok = true;
						break;
					}
				}

				if (!ok) {
					log_warn(log, "TLV appears more than"
					    " once in PDU; discarding PDU",
					    LOG_T_UINT32, "type", tlv.tlv_type,
					    LOG_T_STRING, "type_str",
					    lldp_tlv_type_str(tlv.tlv_type),
					    LOG_T_END);
					ret = false;
					goto done;
				}
			}

			if (!tlv_list_add(&nb->nb_core_tlvs, &tlv)) {
				ret = false;
				goto done;
			}
			pdu_count[tlv.tlv_type]++;
		} else {
			if (!tlv_list_add(&nb->nb_unknown_tlvs, &tlv)) {
				ret = false;
				goto done;
			}
		}
	}

	if (pdu_count[LLDP_TLV_END] == 0) {
		log_warn(log, "PDU did not end with an END tlv; discarding",
		    LOG_T_END);
		ret = false;
		goto done;
	}

done:
	if (!ret) {
		neighbor_free(nb);
		nb = NULL;
	}

	*np = nb;

	TRACE_RETURN(log);
	return (ret);
}

static void
write_tlv_table(tlv_tbl_t *tbl, uint_t tbl_len, uint_t tlvs, agent_t *a,
    buf_t *w)
{
	for (uint_t i = 0; i < tbl_len; i++) {
		/* TLV not marked for TX, skip */
		if ((tbl[i].tlv & tlvs) == 0)
			continue;

		/*
		 * If this TLV is too big (no space left), we skip it.
		 * However, subsequent TLVs might still be able to fit.
		 * make_pdu() guarantees that space is left for the final
		 * END TLV, so we don't need to worry about that here.
		 */
		buf_t save = *w;
		if (!tbl[i].write(a, w))
			*w = save;
	}
}

static bool
get_tlv(log_t *log, buf_t *buf, tlv_t *tlvp)
{
	uint16_t tl;

	TRACE_ENTER(log);

	if (!buf_get16(buf, &tl)) {
		log_warn(log, "unexpected PDU during processing", LOG_T_END);
		TRACE_RETURN(log)
		return (false);
	}

	log_debug(log, "read TLV header",
	    LOG_T_XINT32, "header", (uint32_t)tl,
	    LOG_T_UINT32, "type", tlv_type(tl),
	    LOG_T_STRING, "type_str", lldp_tlv_type_str(tlv_type(tl)),
	    LOG_T_UINT32, "len", tlv_len(tl),
	    LOG_T_END);

	tlvp->tlv_type = tlv_type(tl);
	if (!buf_take(buf, tlv_len(tl), &tlvp->tlv_buf)) {
		log_warn(log, "TLV length larger than remaining data in PDU",
		    LOG_T_UINT32, "tlv_len", tlv_len(tl),
		    LOG_T_UINT32, "remaining", buf_len(buf),
		    LOG_T_END);
		TRACE_RETURN(log)
		return (false);
	}

	TRACE_RETURN(log)
	return (true);
}

static bool
get_tlv_expect(log_t *log, buf_t *buf, lldp_tlv_type_t type, tlv_t *tlvp)
{
	TRACE_ENTER(log);

	log_debug(log, "expecting TLV type",
	    LOG_T_UINT32, "type", type,
	    LOG_T_STRING, "type_str", lldp_tlv_type_str(type),
	    LOG_T_END);

	if (!get_tlv(log, buf, tlvp)) {
		TRACE_RETURN(log)
		return (false);
	}

	if (tlvp->tlv_type != type) {
		log_warn(log, "Unexpected TLV type while processing PDU",
		    LOG_T_STRING, "tlv_type_str",
		    lldp_tlv_type_str(tlvp->tlv_type),
		    LOG_T_UINT32, "tlv_type", (uint32_t)tlvp->tlv_type,
		    LOG_T_STRING, "expecting", lldp_tlv_type_str(type),
		    LOG_T_END);
		TRACE_RETURN(log)
		return (false);
	}

	TRACE_RETURN(log)
	return (true);
}

static bool
write_end(buf_t *w)
{
	uint16_t tv = make_tlv(LLDP_TLV_END, 0);
	return (buf_put16(w, tv));
}

static bool
write_chassis_id(buf_t *w)
{
	lldp_chassis_t *chassis = &lldp_config.lcfg_chassis;
	uint16_t tv;

	VERIFY(MUTEX_HELD(&lldp_config_lock));
	tv = make_tlv(LLDP_TLV_CHASSIS_ID, chassis->llc_len + 1);

	if (!buf_put16(w, tv))
		return (false);
	if (!buf_put8(w, chassis->llc_type))
		return (false);
	if (!buf_putbytes(w, chassis->llc_id, chassis->llc_len))
		return (false);

	return (true);
}

static bool
write_port_id(agent_t *a, buf_t *w)
{
	lldp_port_t *port = &a->a_cfg.ac_port;
	uint16_t tv = make_tlv(LLDP_TLV_PORT_ID, port->llp_len);

	if (!buf_put16(w, tv))
		return (false);
	if (!buf_put8(w, port->llp_type))
		return (false);
	if (!buf_putbytes(w, port->llp_id, port->llp_len))
		return (false);

	return (true);
}

static bool
write_ttl(buf_t *w, uint16_t ttl)
{
	uint16_t tv = make_tlv(LLDP_TLV_TTL, sizeof (ttl));

	if (!buf_put16(w, tv))
		return (false);
	if (!buf_put16(w, ttl))
		return (false);
	return (true);
}

static bool
write_portdesc(agent_t *a, buf_t *w)
{
	VERIFY(MUTEX_HELD(&a->a_lock));

	size_t desclen;
	uint16_t tv;

	desclen = (a->a_cfg.ac_desc == NULL) ? 0 : strlen(a->a_cfg.ac_desc);
	if (desclen > LLDP_PORT_DESC_MAX) {
		log_warn(a->a_tx.tx_log, "port description is too long; TLV "
		    "will be truncated",
		    LOG_T_UINT32, "len", desclen,
		    LOG_T_END);
		desclen = LLDP_PORT_DESC_MAX;
	}

	tv = make_tlv(LLDP_TLV_PORT_DESC, desclen);
	if (!buf_put16(w, tv))
		return (false);
	if (!buf_putbytes(w, a->a_cfg.ac_desc, desclen))
		return (false);

	return (true);
}

static bool
write_sysname(agent_t *a, buf_t *w)
{
	VERIFY(MUTEX_HELD(&lldp_config_lock));

	size_t namelen;
	uint16_t tv;

	namelen = (lldp_config.lcfg_sysname == NULL) ?
	    0 : strlen(lldp_config.lcfg_sysname);
	if (namelen > LLDP_SYS_NAME_MAX) {
		log_warn(a->a_tx.tx_log, "system name is too long; TLV "
		    "will be truncated",
		    LOG_T_UINT32, "len", namelen,
		    LOG_T_END);
		namelen = LLDP_SYS_NAME_MAX;
	}

	tv = make_tlv(LLDP_TLV_SYS_NAME, namelen);
	if (!buf_put16(w, tv))
		return (false);
	if (!buf_putbytes(w, lldp_config.lcfg_sysname, namelen))
		return (false);
	
	return (true);
}

static bool
write_sysdesc(agent_t *a, buf_t *w)
{
	VERIFY(MUTEX_HELD(&lldp_config_lock));

	size_t desclen;
	uint16_t tv;

	desclen = (lldp_config.lcfg_sysdesc == NULL) ?
	    0 : strlen(lldp_config.lcfg_sysdesc);
	if (desclen > LLDP_SYS_DESC_MAX) {
		log_warn(a->a_tx.tx_log, "system description is too long; TLV "
		    "will be truncated",
		    LOG_T_UINT32, "len", desclen,
		    LOG_T_END);
		desclen = LLDP_SYS_NAME_MAX;
	}

	tv = make_tlv(LLDP_TLV_SYS_DESC, desclen);
	if (!buf_put16(w, tv))
		return (false);
	if (!buf_putbytes(w, lldp_config.lcfg_sysdesc, desclen))
		return (false);
	
	return (true);
}

static bool
write_syscap(agent_t *a, buf_t *w)
{
	VERIFY(MUTEX_HELD(&lldp_config_lock));

	uint16_t tv = make_tlv(LLDP_TLV_SYS_CAP, 4);

	if (!buf_put16(w, tv))
		return (false);
	if (!buf_put16(w, lldp_config.lcfg_syscap))
		return (false);
	if (!buf_put16(w, lldp_config.lcfg_encap))
		return (false);

	return (false);
}

static bool
write_mgmtaddr(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_native_vlan(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_vlans(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_vlan_name(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_mgmt_vlan(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_phycfg(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_power(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_aggr(agent_t *a, buf_t *w)
{
	return (false);
}

static bool
write_mtu(agent_t *a, buf_t *w)
{
	return (false);
}
