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
#include <liblldp.h>

#include "agent.h"
#include "buf.h"
#include "log.h"
#include "neighbor.h"
#include "pdu.h"

#define	TLV_LEN_MAX	(0x1ff)

typedef struct tlv {
	lldp_tlv_type_t	tlv_type;
	buf_t		tlv_buf;
} tlv_t;

typedef struct tlv_list {
	tlv_t	*tlvl_list;
	uint_t	tlvl_n;
	uint_t	tlvl_size;
} tlv_list_t;

typedef struct parsed_pdu {
	tlv_t		pp_chassis_id;
	tlv_t		pp_port_id;
	tlv_t		pp_ttl;
	tlv_list_t	pp_core;
	tlv_list_t	pp_org_specific;
	tlv_list_t	pp_unknown;
} parsed_pdu_t;

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

static inline uint16_t
make_tlv(lldp_tlv_type_t type, uint16_t len)
{
	VERIFY3U(type, <=, LLDP_TLV_MAX);
	VERIFY3U(len, <=, TLV_LEN_MAX);
	return ((uint16_t)type << 9 | len);
}

static bool
write_chassis_id(agent_t *a, buf_t *w)
{
	return (false);
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
write_end(buf_t *w)
{
	uint16_t tv = make_tlv(LLDP_TLV_END, 0);

	return (buf_put16(w, tv));
}

void
make_pdu(agent_t *a, buf_t *buf)
{
}

void
make_shutdown_pdu(agent_t *a, buf_t *buf)
{
	buf_t w = *buf;

	/* We should always have enough space for a shutdown PDU */
	VERIFY(write_chassis_id(a, &w));
	VERIFY(write_port_id(a, &w));
	VERIFY(write_ttl(&w, 0));
	VERIFY(write_end(&w));

	/* Set written length in buf */
	VERIFY(buf_truncate(buf, buf_len(buf) - buf_len(&w)));
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

bool
process_pdu(log_t *log, buf_t *buf, neighbor_t **np)
{
	parsed_pdu_t	pdu = { 0 };
	tlv_t		*chassis = &pdu.pp_chassis_id;
	tlv_t		*port = &pdu.pp_port_id;
	tlv_t		*ttl = &pdu.pp_ttl;

	TRACE_ENTER(log);

	/*
	 * 802.1AB 8.2 -- The first three PDUs must be (in order):
	 * chassis id, port id, and ttl.
	 */
	if (!get_tlv_expect(log, buf, LLDP_TLV_CHASSIS_ID, chassis)) {
		TRACE_RETURN(log);
		return (false);
	}
	if (buf_len(&chassis->tlv_buf) < 2 ||
	    buf_len(&chassis->tlv_buf) > LLDP_CHASSIS_MAX) {
		log_warn(log, "Chassis ID PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&chassis->tlv_buf),
		    LOG_T_END);
		TRACE_RETURN(log);
		return (false);
	}

	if (!get_tlv_expect(log, buf, LLDP_TLV_PORT_ID, port)) {
		TRACE_RETURN(log);
		return (false);
	}
	if (buf_len(&port->tlv_buf) < 2 ||
	    buf_len(&port->tlv_buf) > LLDP_PORT_MAX) {
		log_warn(log, "Port ID PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&port->tlv_buf),
		    LOG_T_END);
		TRACE_RETURN(log);
		return (false);
	}

	if (!get_tlv_expect(log, buf, LLDP_TLV_TTL, ttl)) {
		TRACE_RETURN(log);
		return (false);
	}
	if (buf_len(&ttl->tlv_buf) < 2) {
		log_warn(log, "TTL PDU length is invalid",
		    LOG_T_UINT32, "len", buf_len(&ttl->tlv_buf),
		    LOG_T_END);
		TRACE_RETURN(log);
		return (false);
	}


	TRACE_RETURN(log);
	return (true);
}
