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
 * lldp show-agent [-v | [-p] -o field[,...]] [link]
 *
 * Shows lldpd's agent for each link (or the given link): what it has been
 * configured to do (MODE, its admin_status), what it's actually doing
 * (STATE), and what it sends.
 *
 *	(default)	One line per agent (via libofmt).
 *	-v		Everything about each agent.
 */

#include <err.h>
#include <errno.h>
#include <libintl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

#include "lldp.h"

#define	AGENT_DEFAULT_FIELDS	"link,device,mode,state,nbrs,port"

/* An agent, with its datalink name */
typedef struct agt {
	const lldp_agent_info_t	*g_ai;
	char			g_link[MAXLINKNAMELEN];
} agt_t;

static bool
agent_tx(const lldp_agent_info_t *ai)
{
	return (ai->lai_status == LLDP_LINK_TX ||
	    ai->lai_status == LLDP_LINK_TXRX);
}

static bool
agent_rx(const lldp_agent_info_t *ai)
{
	return (ai->lai_status == LLDP_LINK_RX ||
	    ai->lai_status == LLDP_LINK_TXRX);
}

/* Is it sending LLDPDUs (so that the transmit timers mean something)? */
static bool
agent_sending(const lldp_agent_info_t *ai)
{
	return (agent_tx(ai) && (ai->lai_state == LLDP_AGENT_ACTIVE ||
	    ai->lai_state == LLDP_AGENT_CHANGING));
}

static void
mac_print(const lldp_agent_info_t *ai, char *buf, size_t buflen)
{
	size_t off = 0;

	if (buflen > 0)
		buf[0] = '\0';

	for (uint_t i = 0; i < ai->lai_macaddr_len && off < buflen; i++) {
		int n = snprintf(buf + off, buflen - off, "%s%02x",
		    (i > 0) ? ":" : "", ai->lai_macaddr[i]);
		if (n < 0)
			break;
		off += n;
	}
}

/* All of the TLVs sent (besides the mandatory ones), by property value */
static void
tlvs_print(const lldp_agent_info_t *ai, char *buf, size_t buflen)
{
	static const struct {
		lldp_prop_t	prop;
		size_t		off;
	} sets[] = {
		{ LLDP_PROP_TX_TLVS,
		    offsetof(lldp_agent_info_t, lai_tx_tlvs) },
		{ LLDP_PROP_TX_8021_TLVS,
		    offsetof(lldp_agent_info_t, lai_tx_8021_tlvs) },
		{ LLDP_PROP_TX_8023_TLVS,
		    offsetof(lldp_agent_info_t, lai_tx_8023_tlvs) },
	};
	char s[256];

	(void) strlcpy(buf, "", buflen);

	for (size_t i = 0; i < ARRAY_SIZE(sets); i++) {
		uint32_t flags;

		(void) memcpy(&flags, (const char *)ai + sets[i].off,
		    sizeof (flags));
		if (flags == 0)
			continue;

		(void) lldp_prop_flags_str(sets[i].prop, flags, s, sizeof (s));
		if (buf[0] != '\0')
			(void) strlcat(buf, ",", buflen);
		(void) strlcat(buf, s, buflen);
	}

	if (buf[0] == '\0')
		(void) strlcpy(buf, "none", buflen);
}

/* The operational MAU, as for show-neighbors ("1000BASE-T") */
static const char *
mau_name(const lldp_agent_info_t *ai, lldp_mau_mode_t *modep)
{
	if (ai->lai_mau == LLDP_MAU_UNKNOWN)
		return (NULL);
	return (lldp_mau_str(ai->lai_mau, modep));
}

typedef enum agent_field {
	AF_LINK,
	AF_DEVICE,
	AF_MODE,
	AF_STATE,
	AF_NBRS,
	AF_MAX_NBRS,
	AF_PORT,
	AF_PORT_TYPE,
	AF_PORT_SRC,
	AF_PORTDESC,
	AF_MACADDR,
	AF_MAU,
	AF_INTERVAL,
	AF_HOLD,
	AF_TTL,
	AF_NEXT_TX,
	AF_TLVS,
} agent_field_t;

static boolean_t
agent_ofmt_cb(ofmt_arg_t *arg, char *buf, uint_t buflen)
{
	const agt_t		*g = arg->ofmt_cbarg;
	const lldp_agent_info_t	*ai = g->g_ai;
	char			t[LLDP_TYPESTR_LEN];
	lldp_mau_mode_t		m;
	const char		*s;

	buf[0] = '\0';

	switch (arg->ofmt_id) {
	case AF_LINK:
		(void) strlcpy(buf, g->g_link, buflen);
		break;
	case AF_DEVICE:
		(void) strlcpy(buf, ai->lai_link, buflen);
		break;
	case AF_MODE:
		(void) strlcpy(buf, lldp_admin_status_str(ai->lai_status),
		    buflen);
		break;
	case AF_STATE:
		(void) strlcpy(buf, lldp_agent_state_str(ai->lai_state),
		    buflen);
		break;
	case AF_NBRS:
		/* Without receiving, a count would be meaningless */
		if (agent_rx(ai))
			(void) snprintf(buf, buflen, "%u", ai->lai_neighbors);
		break;
	case AF_MAX_NBRS:
		(void) snprintf(buf, buflen, "%u", ai->lai_neighbor_max);
		break;
	case AF_PORT:
		if (agent_tx(ai) && ai->lai_port.llp_len > 0)
			(void) lldp_port_str(&ai->lai_port, buf, buflen);
		break;
	case AF_PORT_TYPE:
		if (agent_tx(ai) && ai->lai_port.llp_len > 0) {
			(void) strlcpy(buf, lldp_port_typestr(
			    ai->lai_port.llp_type, t, sizeof (t)), buflen);
		}
		break;
	case AF_PORT_SRC:
		(void) strlcpy(buf, lldp_prop_name(LLDP_PROP_PORT_ID_TYPE,
		    ai->lai_port_id_src), buflen);
		break;
	case AF_PORTDESC:
		if (agent_tx(ai) && (ai->lai_tx_tlvs & LLDP_TX_PORTDESC))
			(void) strlcpy(buf, ai->lai_port_desc, buflen);
		break;
	case AF_MACADDR:
		/* It's only used for the port id */
		if (agent_tx(ai))
			mac_print(ai, buf, buflen);
		break;
	case AF_MAU:
		/* What we know of the link is only current while it's up */
		if (ai->lai_state != LLDP_AGENT_ACTIVE &&
		    ai->lai_state != LLDP_AGENT_CHANGING)
			break;
		if ((s = mau_name(ai, &m)) != NULL)
			(void) strlcpy(buf, s, buflen);
		else if (ai->lai_mau != LLDP_MAU_UNKNOWN)
			(void) snprintf(buf, buflen, "%u", ai->lai_mau);
		break;
	case AF_INTERVAL:
		(void) snprintf(buf, buflen, "%u", ai->lai_tx_interval);
		break;
	case AF_HOLD:
		(void) snprintf(buf, buflen, "%u", ai->lai_tx_hold);
		break;
	case AF_TTL:
		(void) snprintf(buf, buflen, "%u", ai->lai_ttl);
		break;
	case AF_NEXT_TX:
		if (agent_sending(ai))
			(void) snprintf(buf, buflen, "%u", ai->lai_next_tx);
		break;
	case AF_TLVS:
		if (agent_tx(ai))
			tlvs_print(ai, buf, buflen);
		break;
	default:
		return (B_FALSE);
	}

	/* libofmt shows a value that doesn't apply (empty) as "--" */
	return (B_TRUE);
}

static const ofmt_field_t agent_fields[] = {
	{ "LINK",		10,	AF_LINK,	agent_ofmt_cb },
	{ "DEVICE",		10,	AF_DEVICE,	agent_ofmt_cb },
	{ "MODE",		10,	AF_MODE,	agent_ofmt_cb },
	{ "STATE",		10,	AF_STATE,	agent_ofmt_cb },
	{ "NBRS",		6,	AF_NBRS,	agent_ofmt_cb },
	{ "MAX-NBRS",		9,	AF_MAX_NBRS,	agent_ofmt_cb },
	{ "PORT",		18,	AF_PORT,	agent_ofmt_cb },
	{ "PORT-TYPE",		10,	AF_PORT_TYPE,	agent_ofmt_cb },
	{ "PORT-SRC",		9,	AF_PORT_SRC,	agent_ofmt_cb },
	{ "PORTDESC",		24,	AF_PORTDESC,	agent_ofmt_cb },
	{ "MACADDR",		18,	AF_MACADDR,	agent_ofmt_cb },
	{ "MAU",		15,	AF_MAU,		agent_ofmt_cb },
	{ "INTERVAL",		9,	AF_INTERVAL,	agent_ofmt_cb },
	{ "HOLD",		5,	AF_HOLD,	agent_ofmt_cb },
	{ "TTL",		6,	AF_TTL,		agent_ofmt_cb },
	{ "NEXT-TX",		8,	AF_NEXT_TX,	agent_ofmt_cb },
	{ "TLVS",		32,	AF_TLVS,	agent_ofmt_cb },
	{ NULL,			0,	0,		NULL }
};

/* Why an agent that isn't active isn't doing anything */
static const char *
state_note(const lldp_agent_info_t *ai)
{
	switch (ai->lai_state) {
	case LLDP_AGENT_DISABLED:
		return (gettext("admin_status is disabled; nothing is sent "
		    "or received"));
	case LLDP_AGENT_OFFLINE:
		return (gettext("the link has been offlined (e.g. for "
		    "dynamic reconfiguration); nothing is sent or received"));
	case LLDP_AGENT_FAILED:
		return (gettext("the link couldn't be opened (see the lldpd "
		    "log); nothing is sent or received"));
	case LLDP_AGENT_DOWN:
		return (gettext("the link is down; nothing is sent or "
		    "received"));
	default:
		return (NULL);
	}
}

static void
agent_print_verbose(const agt_t *g)
{
	const lldp_agent_info_t	*ai = g->g_ai;
	char			buf[MAXPATHLEN + 512], s[LLDP_PORT_MAX * 4 + 1];
	char			t[LLDP_TYPESTR_LEN];
	const char		*note;

	/* "net0 (igb0): txrx, active", or just "disabled" */
	(void) printf("%s", g->g_link);
	if (strcmp(g->g_link, ai->lai_link) != 0)
		(void) printf(" (%s)", ai->lai_link);
	if (ai->lai_state == LLDP_AGENT_DISABLED) {
		(void) printf(": %s\n", lldp_agent_state_str(ai->lai_state));
	} else {
		(void) printf(": %s, %s\n",
		    lldp_admin_status_str(ai->lai_status),
		    lldp_agent_state_str(ai->lai_state));
	}

	if (agent_tx(ai)) {
		if (ai->lai_port.llp_len > 0) {
			(void) lldp_port_str(&ai->lai_port, s, sizeof (s));
			(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
			    lldp_port_typedesc(ai->lai_port.llp_type, t,
			    sizeof (t)));
			vline(TOP_INDENT, gettext("Port ID"), buf);
		}
		if (ai->lai_state == LLDP_AGENT_CHANGING) {
			(void) lldp_port_str(&ai->lai_new_port, s, sizeof (s));
			(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
			    lldp_port_typedesc(ai->lai_new_port.llp_type, t,
			    sizeof (t)));
			vline(TOP_INDENT, gettext("Changing to"), buf);
		}
		vline(TOP_INDENT, gettext("Port ID source"),
		    lldp_prop_name(LLDP_PROP_PORT_ID_TYPE,
		    ai->lai_port_id_src));
		if ((ai->lai_tx_tlvs & LLDP_TX_PORTDESC) &&
		    ai->lai_port_desc[0] != '\0') {
			vline(TOP_INDENT, gettext("Port description"),
			    ai->lai_port_desc);
		}
	}

	/* The MAC address is only used for the port id */
	if (agent_tx(ai) && ai->lai_macaddr_len > 0) {
		mac_print(ai, s, sizeof (s));
		(void) snprintf(buf, sizeof (buf), "%s (%s)", s,
		    ai->lai_mac_factory ? gettext("factory") :
		    gettext("current"));
		vline(TOP_INDENT, gettext("MAC address"), buf);
	}

	/* What we know of the link is only current while it's up */
	if (ai->lai_state == LLDP_AGENT_ACTIVE ||
	    ai->lai_state == LLDP_AGENT_CHANGING) {
		lldp_mau_mode_t	m;
		const char	*mau = mau_name(ai, &m);
		const char	*mode = NULL;
		const char	*an;

		if (mau != NULL)
			mode = lldp_mau_mode_str(m);

		if (!ai->lai_autoneg_sup)
			an = gettext("auto-negotiation not supported");
		else if (ai->lai_autoneg_en)
			an = gettext("auto-negotiation enabled");
		else
			an = gettext("auto-negotiation disabled");

		if (mau == NULL && ai->lai_mau != LLDP_MAU_UNKNOWN) {
			(void) snprintf(buf, sizeof (buf),
			    gettext("unknown MAU (%u), %s"), ai->lai_mau, an);
		} else if (mau == NULL) {
			(void) strlcpy(buf, an, sizeof (buf));
		} else if (mode != NULL) {
			(void) snprintf(buf, sizeof (buf), "%s (%s), %s", mau,
			    mode, an);
		} else {
			(void) snprintf(buf, sizeof (buf), "%s, %s", mau, an);
		}
		vline(TOP_INDENT, gettext("Link"), buf);
	}

	if (agent_tx(ai)) {
		if (agent_sending(ai)) {
			(void) snprintf(buf, sizeof (buf),
			    gettext("every %us, TTL %us; next in %us"),
			    ai->lai_tx_interval, ai->lai_ttl,
			    ai->lai_next_tx);
		} else {
			(void) snprintf(buf, sizeof (buf),
			    gettext("every %us, TTL %us"),
			    ai->lai_tx_interval, ai->lai_ttl);
		}
		vline(TOP_INDENT, gettext("Transmit"), buf);

		if (agent_sending(ai) && ai->lai_tx_fast > 0) {
			(void) snprintf(buf, sizeof (buf),
			    gettext("%u of %u LLDPDUs remaining (every %us)"),
			    ai->lai_tx_fast, ai->lai_tx_fast_init,
			    ai->lai_tx_fast_msg);
			vline(TOP_INDENT, gettext("Fast start"), buf);
		}
		if (agent_sending(ai)) {
			(void) snprintf(buf, sizeof (buf), gettext("%u of %u"),
			    ai->lai_tx_credit, ai->lai_tx_credit_max);
			vline(TOP_INDENT, gettext("Transmit credit"), buf);
		}

		(void) snprintf(buf, sizeof (buf), "%us", ai->lai_reinit_delay);
		vline(TOP_INDENT, gettext("Reinit delay"), buf);

		(void) lldp_prop_flags_str(LLDP_PROP_TX_TLVS, ai->lai_tx_tlvs,
		    buf, sizeof (buf));
		vline(TOP_INDENT, gettext("TLVs sent"), buf);
		if (ai->lai_tx_8021_tlvs != 0) {
			(void) lldp_prop_flags_str(LLDP_PROP_TX_8021_TLVS,
			    ai->lai_tx_8021_tlvs, buf, sizeof (buf));
			vline(SUB_INDENT, "IEEE 802.1", buf);
		}
		if (ai->lai_tx_8023_tlvs != 0) {
			(void) lldp_prop_flags_str(LLDP_PROP_TX_8023_TLVS,
			    ai->lai_tx_8023_tlvs, buf, sizeof (buf));
			vline(SUB_INDENT, "IEEE 802.3", buf);
		}
	}

	if (agent_rx(ai)) {
		(void) snprintf(buf, sizeof (buf), gettext("%u (max %u)"),
		    ai->lai_neighbors, ai->lai_neighbor_max);
		vline(TOP_INDENT, gettext("Neighbors"), buf);
	}

	if (ai->lai_label[0] != '\0' || ai->lai_devname[0] != '\0' ||
	    ai->lai_portnum != UINT32_MAX) {
		buf[0] = '\0';
		if (ai->lai_label[0] != '\0') {
			(void) snprintf(s, sizeof (s), gettext("label \"%s\""),
			    ai->lai_label);
			(void) strlcat(buf, s, sizeof (buf));
		}
		if (ai->lai_devname[0] != '\0') {
			if (buf[0] != '\0')
				(void) strlcat(buf, ", ", sizeof (buf));
			(void) strlcat(buf, ai->lai_devname, sizeof (buf));
		}
		if (ai->lai_portnum != UINT32_MAX) {
			if (buf[0] != '\0')
				(void) strlcat(buf, ", ", sizeof (buf));
			(void) snprintf(s, sizeof (s), gettext("port %u"),
			    ai->lai_portnum);
			(void) strlcat(buf, s, sizeof (buf));
		}
		vline(TOP_INDENT, gettext("Location"), buf);
	}

	if ((note = state_note(ai)) != NULL)
		vline(TOP_INDENT, gettext("Note"), note);
	if (agent_rx(ai) && ai->lai_too_many) {
		vline(TOP_INDENT, gettext("Note"), gettext("too many "
		    "neighbors (neighbor_max); new neighbors are being "
		    "dropped"));
	}
}

int
do_show_agent(int argc, char **argv)
{
	const lldp_cmd_t	*cmd = cmd_lookup("show-agent");
	lldp_ofmt_opts_t	opts = { 0 };
	bool			verbose = false;
	const char		*link = NULL;
	ofmt_handle_t		ofmt = NULL;
	lldp_agent_info_t	*agents = NULL;
	agt_t			*gs;
	uint_t			n = 0;
	int			c, ret;

	optind = 1;
	while ((c = getopt(argc, argv, ":po:v")) != -1) {
		switch (c) {
		case 'p':
			opts.loo_parsable = true;
			break;
		case 'o':
			opts.loo_fields = optarg;
			break;
		case 'v':
			verbose = true;
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

	if (verbose && (opts.loo_parsable || opts.loo_fields != NULL)) {
		warnx(gettext("-v can't be used with -p or -o"));
		cmd_usage(cmd);
	}

	if (argc - optind > 1) {
		warnx(gettext("only one link may be given"));
		cmd_usage(cmd);
	}
	if (argc - optind == 1)
		link = argv[optind];

	/* Check the options before talking to lldpd */
	if (!verbose) {
		if (opts.loo_fields == NULL && !opts.loo_parsable)
			opts.loo_fields = AGENT_DEFAULT_FIELDS;
		ofmt = lldp_ofmt_open(&opts, agent_fields, 0);
	} else {
		vline_init();
	}

	ret = lldp_get_agents(link, &agents, &n);
	if (ret != 0) {
		lldp_warn(ret, link, gettext("agents"));
		if (ofmt != NULL)
			ofmt_close(ofmt);
		return (EXIT_FAILURE);
	}

	if ((gs = calloc(MAX(n, 1), sizeof (agt_t))) == NULL)
		err(EXIT_FAILURE, gettext("failed to allocate memory"));

	for (uint_t i = 0; i < n; i++) {
		gs[i].g_ai = &agents[i];
		link_name(agents[i].lai_link, gs[i].g_link,
		    sizeof (gs[i].g_link));

		if (verbose) {
			if (i > 0)
				(void) putchar('\n');
			agent_print_verbose(&gs[i]);
		} else {
			ofmt_print(ofmt, &gs[i]);
		}
	}

	if (ofmt != NULL)
		ofmt_close(ofmt);
	free(gs);
	lldp_agents_free(agents, n);
	return (EXIT_SUCCESS);
}
