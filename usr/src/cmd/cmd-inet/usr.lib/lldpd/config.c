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

/*
 * Configuration
 *
 * There are two kinds of configuration: system-wide configuration
 * (lldp_config_t) which covers values that are the same for every agent
 * (chassis id, system name, etc.), and per-agent configuration
 * (agent_cfg_t).
 *
 * All configuration is read from properties on our SMF instance (composed
 * with the service, using the running snapshot).
 *
 * System-wide configuration is read from the 'config' property group.
 *
 * Agent configuration is built in layers:
 *
 *   1. During startup (config_init()), a default agent configuration is
 *	created from the built-in defaults (see agent_count_props[] and
 *	config_agent_defaults()).
 *
 *   2. Any properties present in the 'default' property group then
 *	replace the corresponding built-in values. The result
 *	(default_agent_cfg) is the starting configuration for every agent.
 *
 *   3. When an agent is created (config_agent_init()), it starts with a
 *	copy of default_agent_cfg. If a property group of type 'agent'
 *	whose name matches the hardware name of the agent's link (e.g.
 *	'igb0', even if the datalink has been renamed) exists, any
 *	properties present in that property group replace the corresponding
 *	values for that agent only.
 *
 * On SIGHUP (i.e. 'svcadm refresh'), config_refresh() re-reads the running
 * snapshot, rebuilds the system and default agent configurations, and then
 * rebuilds and applies the configuration of every running agent the same
 * way. Information obtained from the system (e.g. via topo) rather than
 * SMF is retained across a refresh.
 *
 * At each layer, a property that is absent (or that has an invalid value)
 * leaves the existing value in place. For example, with:
 *
 *	default/tx_interval = 60
 *	igb0/tx_hold_multiplier = 2	(igb0 is of type 'agent')
 *
 * igb0's agent uses tx_interval=60 and tx_hold_multiplier=2, while every
 * other agent uses tx_interval=60 and the built-in tx_hold_multiplier (4).
 *
 * Since hardware (and datalink) names must end with a digit, an agent
 * property group cannot collide with any of the fixed property group names
 * we use ('config', 'daemon', 'default', 'general').
 *
 * Agent properties:
 *
 *	admin_status		astring	disabled | tx | rx | txrx
 *	port_desc		astring	Port description TLV contents
 *	tx_tlvs			astring	(multi-valued) Optional core TLVs to
 *					send: port-desc, sys-name, sys-desc,
 *					sys-cap, mgmt-addr, or none
 *	tx_8021_tlvs		astring	(multi-valued) native-vlan, vlans,
 *					vlan-name, mgmt-vlan, or none
 *	tx_8023_tlvs		astring	(multi-valued) phy-cfg, mtu, or none
 *	tx_interval		count	msgTxInterval
 *	tx_hold_multiplier	count	msgTxHold
 *	reinit_delay		count	reinitDelay
 *	tx_credit_max		count	txCreditMax
 *	tx_fast_interval	count	msgFastTx
 *	tx_fast_init		count	txFastInit
 *	neighbor_max		count	Max number of neighbors per agent
 *
 * The SMF handles and config state here are only used from the main thread.
 */

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <libscf.h>
#include <umem.h>
#include <unistd.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>

#include "agent.h"
#include "config.h"
#include "lldpd.h"
#include "log.h"
#include "util.h"

#define	CONFIG_PG	"config"
#define	CONFIG_SYSNAME	"sysname"
#define	CONFIG_SYSDESC	"sysdesc"
#define	CONFIG_MGMTIF	"mgmtif"

#define	AGENT_DEFAULT_PG	"default"
#define	AGENT_PG_TYPE		"agent"

#define	AGENT_PROP_STATUS	"admin_status"
#define	AGENT_PROP_PORTDESC	"port_desc"
#define	AGENT_PROP_TX_TLVS	"tx_tlvs"
#define	AGENT_PROP_TX_8021_TLVS	"tx_8021_tlvs"
#define	AGENT_PROP_TX_8023_TLVS	"tx_8023_tlvs"

/* Value of a multi-valued TLV property that explicitly selects nothing */
#define	AGENT_TLV_NONE		"none"

#define	DEFAULT_ADMIN_STATUS	LLDP_LINK_TXRX
#define	DEFAULT_TX_TLVS		\
	(LLDP_TX_PORTDESC | LLDP_TX_SYSNAME | LLDP_TX_SYSDESC | LLDP_TX_SYSCAP)
#define	DEFAULT_TX_8021_TLVS	LLDP_TX_X1_NONE
#define	DEFAULT_TX_8023_TLVS	0

/*
 * The numeric (uint16_t) agent properties. The defaults and ranges are
 * those given in IEEE 802.1AB-2016 (and the LLDP-V2-MIB).
 */
typedef struct agent_count_prop {
	const char	*acp_name;
	size_t		acp_off;
	uint16_t	acp_def;
	uint16_t	acp_min;
	uint16_t	acp_max;
} agent_count_prop_t;

#define	ACP(_name, _field, _def, _min, _max) {		\
	.acp_name = (_name),				\
	.acp_off = offsetof(agent_cfg_t, _field),	\
	.acp_def = (_def),				\
	.acp_min = (_min),				\
	.acp_max = (_max),				\
}

static const agent_count_prop_t agent_count_props[] = {
	ACP("tx_interval",	ac_tx_interval,		30, 1, 3600),
	ACP("tx_hold_multiplier", ac_tx_hold,		4, 2, 10),
	ACP("reinit_delay",	ac_reinit_delay,	2, 1, 10),
	ACP("tx_credit_max",	ac_tx_credit_max,	5, 1, 10),
	ACP("tx_fast_interval",	ac_tx_fast_msg,		1, 1, 3600),
	ACP("tx_fast_init",	ac_tx_fast_init,	4, 1, 8),
	ACP("neighbor_max",	ac_neighbor_max,	32, 1, UINT16_MAX),
};

#undef ACP

typedef struct name_val {
	const char	*nv_name;
	uint_t		nv_val;
} name_val_t;

static const name_val_t admin_status_names[] = {
	{ "disabled",	LLDP_LINK_DISABLED },
	{ "tx",		LLDP_LINK_TX },
	{ "rx",		LLDP_LINK_RX },
	{ "txrx",	LLDP_LINK_TXRX },
};

static const name_val_t core_tlv_names[] = {
	{ "port-desc",	LLDP_TX_PORTDESC },
	{ "sys-name",	LLDP_TX_SYSNAME },
	{ "sys-desc",	LLDP_TX_SYSDESC },
	{ "sys-cap",	LLDP_TX_SYSCAP },
	{ "mgmt-addr",	LLDP_TX_MGMTADDR },
};

static const name_val_t tlv_8021_names[] = {
	{ "native-vlan",	LLDP_TX_X1_NATIVE_VLAN },
	{ "vlans",		LLDP_TX_X1_VLANS },
	{ "vlan-name",		LLDP_TX_X1_VLAN_NAME },
	{ "mgmt-vlan",		LLDP_TX_X2_MGMT_VLAN },
};

static const name_val_t tlv_8023_names[] = {
	{ "phy-cfg",	LLDP_TX_X3_PHYCFG },
	{ "mtu",	LLDP_TX_X3_MTU },
};

/*
 * Per-link information obtained from topo during startup. Agents are
 * created after the topo walk, so we stash what we find here and apply it
 * when each agent is created.
 */
typedef struct topo_link {
	struct topo_link	*tl_next;
	char			*tl_name;
	char			*tl_label;
	char			*tl_devname;
	uint32_t		tl_portnum;
	bool			tl_has_portnum;
} topo_link_t;

static topo_link_t	*topo_links;

mutex_t		lldp_config_lock = ERRORCHECKMUTEX;
lldp_config_t	*lldp_config;

/*
 * The default system config is created during startup and is read-only once
 * created. The default agent config is created during startup and rebuilt
 * on refresh; it is only accessed from the main thread.
 */
static lldp_config_t	lldp_default_config;
static agent_cfg_t	default_agent_cfg;

char		*my_fmri;

scf_handle_t		*rep_handle;
scf_service_t		*scf_svc;
scf_instance_t		*scf_inst;
scf_snapshot_t		*scf_snap;
scf_propertygroup_t	*scf_pg;
scf_property_t		*scf_prop;
scf_value_t		*scf_val;
static scf_iter_t	*scf_iter;

topo_hdl_t		*topo_hdl;

static void config_free(lldp_config_t *);
static bool config_get_defaults(lldp_config_t *);
static void config_get_hostname(log_t *, lldp_config_t *,
    scf_propertygroup_t *);
static void config_get_sysdesc(log_t *, lldp_config_t *, scf_propertygroup_t *);
static void set_chassis_id(lldp_chassis_t *, lldp_chassis_type_t,
    const uint8_t *, uint8_t);

static void config_agent_defaults(agent_cfg_t *);
static void config_agent_default_read(void);
static void config_agent_build(const agent_t *, agent_cfg_t *);
static void config_agent_apply_pg(log_t *, agent_cfg_t *,
    const scf_propertygroup_t *);
static void config_agent_copy(agent_cfg_t *, const agent_cfg_t *);
static void config_agent_log(log_t *, const char *, const agent_cfg_t *);
static const topo_link_t *topo_link_find(const char *);

void
config_init(void)
{
	int e;

	TRACE_ENTER(log);

	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL) {
		my_fmri = LLDP_SVC_FMRI;
		log_info(log,
		    "SMF_FMRI not set (not run from SMF?); using default",
		    LOG_T_STRING, "fmri", my_fmri,
		    LOG_T_END);
	}

	log_debug(log, "SMF FMRI",
	    LOG_T_STRING, "fmri", my_fmri,
	    LOG_T_END);

	rep_handle = scf_handle_create(SCF_VERSION);
	if (rep_handle == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create SMF repository handle");
	}

	log_trace(log, "created repository handle",
	    LOG_T_POINTER, "rep_handle", (void *)rep_handle,
	    LOG_T_END);

	if (scf_handle_bind(rep_handle) != 0) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to bind to SMF repository");
	}

	scf_svc = scf_service_create(rep_handle);
	if (scf_svc == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf service");
	}

	log_trace(log, "create smf service handle",
	    LOG_T_POINTER, "svc_handle", (void *)scf_svc,
	    LOG_T_END);

	scf_inst = scf_instance_create(rep_handle);
	if (scf_inst == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf instance");
	}

	log_trace(log, "created smf instance handle",
	    LOG_T_POINTER, "inst_handle", (void *)scf_inst,
	    LOG_T_END);

	scf_snap = scf_snapshot_create(rep_handle);
	if (scf_snap == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to allocate scf snapshot");
	}

	log_trace(log, "created smf snapshot handle",
	    LOG_T_POINTER, "snap", (void *)scf_snap,
	    LOG_T_END);

	scf_pg = scf_pg_create(rep_handle);
	if (scf_pg == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf property group");
	}

	scf_prop = scf_property_create(rep_handle);
	if (scf_prop == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf property");
	}

	scf_val = scf_value_create(rep_handle);
	if (scf_val == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf value");
	}

	scf_iter = scf_iter_create(rep_handle);
	if (scf_iter == NULL) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to create scf iterator");
	}

	if (scf_handle_decode_fmri(rep_handle, my_fmri,
	    NULL /* scope */, scf_svc, scf_inst, NULL /* pg */, NULL /* prop */,
	    SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		log_fatal_scferr(SMF_EXIT_ERR_FATAL, log,
		    "failed to decode SMF fmri");
	}

	topo_hdl = topo_open(TOPO_VERSION, NULL, &e);
	if (topo_hdl == NULL) {
		log_fatal(SMF_EXIT_ERR_FATAL, log,
		    "failed to obtain topo handle",
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
	}

	if (!config_get_defaults(&lldp_default_config)) {
		log_fatal(SMF_EXIT_ERR_FATAL, log,
		    "failed to obtain default configuration", LOG_T_END);
	}

	config_agent_default_read();
	(void) config_read();

	TRACE_RETURN(log);
}

static lldp_config_t *
config_new(void)
{
	lldp_config_t *cfg;

	cfg = umem_zalloc(sizeof (*cfg), UMEM_NOFAIL);

	/* Populate with defaults */
	(void) memcpy(&cfg->lcfg_chassis, &lldp_default_config.lcfg_chassis,
	    sizeof (cfg->lcfg_chassis));

	cfg->lcfg_sysname = xstrdup(lldp_default_config.lcfg_sysname);
	cfg->lcfg_sysdesc = xstrdup(lldp_default_config.lcfg_sysdesc);
	cfg->lcfg_syscap = lldp_default_config.lcfg_syscap;
	cfg->lcfg_encap = lldp_default_config.lcfg_encap;

	/* TODO: management interfaces */

	return (cfg);
}

bool
config_read(void)
{
	lldp_config_t	*cfg, *old;

	TRACE_ENTER(log);

	log_debug(log, "loading configuration", LOG_T_END);

	cfg = config_new();

	/* Override any settings from SMF */
	if (config_get_pg(log, CONFIG_PG, scf_pg)) {
		config_get_hostname(log, cfg, scf_pg);
		config_get_sysdesc(log, cfg, scf_pg);
	}

	mutex_enter(&lldp_config_lock);
	old = lldp_config;
	lldp_config = cfg;
	mutex_exit(&lldp_config_lock);

	config_free(old);

	TRACE_RETURN(log);
	return (true);
}

struct topo_arg {
	log_t		*ta_log;
	lldp_config_t	*ta_cfg;
	bool		ta_root;
};

static void
topo_do_root(topo_hdl_t *th, tnode_t *np, struct topo_arg *arg)
{
	char		*cid;
	size_t		cidlen;
	int		e;

	if (topo_prop_get_string(np, FM_FMRI_AUTHORITY, FM_FMRI_AUTH_CHASSIS,
	    &cid, &e) != 0) {
		log_fatal(SMF_EXIT_ERR_FATAL, arg->ta_log,
		    "failed to get chassis id",
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
	}

	cidlen = strlen(cid);

	set_chassis_id(&arg->ta_cfg->lcfg_chassis, LLDP_CHASSIS_COMPONENT,
	    (const uint8_t *)cid,
	    MIN(cidlen, sizeof (arg->ta_cfg->lcfg_chassis.llc_id)));

	topo_hdl_strfree(th, cid);
	arg->ta_root = false;
}

static void
topo_do_link(topo_hdl_t *th, tnode_t *np, const char *lname,
    struct topo_arg *arg)
{
	topo_link_t	*tl;
	tnode_t		*parent;
	char		*label, *devdesc;
	int		e;

	if (topo_link_find(lname) != NULL) {
		log_debug(arg->ta_log, "duplicate topo node for link; ignoring",
		    LOG_T_STRING, "link", lname,
		    LOG_T_END);
		return;
	}

	tl = umem_zalloc(sizeof (*tl), UMEM_NOFAIL);
	tl->tl_name = xstrdup(lname);

	/* Datalinks hang off of port nodes; the instance is the port number */
	if (strcmp(topo_node_name(np), "port") == 0) {
		tl->tl_portnum = (uint32_t)topo_node_instance(np);
		tl->tl_has_portnum = true;
	}

	parent = topo_node_parent(np);
	VERIFY3P(parent, !=, NULL);

	/*
	 * Save the parent's label and device-name properties if they
	 * exist.
	 */
	if (topo_prop_get_string(parent, TOPO_PGROUP_PROTOCOL, TOPO_PROP_LABEL,
	    &label, &e) == 0) {
		tl->tl_label = xstrdup(label);
		topo_hdl_strfree(th, label);
	}

	if (topo_prop_get_string(parent, TOPO_PGROUP_PCI, TOPO_PCI_DEVNM,
	    &devdesc, &e) == 0) {
		tl->tl_devname = xstrdup(devdesc);
		topo_hdl_strfree(th, devdesc);
	}

	log_debug(arg->ta_log, "found link in topo",
	    LOG_T_STRING, "link", tl->tl_name,
	    LOG_T_UINT32, "portnum", tl->tl_portnum,
	    LOG_T_STRING, "label", (tl->tl_label != NULL) ? tl->tl_label : "",
	    LOG_T_STRING, "devname",
	    (tl->tl_devname != NULL) ? tl->tl_devname : "",
	    LOG_T_END);

	tl->tl_next = topo_links;
	topo_links = tl;
}

static const topo_link_t *
topo_link_find(const char *name)
{
	for (const topo_link_t *tl = topo_links; tl != NULL; tl = tl->tl_next) {
		if (strcmp(tl->tl_name, name) == 0)
			return (tl);
	}
	return (NULL);
}

static int
topo_cb(topo_hdl_t *th, tnode_t *np, void *argp)
{
	struct topo_arg	*arg = argp;

	/*
	 * XXX: can we use topo_node_parent(np) == NULL to
	 * identify the root node instead?
	 */
	if (arg->ta_root) {
		topo_do_root(th, np, arg);
		return (TOPO_WALK_NEXT);
	}

	char	*link_name;
	int	e;

	if (topo_prop_get_string(np, TOPO_PGROUP_DATALINK,
	    TOPO_PGROUP_DATALINK_LINK_NAME, &link_name, &e) != 0) {
		return (TOPO_WALK_NEXT);
	}

	topo_do_link(th, np, link_name, arg);
	topo_hdl_strfree(th, link_name);

	return (TOPO_WALK_NEXT);
}

static bool
config_get_topo(lldp_config_t *cfg)
{
	topo_walk_t	*wp;
	int		e;
	struct topo_arg	arg = {
		.ta_log = log,
		.ta_cfg = cfg,
		.ta_root = true,
	};

	e = 0;
	(void) topo_snap_hold(topo_hdl, NULL, &e);
	if (e != 0) {
		log_error(log, "failed to create topo snapshot",
		    LOG_T_INT32, "err", e,
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
		return (false);
	}

	wp = topo_walk_init(topo_hdl, FM_FMRI_SCHEME_HC, topo_cb, &arg, &e);
	if (wp == NULL) {
		log_error(log, "failed to start topo walk",
		    LOG_T_INT32, "err", e,
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
		topo_snap_release(topo_hdl);
		return (false);
	}

	while ((e = topo_walk_step(wp, TOPO_WALK_CHILD)) == TOPO_WALK_NEXT)
		;

	topo_walk_fini(wp);
	topo_snap_release(topo_hdl);

	if (e == TOPO_WALK_ERR) {
		log_error(log, "topo walk failed", LOG_T_END);
		return (false);
	}

	return (true);
}

static void
config_get_def_hostname(lldp_config_t *cfg)
{
	char host[MAXHOSTNAMELEN] = { 0 };

	VERIFY0(gethostname(host, sizeof (host)));
	cfg->lcfg_sysname = xstrdup(host);
}

static void
config_get_def_sysdesc(lldp_config_t *cfg)
{
	struct utsname uts = { 0 };

	/*
	 * utsname(2) isn't explicitly defined as returning 0 on success,
	 * so we can't use VERIFY0() here.
	 */
	VERIFY3S(uname(&uts), >=, 0);

	cfg->lcfg_sysdesc = xsprintf("%s %s %s %s %s",
	    uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);
}

static void
config_get_def_syscap(lldp_config_t *cfg)
{
	cfg->lcfg_syscap = LLDP_CAP_ROUTER | LLDP_CAP_STATION;

	/* TODO: Check if IP forwarding is enabled */
	cfg->lcfg_encap = LLDP_CAP_STATION;
}

static void
config_get_def_mgmtaddr(lldp_config_t *cfg __unused)
{
	/* TODO */
}

static bool
config_get_defaults(lldp_config_t *cfg)
{
	if (!config_get_topo(cfg))
		return (false);

	config_get_def_hostname(cfg);
	config_get_def_sysdesc(cfg);
	config_get_def_syscap(cfg);
	config_get_def_mgmtaddr(cfg);

	return (true);
}

static void
config_free(lldp_config_t *cfg)
{
	if (cfg == NULL)
		return;

	free(cfg->lcfg_sysname);
	free(cfg->lcfg_sysdesc);
	if (cfg->lcfg_mgmt_if != NULL) {
		for (uint_t i = 0; cfg->lcfg_mgmt_if[i] != NULL; i++)
			free(cfg->lcfg_mgmt_if[i]);
		free(cfg->lcfg_mgmt_if);
	}
	umem_free(cfg, sizeof (*cfg));
}

/*
 * Log a problem with a property. Property problems are never fatal -- the
 * property is ignored and the existing value is retained.
 */
static void
prop_warn(log_t *l, const scf_propertygroup_t *pg, const char *prop,
    const char *msg, const char *val)
{
	ssize_t lim = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);

	VERIFY3S(lim, >, 0);

	char pgname[lim + 1];

	if (scf_pg_get_name(pg, pgname, sizeof (pgname)) < 0)
		(void) strlcpy(pgname, "<unknown>", sizeof (pgname));

	log_warn(l, msg,
	    LOG_T_STRING, "pg", pgname,
	    LOG_T_STRING, "property", prop,
	    LOG_T_STRING, "value", (val != NULL) ? val : "",
	    LOG_T_END);
}

static void
prop_scferr(log_t *l, const scf_propertygroup_t *pg, const char *prop,
    const char *msg)
{
	prop_warn(l, pg, prop, msg, scf_strerror(scf_error()));
}

/*
 * Retrieve the named property group from our instance, composed with the
 * service. We use the running snapshot so that changes only take effect
 * after a 'svcadm refresh'. If there is no running snapshot (e.g. we're
 * being run by hand), the current property values are used.
 *
 * Returns true if the property group exists. A missing property group is
 * not an error (all of our property groups are optional).
 */
bool
config_get_pg(log_t *l, const char *name, scf_propertygroup_t *pg)
{
	scf_snapshot_t	*snap = scf_snap;
	scf_error_t	serr;

	if (scf_instance_get_snapshot(scf_inst, "running", scf_snap) != 0) {
		serr = scf_error();
		if (serr != SCF_ERROR_NOT_FOUND) {
			log_warn(l, "failed to get running snapshot; using "
			    "current property values",
			    LOG_T_UINT32, "err", serr,
			    LOG_T_STRING, "errmsg", scf_strerror(serr),
			    LOG_T_END);
		}
		snap = NULL;
	}

	if (scf_instance_get_pg_composed(scf_inst, snap, name, pg) == 0)
		return (true);

	serr = scf_error();
	if (serr != SCF_ERROR_NOT_FOUND) {
		log_error(l, "failed to read SMF property group",
		    LOG_T_STRING, "pg", name,
		    LOG_T_UINT32, "err", serr,
		    LOG_T_STRING, "errmsg", scf_strerror(serr),
		    LOG_T_END);
	}

	return (false);
}

/*
 * Retrieve the (single) value of the named property into val. Returns false
 * if the property doesn't exist, has no values, or can't be read.
 */
bool
config_get_prop(log_t *l, const scf_propertygroup_t *pg, const char *name,
    scf_value_t *val)
{
	if (scf_pg_get_property(pg, name, scf_prop) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			prop_scferr(l, pg, name, "failed to read SMF property");
		return (false);
	}

	if (scf_property_get_value(scf_prop, val) == 0)
		return (true);

	switch (scf_error()) {
	case SCF_ERROR_NOT_FOUND:
		/* No values set */
		return (false);
	case SCF_ERROR_CONSTRAINT_VIOLATED:
		prop_warn(l, pg, name,
		    "SMF property has multiple values; ignoring", NULL);
		return (false);
	default:
		prop_scferr(l, pg, name, "failed to read SMF property value");
		return (false);
	}
}

/*
 * Retrieve a string property. On success, *sp is set to a newly allocated
 * copy of the string, which the caller must free.
 */
static bool
pg_get_string(log_t *l, const scf_propertygroup_t *pg, const char *name,
    char **sp)
{
	if (!config_get_prop(l, pg, name, scf_val))
		return (false);

	ssize_t lim = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	VERIFY3S(lim, >, 0);

	char buf[lim + 1];

	if (scf_value_get_astring(scf_val, buf, sizeof (buf)) < 0) {
		prop_scferr(l, pg, name,
		    "SMF property is not a string; ignoring");
		return (false);
	}

	*sp = xstrdup(buf);
	return (true);
}

static bool
pg_get_count(log_t *l, const scf_propertygroup_t *pg,
    const agent_count_prop_t *p, uint16_t *vp)
{
	uint64_t v;

	if (!config_get_prop(l, pg, p->acp_name, scf_val))
		return (false);

	if (scf_value_get_count(scf_val, &v) != 0) {
		prop_scferr(l, pg, p->acp_name,
		    "SMF property is not a count; ignoring");
		return (false);
	}

	if (v < p->acp_min || v > p->acp_max) {
		char buf[64];

		(void) snprintf(buf, sizeof (buf), "%" PRIu64
		    " (valid range %u-%u)", v, p->acp_min, p->acp_max);
		prop_warn(l, pg, p->acp_name,
		    "SMF property value out of range; ignoring", buf);
		return (false);
	}

	*vp = (uint16_t)v;
	return (true);
}

static bool
name_lookup(const name_val_t *tbl, size_t n, const char *name, uint_t *vp)
{
	for (size_t i = 0; i < n; i++) {
		if (strcmp(tbl[i].nv_name, name) == 0) {
			*vp = tbl[i].nv_val;
			return (true);
		}
	}
	return (false);
}

/*
 * Retrieve a multi-valued astring property where each value is the name of
 * a flag in tbl, and OR the corresponding flags together. A property
 * with no values (or only the value 'none') yields 0. Unknown values are
 * logged and skipped.
 */
static bool
pg_get_flags(log_t *l, const scf_propertygroup_t *pg, const char *name,
    const name_val_t *tbl, size_t n, uint_t *vp)
{
	uint_t	flags = 0;
	int	ret;

	if (scf_pg_get_property(pg, name, scf_prop) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			prop_scferr(l, pg, name, "failed to read SMF property");
		return (false);
	}

	if (scf_iter_property_values(scf_iter, scf_prop) != 0) {
		prop_scferr(l, pg, name, "failed to iterate SMF property");
		return (false);
	}

	ssize_t lim = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);

	VERIFY3S(lim, >, 0);

	char buf[lim + 1];

	while ((ret = scf_iter_next_value(scf_iter, scf_val)) == 1) {
		uint_t v;

		if (scf_value_get_astring(scf_val, buf, sizeof (buf)) < 0) {
			prop_scferr(l, pg, name,
			    "SMF property is not a string; ignoring");
			return (false);
		}

		if (strcmp(buf, AGENT_TLV_NONE) == 0)
			continue;

		if (!name_lookup(tbl, n, buf, &v)) {
			prop_warn(l, pg, name,
			    "unknown SMF property value; ignoring value", buf);
			continue;
		}

		flags |= v;
	}

	if (ret != 0) {
		prop_scferr(l, pg, name, "failed to read SMF property values");
		return (false);
	}

	*vp = flags;
	return (true);
}

static void
config_agent_defaults(agent_cfg_t *cfg)
{
	(void) memset(cfg, '\0', sizeof (*cfg));

	cfg->ac_status = DEFAULT_ADMIN_STATUS;
	cfg->ac_tx_tlvs = DEFAULT_TX_TLVS;
	cfg->ac_tx_8021_tlvs = DEFAULT_TX_8021_TLVS;
	cfg->ac_tx_8023_tlvs = DEFAULT_TX_8023_TLVS;

	for (size_t i = 0; i < ARRAY_SIZE(agent_count_props); i++) {
		const agent_count_prop_t *p = &agent_count_props[i];
		uint16_t *fp = (uint16_t *)((char *)cfg + p->acp_off);

		*fp = p->acp_def;
	}
}

/*
 * Replace any values in cfg with those of any properties present in pg.
 */
static void
config_agent_apply_pg(log_t *l, agent_cfg_t *cfg,
    const scf_propertygroup_t *pg)
{
	char	*s;
	uint_t	v;

	if (pg_get_string(l, pg, AGENT_PROP_STATUS, &s)) {
		if (name_lookup(admin_status_names,
		    ARRAY_SIZE(admin_status_names), s, &v)) {
			cfg->ac_status = (lldp_admin_status_t)v;
		} else {
			prop_warn(l, pg, AGENT_PROP_STATUS,
			    "invalid admin status; ignoring", s);
		}
		free(s);
	}

	if (pg_get_string(l, pg, AGENT_PROP_PORTDESC, &s)) {
		free(cfg->ac_desc);
		cfg->ac_desc = s;
	}

	if (pg_get_flags(l, pg, AGENT_PROP_TX_TLVS, core_tlv_names,
	    ARRAY_SIZE(core_tlv_names), &v)) {
		cfg->ac_tx_tlvs = (lldp_tx_core_tlv_t)v;
	}

	if (pg_get_flags(l, pg, AGENT_PROP_TX_8021_TLVS, tlv_8021_names,
	    ARRAY_SIZE(tlv_8021_names), &v)) {
		cfg->ac_tx_8021_tlvs = (lldp_tx_8021_tlv_t)v;
	}

	if (pg_get_flags(l, pg, AGENT_PROP_TX_8023_TLVS, tlv_8023_names,
	    ARRAY_SIZE(tlv_8023_names), &v)) {
		cfg->ac_tx_8023_tlvs = (lldp_tx_8023_tlv_t)v;
	}

	for (size_t i = 0; i < ARRAY_SIZE(agent_count_props); i++) {
		const agent_count_prop_t *p = &agent_count_props[i];
		uint16_t *fp = (uint16_t *)((char *)cfg + p->acp_off);

		(void) pg_get_count(l, pg, p, fp);
	}
}

static void
config_agent_copy(agent_cfg_t *dst, const agent_cfg_t *src)
{
	*dst = *src;

	if (src->ac_desc != NULL)
		dst->ac_desc = xstrdup(src->ac_desc);
	if (src->ac_label != NULL)
		dst->ac_label = xstrdup(src->ac_label);
	if (src->ac_devname != NULL)
		dst->ac_devname = xstrdup(src->ac_devname);
}

void
config_agent_cfg_free(agent_cfg_t *cfg)
{
	free(cfg->ac_desc);
	free(cfg->ac_label);
	free(cfg->ac_devname);
	cfg->ac_desc = cfg->ac_label = cfg->ac_devname = NULL;
}

static void
config_agent_log(log_t *l, const char *msg, const agent_cfg_t *cfg)
{
	log_debug(l, msg,
	    LOG_T_STRING, "admin_status", lldp_admin_status_str(cfg->ac_status),
	    LOG_T_STRING, "port_desc",
	    (cfg->ac_desc != NULL) ? cfg->ac_desc : "",
	    LOG_T_XINT32, "tx_tlvs", (uint32_t)cfg->ac_tx_tlvs,
	    LOG_T_XINT32, "tx_8021_tlvs", (uint32_t)cfg->ac_tx_8021_tlvs,
	    LOG_T_XINT32, "tx_8023_tlvs", (uint32_t)cfg->ac_tx_8023_tlvs,
	    LOG_T_UINT32, "tx_interval", (uint32_t)cfg->ac_tx_interval,
	    LOG_T_UINT32, "tx_hold_multiplier", (uint32_t)cfg->ac_tx_hold,
	    LOG_T_UINT32, "reinit_delay", (uint32_t)cfg->ac_reinit_delay,
	    LOG_T_UINT32, "tx_credit_max", (uint32_t)cfg->ac_tx_credit_max,
	    LOG_T_UINT32, "tx_fast_interval", (uint32_t)cfg->ac_tx_fast_msg,
	    LOG_T_UINT32, "tx_fast_init", (uint32_t)cfg->ac_tx_fast_init,
	    LOG_T_UINT32, "neighbor_max", (uint32_t)cfg->ac_neighbor_max,
	    LOG_T_END);
}

/*
 * (Re)build the default agent configuration: the built-in defaults,
 * overridden by anything set in the 'default' property group.
 */
static void
config_agent_default_read(void)
{
	agent_cfg_t cfg;

	config_agent_defaults(&cfg);
	if (config_get_pg(log, AGENT_DEFAULT_PG, scf_pg))
		config_agent_apply_pg(log, &cfg, scf_pg);

	config_agent_cfg_free(&default_agent_cfg);
	default_agent_cfg = cfg;

	config_agent_log(log, "default agent configuration",
	    &default_agent_cfg);
}

/*
 * Build the SMF-derived configuration for an agent: a copy of the default
 * agent configuration, overridden by the contents of a property group of
 * type 'agent' named after the agent's hardware link name (if one exists).
 * Only the SMF-configurable fields of cfg are meaningful; the caller is
 * responsible for any system-derived fields (port id, topo info, etc).
 */
static void
config_agent_build(const agent_t *a, agent_cfg_t *cfg)
{
	log_t *l = a->a_log;

	config_agent_copy(cfg, &default_agent_cfg);

	if (!config_get_pg(l, a->a_name, scf_pg))
		return;

	ssize_t lim = scf_limit(SCF_LIMIT_MAX_PG_TYPE_LENGTH);

	VERIFY3S(lim, >, 0);

	char type[lim + 1];

	if (scf_pg_get_type(scf_pg, type, sizeof (type)) < 0) {
		log_error(l, "failed to get SMF property group type",
		    LOG_T_STRING, "pg", a->a_name,
		    LOG_T_STRING, "errmsg", scf_strerror(scf_error()),
		    LOG_T_END);
		return;
	}

	if (strcmp(type, AGENT_PG_TYPE) != 0) {
		log_warn(l, "SMF property group for agent has wrong "
		    "type; ignoring",
		    LOG_T_STRING, "pg", a->a_name,
		    LOG_T_STRING, "type", type,
		    LOG_T_STRING, "expected_type", AGENT_PG_TYPE,
		    LOG_T_END);
		return;
	}

	log_debug(l, "applying agent-specific configuration",
	    LOG_T_STRING, "pg", a->a_name,
	    LOG_T_END);
	config_agent_apply_pg(l, cfg, scf_pg);
}

/*
 * Set the initial configuration of a newly created agent. Must be called
 * from the main thread before the agent's thread is started.
 */
void
config_agent_init(agent_t *a)
{
	agent_cfg_t		*cfg = &a->a_cfg;
	const topo_link_t	*tl;
	log_t			*l = a->a_log;

	TRACE_ENTER(l);

	config_agent_build(a, cfg);

	tl = topo_link_find(a->a_name);
	if (tl != NULL) {
		if (tl->tl_has_portnum)
			cfg->ac_portnum = tl->tl_portnum;
		if (tl->tl_label != NULL) {
			free(cfg->ac_label);
			cfg->ac_label = xstrdup(tl->tl_label);
		}
		if (tl->tl_devname != NULL) {
			free(cfg->ac_devname);
			cfg->ac_devname = xstrdup(tl->tl_devname);
		}
	}

	config_agent_log(l, "agent configuration", cfg);

	TRACE_RETURN(l);
}

/*
 * Re-read the running configuration from SMF and apply it to the system
 * and to every running agent. Called from the main thread on SIGHUP.
 */
void
config_refresh(void)
{
	uu_list_walk_t	*wk;
	agent_t		*a;

	TRACE_ENTER(log);

	log_info(log, "refreshing configuration", LOG_T_END);

	(void) config_read();
	config_agent_default_read();

	mutex_enter(&agent_list_lock);
	wk = xuu_list_walk_start(agent_list, 0);
	while ((a = uu_list_walk_next(wk)) != NULL) {
		agent_cfg_t cfg;

		config_agent_build(a, &cfg);
		config_agent_log(a->a_log, "refreshed agent configuration",
		    &cfg);

		/* agent_set_cfg() takes ownership of cfg's contents */
		agent_set_cfg(a, &cfg);
	}
	uu_list_walk_end(wk);
	mutex_exit(&agent_list_lock);

	TRACE_RETURN(log);
}

static void
set_chassis_id(lldp_chassis_t *c, lldp_chassis_type_t type,
    const uint8_t *val, uint8_t len)
{
	c->llc_type = type;
	c->llc_len = len;
	(void) memcpy(c->llc_id, val, len);

	/* For easy of observability, make sure any unused space is NUL */
	if (len < sizeof (c->llc_id)) {
		(void) memset(c->llc_id + len, '\0', sizeof (c->llc_id) - len);
	}
}

static void
config_get_hostname(log_t *l, lldp_config_t *cfg, scf_propertygroup_t *pg)
{
	char *name;

	if (!pg_get_string(l, pg, CONFIG_SYSNAME, &name))
		return;

	/* An empty value means use the default */
	if (*name == '\0') {
		free(name);
		return;
	}

	free(cfg->lcfg_sysname);
	cfg->lcfg_sysname = name;
}

static void
config_get_sysdesc(log_t *l, lldp_config_t *cfg, scf_propertygroup_t *pg)
{
	char *desc;

	if (!pg_get_string(l, pg, CONFIG_SYSDESC, &desc))
		return;

	/* An empty value means use the default */
	if (*desc == '\0') {
		free(desc);
		return;
	}

	free(cfg->lcfg_sysdesc);
	cfg->lcfg_sysdesc = desc;
}
