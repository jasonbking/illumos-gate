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

#include <netdb.h>
#include <stdbool.h>
#include <string.h>
#include <synch.h>
#include <libscf.h>
#include <umem.h>
#include <unistd.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <sys/debug.h>
#include <sys/utsname.h>

#include "config.h"
#include "lldpd.h"
#include "log.h"
#include "util.h"

#define	CONFIG_PG	"config"
#define	CONFIG_SYSNAME	"sysname"
#define	CONFIG_SYSDESC	"sysdesc"
#define	CONFIG_MGMTIF	"mgmtif"

mutex_t		lldp_config_lock = ERRORCHECKMUTEX;
lldp_config_t	*lldp_config;

/*
 * The default config is created during startup and is read-only once
 * created.
 */
lldp_config_t	lldp_default_config;

char		*my_fmri;

scf_handle_t		*rep_handle;
scf_service_t		*scf_svc;
scf_instance_t		*scf_inst;
scf_snapshot_t		*scf_snap;
scf_propertygroup_t	*scf_pg;
scf_property_t		*scf_prop;
scf_value_t		*scf_val;

topo_hdl_t		*topo_hdl;

static void config_free(lldp_config_t *);
static scf_error_t config_get_pg(log_t *, const char *, const char *,
    scf_propertygroup_t *);
static bool config_get_defaults(lldp_config_t *);
static void config_get_hostname(log_t *, lldp_config_t *,
    scf_propertygroup_t *);
static void config_get_sysdesc(log_t *, lldp_config_t *, scf_propertygroup_t *);
static void set_chassis_id(log_t *, lldp_chassis_t *, const char *);

void
config_init(void)
{
	int e;

	TRACE_ENTER(log);

	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL) {
		my_fmri = LLDP_FMRI;
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

	config_read();

	TRACE_RETURN(log);
}

static lldp_config_t *
config_new(void)
{
	lldp_config_t *cfg;

	cfg = umem_zalloc(sizeof (*cfg), UMEM_DEFAULT);
	if (cfg == NULL) {
		log_syserr(log, "failed to allocate new lldp config", errno);
		return (NULL);
	}

	/* Populate with defaults */
	(void) memcpy(&cfg->lcfg_chassis, &lldp_default_config.lcfg_chassis,
	    sizeof (cfg->lcfg_chassis));

	cfg->lcfg_sysname = strdup(lldp_default_config.lcfg_sysname);
	if (cfg->lcfg_sysname == NULL) {
		log_syserr(log, "failed to allocate memory for system name",
		    errno);
		config_free(cfg);
		return (NULL);
	}

	cfg->lcfg_sysdesc = strdup(lldp_default_config.lcfg_sysdesc);
	if (cfg->lcfg_sysdesc == NULL) {
		log_syserr(log,
		    "failed to allocate mmeory for system description", errno);
		config_free(cfg);
	}

	cfg->lcfg_syscap = lldp_default_config.lcfg_syscap;
	cfg->lcfg_encap = lldp_default_config.lcfg_encap;

	/* TODO: management interfaces */

	return (cfg);
}

bool
config_read(void)
{
	lldp_config_t	*cfg = NULL;
	bool		ret = true;

	TRACE_ENTER(log);

	log_debug(log, "loading configuration", LOG_T_END);

	cfg = config_new();
	if (cfg == NULL)
		return (false);

	/* Override any settings from SMF */
	if (!config_get_pg(log, "default", CONFIG_PG, scf_pg)) {
		config_free(cfg);
		goto done;
	}

	config_get_hostname(log, cfg, scf_pg);
	config_get_sysdesc(log, cfg, scf_pg);

done:
	mutex_enter(&lldp_config_lock);
	lldp_config = cfg;
	mutex_exit(&lldp_config_lock);

	TRACE_RETURN(log);
	return (ret);
}

static int
topo_cb(topo_hdl_t *th, tnode_t *np, void *arg)
{
	lldp_config_t	*cfg = arg;
	char		*cid;
	size_t		cidlen;
	int		e;

	/* Currently we only use the root node */

	cid = topo_prop_get_string(np, FM_FMRI_AUTHORITY, FM_FMRI_AUTH_CHASSIS,
	    &cid, &e);
	if (cid == NULL) {
		log_fatal(SMF_EXIT_ERR_FATAL, "failed to get chassis id",
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
		return (TOPO_WALK_TERMINATE);
	}

	cidlen = strlen(cid);

	set_chassis_id(&cfg->lcfg_chassis, LLDP_CHASSIS_COMPONENT,
	    cid, MIN(cidlen, sizeof (cfg->lcfg_chassis.llc_id)));

	topo_hdl_strfree(th, cid);
	return (TOPO_WALK_TERMINATE);
}

static bool 
config_get_topo(lldp_config_t *cfg)
{
	topo_walk_t	*wp;
	int		e;

	e = 0;	    
	(void) topo_snap_hold(topo_hdl, NULL, &e);
	if (e != 0) {
		log_error(log, "failed to create topo snapshot",
		    LOG_T_INT32, "err", e,
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
		umem_free(cfg, sizeof (*cfg));
		return (false);
	}

	wp = topo_walk_init(topo_hdl, FM_FMRI_SCHEME_HC, topo_cb, cfg, &e);
	if (wp == NULL) {
		log_error(log, "failed to start topo walk",
		    LOG_T_INT, "err",
		    LOG_T_STRING, "errmsg", topo_strerror(e),
		    LOG_T_END);
		return (false);
	}

	while ((e = topo_walk_step(wp, TOPO_WALK_CHILD)) == TOPO_WALK_NEXT)
		;

	if (e == TOPO_WALK_ERR) {
		log_error(log, "topo walk failed", LOG_T_END);
		topo_walk_fini(wp);
		return (false);
	}

	topo_walk_fini(wp);
	topo_snap_release(topo_hdl);

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
config_get_hostname(log_t *log, lldp_config_t *cfg, scf_propertygroup_t *pg)
{
	if (!config_get_prop(log, pg, CONFIG_SYSNAME, scf_val))
		return;

	if (scf_value_is_type(scf_val, SCF_TYPE_HOST) != SCF_SUCCESS) {
		/* TODO: errmsg */
		scf_value_reset(scf_val);
		return;
	}

	ssize_t len = scf_value_get_ustring(scf_val, NULL, 0);

	if (len == 0) {
		/* TODO: msg */
		scf_value_reset(scf_val);
		return;
	}

	char *name = calloc(1, len + 1);

	if (name == NULL) {
		/* TODO: msg */
		scf_value_reset(scf_val);
		return;
	}

	free(cfg->lcfg_sysname);
	cfg->lcfg_sysname = name;
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
config_get_sysdesc(log_t *log, lldp_config_t *cfg, scf_propertygroup_t *pg)
{
	if (!config_get_prop(log, pg, CONFIG_SYSDESC, scf_val))
		return;

	if (scf_value_is_type(scf_val, SCF_TYPE_USTRING) != SCF_SUCCESS) {
		/* TODO: errmsg */
		scf_value_reset(scf_val);
		return;
	}

	ssize_t len = scf_value_get_ustring(scf_val, NULL, 0);

	if (len == 0) {
		/* TODO: msg */
		scf_value_reset(scf_val);
		return;
	}

	char *desc = calloc(1, len + 1);

	if (desc == NULL) {
		/* TODO: msg */
		scf_value_reset(scf_val);
		return;
	}

	free(cfg->lcfg_sysdesc);
	cfg->lcfg_sysdesc = desc;
}

static void
config_get_def_syscap(lldp_config_t *cfg)
{
	cfg->lcfg_syscap = LLDP_CAP_ROUTER | LLDP_CAP_STATION;

	/* TODO: Check if IP forwarding is enabled */
	cfg->lcfg_encap = LLDP_CAP_STATION;
}

static void
config_get_def_mgmtaddr(lldp_config_t *cfg)
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
		for (uint_t i = 0; i < cfg->lcfg_mgmt_if[i]; i++)
			free(cfg->lcfg_mgmt_if[i]);
		free(cfg->lcfg_mgmt_if);
	}
	umem_free(cfg, sizeof (*cfg));
}

scf_error_t
config_get_pg(log_t *log, const char *inst, const char *name,
    scf_propertygroup_t *pg)
{
	if (scf_service_get_instance(scf_svc, name, scf_inst) == 0) {
		return (scf_error());
	}

	if (scf_instance_get_snapshot(scf_inst, "running", scf_snap) == 0) {
		return (scf_error());
	}

	if (scf_instance_get_pg_composed(inst, scf_inst, name, pg) != 0)
		return (SCF_ERROR_NONE);

	scf_error_t serr = scf_error();

	/*
	 * For any property group (for now at least), it's not an error
	 * if it doesn't exist, but other errors are probably something
	 * we want to note.
	 */
	if (serr != SCF_ERROR_NOT_FOUND) {
		log_error(log, "failed to read SMF property group",
		    LOG_T_STRING, "pg", name,
		    LOG_T_UINT32, "err", serr,
		    LOG_T_STRING, "errmsg", scf_strerror(serr),
		    LOG_T_END);
	}

	return (serr);
}

bool
config_get_prop(log_t *log, const scf_propertygroup_t *pg, const char *name,
    scf_value_t *val)
{
	const char *errmsg = NULL;
	scf_error_t serr;
	ssize_t lim;

	if (scf_pg_get_property(pg, name, prop) != 0) {
		serr = scf_error();

		if (serr == SCF_ERROR_NOT_FOUND)
			return (false);

		errmsg = "failed to read SMF property";
		goto fail;
	}

	if (scf_property_get_value(prop, val) == 0)
		return (true);

	serr = scf_error();
	if (serr == SCF_ERROR_NOT_SET)
		return (false);

	errmsg = "failed to read SMF property value";

fail:
	lim = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	VERIFY3S(lim, >, 0);

	char buf[lim];

	(void) scf_pg_get_name(pg, buf, lim);

	log_error(log, errmsg,
	    LOG_T_STRING, "pg", buf,
	    LOG_T_STRING, "property", name,
	    LOG_T_UINT32, "err", serr,
	    LOG_T_STRING, "errmsg", scf_strerror(serr),
	    LOG_T_END);

	return (false);
}

static void
set_chassis_id(lldp_chassis_t *c, lldp_chassis_type_t type,
    const uint8_t *val, const uint8_t len)
{
	c->llc_type = type;
	(void) memcpy(c->llc_id, val, len);

	/* For easy of observability, make sure any unused space is NUL */
	if (len < sizeof (c->llc_id)) {
		(void) memset(c->llc_id + len, '\0', sizeof (c->llc_id) - len);
	}
}
