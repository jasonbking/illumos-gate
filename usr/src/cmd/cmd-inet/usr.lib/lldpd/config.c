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
#include <smbios.h>
#include <synch.h>
#include <libscf.h>
#include <unistd.h>
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

/*
 * We maintain two copies of the configuration. When refreshing/loading the
 * configuration, we update the 'non-active' copy and then switch to it.
 * This way we're never left with a partial configuration -- if we fail
 * to update, we continue to use the existing config.
 */
static lldp_config_t	i_cfg[2];
static uint_t		i_cfg_gen;

lldp_config_t	*lldp_config = &i_cfg[0];
mutex_t		lldp_config_lock = ERRORCHECKMUTEX;

char		*my_fmri;

scf_handle_t		*rep_handle;
scf_service_t		*scf_svc;
scf_instance_t		*scf_inst;
scf_propertygroup_t	*scf_pg;
scf_property_t		*scf_prop;
scf_value_t		*scf_val;

static void set_chassis_id(log_t *, lldp_chassis_t *, const char *);

void
config_init(void)
{
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

	TRACE_RETURN(log);
}

bool
config_read(void)
{
	lldp_config_t	*cfg;
	char		host[MAXHOSTNAMELEN] = { 0 };
	struct utsname	uts = { 0 };
	bool		ret = true;

	TRACE_ENTER(log);

	log_debug(log, "loading configuration", LOG_T_END);

	cfg = &i_cfg[i_cfg_gen ^ 1];

	VERIFY0(gethostname(host, MAXHOSTNAMELEN));

	/* First set to hardwired defaults */
	set_chassis_id(log, &cfg->lcfg_chassis, host);

	if (cfg->lcfg_sysname != NULL)
		free(cfg->lcfg_sysname);
	cfg->lcfg_sysname = xstrdup(host);

	if (uname(&uts) < 0)
		log_fatal_syserr(log, "uname failed", SMF_EXIT_ERR_FATAL);

	if (cfg->lcfg_sysdesc != NULL)
		free(cfg->lcfg_sysdesc);
	cfg->lcfg_sysdesc = xsprintf("%s %s %s %s %s",
	    uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);

	cfg->lcfg_syscap = LLDP_CAP_ROUTER | LLDP_CAP_STATION;

	/* XXX: Check ip forwarding */
	cfg->lcfg_encap = LLDP_CAP_STATION;

	if (cfg->lcfg_mgmt_if != NULL) {
		for (uint_t i = 0; cfg->lcfg_mgmt_if[i] != NULL; i++)
			free(cfg->lcfg_mgmt_if[i]);
		free(cfg->lcfg_mgmt_if);
		cfg->lcfg_mgmt_if = NULL;
	}

	/* Override any settings from SMF */
	if (!config_get_pg(log, scf_inst, CONFIG_PG, scf_pg))
		goto done;

	if (config_get_prop(log, scf_pg, CONFIG_SYSNAME, scf_prop) &&
	    config_get_value(log, scf_prop, scf_val)) {
		if (scf_value_is_type(scf_val, SCF_TYPE_HOST)) {
			ssize_t len;

			len = scf_value_get_ustring(scf_val, NULL, 0);
			if (len > 0) {
				cfg->lcfg_sysname = calloc(1, len + 1);

				if (cfg->lcfg_sysname == NULL)
					nomem();

				(void) scf_value_get_ustring(scf_val,
				    cfg->lcfg_sysname, len + 1);
			} else {
				log_debug(log,
				    "sysname property exists but empty",
				    LOG_T_END);
			}
		} else {
			log_error(log, "sysname property is not SCF_TYPE_HOST",
			    LOG_T_STRING, "type",
			    scf_type_to_string(scf_value_type(scf_val)),
			    LOG_T_END);
		}
	}

	if (config_get_prop(log, scf_pg, CONFIG_SYSDESC, scf_prop) &&
	    config_get_value(log, scf_prop, scf_val)) {
		if (scf_value_is_type(scf_val, SCF_TYPE_USTRING)) {
			ssize_t len;

			len = scf_value_get_ustring(scf_val, NULL, 0);
			if (len > 0) {
				cfg->lcfg_sysdesc = calloc(1, len + 1);
				if (cfg->lcfg_sysdesc == NULL)
					nomem();

				(void) scf_value_get_ustring(scf_val,
				    cfg->lcfg_sysdesc, len + 1);
			} else {
				log_debug(log,
				    "sysdesc property exists but empty",
				    LOG_T_END);
			}
		} else {
			log_error(log,
			    "sysdesc property is not SCF_TYPE_USTRING",
			    LOG_T_STRING, "type",
			    scf_type_to_string(scf_value_type(scf_val)),
			    LOG_T_END);
		}
	}

done:
	mutex_enter(&lldp_config_lock);

	lldp_config = cfg;
	i_cfg_gen ^= 1;

	mutex_exit(&lldp_config_lock);

	TRACE_RETURN(log);
	return (ret);
}

/*
 * Set the LLDP chassis id value using the SMBIOS serial field of
 * the SMB_TYPE_SYSTEM struct. This should match what fmd uses as its
 * chassis id in the hc topology, so it's hopefully consistent.
 */
static bool
chassis_serial_smbios(log_t *l, lldp_chassis_t *chassis)
{
	smbios_hdl_t	*shp = NULL;
	smbios_struct_t	st = { 0 };
	smbios_info_t	info = { 0 };
	size_t		len;
	int		errval;

	shp = smbios_open(NULL, SMB_VERSION, 0, &errval);
	if (shp == NULL) {
		log_warn(l, "failed to load SMBIOS info",
		    LOG_T_INT32, "err", errval,
		    LOG_T_STRING, "errmsg", smbios_errmsg(errval),
		    LOG_T_END);
		return (false);
	}

	if (smbios_truncated(shp)) {
		log_warn(l, "SMBIOS table is truncated", LOG_T_END);
		goto fail;
	}

	if (smbios_lookup_type(shp, SMB_TYPE_SYSTEM, &st) != 0) {
		log_warn(l, "failed to find SMB_TYPE_SYSTEM entry", LOG_T_END);
		goto fail;
	}

	if (smbios_info_common(shp, st.smbstr_id, &info) != 0) {
		log_warn(l, "failed to get SMB_TYPE_SYSTEM common info",
		    LOG_T_END);
		goto fail;
	}

	len = strlen(info.smbi_serial);
	if (len > LLDP_CHASSIS_MAX) {
		log_warn(l, "SMBIOS system serial too long; value will be "
		    "truncated", LOG_T_END);
	}

	/*
	 * There is no chassis id type for a serial number.
	 * LLDP_CHASSIS_COMPONENT seems like the closest analogue, so
	 * we use that.
	 */
	chassis->llc_type = LLDP_CHASSIS_COMPONENT;
	(void) strncpy((char *)chassis->llc_id, info.smbi_serial,
	    LLDP_CHASSIS_MAX);
	chassis->llc_len = len;

	smbios_close(shp);
	return (true);

fail:
	smbios_close(shp);
	return (false);
}

static void
set_chassis_id(log_t *log, lldp_chassis_t *chassis, const char *def)
{
	(void) memset(chassis->llc_id, '\0', LLDP_CHASSIS_MAX);

	if (chassis_serial_smbios(log, chassis))
		return;

	size_t hlen = strlen(def);

	/* Fall back to local assigned for chassis id */
	chassis->llc_type = LLDP_CHASSIS_LOCAL;
	(void) strncpy((char *)chassis->llc_id, def, LLDP_CHASSIS_MAX);
	chassis->llc_len = hlen;
}

bool
config_get_pg(log_t *log, const scf_instance_t *inst, const char *name,
    scf_propertygroup_t *pg)
{
	if (scf_instance_get_pg_composed(inst, NULL, name, pg) == 0)
		return (true);

	uint_t serr = scf_error();

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

	return (false);
}

bool
config_get_prop(log_t *log, const scf_propertygroup_t *pg, const char *name,
    scf_property_t *prop)
{
	if (scf_pg_get_property(pg, name, prop) == 0)
		return (true);

	uint_t serr = scf_error();

	if (serr != SCF_ERROR_NOT_FOUND) {
		ssize_t lim = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);

		VERIFY3S(lim, >, 0);

		char buf[lim];

		(void) scf_pg_get_name(pg, buf, lim);

		log_error(log, "failed to read SMF property",
		    LOG_T_STRING, "pg", buf,
		    LOG_T_STRING, "property", name,
		    LOG_T_UINT32, "err", serr,
		    LOG_T_STRING, "errmsg", scf_strerror(serr),
		    LOG_T_END);
	}

	return (false);
}

bool
config_get_value(log_t *log, const scf_property_t *prop, scf_value_t *val)
{
	if (scf_property_get_value(prop, val) == 0)
		return (true);

	uint_t serr = scf_error();
	ssize_t lim = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);

	VERIFY3S(lim, >, 0);

	char propstr[lim];

	(void) scf_property_get_name(prop, propstr, lim);

	log_error(log, "failed to read SMF property value",
	    LOG_T_STRING, "property", propstr,
	    LOG_T_UINT32, "err", serr,
	    LOG_T_STRING, "errmsg", scf_strerror(serr),
	    LOG_T_END);

	return (false);
}
