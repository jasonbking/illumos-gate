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

#ifndef _CONFIG_H
#define	_CONFIG_H

#include <stdbool.h>
#include <synch.h>
#include <libscf.h>
#include <liblldp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct agent;
struct log;

extern lldp_config_t *lldp_config;
extern mutex_t lldp_config_lock;

extern char		*my_fmri;

extern scf_handle_t		*rep_handle;
extern scf_service_t		*scf_svc;
extern scf_instance_t		*scf_inst;
extern scf_snapshot_t		*scf_snap;
extern scf_propertygroup_t	*scf_pg;
extern scf_property_t		*scf_prop;
extern scf_value_t		*scf_val;

void config_init(void);
bool config_read(void);
void config_agent_init(struct agent *);
bool config_agent_read(struct agent *);


bool config_get_pg(struct log *, const scf_instance_t *, const char *,
    scf_propertygroup_t *);
bool config_get_prop(struct log *, const scf_propertygroup_t *, const char *,
    scf_property_t *);
bool config_get_value(struct log *, const scf_property_t *, scf_value_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFIG_H */
