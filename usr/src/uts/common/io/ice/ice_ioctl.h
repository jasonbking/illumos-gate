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
 * Copyright 2026 RackTop Systems, Inc.
 */

#ifndef	_ICE_IOCTL_H
#define	_ICE_IOCTL_H

/*
 * Private ioctls for the ice driver,
 * mc_ioctl (M_IOCTL) path -- see ice_m_ioctl() in ice_gld.c. These are
 * modeled on the sfxge driver's SFXGE_*_IOC ioctls (see sfxge_ioc.h and
 * sfxge_ioctl()).
 *
 * These allow configuring the internal firmware logging subsystem (which
 * modules log at which verbosity, and whether messages are delivered over
 * the AdminQ) and reading firmware/hardware internal debug data ("FW debug
 * dump").
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	ICE_IOC	(('I' << 24) | ('C' << 16) | ('E' << 8))

/*
 * Get/Set the FW logging configuration for a single facility (module).
 */
#define	ICE_IOC_FWLOG_GET_CFG	(ICE_IOC | 0x01)
#define	ICE_IOC_FWLOG_SET_CFG	(ICE_IOC | 0x02)

typedef struct ice_ioc_fwlog_cfg {
	uint32_t	ifc_facility;	/* ICE_FWLOG_FACILITY_* */
	uint32_t	ifc_level;	/* ICE_FWLOG_LEVEL_* */
	uint32_t	ifc_arq_ena;	/* boolean: deliver over ARQ */
} ice_ioc_fwlog_cfg_t;

/*
 * Facility (FW module) identifiers, mirroring ice_cq_fw_log_id_t in
 * ice_controlq.h. ICE_FWLOG_FACILITY_ALL applies ifc_level to every
 * facility in a single call.
 */
#define	ICE_FWLOG_FACILITY_GENERAL		0
#define	ICE_FWLOG_FACILITY_CTRL			1
#define	ICE_FWLOG_FACILITY_LINK			2
#define	ICE_FWLOG_FACILITY_LINK_TOPO		3
#define	ICE_FWLOG_FACILITY_DNL			4
#define	ICE_FWLOG_FACILITY_I2C			5
#define	ICE_FWLOG_FACILITY_SDP			6
#define	ICE_FWLOG_FACILITY_MDIO			7
#define	ICE_FWLOG_FACILITY_ADMINQ		8
#define	ICE_FWLOG_FACILITY_HDMA			9
#define	ICE_FWLOG_FACILITY_LLDP			10
#define	ICE_FWLOG_FACILITY_DCBX			11
#define	ICE_FWLOG_FACILITY_DCB			12
#define	ICE_FWLOG_FACILITY_XLR			13
#define	ICE_FWLOG_FACILITY_NVM			14
#define	ICE_FWLOG_FACILITY_AUTH			15
#define	ICE_FWLOG_FACILITY_VPD			16
#define	ICE_FWLOG_FACILITY_IOSF			17
#define	ICE_FWLOG_FACILITY_PARSER		18
#define	ICE_FWLOG_FACILITY_SW			19
#define	ICE_FWLOG_FACILITY_SCHEDULER		20
#define	ICE_FWLOG_FACILITY_TXQ			21
#define	ICE_FWLOG_FACILITY_RSVD			22
#define	ICE_FWLOG_FACILITY_POST			23
#define	ICE_FWLOG_FACILITY_WATCHDOG		24
#define	ICE_FWLOG_FACILITY_TASK_DISPATCH	25
#define	ICE_FWLOG_FACILITY_MNG			26
#define	ICE_FWLOG_FACILITY_SYNCE		27
#define	ICE_FWLOG_FACILITY_HEALTH		28
#define	ICE_FWLOG_FACILITY_TSDRV		29
#define	ICE_FWLOG_FACILITY_PFREG		30
#define	ICE_FWLOG_FACILITY_MDLVER		31
#define	ICE_FWLOG_FACILITY_ALL			0xfffffffeu

/*
 * FW logging verbosity levels.
 */
#define	ICE_FWLOG_LEVEL_NONE	0
#define	ICE_FWLOG_LEVEL_ERROR	1
#define	ICE_FWLOG_LEVEL_WARNING	2
#define	ICE_FWLOG_LEVEL_NORMAL	3
#define	ICE_FWLOG_LEVEL_VERBOSE	4

/*
 * Read up to ICE_FWDUMP_MAX_BUF bytes of opaque internal FW/HW debug data
 * for a single cluster/table/offset. This is a thin pass-through of a
 * single "Debug Dump Internal Data" AQ command (see
 * ice_cmd_debug_dump() in ice_controlq.c); the caller is responsible for
 * iterating using the returned ifd_next_* fields until the firmware
 * indicates there is no more data (typically signaled by
 * ifd_next_table/ifd_next_offset being 0xffff/0xffffffff, though the exact
 * termination convention is FW/cluster dependent -- see the FreeBSD ice
 * driver's ice_fw_debug_dump_print_cluster() for a reference
 * implementation of the full iteration logic).
 */
#define	ICE_IOC_FWDUMP		(ICE_IOC | 0x03)

#define	ICE_FWDUMP_MAX_BUF	4096

typedef struct ice_ioc_fwdump {
	uint32_t	ifd_cluster_id;		/* in: cluster to read */
	uint32_t	ifd_table_id;		/* in: table within cluster */
	uint32_t	ifd_offset;		/* in: start index/offset */
	uint32_t	ifd_next_cluster;	/* out */
	uint32_t	ifd_next_table;		/* out */
	uint32_t	ifd_next_offset;	/* out */
	uint32_t	ifd_buflen;		/* inout */
	uint8_t		ifd_buf[ICE_FWDUMP_MAX_BUF];
} ice_ioc_fwdump_t;

#define	ICE_IOC_RESET		(ICE_IOC | 0x04)

/* Only our PF */
#define	ICE_RESET_REQ_PFR	0
/* All PF and ports */
#define	ICE_RESET_REQ_CORER	1
/* All PF and ports */
#define	ICE_RESET_REQ_GLOBR	2

typedef struct ice_ioc_reset {
	uint32_t	ir_type;	/* in: ICE_RESET_REQ_* */
} ice_ioc_reset_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _ICE_IOCTL_H */
