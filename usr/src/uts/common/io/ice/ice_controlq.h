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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

#ifndef _ICE_ADMINQ_H
#define	_ICE_ADMINQ_H

/*
 * This header file describes everything required to drive the ice
 * control queue.  The control queue is the means by which software makes
 * requests to firmware.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These are the opcodes that define valid commands. These are a subset of valid
 * opcodes. Not all codes may be listed here and not all of the codes listed
 * here are necessarily wired up.
 */
typedef enum ice_cq_opcode {
	/*
	 * General Commands
	 */
	ICE_CQ_OP_GET_VER = 0x1,
	ICE_CQ_OP_DRIVER_VERSION = 0x2,
	ICE_CQ_OP_QUEUE_SHUTDOWN = 0x3,
	ICE_CQ_OP_SET_PF_CONTEXT = 0x4,
	ICE_CQ_OP_GET_AQ_ERROR = 0x5,
	ICE_CQ_OP_REQUEST_RESOURCE = 0x8,
	ICE_CQ_OP_RELEASE_RESOURCE = 0x9,
	ICE_CQ_OP_DISCOVER_FUNCTION_CAPS = 0xA,
	ICE_CQ_OP_DISCOVER_DEVICE_CAPS = 0xB,
	ICE_CQ_OP_VMVF_RESET = 0xC31,
	/*
	 * MAC address
	 */
	ICE_CQ_OP_MANAGE_MAC_READ = 0x107,
	/*
	 * Receive Queue
	 */
	ICE_CQ_OP_CLEAR_PXE = 0x110,
	/*
	 * Switch configuration
	 */
	ICE_CQ_OP_GET_SWITCH_CONFIG = 0x200,
	ICE_CQ_OP_ALLOCATE_RESOURCE = 0x208,
	ICE_CQ_OP_FREE_RESOURCE = 0x209,
	/*
	 * Switch commands (needed for promisc/addmac/remmac)
	 */
	ICE_CQ_OP_ADD_SW_RULES = 0x2a0,
	ICE_CQ_OP_UPDATE_SW_RULES = 0x2a1,
	ICE_CQ_OP_REMOVE_SW_RULES = 0x2a2,
	ICE_CQ_OP_GET_SW_RULES = 0x2a3,
	ICE_CQ_OP_CLEAR_PF_CFG = 0x2a4,
	/*
	 * VSI commands
	 */
	ICE_CQ_OP_ADD_VSI = 0x0210,
	ICE_CQ_OP_UPDATE_VSI = 0x0211,
	ICE_CQ_OP_GET_VSI = 0x0212,
	ICE_CQ_OP_FREE_VSI = 0x0213,
	/*
	 * Binary Classifier Population
	 */
	ICE_CQ_OP_CLEAR_PF_CONFIGURATION = 0x2a4,
	/*
	 * TX Scheduler Information
	 */
	ICE_CQ_OP_QUERY_DEFAULT_SCHEDULER = 0x400,
	ICE_CQ_OP_ADD_SCHED_ELEMENTS = 0x401,
	ICE_CQ_OP_DELETE_SCHED_ELEMENTS = 0x40f,
	ICE_CQ_OP_QUERY_SCHED_RES_ALLOC = 0x412,
	/*
	 * Link Configuration
	 */
	ICE_CQ_OP_SET_PHY_CONFIG = 0x601,
	ICE_CQ_OP_SET_MAC_CONFIG = 0x603,
	ICE_CQ_OP_SETUP_LINK = 0x605,
	ICE_CQ_OP_GET_PHY_ABILITIES = 0x600,
	ICE_CQ_OP_GET_LINK_STATUS = 0x607,
	ICE_CQ_OP_SET_EVENT_MASK = 0x613,
	/*
	 * LED commands
	 */
	ICE_CQ_OP_SET_PORT_ID_LED = 0x6e9,
	/*
	 * SFF (SFP/QSFP) module commands
	 */
	ICE_CQ_OP_SFF_EEPROM = 0x6ee,
	/*
	 * Sensors
	 */
	ICE_CQ_OP_GET_SENSOR_READING = 0x632,
	/*
	 * NVM commands
	 */
	ICE_CQ_OP_NVM_READ = 0x701,
	ICE_CQ_OP_NVM_ERASE = 0x702,
	ICE_CQ_OP_NVM_WRITE = 0x703,
	ICE_CQ_OP_NVM_CONFIG_READ = 0x704,
	ICE_CQ_OP_NVM_CONFIG_WRITE = 0x705,
	ICE_CQ_OP_NVM_CHECKSUM = 0x706,
	ICE_CQ_OP_NVM_WRITE_ACTIVATE = 0x707,
	/*
	 * RSS Commands
	 */
	ICE_CQ_OP_SET_RSS_KEY = 0xB02,
	ICE_CQ_OP_SET_RSS_LUT = 0xB03,
	/*
	 * Transmit Queue Commands
	 */
	ICE_CQ_OP_ADD_TXQ = 0xC30,
	ICE_CQ_OP_DISABLE_FLOW = 0xC31,
	ICE_CQ_OP_MOVE_TXQ = 0xC32,
	ICE_CQ_OP_ADD_RDMA_TQSET = 0xC33,
	ICE_CQ_OP_MOVE_RDMA_TQSET = 0xC34,
	/*
	 * Package Commands
	 */
	ICE_CQ_OP_DOWNLOAD_PKG = 0xC40,
	ICE_CQ_OP_UPDATE_PKG = 0xC42,
	ICE_CQ_OP_GET_PKG_INFO = 0xC43,
	/*
	 * Debug Dump Internal Data
	 */
	ICE_CQ_OP_DEBUG_DUMP_INTERNALS = 0xFF08,
	/*
	 * FW Health Status
	 */
	ICE_CQ_OP_SET_HEALTH_STATUS_CONFIG = 0xFF20,
	ICE_CQ_OP_GET_HEALTH_STATUS = 0xFF22,
	/*
	 * FW Logging
	 */
	ICE_CQ_OP_FW_LOGS_CONFIG = 0xFF30,
	ICE_CQ_OP_FW_LOGS_REGISTER = 0xFF31,
	ICE_CQ_OP_FW_LOGS_EVENT = 0xFF33,

} ice_cq_opcode_t;

/*
 * Error codes that are defined to be returned by the hardware.
 */
typedef enum ice_cq_errno {
	ICE_CQ_SUCCESS		= 0,
	ICE_CQ_EPERM		= 1,
	ICE_CQ_ENOENT		= 2,
	ICE_CQ_ESRCH		= 3,
	ICE_CQ_EINTR		= 4,
	ICE_CQ_EIO		= 5,
	ICE_CQ_ENXIO		= 6,
	ICE_CQ_E2BIG		= 7,
	ICE_CQ_EAGAIN		= 8,
	ICE_CQ_ENOMEM		= 9,
	ICE_CQ_EACCESS		= 10,
	ICE_CQ_EFAULT		= 11,
	ICE_CQ_EBUSY		= 12,
	ICE_CQ_EEXIST		= 13,
	ICE_CQ_EINVAL		= 14,
	ICE_CQ_ENOTTY		= 15,
	ICE_CQ_ENOSPC		= 16,
	ICE_CQ_ENOSYS		= 17,
	ICE_CQ_ERANGE		= 18,
	ICE_CQ_EFLUSHED		= 19,
	ICE_CQ_BAD_ADDR		= 20,
	ICE_CQ_EMODE		= 21,
	ICE_CQ_EFBIG		= 22,
	ICE_CQ_ESBCOMP		= 23,
	ICE_CQ_RC_ENOSEC	= 24,
	ICE_CQ_RC_EBADSIG	= 25,
	ICE_CQ_RC_ESVN		= 26,
	ICE_CQ_RC_EBADMAN	= 27,
	ICE_CQ_RC_EBADBUF	= 28,
	ICE_CQ_EACCES_BMCU	= 29,
} ice_cq_errno_t;

/*
 * This is the value in bytes that indicate when we have a 'large' indirect
 * buffer. When this is true the 'LB' flag must be set.
 */
#define	ICE_CQ_LARGE_BUF	512

/*
 * This is the largest size of an indirect buffer for the control queue.
 */
#define	ICE_CQ_MAX_BUF		4096

/*
 * Get Version
 * Direct Command
 *
 * Requests the firmware version information. On request, this is all empty.
 */
typedef struct ice_cq_cmd_get_version {
	uint32_t	iccgv_rom_build;
	uint32_t	iccgv_fw_build;
	uint8_t		iccgv_fw_branch;
	uint8_t		iccgv_fw_major;
	uint8_t		iccgv_fw_minor;
	uint8_t		iccgv_fw_patch;
	uint8_t		iccgv_aq_branch;
	uint8_t		iccgv_aq_major;
	uint8_t		iccgv_aq_minor;
	uint8_t		iccgv_aq_patch;
} ice_cq_cmd_get_version_t;

typedef struct ice_cq_cmd_driver_version {
	uint8_t		iccdv_major;
	uint8_t		iccdv_minor;
	uint8_t		iccdv_build;
	uint8_t		iccdv_sub_build;
	uint8_t		iccdv_reserved[3];
	uint32_t	iccdv_data_high;
	uint32_t	iccdv_data_low;
} ice_cq_cmd_driver_version_t;

/*
 * Shutdown Queue
 * Direct Command
 *
 * Sent by software to indicate that the queue is being shut down.
 */
typedef struct ice_cq_cmd_queue_shutdown {
	uint8_t		iccqs_flags;
	uint8_t		iccqs_reserved[15];
} ice_cq_cmd_queue_shutdown_t;

/*
 * This flag, set in iccqs_flags, indicates that the software driver is
 * intending to unload.
 */
#define	ICE_CQ_CMD_QUEUE_SHUTDOWN_UNLOADING	0x01

typedef struct ice_cq_cmd_clear_pxe {
	uint8_t	icccp_flags;
	uint8_t	icccp_reserved[15];
} ice_cq_cmd_clear_pxe_t;

/*
 * This flag is required to be set in the clear pxe command. Unfortunately the
 * datasheet doesn't say why.
 */
#define	ICE_CQ_CLEAR_PXE_FLAG	0x02

/*
 * This structure is shared by both the acquire and release resource admin queue
 * commands.
 */
typedef struct ice_cq_cmd_request_resource {
	uint16_t	iccrr_res_id;
	uint16_t	iccrr_acc_type;
	uint32_t	iccrr_timeout;
	uint32_t	iccrr_res_number;
	uint16_t	iccrr_status;
	uint16_t	iccrr_reserved;
} ice_cq_cmd_request_resource_t;

#define	ICE_CQ_RESOURCE_NVM		0x01
#define	ICE_CQ_RESOURCE_SPD		0x02
#define	ICE_CQ_RESOURCE_CHANGE_LOCK	0x03
#define	ICE_CQ_RESOURCE_GLOBAL_CONFIG	0x04

/*
 * Unlike every other shared resource, a request for the Global Config Lock
 * (ICE_CQ_RESOURCE_GLOBAL_CONFIG) always completes successfully at the
 * generic AQ completion level (i.e. ice_cmd_result() always indicates
 * success): the real disposition of the request is instead reported in the
 * command-specific Status field (iccrr_status) below. See the E810
 * datasheet, "Request Resource Ownership (0x0008)", Table 9-46.
 */
#define	ICE_CQ_GLBL_STAT_SUCCESS	0x0000
#define	ICE_CQ_GLBL_STAT_INPROGRESS	0x0001
#define	ICE_CQ_GLBL_STAT_COMPLETED	0x0002

#define	ICE_CQ_ACCESS_READ	0x01
#define	ICE_CQ_ACCESS_WRITE	0x02

/*
 * Default timeout values that are suggested by the datasheet for various
 * operations.
 */
#define	ICE_CQ_TIMEOUT_NVM_READ		3000
#define	ICE_CQ_TIMEOUT_NVM_WRITE	18000
#define	ICE_CQ_TIMEOUT_CHANGE_LOCK	1000
#define	ICE_CQ_TIMEOUT_GLOBAL_CONFIG	3000


typedef struct ice_cq_cmd_nvm_read {
	uint8_t		iccnr_offset[3];
	uint8_t		iccnr_flags;
	uint16_t	iccnr_module_type;
	uint16_t	iccnr_length;
	uint32_t	iccnr_data_high;
	uint32_t	iccnr_data_low;
} ice_cq_cmd_nvm_read_t;

#define	ICE_CQ_NVM_READ_LAST_COMMAND	0x01
#define	ICE_CQ_NVM_READ_SKIP_SHADOW	0x80

typedef struct ice_cq_cmd_set_mac_cfg {
	uint16_t	iccsmc_mtu;
	uint8_t		iccsmc_pacing_cfg;
	uint8_t		iccsmc_tx_tpri;
	uint16_t	iccsmc_tx_tval;
	uint16_t	iccsmc_fc_thres;
	uint8_t		iccsmc_drop_blocked_pkts;
	uint8_t		iccsmc_rsvd[7];
} ice_cq_cmd_set_mac_cfg_t;
#define	ICE_CQ_SET_MAC_CFG_PACING(r, v)		ice_bitset8(r, 6, 3, v)
#define	ICE_CQ_SET_MAC_CFG_PACING_TYPE(r, v)	ice_bitset8(r, 7, 7, v)
#define	ICE_CQ_SET_MAC_CFG_PACING_DATA		0
#define	ICE_CQ_SET_MAC_CFG_PACING_FIXED		1

typedef struct ice_cq_cmd_manage_mac_read {
	uint16_t	iccmmr_flags;
	uint16_t	iccmmr_rsvd;
	uint8_t		iccmmr_count;
	uint8_t		iccmmr_rsvd1[3];
	uint32_t	iccmmr_data_high;
	uint32_t	iccmmr_data_low;
} ice_cq_cmd_manage_mac_read_t;

#define	ICE_CQ_MANAGE_MAC_READ_BUFSIZE	0x18
#define	ICE_CQ_MANAGE_MAC_READ_LAN_VALID	0x0010
#define	ICE_CQ_MANAGE_MAC_READ_WOL_VALID	0x0080
#define	ICE_CQ_MANAGE_MAC_READ_MC_MAG_EN	0x0100
#define	ICE_CQ_MANAGE_MAC_READ_WOL_PRESERVE	0x0200

typedef struct ice_cq_cmd_get_phy_abilities {
	uint16_t	iccgpa_rsvd;
	uint16_t	iccgpa_param0;
	uint32_t	iccgpa_rsvd1;
	uint32_t	iccgpa_data_high;
	uint32_t	iccgpa_data_low;
} ice_cq_cmd_get_phy_abilities_t;

#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_MODS		0x01
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_WO_MEDIA	0x00
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_MEDIA		0x02
#define	ICE_CQ_GET_PHY_ABILITIES_REPORT_SW		0x04

typedef struct ice_cq_cmd_get_link_status {
	uint16_t	iccgls_rsvd;
	uint16_t	iccgls_flags;
	uint32_t	iccgls_rsvd1;
	uint32_t	iccgls_data_high;
	uint32_t	iccgls_data_low;
} ice_cq_cmd_get_link_status_t;

#define	ICE_CQ_GET_LINK_STATUS_MASK		0x03
#define	ICE_CQ_GET_LINK_STATUS_LSE_NOP		0
#define	ICE_CQ_GET_LINK_STATUS_LSE_ENABLED	1
#define	ICE_CQ_GET_LINK_STATUS_LSE_DISABLE	2
#define	ICE_CQ_GET_LINK_STATUS_LSE_ENABLE	3

typedef struct ice_cq_cmd_set_event_mask {
	uint64_t	iccsem_rsvd;
	uint16_t	iccsem_mask;
	uint8_t		iccsem_rsvd1[6];
} ice_cq_cmd_set_event_mask_t;

#define	ICE_CQ_SET_EVENT_MASK_LINK_UP		0x0002
#define	ICE_CQ_SET_EVENT_MASK_MEDIA_AVAIL	0x0004
#define	ICE_CQ_SET_EVENT_MASK_LINK_FAULT	0x0008
#define	ICE_CQ_SET_EVENT_MASK_PHY_TEMP		0x0010
#define	ICE_CQ_SET_EVENT_MASK_EXCESSIVE_ERRS	0x0020
#define	ICE_CQ_SET_EVENT_MASK_SIGNAL_DETECT	0x0040
#define	ICE_CQ_SET_EVENT_MASK_AUTONEG		0x0080
#define	ICE_CQ_SET_EVENT_MASK_TX_SUSPEND	0x0100
#define	ICE_CQ_SET_EVENT_MASK_TOPO_CONFLICT	0x0200
#define	ICE_CQ_SET_EVENT_MASK_MEDIA_CONFLICT	0x0400

typedef struct ice_cq_cmd_setup_link {
	uint16_t	iccsl_rsvd;
	uint8_t		iccsl_flags;
	uint8_t		icssl_rsvd1[13];
} ice_cq_cmd_setup_link_t;

#define	ICE_CQ_SETUP_LINK_RESTART_LINK	0x02
#define	ICE_CQ_SETUP_LINK_ENABLE_LINK	0x04

typedef struct ice_cq_cmd_set_port_id_led {
	uint8_t		iccspil_lport;
	uint8_t		iccspil_lport_valid;
	uint8_t		iccspil_ident_mode;
	uint8_t		iccspil_rsvd[13];
} ice_cq_cmd_set_port_id_led_t;

#define	ICE_CQ_PORT_ID_LED_LPORT_VALID	(1 << 0)

#define	ICE_CQ_PORT_ID_LED_ORIG	0x00
#define	ICE_CQ_PORT_ID_LED_BLINK	(1 << 0)

typedef struct ice_cq_cmd_sff_eeprom {
	uint8_t		iccse_lport;
	uint8_t		iccse_lport_valid;
	uint16_t	iccse_i2c_bus_addr;
	uint16_t	iccse_i2c_mem_addr;
	uint16_t	iccse_eeprom_page;
	uint32_t	iccse_data_high;
	uint32_t	iccse_data_low;
} ice_cq_cmd_sff_eeprom_t;

#define	ICE_CQ_SFF_EEPROM_I2C_7BIT_MASK	0x7f
#define	ICE_CQ_SFF_EEPROM_IS_WRITE		(1 << 15)
#define	ICE_CQ_SFF_EEPROM_MAX_LEN		16

typedef struct ice_cq_cmd_get_switch_config {
	uint16_t	iccgsc_flags;
	uint16_t	iccgsc_next_elt;
	uint16_t	iccgsc_nelts;
	uint16_t	iccgsc_rsvd;
	uint32_t	iccgsc_data_high;
	uint32_t	iccgsc_data_low;
} ice_cq_cmd_get_switch_config_t;

/*
 * Maximum buffer size allowed for the Get Switch Config command.
 */
#define	ICE_CQ_GET_SWITCH_CONFIG_BUF_MAX	2048

typedef struct ice_cq_cmd_add_vsi {
	uint16_t	iccav_vsi;
	uint8_t		iccav_rsvd[2];
	uint8_t		iccav_vfid;
	uint8_t		iccav_rsvd1;
	uint16_t	iccav_type;
	uint32_t	iccav_data_high;
	uint32_t	iccav_data_low;
} ice_cq_cmd_add_vsi_t;
CTASSERT(sizeof (ice_cq_cmd_add_vsi_t) == 16);

/*
 * The ADD VSI reply structure is different enough from the input one that it's
 * worth having a separate struct definition for.
 */
typedef struct ice_cq_cmd_add_vsi_reply {
	uint16_t	iccavr_vsi;
	uint16_t	iccavr_ext_status;
	uint16_t	iccavr_vsi_alloc;
	uint16_t	iccavr_vsi_unalloc;
	uint32_t	iccavr_data_high;
	uint32_t	iccavr_data_low;
} ice_cq_cmd_add_vsi_reply_t;
CTASSERT(sizeof (ice_cq_cmd_add_vsi_reply_t) == 16);

typedef struct ice_cq_cmd_free_vsi {
	uint16_t	iccfv_vsi;
	uint16_t	iccfv_flags;
	uint8_t		iccfv_rsvd[12];
} ice_cq_cmd_free_vsi_t;

#define	ICE_CQ_VSI_VALID	(1 << 15)
#define	ICE_CQ_VSI_MASK		0x02ff

#define	ICE_CQ_VSI_TYPE_VF	0x00
#define	ICE_CQ_VSI_TYPE_VMDQ2	0x01
#define	ICE_CQ_VSI_TYPE_PF	0x02
#define	ICE_CQ_VSI_TYPE_EMP_MNG	0x03

#define	ICE_CQ_VSI_KEEP_ALLOC	(1 << 0)

typedef struct ice_cq_cmd_set_rss_key {
	uint16_t	iccsrk_vsi_id;
	uint8_t		iccsrk_rsvd[6];
	uint32_t	iccsrk_data_high;
	uint32_t	iccsrk_data_low;
} ice_cq_cmd_set_rss_key_t;

typedef struct ice_cq_cmd_set_rss_lut {
	uint16_t	iccsrl_vsi_id;
	uint16_t	iccsrl_flags;
	uint32_t	iccsrl_rsvd;
	uint32_t	iccsrl_data_high;
	uint32_t	iccsrl_data_low;
} ice_cq_cmd_set_rss_lut_t;

#define	ICE_CQ_RSS_LUT_TYPE_VSI		0x00
#define	ICE_CQ_RSS_LUT_TYPE_PF		0x01
#define	ICE_CQ_RSS_LUT_TYPE_GLOBAL	0x02
#define	ICE_CQ_RSS_LUT_SET_TYPE(r, v)	ice_bitset16(r, 1, 0, v)

#define	ICE_CQ_RSS_LUT_SIZE_VSI		0x00
#define	ICE_CQ_RSS_LUT_SIZE_PF_128	0x00
#define	ICE_CQ_RSS_LUT_SIZE_PF_512	0x01
#define	ICE_CQ_RSS_LUT_SIZE_PF_2K	0x02
#define	ICE_CQ_RSS_LUT_SIZE_GLOBAL_128	0x00
#define	ICE_CQ_RSS_LUT_SIZE_GLOBAL_512	0x01
#define	ICE_CQ_RSS_LUT_SET_SIZE(r, v)	ice_bitset16(r, 3, 2, v)
#define	ICE_CQ_RSS_LUT_SET_GLOBAL_INDEX(r, v)	ice_bitset16(r, 7, 4, v)

typedef struct ice_cq_cmd_query_default_scheduler {
	uint8_t		iccqds_rsvd;
	uint8_t		iccqds_nbranches;
	uint16_t	iccqds_rsvd1;
	uint32_t	iccqds_rsvd2;
	uint32_t	iccqds_data_high;
	uint32_t	iccqds_data_low;
} ice_cq_cmd_query_default_scheduler_t;

#define	ICE_CQ_QUERY_DEFAULT_SCHED_BUF_SIZE	4096

typedef struct ice_cq_cmd_add_sched_elements {
	uint16_t	iccase_ngroups;
	uint16_t	iccase_nadded;
	uint8_t		iccase_resv[4];
	uint32_t	iccase_data_high;
	uint32_t	iccase_data_low;
} ice_cq_cmd_add_sched_elements_t;

typedef struct ice_cq_cmd_delete_sched_elements {
	uint16_t	iccdse_ngroups;
	uint16_t	iccdse_ndeleted;
	uint8_t		iccdse_resv[4];
	uint32_t	iccdse_data_high;
	uint32_t	iccdse_data_low;
} ice_cq_cmd_delete_sched_elements_t;

typedef struct ice_cq_cmd_add_txq {
	uint8_t		iccat_ngrp;
	uint8_t		iccat_rsvd[7];
	uint32_t	iccat_data_high;
	uint32_t	iccat_data_low;
} ice_cq_cmd_add_txq_t;

typedef struct ice_cq_cmd_txq_disable_flow {
	uint8_t		icctdf_flags;
	uint8_t		icctdf_nqgrp;
	uint8_t		icctdf_resv;
	uint8_t		icctdf_timeout;
	uint8_t		icctdf_blocked;
	uint8_t		icctdf_resv2[3];
	uint32_t	icctdf_data_high;
	uint32_t	icctdf_data_low;
} ice_cq_cmd_txq_disable_flow_t;
#define	ICE_CQ_DISABLE_FLOW_F_NORESET		(1 << 0)
#define	ICE_CQ_DISABLE_FLOW_F_SUBSEQUENT	(1 << 2)
#define	ICE_CQ_DISABLE_FLOW_F_FLUSH		(1 << 3)
#define	ICE_CQ_DISABLE_FLOW_SET_TIMEOUT(v)	ice_bitset8(0, 7, 2, v)

typedef struct ice_cq_cmd_add_switch_rule {
	uint16_t	iccasr_nrules;
	uint8_t		iccasr_resv[6];
	uint32_t	iccasr_data_high;
	uint32_t	iccasr_data_low;
} ice_cq_cmd_add_switch_rule_t;

typedef struct ice_cq_cmd_download_pkg {
	uint8_t		iccdp_flags;
	uint8_t		iccdp_resv[7];
	uint32_t	iccdp_data_high;
	uint32_t	iccdp_data_low;
} ice_cq_cmd_download_pkg_t;

typedef struct ice_cq_cmd_allocate_resource {
	uint16_t	iccar_nres;
	uint8_t		iccar_resv[6];
	uint32_t	iccar_data_high;
	uint32_t	iccar_data_low;
} ice_cq_cmd_allocate_resource_t;

typedef struct ice_cq_cmd_get_sensor_reading {
	uint8_t		iccgsr_sensor;
	uint8_t		iccgsr_format;
	uint8_t		iccgsr_resv[14];
} ice_cq_cmd_get_sensor_reading_t;

#define	ICE_CQ_SENSOR_INT_TEMP		0x0
#define	ICE_CQ_SENSOR_INT_TEMP_FORMAT	0x0

typedef struct ice_cq_cmd_get_sensor_reading_resp {
	int8_t		iccgsrr_temp;
	uint8_t		iccgsrr_temp_warning_threshold;
	uint8_t		iccgsrr_temp_critical_threshold;
	uint8_t		iccgsrr_temp_fatal_threshold;
	uint8_t		iccgsrr_resv[12];
} ice_cq_cmd_get_sensor_reading_resp_t;

typedef struct ice_cq_cmd_set_health_status_config {
	uint8_t		icchsc_event_source;
	uint8_t		icchsc_resv[15];
} ice_cq_cmd_set_health_status_config_t;

#define	ICE_CQ_HEALTH_STATUS_SET_PF_SPECIFIC	(1 << 0)
#define	ICE_CQ_HEALTH_STATUS_SET_ALL_PF	(1 << 1)
#define	ICE_CQ_HEALTH_STATUS_SET_GLOBAL	(1 << 2)

typedef struct ice_cq_cmd_get_health_status {
	uint16_t	icchs_status_count;
	uint8_t		icchs_resv[6];
	uint32_t	icchs_data_high;
	uint32_t	icchs_data_low;
} ice_cq_cmd_get_health_status_t;

typedef struct ice_cq_health_status_elem {
	uint16_t	icchse_status_code;
	uint16_t	icchse_event_source;
	uint32_t	icchse_data1;
	uint32_t	icchse_data2;
} ice_cq_health_status_elem_t;

#define	ICE_CQ_HEALTH_STATUS_SOURCE_PF		0x1
#define	ICE_CQ_HEALTH_STATUS_SOURCE_PORT	0x2
#define	ICE_CQ_HEALTH_STATUS_SOURCE_GLOBAL	0x3

/*
 * Health status codes, as reported in icchse_status_code above.
 */
#define	ICE_CQ_HEALTH_STATUS_ERR_UNKNOWN_MOD_STRICT		0x101
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_TYPE			0x102
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_QUAL			0x103
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_COMM			0x104
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_CONFLICT			0x105
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_NOT_PRESENT		0x106
#define	ICE_CQ_HEALTH_STATUS_INFO_MOD_UNDERUTILIZED		0x107
#define	ICE_CQ_HEALTH_STATUS_ERR_UNKNOWN_MOD_LENIENT		0x108
#define	ICE_CQ_HEALTH_STATUS_ERR_MOD_DIAGNOSTIC_FEATURE	0x109
#define	ICE_CQ_HEALTH_STATUS_ERR_INVALID_LINK_CFG		0x10B
#define	ICE_CQ_HEALTH_STATUS_ERR_PORT_ACCESS			0x10C
#define	ICE_CQ_HEALTH_STATUS_ERR_PORT_UNREACHABLE		0x10D
#define	ICE_CQ_HEALTH_STATUS_INFO_PORT_SPEED_MOD_LIMITED	0x10F
#define	ICE_CQ_HEALTH_STATUS_ERR_PARALLEL_FAULT		0x110
#define	ICE_CQ_HEALTH_STATUS_INFO_PORT_SPEED_PHY_LIMITED	0x111
#define	ICE_CQ_HEALTH_STATUS_ERR_NETLIST_TOPO			0x112
#define	ICE_CQ_HEALTH_STATUS_ERR_NETLIST			0x113
#define	ICE_CQ_HEALTH_STATUS_ERR_TOPO_CONFLICT			0x114
#define	ICE_CQ_HEALTH_STATUS_ERR_LINK_HW_ACCESS		0x115
#define	ICE_CQ_HEALTH_STATUS_ERR_LINK_RUNTIME			0x116
#define	ICE_CQ_HEALTH_STATUS_ERR_DNL_INIT			0x117
#define	ICE_CQ_HEALTH_STATUS_ERR_PHY_NVM_PROG			0x120
#define	ICE_CQ_HEALTH_STATUS_ERR_PHY_FW_LOAD			0x121
#define	ICE_CQ_HEALTH_STATUS_INFO_RECOVERY			0x500
#define	ICE_CQ_HEALTH_STATUS_ERR_FLASH_ACCESS			0x501
#define	ICE_CQ_HEALTH_STATUS_ERR_NVM_AUTH			0x502
#define	ICE_CQ_HEALTH_STATUS_ERR_OROM_AUTH			0x503
#define	ICE_CQ_HEALTH_STATUS_ERR_DDP_AUTH			0x504
#define	ICE_CQ_HEALTH_STATUS_ERR_NVM_COMPAT			0x505
#define	ICE_CQ_HEALTH_STATUS_ERR_OROM_COMPAT			0x506
#define	ICE_CQ_HEALTH_STATUS_ERR_NVM_SEC_VIOLATION		0x507
#define	ICE_CQ_HEALTH_STATUS_ERR_OROM_SEC_VIOLATION		0x508
#define	ICE_CQ_HEALTH_STATUS_ERR_DCB_MIB			0x509
#define	ICE_CQ_HEALTH_STATUS_ERR_MNG_TIMEOUT			0x50A
#define	ICE_CQ_HEALTH_STATUS_ERR_BMC_RESET			0x50B
#define	ICE_CQ_HEALTH_STATUS_ERR_LAST_MNG_FAIL			0x50C
#define	ICE_CQ_HEALTH_STATUS_ERR_RESOURCE_ALLOC_FAIL		0x50D
#define	ICE_CQ_HEALTH_STATUS_ERR_FW_LOOP			0x1000
#define	ICE_CQ_HEALTH_STATUS_ERR_FW_PFR_FAIL			0x1001
#define	ICE_CQ_HEALTH_STATUS_ERR_LAST_FAIL_AQ			0x1002

/*
 * FW module identifiers, used to select which internal firmware subsystem a
 * given fw logging configuration entry (ice_cq_fw_log_module_t) applies to.
 */
typedef enum ice_cq_fw_log_id {
	ICE_CQ_FW_LOG_ID_GENERAL = 0,
	ICE_CQ_FW_LOG_ID_CTRL,
	ICE_CQ_FW_LOG_ID_LINK,
	ICE_CQ_FW_LOG_ID_LINK_TOPO,
	ICE_CQ_FW_LOG_ID_DNL,
	ICE_CQ_FW_LOG_ID_I2C,
	ICE_CQ_FW_LOG_ID_SDP,
	ICE_CQ_FW_LOG_ID_MDIO,
	ICE_CQ_FW_LOG_ID_ADMINQ,
	ICE_CQ_FW_LOG_ID_HDMA,
	ICE_CQ_FW_LOG_ID_LLDP,
	ICE_CQ_FW_LOG_ID_DCBX,
	ICE_CQ_FW_LOG_ID_DCB,
	ICE_CQ_FW_LOG_ID_XLR,
	ICE_CQ_FW_LOG_ID_NVM,
	ICE_CQ_FW_LOG_ID_AUTH,
	ICE_CQ_FW_LOG_ID_VPD,
	ICE_CQ_FW_LOG_ID_IOSF,
	ICE_CQ_FW_LOG_ID_PARSER,
	ICE_CQ_FW_LOG_ID_SW,
	ICE_CQ_FW_LOG_ID_SCHEDULER,
	ICE_CQ_FW_LOG_ID_TXQ,
	ICE_CQ_FW_LOG_ID_RSVD,
	ICE_CQ_FW_LOG_ID_POST,
	ICE_CQ_FW_LOG_ID_WATCHDOG,
	ICE_CQ_FW_LOG_ID_TASK_DISPATCH,
	ICE_CQ_FW_LOG_ID_MNG,
	ICE_CQ_FW_LOG_ID_SYNCE,
	ICE_CQ_FW_LOG_ID_HEALTH,
	ICE_CQ_FW_LOG_ID_TSDRV,
	ICE_CQ_FW_LOG_ID_PFREG,
	ICE_CQ_FW_LOG_ID_MDLVER,
	ICE_CQ_FW_LOG_ID_MAX
} ice_cq_fw_log_id_t;

/*
 * FW logging verbosity levels, used in ice_cq_fw_log_module_t.iclm_log_level
 * below.
 */
#define	ICE_CQ_FW_LOG_LEVEL_NONE	0
#define	ICE_CQ_FW_LOG_LEVEL_ERROR	1
#define	ICE_CQ_FW_LOG_LEVEL_WARNING	2
#define	ICE_CQ_FW_LOG_LEVEL_NORMAL	3
#define	ICE_CQ_FW_LOG_LEVEL_VERBOSE	4

/*
 * Set/Query FW Logging Configuration (indirect 0xFF30) command structure.
 * The indirect buffer contains an array of ice_cq_fw_log_module_t entries,
 * one per module being configured, icfl_ops.cfg.mdl_cnt entries in total.
 */
typedef struct ice_cq_cmd_fw_log {
	uint8_t		icfl_cmd_flags;
	uint8_t		icfl_rsp_flag;
	uint16_t	icfl_fw_rt_msb;
	union {
		uint32_t	fw_rt_lsb;
		struct {
			uint16_t	log_resolution;
			uint16_t	mdl_cnt;
		} cfg;
	} icfl_ops;
	uint32_t	icfl_addr_high;
	uint32_t	icfl_addr_low;
} ice_cq_cmd_fw_log_t;

#define	ICE_CQ_FW_LOG_CONF_UART_EN	(1 << 0)
#define	ICE_CQ_FW_LOG_CONF_AQ_EN	(1 << 1)
#define	ICE_CQ_FW_LOG_CONF_SET_VALID	(1 << 3)

#define	ICE_CQ_FW_LOG_AQ_REGISTER	(1 << 0)

#define	ICE_CQ_FW_LOG_MIN_RESOLUTION	1
#define	ICE_CQ_FW_LOG_MAX_RESOLUTION	128

typedef struct ice_cq_fw_log_module {
	uint16_t	iclm_module_id;
	uint8_t		iclm_log_level;
	uint8_t		iclm_resv;
} ice_cq_fw_log_module_t;

typedef struct ice_cq_cmd_debug_dump {
	uint16_t	icdd_cluster_id;
	uint16_t	icdd_table_id;
	uint32_t	icdd_idx;
	uint32_t	icdd_addr_high;
	uint32_t	icdd_addr_low;
} ice_cq_cmd_debug_dump_t;

/*
 * This is a generic structure of a command that may be used.
 */
typedef struct ice_cq_cmd_generic {
	uint32_t	iccg_param0;
	uint32_t	iccg_param1;
	uint32_t	iccg_data_high;
	uint32_t	iccg_data_low;
} ice_cq_cmd_generic_t;

typedef union ice_cq_cmd {
	uint8_t icc_raw[16];
	ice_cq_cmd_generic_t icc_generic;
	ice_cq_cmd_get_version_t icc_get_version;
	ice_cq_cmd_driver_version_t icc_driver_version;
	ice_cq_cmd_queue_shutdown_t icc_queue_shutdown;
	ice_cq_cmd_clear_pxe_t icc_clear_pxe;
	ice_cq_cmd_request_resource_t icc_request_resource;
	ice_cq_cmd_nvm_read_t icc_nvm_read;
	ice_cq_cmd_manage_mac_read_t icc_mac_read;
	ice_cq_cmd_get_phy_abilities_t icc_phy_abilities;
	ice_cq_cmd_set_mac_cfg_t icc_set_mac_cfg;
	ice_cq_cmd_get_link_status_t icc_get_link_status;
	ice_cq_cmd_set_event_mask_t icc_set_event_mask;
	ice_cq_cmd_setup_link_t icc_setup_link;
	ice_cq_cmd_set_port_id_led_t icc_set_port_id_led;
	ice_cq_cmd_sff_eeprom_t icc_sff_eeprom;
	ice_cq_cmd_get_switch_config_t icc_get_switch_config;
	ice_cq_cmd_add_sched_elements_t icc_add_sched_elements;
	ice_cq_cmd_delete_sched_elements_t icc_del_sched_elements;
	ice_cq_cmd_add_vsi_t icc_add_vsi;
	ice_cq_cmd_add_vsi_reply_t icc_add_vsi_reply;
	ice_cq_cmd_free_vsi_t icc_free_vsi;
	ice_cq_cmd_set_rss_key_t icc_set_rss_key;
	ice_cq_cmd_set_rss_lut_t icc_set_rss_lut;
	ice_cq_cmd_query_default_scheduler_t icc_query_default_scheduler;
	ice_cq_cmd_add_txq_t icc_add_txq;
	ice_cq_cmd_txq_disable_flow_t icc_txq_disable_flow;
	ice_cq_cmd_add_switch_rule_t icc_add_switch_rule;
	ice_cq_cmd_download_pkg_t icc_download_pkg;
	ice_cq_cmd_allocate_resource_t icc_allocate_resource;
	ice_cq_cmd_get_sensor_reading_t icc_get_sensor_reading;
	ice_cq_cmd_get_sensor_reading_resp_t icc_get_sensor_reading_resp;
	ice_cq_cmd_set_health_status_config_t icc_set_health_status_config;
	ice_cq_cmd_get_health_status_t icc_get_health_status;
	ice_cq_cmd_fw_log_t icc_fw_log;
	ice_cq_cmd_debug_dump_t icc_debug_dump;
} ice_cq_cmd_t;
CTASSERT(sizeof (ice_cq_cmd_t) == 16);

/*
 * This represents a single entry in the control queue.
 */
typedef struct ice_cq_desc {
	uint16_t	icqd_flags;
	uint16_t	icqd_opcode;
	uint16_t	icqd_data_len;
	uint16_t	icqd_id_ret;
	uint32_t	icqd_cookie_high;
	uint32_t	icqd_cookie_low;
	ice_cq_cmd_t	icqd_command;
} ice_cq_desc_t;

/*
 * This flag is set by firmware to indicate that it is done being processed.
 */
#define	ICE_CQ_DESC_FLAGS_DD	0x0001

/*
 * This flag is set by firmware to indicate that the command completed
 * successfully.
 */
#define	ICE_CQ_DESC_FLAGS_CMP	0x0002

/*
 * This flag is set by firmware to indicate that the command had an error.
 */
#define	ICE_CQ_DESC_FLAGS_ERR	0x0004

/*
 * This flag is set by firmware to indicate it came from a Virtual Function.
 */
#define	ICE_CQ_DESC_FLAGS_VFE	0x0008

/*
 * This flag is set by software to indicate that it has a buffer larger than 512
 * bytes (ICE_CQ_LARGE_BUF).
 */
#define	ICE_CQ_DESC_FLAGS_LB	0x0200

/*
 * This flag is set by software to indicate that the firmware needs to read the
 * indirect buffer members of the descriptor, (icqd_data_high, icqd_data_low).
 * This may be used either when we're using those fields for additional data or
 * when we have an actual indirect descriptor.
 */
#define	ICE_CQ_DESC_FLAGS_RD	0x0400

/*
 * This flag is set by software to indicate that this came from a virtual
 * function.
 */
#define	ICE_CQ_DESC_FLAGS_VFC	0x0800

/*
 * This flag is set by software to indicate that there is an indirect buffer
 * present that needs to be read.
 */
#define	ICE_CQ_DESC_FLAGS_BUF	0x1000

/*
 * This flag is set by software to indicate that it'd like an interrupt when the
 * command in question completes.
 */
#define	ICE_CQ_DESC_FLAGS_SI	0x2000

/*
 * This flag is set by software to indicate that it'd like an interrupt when an
 * error occurs. If this is set, and an error occurs, the value in SI doesn't
 * matter.
 */
#define	ICE_CQ_DESC_FLAGS_EI	0x4000

/*
 * This flag is set by software to indicate that the entry should be flushed if
 * an error occurs on the previous command.
 */
#define	ICE_CQ_DESC_FLAGS_FE	0x8000

/*
 * The return code is split into two uint8_t values. The lower byte is an error
 * constant in the form of an ice_cq_errno_t. However, the upper byte is a
 * private entry that varies based on hardware. The following macros are used to
 * pry these apart.
 */
#define	ICE_CQ_ERR_CODE_MASK		0x00ff
#define	ICE_CQ_ERR_CODE_FW_MASK		0xff00
#define	ICE_CQ_ERR_CODE_FW_SHIFT	8

/*
 * The get package info list command (per 7.11.9.4) requires a 4k buffer
 * for the response.
 */
#define	ICE_CQ_GET_PKG_INFO_BUF_SZ	4096

#ifdef __cplusplus
}
#endif

#endif /* _ICE_ADMINQ_H */
