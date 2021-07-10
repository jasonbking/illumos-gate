#ifndef _MRS_SAS_H
#define	_MRS_SAS_H

typedef enum mrs_sas_adapter_class {
	MRS_ACLASS_GEN3,
	MRS_ACLASS_VENTURA,
	MRS_ACLASS_AERO,
	MRS_ACLASS_OTHER,
} mrs_sas_adapter_class_t;

/* For now, we keep the same ioctl values as mr_sas */
#define	MRS_SAS_IOCTL_DRIVER	0x12341234
#define	MRS_SAS_IOCTL_FIRMWARE	0x12345678
#define	MRS_SAS_IOCTL_AEN	0x87654321

#define	MRS_SAS_IO_TIMEOUT	(180000)	/* ms - 180s timeout */

/* By default, the firmware programs for 8k of memory */
#define	MRS_SAS_MFI_MIN_MEM	4096
#define	MRS_SAS_MFI_DEF_MEM	8192

#define	MRS_SAS_MAX_SGE_CNT	0x50

typedef enum mrs_sas_init_level {
	MRS_INITLEVEL_BASIC =		(1 << 0),
	MRS_INITLEVEL_PCI_CONFIG =	(1 << 1),
	MRS_INITLEVEL_FM =		(1 << 2),
	MRS_INITLEVEL_REGS =		(1 << 3),
	MRS_INITLEVEL_INTR =		(1 << 4),
	MRS_INITLEVEL_SYNC =		(1 << 5),
	MRS_INITLEVEL_HBA =		(1 << 6),
	MRS_INITLEVEL_NODE =		(1 << 7),
	MRS_INITLEVEL_TASKQ =		(1 << 8),
	MRS_INITLEVEL_AEN =		(1 << 9),
} mrs_sas_init_level_t;

#define	INITLEVEL_SET(_mrs, name)				\
	do {							\
		VERIFY(!((_mrs)->mrs_init_level & (name)));	\
		(_mrs)->mrs_init_level |= (name);		\
	} while (0)

#define	INITLEVEL_CLEAR(_mrs, name)				\
	do {							\
		VERIFY((_mrs)->mrs_init_level & (name));	\
		(_mrs)->mrs_init_level &= ~(name);		\
	} while (0)

#define	INITLEVEL_ACTIVE(_mrs, name)				\
	(((_mrs)->mrs_init_level & (name)) != 0)

#define	MRS_SAS_IOCLEN		16

typedef struct mrs_sas {
	dev_info_t		*mrs_dip;
	uint32_t		mrs_instance;
	char			mrs_iocname;

	mrs_sas_init_level_t	mrs_init_level;
	mrs_sas_adapter_class_t	mrs_class;
	ddi_acc_handle_t	mrs_pci_handle;

	ddi_dma_attr_t		mrs_hba_dma_attr;
	ddi_device_acc_attr_t	mrs_hba_acc_attr;
	caddr_t			mrs_regmap;
	ddi_acc_handle_t	mrs_reghandle;
	uint_t			mrs_max_num_seg;

	ddi_intr_handle_t	*mrs_intr_htable;
	size_t			mrs_intr_htable_size;
	int			mrs_intr_type;
	int			mrs_intr_count;
	uint_t			mrs_intr_pri;
	int			mrs_intr_cap;
	boolean_t		mrs_mask_interrupts;
	int			mrs_fm_capabilities;

	ddi_taskq_t		mrs_taskq;

	/* Tunables */
	uint32_t		mrs_io_timeout;
	uint32_t		mrs_fw_fault_check_delay;
	uint32_t		mrs_block_sync_cache;
	uint32_t		mrs_drv_stream_detection;
	int			mrs_lb_pending_cmds;

	uint32_t		mrs_reset_count;
	uint32_t		mrs_reset_in_progress;

	uint32_t		mrs_max_fw_cmds;
	uint32_t		mrs_max_scsi_cmds;

	scsi_hba_tran_t		*mrs_hba_tran;
	dev_info_t		*mrs_iport;
	scsi_hba_tgtmap_t	*mrs_tgtmap;

	kmutex_t		mrs_mpt_cmd_lock;
	list_t			mrs_mpt_cmd_list;

	kmutex_t		mrs_mfi_cmd_lock;
	list_t			mrs_mfi_cmd_list;

	kmutex_t		mrs_ioctl_count_lock;
	kcondvar_t		mrs_ioctl_count_cv;
	uint_t			mrs_ioctl_count;
} mrs_sas_t;

typedef struct mrs_sas_sge32 {
	uint32_t	mrss_phys_addr;
	uint32_t	mrss_length;
} mrs_sas_sge32_t;

typedef struct mrs_sas_sge64 {
	uint64_t	mrss_phys_addr;
	uint32_t	mrss_length;
} mrs_sas_sge64_t;

typedef union mrs_sas_sgl {
	mrs_sas_sge32_t	mrss_32;
	mrs_sas_sge64_t	mrss_64;
} mrs_sas_sgl_t;

typedef struct mfi_capabilities {
	uint32_t	mc_flags;
	uint32_t	mc_reg;
} mfi_capabilities_t;
#define	_MFI_BIT(x) ((uint32_t)1 << (x))
#define	MFI_SUPPORT_FP_REMOTE_LUN		_MFI_BIT(0)
#define	MFI_SUPPORT_ADDTL_MSIX			_MFI_BIT(1)
#define	MFI_SUPPORT_FASTPATH_WB			_MFI_BIT(2)
#define	MFI_SUPPORT_MAX_255LDS			_MFI_BIT(3)
#define	MFI_SUPPORT_NDRIVE_R1_LB		_MFI_BIT(4)
#define	MFI_SUPPORT_CORE_AFFINITY		_MFI_BIT(5)
#define	MFI_SUPPORT_SECURITY_PROTOCOLS_CMDS 	_MFI_BIT(6)
#define	MFI_SUPPORT_EXT_QDEPTH			_MFI_BIT(7)
#define	MFI_SUPPORT_EXT_IO_SIZE			_MFI_BIT(8)

typedef struct mrs_sas_header __packed {
	uint8_t			mrsh_cmd;
	uint8_t			mrsh_sense_len;
	uint8_t			mrsh_cmd_status;
	uint8_t			mrsh_scsi_status;

	uint8_t			mrsh_target_id;
	uint8_t			mrsh_lun;
	uint8_t			mrsh_cdb_len;
	uint8_t			mrsh_sge_count;

	uint32_t		mrsh_context;
	uint32_t		mrsh_pad_0;

	uint16_t		mrsh_flags;
	uint16_t		mrsh_timeout;
	uint32_t		mrsh_data_xferlen;
} mrs_sas_header_t;

typedef struct mrs_sas_init_frame __packed {
	uint8_t			mrsif_cmd;
	uint8_t			mrsif_reserved_0;
	uint8_t			mrsif_cmd_status;

	uint8_t			mrsif_reserved_1;
	mfi_capabilities_t	mrsif_driver_operations;
	uint32_t		mrsif_context;
	uint32_t		mrsif_pad_0;

	uint16_t		mrsif_flags;
	uint16_t		mrsif_reserved_3;
	uint32_t		mrsif_data_xfer_len;

	uint32_t		mrsif_queue_info_new_phys_addr_lo;
	uint32_t		mrsif_queue_info_new_phys_addr_hi;
	uint32_t		mrsif_queue_info_old_phys_addr_lo;
	uint32_t		mrsif_queue_info_old_phys_addr_hi;
	uint32_t		mrsif_driver_ver_lo;
	uint32_t		mrsif_driver_ver_hi;
	uint32_t		mrsif_reserved_4[4];
} mrs_sas_init_frame_t;

typedef struct mrs_sas_io_frame __packed {
	uint8_t			mrsiof_cmd;
	uint8_t			mrsiof_sense_len;
	uint8_t			mrsiof_cmd_status;
	uint8_t			mrsiof_scsi_status;

	uint8_t			mrsiof_target_id;
	uint8_t			mrsiof_access_byte;
	uint8_t			mrsiof_reserved_0;
	uint8_t			mrsiof_sge_count;

	uint32_t		mrsiof_context;
	uint32_t		mrsiof_pad_0;

	uint16_t		mrsiof_flags;
	uint16_t		mrsiof_timeout;
	uint32_t		mrsiof_lba_count;

	uint32_t		mrsiof_sense_buf_phys_addr_lo;
	uint32_t		mrsiof_sense_buf_phts_addr_hi;

	uint32_t		mrsiof_start_lba_lo;
	uint32_t		mrsiof_start_lba_hi;

	mrs_sas_sgl_t		mrsiof_sgl;
} mrs_sas_io_frame_t;

typedef struct mrs_sas_pthru_frame __packed {
	uint8_t			mrspf_cmd;
	uint8_t			mrspf_sense_len;
	uint8_t			mrspf_cmd_status;
	uint8_t			mrspf_scsi_status;

	uint8_t			mrspf_target_id;
	uint8_t			mrspf_lun;
	uint8_t			mrspf_cdb_len;
	uint8_t			mrspf_sge_count;

	uint32_t		mrspf_context;
	uint32_t		mrspf_pad_0;

	uint16_t		mrspf_flags;
	uint16_t		mrspf_timeout;
	uint32_t		mrspf_data_xfer_len;
	
	uint32_t		mrspf_sense_buf_phys_addr_lo;
	uint32_t		mrspf_sense_buf_phys_addr_hi;

	uint8_t			mrspf_cdb[16];

	mrs_sas_sgl_t		mrspf_sgl;
} mrs_sas_pthru_frame_t;

typedef struct mrs_sas_dcmd_frame __packed {
	uint8_t			mrsdf_cmd;
	uint8_t			mrsdf_reserved_0;
	uint8_t			mrsdf_cmd_status;
	uint8_t			mrsdf_reserved_1[4];
	uint8_t			mrsdf_sge_count;

	uint32_t		mrsdf_context;
	uint32_t		mrsdf_pad_0;

	uint16_t		mrsdf_flags;
	uint16_t		mrsdf_timeout;

	uint32_t		mrsdf_data_xfer_len;
	uint32_t		mrsdf_opcode;

	union {
		uint8_t		mrsmb_b[12];
		uint16_t	mrsmb_s[6];
		uint32_t	mrsmb_w[3];
	} mrsdf_mbox;

	mrs_sas_sgl_t		mrsdf_sgl;
} mrs_sas_dcmd_frame_t;

typedef struct mrs_sas_abort_frame __packed {
	uint8_t			mrsaf_cmd;
	uint8_t			mrsaf_reserved_0;
	uint8_t			mrsaf_cmd_status;

	uint8_t			mrsaf_reserved_1;
	mfi_capabilities_t	mrsaf_driver_operations;
	uint32_t		mrsaf_context;
	uint32_t		mrsaf_pad_0;

	uint16_t		mrsaf_flags;
	uint16_t		mrsaf_reserved_3;
	uint32_t		mrsaf_reserved_4;

	uint32_t		mrsaf_abort_context;
	uint32_t		mrsaf_pad_1;
	uint32_t		mrsaf_abort_mfi_phys_addr_lo;
	uint32_t		mrsaf_abort_mfi_phys_addr_hi;

	uint32_t		mrsaf_reserved_5[6];
} mrs_sas_abort_frame_t;

typedef union mrs_sas_frame {
	mrs_sas_header_t	mrsf_hdr;
	mrs_sas_init_frame_t	mrsf_init;
	mrs_sas_io_frame_t	mrsf_io;
	mrs_sas_pthru_frame_t	mrsf_pthru;
	mrs_sas_dcmd_frame_t	mrsf_dcmd;
	mrs_sas_abort_frame_t	mrsf_abort;
	uint8_t			mrsf_raw[64];
} mrs_sas_frame_t;

typedef struct mrs_sas_ioctl {
	uint16_t		mrsioc_version;
	uint16_t		mrsioc_controller_id;
	uint8_t			mrsioc_signature[8];
	uint32_t		mrsioc_reserved_1;
	uint32_t		mrsioc_control_code;
	uint32_t		mrsioc_reserved_2[2];
	uint8_t			mrsioc_frame[64];
	mrs_sas_sgl_t		mrsioc_sgl_frame;
	uint8_t			mrsioc_sense_buf[MRS_SAS_MAX_SENSE_LENGTH];
	uint8_t			data[1];
} mrs_sas_ioctl_t;

typedef struct mrs_sas_aen {
	uint16_t	mrsa_host_no;
	uint16_t	mrsa_cmd_status;
	uint32_t	mrsa_seq_num;
	uint32_t	mrsa_class_locale_word;
} mrs_sas_aen_t;

int mrs_sas_check_acc_handle(ddi_acc_handle_t);

void mrs_sas_disable_intr(mrs_sas_t *);
void mrs_sas_enable_intr(mrs_sas_t *);

uint32_t mrs_sas_read_reg(mrs_sas_t *, uint32_t);
uint32_t mrs_sas_read_reg_retry(mrs_sas_t *, uint32_t);
void mrs_sas_write_reg(mrs_sas_t *, uint32_t, uint32_t);

void mrs_sas_fm_ereport(mrs_sas_t *, const char *);

int mrs_sas_hba_attach(mrs_sas_t *);
int mrs_sas_hba_detach(mrs_sas_t *);
int mrs_sas_iport_attach(dev_info_t *, ddi_attach_cmd_t);
int mrs_sas_iport_detach(dev_info_t *, ddi_detach_cmd_t);

int mrs_sas_init_fw(mrs_sas_t *);
int mrs_sas_start_mfi_aen(mrs_sas_t *);

int mrs_sas_drv_ioctl(mrs_sas_t *, mrs_sas_ioctl_t *, int);
int mrs_sas_mfi_ioctl(mrs_sas_t *, mrs_sas_ioctl_t *, int);
int mrs_sas_mfi_aen_ioctl(mrs_sas_t *, mrs_sas_aen_t *);

#endif /* _MRS_SAS_H */
