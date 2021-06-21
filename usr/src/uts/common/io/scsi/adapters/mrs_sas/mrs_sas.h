#ifndef _MRS_SAS_H
#define	_MRS_SAS_H

typedef enum mrs_sas_adapter_class {
	MRS_ACLASS_GEN3,
	MRS_ACLASS_VENTURA,
	MRS_ACLASS_AERO,
	MRS_ACLASS_OTHER,
} mrs_sas_adapter_class_t;

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

typedef struct mrs_sas {
	dev_info_t		*mrs_dip;
	uint32_t		mrs_instance;

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

	/* Tunables */
	uint32_t		mrs_io_timeout;
	uint32_t		mrs_fw_fault_check_delay;
	uint32_t		mrs_block_sync_cache;
	uint32_t		mrs_drv_stream_detection;
	int			mrs_lb_pending_cmds;

	uint32_t		mrs_reset_count;
	uint32_t		mrs_reset_in_progress;

	scsi_hba_tran_t		*mrs_hba_tran;
	dev_info_t		*mrs_iport;
	scsi_hba_tgtmap_t	*mrs_tgtmap;
} mrs_sas_t;

int mrs_sas_check_acc_handle(ddi_acc_handle_t);

void mrs_sas_disable_intr(mrs_sas_t *);
void mrs_sas_enable_intr(mrs_sas_t *);

uint32_t mrs_sas_read_reg(mrs_sas_t *, uint32_t);
uint32_t mrs_sas_read_reg_retry(mrs_sas_t *, uint32_t);
void mrs_sas_write_reg(mrs_sas_t *, uint32_t, uint32_t);

void mrs_sas_fm_ereport(mrs_sas_t *, const char *);

int mrs_sas_iport_attach(dev_info_t *, ddi_attach_cmd_t);
int mrs_sas_iport_detach(dev_info_t *, ddi_detach_cmd_t);

int mrs_sas_init_fw(mrs_sas_t *);

#endif /* _MRS_SAS_H */
