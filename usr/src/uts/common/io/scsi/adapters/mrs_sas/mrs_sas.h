#ifndef _MRS_SAS_H
#define	_MRS_SAS_H

#define	MRS_SAS_MAX_SGE_CNT	0x50

typedef struct mrs_sas {
	dev_info_t	*mrs_dip;
	uint32_t	mrs_instance;
} mrs_sas_t;

#endif /* _MRS_SAS_H */
