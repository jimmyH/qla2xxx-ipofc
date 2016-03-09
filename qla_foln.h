/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#ifndef __QLA_FOLN_H
#define	__QLA_FOLN_H

#if defined(CONFIG_SCSI_QLA2XXX_FAILOVER)

#include "exioct.h"
#include "qla_fo.h"
#include "qla_cfg.h"

// Inbound or Outbound tranfer of data
#define QLA2X00_UNKNOWN  0
#define QLA2X00_READ	1
#define QLA2X00_WRITE	2

/*
 * Device configuration table
 *
 * This table provides a library of information about the device
 */
struct cfg_device_info {
	const char *vendor;
	const char *model;
	const int  flags;	/* bit 0 (0x1) -- translate the real
				   WWNN to the common WWNN for the target AND
				   XP_DEVICE */
				/* bit 1 -- MSA 1000  */
				/* bit 2 -- EVA  */
				/* bit 3 -- DISABLE FAILOVER  */
				/* bit 4 -- Adaptec failover */
				/* bit 5 -- EVA AA failover */
				/* bit 6 -- IBM */
				/* bit 7 -- MSA AA failover */
				/* bit 8 -- HDS */
				/* bit 9 -- Incipient */
	const int  notify_type;	/* support the different types: 1 - 4 */
	int	( *fo_combine)(void *,
		 uint16_t, fc_port_t *, uint16_t );
	 /* Devices which support Report Target Port Groups */
        int     (*fo_target_port) (fc_port_t *, fc_lun_t *, int);
	int	( *fo_detect)(void);
	int	( *fo_notify)(void);
	int	( *fo_select)(void);
};

#define VITAL_PRODUCT_DATA_SIZE 128
#define INQ_EVPD_SET	1
#define INQ_DEV_IDEN_PAGE  0x83
#define WWLUN_SIZE	32
/* code set values */
#define  CODE_SET_BINARY	0x01

/* Association field values */
#define  ASSOCIATION_LOGICAL_DEVICE	0x00
#define  ASSOCIATION_TARGET_PORT	0x01
#define  ASSOCIATION_TARGET_DEVICE	0x02

/* Identifier type values */
#define  TYPE_REL_TGT_PORT	0x04
#define  TYPE_TPG_GROUP		0x05

/* Identifier length */
#define  DEFAULT_IDENT_LEN	4

/* Volume Access Control VPD Page */
#define VOL_ACCESS_CTRL_VPD_PAGE	0xc9

/* Volume Preferred Path Priority */
#define	 PREFERRED_PATH_PRIORITY	0x1
#define	 SECONDARY_PATH_PRIORITY	0x2

/* Volume Ownership VPD Page */
#define VOL_OWNERSHIP_VPD_PAGE		0xe0
#define VOL_OWNERSHIP_BIT		BIT_6
#define VOL_OWNERSHIP_BIT_VALID		BIT_7


typedef struct {
	union {
		cmd_a64_entry_t cmd;
		sts_entry_t rsp;
		struct cmd_type_7 cmd24;
		struct sts_entry_24xx rsp24;
	} p;
	uint8_t inq[VITAL_PRODUCT_DATA_SIZE];
} evpd_inq_cmd_rsp_t;

typedef struct {
	union {
		cmd_a64_entry_t cmd;
		sts_entry_t rsp;
		struct cmd_type_7 cmd24;
		struct sts_entry_24xx rsp24;
	} p;
} tur_cmd_rsp_t;

/* We know supports 2 x 2 - 2 target port groups with 2 relative
*  target ports each. */
/* SCSI Report/Set Target Port Groups command and data definitions */
#define SCSIOP_MAINTENANCE_IN       0xA3
#define SCSIOP_MAINTENANCE_OUT      0xA4

#define SCSISA_TARGET_PORT_GROUPS   0x0A

#define TGT_PORT_GRP_COUNT	2
#define	REL_TGT_PORT_GRP_COUNT	2

/* RTPG parameter data format */
typedef struct {
	uint32_t len;
	/* Variable-length descriptors.*/
	uint8_t  tpg_desc_entry[1];
} rtpg_param_data_t;

/* Qlogic RTPG IOCB format */
typedef struct {
	union {
		cmd_a64_entry_t cmd;
		sts_entry_t rsp;
		struct cmd_type_7 cmd24;
		struct sts_entry_24xx rsp24;
	} p;
	rtpg_param_data_t data;
} rtpg_param_data_rsp_t;

typedef struct {
	uint8_t obsolete[2];
	uint8_t rel_port_id[2];
} rel_tport_desc_t;

/* Target Port Groups descriptor format */
typedef struct {
	struct {
		/* indicates the state of corresponding tgt port group */
		uint8_t asym_acc_state : 4;
		uint8_t rsvd_1 : 3;
		uint8_t pref :1;

		uint8_t supp_acc_state : 4;
		uint8_t rsvd_2 : 4;
	} state;
	/* 1st target port group identifier */
	uint8_t tpg_id[2];
	uint8_t rsvd;
	/* indicates reason for the last fail over operation */
	uint8_t status_code;
	uint8_t vendor_unique;
	/* no of ports on this controller */
	uint8_t tgt_port_count;
	/* Variable-length data.*/
	rel_tport_desc_t        rel_tgt_port_entry[1];
} tpg_desc_t;


/* Single port per tgt port grp descriptor */
typedef struct {
	struct {
		/* indicates the state of corresponding tgt port group */
		uint8_t	asym_acc_state : 4;
		uint8_t	rsvd_1 : 3;
		uint8_t	pref :1;

		uint8_t	supp_acc_state : 4;
		uint8_t	rsvd_2 : 4;
	} state;
	/* identifies the controller */
	uint8_t tgt_port_grp[2];
	uint8_t rsvd;
	/* indicates reason for the last fail over operation */
	uint8_t	status_code;
	uint8_t vendor_unique;
	/* no of ports on corresponding controller */
	uint8_t tgt_port_count;
	uint8_t	rel_tgt_port[REL_TGT_PORT_GRP_COUNT][4];
} tgt_port_grp_desc;

/* Single port per tgt port grp descriptor */
typedef struct {
	struct {
		/* indicates the state of corresponding tgt port group */
		uint8_t asym_acc_state : 4;
		uint8_t rsvd_1 : 3;
		uint8_t pref :1;

		uint8_t supp_acc_state : 4;
		uint8_t rsvd_2 : 4;
	} state;
	/* identifies the controller */
	uint8_t tgt_port_grp[2];
	uint8_t rsvd;
	/* indicates reason for the last fail over operation */
	uint8_t status_code;
	uint8_t vendor_unique;
	/* no of ports on corresponding controller */
	uint8_t tgt_port_count;
	/* Single port per controller */
	uint8_t rel_tgt_port[4];
} tgt_port_grp_desc_0;


typedef struct {
	uint32_t len;
	//rename it to descriptor ??
	tgt_port_grp_desc tport_grp[TGT_PORT_GRP_COUNT];
} rpt_tport_grp_data_t;

typedef struct {
	union {
		cmd_a64_entry_t cmd;
		sts_entry_t rsp;
		struct cmd_type_7 cmd24;
		struct sts_entry_24xx rsp24;
	} p;
	rpt_tport_grp_data_t list;
} rpt_tport_grp_rsp_t;

typedef struct {
	/* indicates the state of corresponding tgt port group */
	uint8_t	asym_acc_state : 4;
	uint8_t	rsvd_1 : 4;
	uint8_t	rsvd_2;
	/* identifies the controller */
	uint8_t tgt_port_grp[2];
} set_tgt_port_grp_desc;

typedef struct {
	uint32_t rsvd;
	set_tgt_port_grp_desc descriptor[TGT_PORT_GRP_COUNT];
} set_tport_grp_data_t;

typedef struct {
	union {
		cmd_a64_entry_t cmd;
		sts_entry_t rsp;
		struct cmd_type_7 cmd24;
		struct sts_entry_24xx rsp24;
	} p;
	set_tport_grp_data_t list;
} set_tport_grp_rsp_t;

/*
 * Global Data in qla_fo.c source file.
 */
extern SysFoParams_t qla_fo_params;

/*
 * Global Function Prototypes in qla_fo.c source file.
 */
extern scsi_qla_host_t *qla2x00_get_hba(unsigned long);
extern uint32_t qla2x00_send_fo_notification(fc_lun_t *fclun_p, fc_lun_t *olun_p);
extern void qla2x00_fo_init_params(scsi_qla_host_t *ha);
extern uint8_t qla2x00_fo_enabled(scsi_qla_host_t *ha, int instance);
extern int qla2x00_fo_ioctl(scsi_qla_host_t *, int, EXT_IOCTL *, int);

extern int qla2x00_fo_missing_port_summary(scsi_qla_host_t *,
    EXT_DEVICEDATAENTRY *, void *, uint32_t, uint32_t *, uint32_t *);
extern uint32_t qla2x00_wait_for_tpg_ready(fc_lun_t *);

/*
 * Global Data in qla_cfg.c source file.
 */
extern mp_host_t *mp_hosts_base;
extern int mp_config_required;

/*
 * Global Function Prototypes in qla_cfg.c source file.
 */

extern mp_device_t *qla2x00_find_mp_dev_by_nodename(mp_host_t *, uint8_t *);
extern mp_device_t *qla2x00_find_mp_dev_by_portname(mp_host_t *, uint8_t *,
    uint16_t *);
extern mp_host_t *qla2x00_cfg_find_host(scsi_qla_host_t *);
extern int qla2x00_is_portname_in_device(mp_device_t *, uint8_t *);
extern int qla2x00_cfg_path_discovery(scsi_qla_host_t *);
extern int qla2x00_cfg_event_notify(scsi_qla_host_t *, uint32_t);
extern fc_lun_t *qla2x00_cfg_failover(scsi_qla_host_t *, fc_lun_t *,
    os_tgt_t *, srb_t *);
extern int qla2x00_cfg_get_paths(EXT_IOCTL *, FO_GET_PATHS *, int);
extern int qla2x00_cfg_set_current_path(EXT_IOCTL *, FO_SET_CURRENT_PATH *,
    int);
extern void qla2x00_fo_properties(scsi_qla_host_t *);
extern mp_host_t *qla2x00_add_mp_host(uint8_t *);
extern mp_host_t *qla2x00_alloc_host(scsi_qla_host_t *);
extern uint8_t qla2x00_fo_check(scsi_qla_host_t *ha, srb_t *);
extern mp_path_t *qla2x00_find_path_by_name(mp_host_t *, mp_path_list_t *,
    uint8_t *);

extern int __qla2x00_is_fcport_in_config(scsi_qla_host_t *, fc_port_t *);
extern int qla2x00_cfg_init(scsi_qla_host_t *);
extern void qla2x00_cfg_mem_free(scsi_qla_host_t *);

extern int qla2x00_cfg_remap(scsi_qla_host_t *);
extern void qla2x00_set_device_flags(scsi_qla_host_t *, fc_port_t *);

extern int16_t qla2x00_cfg_lookup_device(unsigned char *);
extern int qla2x00_combine_by_lunid(void *, uint16_t, fc_port_t *, uint16_t);
extern int qla2x00_export_target(void *, uint16_t, fc_port_t *, uint16_t);

extern int qla2x00_test_active_lun(fc_port_t *, fc_lun_t *, uint8_t *);

extern int qla2x00_test_active_port(fc_port_t *);

extern int qla2x00_is_fcport_in_foconfig(scsi_qla_host_t *, fc_port_t *);
extern int qla2x00_get_target_ports(fc_port_t *, fc_lun_t *, int);
extern int qla2x00_get_target_xports(fc_port_t *, fc_lun_t *, int);
extern void qla2x00_cfg_select_route(srb_t *);
extern int qla2x00_cfg_is_lbenable(fc_lun_t *);
extern int qla2x00_del_fclun_from_active_list(mp_lun_t *, fc_lun_t *, srb_t *);
extern int qla2x00_spinup(scsi_qla_host_t *, fc_port_t *, uint16_t );

/*
 * Global Function Prototypes in qla_cfgln.c source file.
 */
extern void qla2x00_cfg_build_path_tree( scsi_qla_host_t *ha);
extern uint8_t qla2x00_update_mp_device(mp_host_t *,
    fc_port_t  *, uint16_t, uint16_t);
extern void qla2x00_cfg_display_devices(int);


/*
 * Global Function Prototypes in qla_foln.c source file.
 */
extern int qla2x00_search_failover_queue(scsi_qla_host_t *, struct scsi_cmnd *);
extern void qla2x00_process_failover_event(scsi_qla_host_t *);
extern int qla2x00_do_fo_check(scsi_qla_host_t *, srb_t *, scsi_qla_host_t *);
extern void qla2xxx_start_all_adapters(scsi_qla_host_t *);
extern void qla2x00_failover_cleanup(srb_t *);

extern int ql2xfailover;
extern int ql2xrecoveryTime;
extern int ql2xfailbackTime;

extern int MaxPathsPerDevice;
extern int MaxRetriesPerPath;
extern int MaxRetriesPerIo;
extern int qlFailoverNotifyType;
extern int ql2xlbType;
extern int ql2xexcludemodel;
extern int ql2xtgtemul;
extern int ql2xautorestore;
extern int ql2xmap2actpath;

extern struct cfg_device_info cfg_device_list[];

#define qla2x00_failover_enabled(ha)				(ql2xfailover)

#else

#define qla2x00_is_fcport_in_foconfig(ha, fcport)		(0)
#define qla2x00_fo_missing_port_summary(ha, e, s, m, c, r)	(0)
/* qla2x00_cfg_init() is declared int but the retval isn't checked.. */
#define qla2x00_cfg_init(ha)					do { } while (0)
#define qla2x00_cfg_mem_free(ha)				do { } while (0)
#define qla2x00_cfg_display_devices()				do { } while (0)
#define qla2x00_process_failover_event(ha)			do { } while (0)
#define qla2xxx_start_all_adapters(ha)				do { } while (0)
#define qla2x00_search_failover_queue(ha, cmd)			(0)
#define qla2x00_do_fo_check(ha, sp, vis_ha)			(0)
#define qla2x00_failover_enabled(ha)				(0)
#endif /* CONFIG_SCSI_QLA2XXX_FAILOVER */

static __inline int
qla2x00_is_fcport_in_config(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	if (qla2x00_failover_enabled(ha))
		return qla2x00_is_fcport_in_foconfig(ha, fcport);
	else if (fcport->flags & FC_PERSISTENT_BOUND)
		return 1;
	return 0;
}


#endif /* __QLA_FOLN_H */
