/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */

/*
 * QLogic ISP2x00 Multi-path LUN Support
 * Multi-path include file.
 */

#if !defined(_QLA_CFG_H)
#define	_QLA_CFG_H

#if defined(__cplusplus)
extern "C"
{
#endif

/*
 * Failover definitions
 */
#define FAILOVER_TYPE_COUNT		4
#define MP_NOTIFY_RESET_DETECTED	1
#define MP_NOTIFY_PWR_LOSS		2
#define MP_NOTIFY_LOOP_UP		3
#define MP_NOTIFY_LOOP_DOWN		4
#define MP_NOTIFY_BUS_RESET		5
#define FAILOVER_TYPE_ERROR_RETRY	1
#define MAX_NUMBER_PATHS		FO_MAX_PATHS
#define PORT_NAME_SIZE			WWN_SIZE
#define FAILOVER_NOTIFY_STATUS_ERROR	QLA_SUCCESS
#define FAILOVER_NOTIFY_STATUS_SUCCESS  QLA_SUCCESS
#define FAILOVER_NOTIFY_CDB_LENGTH_MAX	FO_NOTIFY_CDB_LENGTH_MAX
#define MAX_TARGETS_PER_DEVICE		SDM_DEF_MAX_TARGETS_PER_DEVICE

/*
 * Limits definitions.
 */
#define MAX_LUNS_PER_DEVICE	MAX_LUNS	/* Maximum # of luns */
#define MAX_MP_DEVICES		MAX_TARGETS	/* Maximum # of virtual devs */
#define MAX_PATHS_PER_DEVICE	64		/* Maximum # of paths */
#define MAX_TPG_PORTS		128		/* Max Ports per Tgt Port Group */
#if !defined(MAX_LUNS)
#define	MAX_LUNS		4096
#endif
#define MAX_HOSTS		MAX_HOST_COUNT

/* Async notification types */
#define NOTIFY_EVENT_LINK_DOWN      1		/* Link went down */
#define NOTIFY_EVENT_LINK_UP        2		/* Link is back up */
#define NOTIFY_EVENT_RESET_DETECTED 3		/* Reset detected */

/* MACROS */
#define qla2x00_is_portname_equal(N1,N2) \
	((memcmp((N1),(N2),WWN_SIZE)==0 ? 1: 0))
#define qla2x00_is_nodename_equal(N1,N2) \
	((memcmp((N1),(N2),WWN_SIZE)==0 ? 1: 0))

/*
 * Per-multipath driver parameters
 */
typedef struct _mp_lun_data {
	uint8_t 	data[MAX_LUNS];
#define LUN_DATA_ENABLED		BIT_7
#define LUN_DATA_PREFERRED_PATH		BIT_6
}
mp_lun_data_t;


#define PATH_INDEX_INVALID		0xff

extern int
qla2x00_get_vol_access_path(fc_port_t *fcport, fc_lun_t *fclun, int modify);
/*
 * Per-device collection of all paths.
 */
typedef struct _mp_path_list {
	struct _mp_path *last;		/* ptrs to end of circular list of paths */
	uint8_t		path_cnt;	/* number of paths */
	uint8_t		visible;	/* visible path */
	uint16_t	reserved1;	/* Memory alignment */
	uint32_t	reserved2;	/* Memory alignment */
	uint8_t		current_path[ MAX_LUNS_PER_DEVICE ]; /* current path for a given lun */
	uint16_t	failover_cnt[ FAILOVER_TYPE_COUNT ];
}
mp_path_list_t;

typedef struct _lu_path {
	struct list_head	list;
	struct list_head	next_active; /* list of active path */
	struct _mp_host		*host;
	uint8_t			hba_instance;
	uint16_t		path_id;	/* path id (index) */
	uint16_t		flags;
#define LPF_TPG_UNKNOWN	 BIT_0
	fc_lun_t		*fclun;	/* fclun for this path */
	/*
	 *	tpg_id[0] : msb
	 *	tpg_id[1] : lsb
	 */
	uint8_t			tpg_id[2]; /* target port group id */
	/*
         *      rel_tport_id[0] : msb
         *      rel_tport_id[1] : lsb
         */
        uint8_t 		rel_tport_id[2];  /* relative target port id */
        uint8_t 		asym_acc_state; /* asymmetric access state */
	uint8_t			portname[WWN_SIZE]; /* portname of this tgt */
}
lu_path_t;
/*
 * Definitions for failover notify SRBs.  These SRBs contain failover notify
 * CDBs to notify a target that a failover has occurred.
 *
 */
typedef struct _failover_notify_srb {
	srb_t		*srb;
	uint16_t	status;
	uint16_t	reserved;
}
failover_notify_srb_t;

#define	WWULN_SIZE		32
typedef struct _mp_lun {
   	struct _mp_lun   	*next;
	struct _mp_device	*dp; 			/* Multipath device */
	struct list_head 	lu_paths;   		/* list of lu_paths */
	struct list_head 	active_list;		/* list of active lu_paths */
    	spinlock_t mplock;
	int			active;
	int			act_cnt;
	struct list_head	ports_list;
	struct list_head 	tport_grps_list;   /* list of target port groups */
	int			number;			/* actual lun number */
	int			load_balance_type; /* load balancing method */
#define	LB_NONE		0	/* All the luns on the first active path */
#define LB_STATIC	1	/* All the luns distributed across all the paths
			    	   on active optimised controller */
#define	LB_LRU		2
#define	LB_LST		3
#define	LB_RR		4
#define	LB_LRU_BYTES	5
	uint16_t		cur_path_id;	/* current path */
	uint16_t		pref_path_id;	/* preferred path */
	uint16_t		config_pref_id;	/* configuration preferred path */
	fc_lun_t		*paths[MAX_PATHS_PER_DEVICE];	/* list of fcluns */
	int			path_cnt;	/* Must be > 1 for fo device  */
	int			siz;		/* Size of wwuln  */
	uint8_t			wwuln[WWULN_SIZE];/* lun id from inquiry page 83. */
	uint8_t			asymm_support;
}
mp_lun_t;

typedef struct _mp_port {
    	struct list_head   list;
	uint8_t		portname[WWN_SIZE];
	uint8_t		path_list[ MAX_HOSTS ]; /* path index for a given HBA */
	scsi_qla_host_t	*hba_list[ MAX_HOSTS ];
	int		cnt;
	int		fo_cnt;
	ulong 	total_blks;	/* blocks transferred on this port */
	 /* page 83 type=4 relative tgt port group identifier.
         * For adaptec its set to 1 for Port A and 2 for Port B on
         * the controller
         *      rel_tport_id[0] : msb
         *      rel_tport_id[1] : lsb
        */
        uint8_t rel_tport_id[2];  /* relative target port id */
        uint8_t flags;
#define MP_NO_REL_TPORT_ID       BIT_0

}
mp_port_t;

/*
 * Describes target port groups.
 */
typedef struct _mp_tport_grp {
        struct list_head list;
        /* page 83 type=5 target port group identifier in big endian format.
         * IBM has groups 0 and 1
         *      tpg_id[0] : msb
         *      tpg_id[1] : lsb
         */

        /* list of mp_ports */
        mp_port_t *ports_list[MAX_TPG_PORTS];
        uint8_t tpg_id[2];
        uint8_t asym_acc_state; /* asymmetric access state */
#define TPG_ACT_OPT     0
#define TPG_ACT_NON_OPT 1
#define TPG_STANDBY     2
#define TPG_UNAVAIL     3
#define TPG_ILLEGAL     f
}
mp_tport_grp_t;


/*
 * Per-device multipath control data.
 */
typedef struct _mp_device {
	mp_path_list_t	*path_list;		/* Path list for device.  */
	int				dev_id;
	int			use_cnt;	/* number of users */
	int			lbtype;
 	struct 	_mp_device	*mpdev;
    	struct _mp_lun   *luns;			/* list of luns */
	uint8_t         nodename[WWN_SIZE];	/* World-wide node name for device. */

	/* World-wide node names. */
	uint8_t         nodenames[MAX_PATHS_PER_DEVICE][WWN_SIZE];
	/* World-wide port names. */
	uint8_t         portnames[MAX_PATHS_PER_DEVICE][WWN_SIZE];
}
mp_device_t;

/*
 * Per-adapter multipath Host
 */
typedef struct _mp_host {
	struct _mp_host	*next;	/* ptr to next host adapter in list */
	scsi_qla_host_t	*ha;	/* ptr to lower-level driver adapter struct */
	int		instance;	/* OS instance number */
	struct list_head *fcports;	/* Port chain for this adapter */
	mp_device_t	*mp_devs[MAX_MP_DEVICES]; /* Multipath devices */

	uint32_t	flags;
#define MP_HOST_FLAG_NEEDS_UPDATE  BIT_0  /* Need to update device data. */
#define MP_HOST_FLAG_FO_ENABLED	   BIT_1  /* Failover enabled for this host */
#define MP_HOST_FLAG_DISABLE	   BIT_2  /* Bypass qla_cfg. */
#define MP_HOST_FLAG_LUN_FO_ENABLED   BIT_3  /* lun Failover enabled */

	uint8_t		nodename[WWN_SIZE];
	uint8_t		portname[WWN_SIZE];
	uint16_t	MaxLunsPerTarget;

	uint16_t	relogin_countdown;
}
mp_host_t;

/*
 * Describes path a single.
 */
typedef struct _mp_path {
	struct _mp_path	*next;			/* next path in list  */
	struct _mp_host	*host;			/* Pointer to adapter */
	fc_port_t	*port;			/* FC port info  */
	uint16_t	id;			/* Path id (index) */
	uint16_t	flags;
	uint8_t		mp_byte;		/* Multipath control byte */
#define MP_MASK_HIDDEN		0x80
#define MP_MASK_UNCONFIGURED	0x40
#define MP_MASK_OVERRIDE	0x10		/* MC_MASK_SEPARATE_TARGETS */
#define MP_MASK_PRIORITY	0x07

	uint8_t		relogin;		/* Need to relogin to port */
	uint8_t		config;			/* User configured path	*/
	uint8_t		reserved[3];
	mp_lun_data_t	lun_data;		/* Lun data information */
	uint8_t		portname[WWN_SIZE];	/* Port name of this target. */
}
mp_path_t;

/*
 * Failover notification requests from host driver.
 */
typedef struct failover_notify_entry {
	struct scsi_address		*os_addr;
}
failover_notify_t;

struct osl_fo_info {
	uint8_t path_cnt;
	uint32_t fo_retry_cnt[MAX_PATHS_PER_DEVICE];
};

#endif /* _QLA_CFG_H */
