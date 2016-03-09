/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/blkdev.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>

#include "exioct.h"
#include "qla_foln.h"
#include "qlfoln.h"
#include "inioct.h"

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
#include "qla_32ioctl.h"
#endif

#define QLA_PT_CMD_DRV_TOV		(ql2xioctltimeout + 1) /* drv timeout */
#define QLA_IOCTL_ACCESS_WAIT_TIME	(ql2xioctltimeout + 10) /* wait_q tov */
#define QLA_INITIAL_IOCTLMEM_SIZE	8192
#define QLA_IOCTL_SCRAP_SIZE		16384 /* scrap memory for local use. */

/* ELS related defines */
#define FC_HEADER_LEN		24
#define ELS_RJT_LENGTH		0x08	/* 8  */
#define ELS_RPS_ACC_LENGTH	0x40	/* 64 */
#define ELS_RLS_ACC_LENGTH	0x1C	/* 28 */

/* ELS cmd Reply Codes */
#define ELS_STAT_LS_RJT		0x01
#define ELS_STAT_LS_ACC		0x02

#define IOCTL_INVALID_STATUS    0xffff


struct hba_ioctl {
	/* Ioctl cmd serialization */
	struct semaphore	access_sem;

	/* Passthru cmd/completion */
	struct semaphore	cmpl_sem;
	struct timer_list	cmpl_timer;
	uint8_t		ioctl_tov;
	uint8_t		SCSIPT_InProgress;
	uint8_t		MSIOCB_InProgress;

	os_tgt_t	*ioctl_tq;
	os_lun_t	*ioctl_lq;

	/* AEN queue */
	void		*aen_tracking_queue;/* points to async events buffer */
	uint8_t		aen_q_head;	/* index to the current head of q */
	uint8_t		aen_q_tail;	/* index to the current tail of q */

	/* Misc. */
	uint32_t	flags;
#define	IOCTL_OPEN			BIT_0
#define	IOCTL_AEN_TRACKING_ENABLE	BIT_1
	uint8_t		*scrap_mem;	/* per ha scrap buf for ioctl usage */
	uint32_t	scrap_mem_size; /* total size */
	uint32_t	scrap_mem_used; /* portion used */
};

/*
 * From qla_inioctl.c
 */
extern int qla2x00_read_nvram(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_update_nvram(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_send_loopback(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_read_option_rom(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_update_option_rom(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_get_option_rom_layout(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_get_vpd(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_update_vpd(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_get_sfp_data(scsi_qla_host_t *, EXT_IOCTL *, int);
extern int qla2x00_update_port_param(scsi_qla_host_t *, EXT_IOCTL *, int);

/*
 * Local prototypes
 */
static int qla2x00_find_curr_ha(uint16_t, scsi_qla_host_t **);

static int qla2x00_get_driver_specifics(EXT_IOCTL *, scsi_qla_host_t *);

static int qla2x00_aen_reg(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_aen_get(scsi_qla_host_t *, EXT_IOCTL *, int);

static int qla2x00_query(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_hba_node(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_hba_port(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_disc_port(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_disc_tgt(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_chip(scsi_qla_host_t *, EXT_IOCTL *, int);

static int qla2x00_get_data(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_get_statistics(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_get_fc_statistics(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_get_port_summary(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_get_fcport_summary(scsi_qla_host_t *, EXT_DEVICEDATAENTRY *,
    void *, uint32_t, uint32_t, uint32_t *, uint32_t *);
static int qla2x00_std_missing_port_summary(scsi_qla_host_t *,
    EXT_DEVICEDATAENTRY *, void *, uint32_t, uint32_t *, uint32_t *);
static int qla2x00_query_driver(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_query_fw(scsi_qla_host_t *, EXT_IOCTL *, int);

static int qla2x00_msiocb_passthru(scsi_qla_host_t *, EXT_IOCTL *, int, int);
static int qla2x00_send_els_passthru(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, int);
static int qla2x00_send_fcct(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, int);
static int qla2x00_ioctl_ms_queuecommand(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, EXT_ELS_PT_REQ *);
static int qla2x00_start_ms_cmd(scsi_qla_host_t *, EXT_IOCTL *, srb_t *,
    EXT_ELS_PT_REQ *);

static int qla2x00_wwpn_to_scsiaddr(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_scsi_passthru(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_sc_scsi_passthru(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
static int qla2x00_sc_fc_scsi_passthru(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
static int qla2x00_sc_scsi3_passthru(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
static int qla2x00_ioctl_scsi_queuecommand(scsi_qla_host_t *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, fc_port_t *, fc_lun_t *);

static int qla2x00_send_els_rnid(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_get_rnid_params(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_host_data(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_rnid_params(scsi_qla_host_t *, EXT_IOCTL *, int);

static int qla2x00_get_led_state(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_led_state(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_led_23xx(scsi_qla_host_t *, EXT_BEACON_CONTROL *,
    uint32_t *, uint32_t *);

static int qla2x00_get_led_state(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_led_state(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_set_led_23xx(scsi_qla_host_t *, EXT_BEACON_CONTROL *,
    uint32_t *, uint32_t *);
static int qla2x00_set_led_24xx(scsi_qla_host_t *, EXT_BEACON_CONTROL *,
    uint32_t *, uint32_t *);

static int qla2x00_get_tgt_lun_by_q(scsi_qla_host_t *, EXT_IOCTL *, int);


/* Init/Exit routines */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
static struct class *apidev_class;
#else
static struct class_simple *apidev_class;
#endif
static int apidev_major;

static int
apidev_ioctl(struct inode *inode, struct file *fp, unsigned int cmd,
    unsigned long arg)
{
	return (qla2x00_ioctl(NULL, (int)cmd, (void*)arg));
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,14)
static long
qla2xxx_ioctl32(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rval = -ENOIOCTLCMD;

	lock_kernel();
	rval = apidev_ioctl(file->f_dentry->d_inode, file, cmd, arg);
	unlock_kernel();

	return rval;
}
#endif

static struct file_operations apidev_fops = {
	.owner = THIS_MODULE,
	.ioctl = apidev_ioctl,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,14)
	.compat_ioctl = qla2xxx_ioctl32,
#endif
};

int
qla2x00_ioctl_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	apidev_class = class_create(THIS_MODULE, "qla2xxx");
#else
	apidev_class = class_simple_create(THIS_MODULE, "qla2xxx");
#endif
	if (IS_ERR(apidev_class)) {
		DEBUG(printk("%s(): Unable to sysfs class for qla2xxx.\n",
		    __func__));

		apidev_class = NULL;
		return 1;

	}

	apidev_major = register_chrdev(0, "qla2xxx", &apidev_fops);
	if (apidev_major < 0) {
		DEBUG(printk("%s(): Unable to register CHAR device (%d)\n",
		    __func__, apidev_major));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
		class_destroy(apidev_class);
#else
		class_simple_destroy(apidev_class);
#endif
		apidev_class = NULL;

		return apidev_major;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
	class_simple_device_add(apidev_class, MKDEV(apidev_major, 0), NULL,
	    "qla2xxx");
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
	class_device_create(apidev_class, MKDEV(apidev_major, 0), NULL,
	    "qla2xxx");
#else
	class_device_create(apidev_class, NULL, MKDEV(apidev_major, 0), NULL,
	    "qla2xxx");
#endif

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	apidev_init_32ioctl_reg();
#endif

	return 0;
}

int
qla2x00_ioctl_exit(void)
{
	if (!apidev_class)
		return 1;

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	apidev_cleanup_32ioctl_unreg();
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	class_device_destroy(apidev_class, MKDEV(apidev_major, 0));
#else
	class_simple_device_remove(MKDEV(apidev_major, 0));
#endif

	unregister_chrdev(apidev_major, "qla2xxx");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	class_destroy(apidev_class);
#else
	class_simple_destroy(apidev_class);
#endif

	apidev_class = NULL;

	return 0;
}

void *
Q64BIT_TO_PTR(uint64_t buf_addr, uint16_t addr_mode)
{
#if (defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)) || !defined(CONFIG_64BIT)
	union ql_doublelong {
		struct {
			uint32_t	lsl;
			uint32_t	msl;
		} longs;
		uint64_t	dl;
	};

	union ql_doublelong tmpval;

	tmpval.dl = buf_addr;
/*
#if defined(CONFIG_X86_64)
	if (addr_mode == EXT_DEF_ADDR_MODE_32)
		return((void *)(uint64_t)(tmpval.longs.lsl));
	else
		return((void *)buf_addr);
*/
#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	/* 32bit user - 64bit kernel */
	if (addr_mode == EXT_DEF_ADDR_MODE_32) {
		DEBUG9(printk("%s: got 32bit user address.\n", __func__));
		return((void *)(uint64_t)(tmpval.longs.lsl));
	} else {
		DEBUG9(printk("%s: got 64bit user address.\n", __func__));
		return((void *)buf_addr);
	}
#else
	return((void *)(tmpval.longs.lsl));
#endif
#else
	return((void *)buf_addr);
#endif
}

/*****************************************************************************/

/*
 * qla2x00_ioctl_sleep_done
 *
 * Description:
 *   This is the callback function to wakeup ioctl completion semaphore
 *   for the ioctl request that is waiting.
 *
 * Input:
 *   sem - pointer to the ioctl completion semaphore.
 *
 * Returns:
 */
static void
qla2x00_ioctl_sleep_done(struct semaphore * sem)
{
	DEBUG9(printk("%s: entered.\n", __func__));

	if (sem != NULL) {
		DEBUG9(printk("ioctl_sleep: wake up sem.\n"));
		up(sem);
	}

	DEBUG9(printk("%s: exiting.\n", __func__));
}

/*
 * qla2x00_ioctl_sem_init
 *
 * Description:
 *   Initialize the ioctl timer and semaphore used to wait for passthru
 *   completion.
 *
 * Input:
 *   ha - pointer to scsi_qla_host_t structure used for initialization.
 *
 * Returns:
 *   None.
 */
static void
qla2x00_ioctl_sem_init(scsi_qla_host_t *ha)
{
	init_MUTEX_LOCKED(&ha->ioctl->cmpl_sem);
	init_timer(&(ha->ioctl->cmpl_timer));
	ha->ioctl->cmpl_timer.data = (unsigned long)&ha->ioctl->cmpl_sem;
	ha->ioctl->cmpl_timer.function =
	    (void (*)(unsigned long))qla2x00_ioctl_sleep_done;
}

/*
 * qla2x00_scsi_pt_done
 *
 * Description:
 *   Resets ioctl progress flag and wakes up the ioctl completion semaphore.
 *
 * Input:
 *   pscsi_cmd - pointer to the passthru Scsi cmd structure which has completed.
 *
 * Returns:
 */
static void
qla2x00_scsi_pt_done(struct scsi_cmnd *pscsi_cmd)
{
	struct Scsi_Host *host;
	scsi_qla_host_t  *ha;

	host = pscsi_cmd->device->host;
	ha = (scsi_qla_host_t *) host->hostdata;

	DEBUG9(printk("%s post function called OK\n", __func__));

	/* save detail status for IOCTL reporting */
	ha->ioctl->SCSIPT_InProgress = 0;
	ha->ioctl->ioctl_tov = 0;
	ha->ioctl_err_cmd = NULL;

	up(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s: exiting.\n", __func__));

	return;
}

/*
 * qla2x00_msiocb_done
 *
 * Description:
 *   Resets MSIOCB ioctl progress flag and wakes up the ioctl completion
 *   semaphore.
 *
 * Input:
 *   cmd - pointer to the passthru Scsi cmd structure which has completed.
 *
 * Returns:
 */
static void
qla2x00_msiocb_done(struct scsi_cmnd *pscsi_cmd)
{
	struct Scsi_Host *host;
	scsi_qla_host_t  *ha;

	host = pscsi_cmd->device->host;
	ha = (scsi_qla_host_t *) host->hostdata;

	DEBUG9(printk("%s post function called OK\n", __func__));

	ha->ioctl->MSIOCB_InProgress = 0;
	ha->ioctl->ioctl_tov = 0;

	up(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s: exiting.\n", __func__));
		
	return;
}

/*************************************************************************
 * qla2x00_ioctl
 *
 * Description:
 *   Performs additional ioctl requests not satisfied by the upper levels.
 *
 * Returns:
 *   ret  = 0    Success
 *   ret != 0    Failed; detailed status copied to EXT_IOCTL structure
 *               if possible
 *************************************************************************/
int
qla2x00_ioctl(struct scsi_device *dev, int cmd, void *arg)
{
	int		mode = 0;
	int		tmp_rval = 0;
	int		ret = -EINVAL;

	uint8_t		*temp;
	uint8_t		tempbuf[8];
	uint32_t	i;
	uint32_t	status;

	EXT_IOCTL	*pext;

	scsi_qla_host_t	*ha;


	DEBUG9(printk("%s: entry to command (%x), arg (%p)\n",
	    __func__, cmd, arg));

	/* Catch any non-exioct ioctls */
	if (_IOC_TYPE(cmd) != QLMULTIPATH_MAGIC) {
		return (ret);
	}

	/* Allocate ioctl structure buffer to support multiple concurrent
	 * entries.
	 */
	pext = kmalloc(sizeof(EXT_IOCTL), GFP_KERNEL);
	if (pext == NULL) {
		/* error */
		printk(KERN_WARNING
		    "qla2x00: ERROR in main ioctl buffer allocation.\n");
		return (-ENOMEM);
	}

	/* copy in application layer EXT_IOCTL */
	ret = copy_from_user(pext, arg, sizeof(EXT_IOCTL));
	if (ret) {
		DEBUG9_10(printk("%s: ERROR COPY_FROM_USER "
		    "EXT_IOCTL sturct. cmd=%x arg=%p.\n",
		    __func__, cmd, arg));

		kfree(pext);
		return (ret);
	}

	/* check signature of this ioctl */
	temp = (uint8_t *) &pext->Signature;

	for (i = 0; i < 4; i++, temp++)
		tempbuf[i] = *temp;

	if ((tempbuf[0] == 'Q') && (tempbuf[1] == 'L') &&
	    (tempbuf[2] == 'O') && (tempbuf[3] == 'G'))
		status = 0;
	else
		status = 1;

	if (status != 0) {
		DEBUG9_10(printk("%s: signature did not match. "
		    "cmd=%x arg=%p.\n", __func__, cmd, arg));
		pext->Status = EXT_STATUS_INVALID_PARAM;
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

		kfree(pext);
		return (ret);
	}

	/* check version of this ioctl */
	if (pext->Version > EXT_VERSION) {
		printk(KERN_WARNING
		    "qla2x00: ioctl interface version not supported = %d.\n",
		    pext->Version);

		kfree(pext);
		return (-EINVAL);
	}

	/* check for special cmds used during application's setup time. */
	switch (cmd) {
	case EXT_CC_GET_HBA_CNT:
		DEBUG9(printk("%s: got startioctl command.\n", __func__));

		pext->Instance = num_hosts;
		pext->Status = EXT_STATUS_OK;
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

		kfree(pext);
		return (ret);

	case EXT_CC_SETINSTANCE:
		/* This call is used to return the HBA's host number to
		 * ioctl caller.  All subsequent ioctl commands will put
		 * the host number in HbaSelect field to tell us which
		 * HBA is the destination.
		 */
		if (pext->Instance < num_hosts) {
			if (!(pext->VendorSpecificData &
			    EXT_DEF_USE_HBASELECT)) {
				DEBUG9(printk(
				    "%s: got setinstance cmd w/o HbaSelect.\n",
				    __func__));
				/* Backward compatible code. */
				apiHBAInstance = pext->Instance;
			}

			/*
			 * Return host number via pext->HbaSelect for
			 * specified API instance number.
			 */
			if (qla2x00_find_curr_ha(pext->Instance, &ha) != 0) {
				pext->Status = EXT_STATUS_DEV_NOT_FOUND;
				ret = copy_to_user(arg, pext,
				    sizeof(EXT_IOCTL));
				DEBUG9_10(printk("%s: SETINSTANCE invalid inst "
				    "%d. num_hosts=%d ha=%p ret=%d.\n",
				    __func__, pext->Instance, num_hosts, ha,
				    ret));

				kfree(pext);
				return (ret); /* ioctl completed ok */
			}

			pext->HbaSelect = ha->host_no;
			pext->Status = EXT_STATUS_OK;

			DEBUG9(printk("%s: Matching instance %d to hba "
			    "%ld.\n", __func__, pext->Instance, ha->host_no));
		} else {
			DEBUG9_10(printk("%s: ERROR EXT_SETINSTANCE."
			    " Instance=%d num_hosts=%d ha=%p.\n",
			    __func__, pext->Instance, num_hosts, ha));

			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		}
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));
		kfree(pext);

		DEBUG9(printk("%s: SETINSTANCE exiting. ret=%d.\n",
		    __func__, ret));

		return (ret);

	case EXT_CC_DRIVER_SPECIFIC:
		if (qla2x00_find_curr_ha(pext->HbaSelect, &ha) != 0) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));
		} else {
			ret = qla2x00_get_driver_specifics(pext, ha);
			tmp_rval = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

			if (ret == 0)
				ret = tmp_rval;
		}

		kfree(pext);
		return (ret);

	default:
		break;
	}

	if (!(pext->VendorSpecificData & EXT_DEF_USE_HBASELECT)) {
		/* Backward compatible code. */
		/* Will phase out soon. */

		/* Check for valid apiHBAInstance (set previously by
		 * EXT_SETINSTANCE or default 0)  and set ha context
		 * for this IOCTL.
		 */
		DEBUG9(printk("%s: not using HbaSelect. apiHBAInstance=%d.\n",
		    __func__, apiHBAInstance));
		if (qla2x00_find_curr_ha(apiHBAInstance, &ha) != 0) {

			DEBUG9_10(printk("%s: ERROR matching apiHBAInstance "
			    "%d to an HBA Instance.\n",
			    __func__, apiHBAInstance));

			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

			kfree(pext);
			return (ret);
		}

		DEBUG9(printk("%s: active apiHBAInstance=%d host_no=%ld "
		    "CC=%x SC=%x.\n",
		    __func__, apiHBAInstance, ha->host_no, cmd, pext->SubCode));

	} else {
		/* Use HbaSelect value to get a matching ha instance
		 * for this ioctl command.
		 */
		if (qla2x00_find_curr_ha(pext->HbaSelect, &ha) != 0) {

			DEBUG9_10(printk("%s: ERROR matching pext->HbaSelect "
			    "%d to an HBA Instance.\n",
			    __func__, pext->HbaSelect));

			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

			kfree(pext);
			return (ret);
		}

		DEBUG9(printk("%s: active host_inst=%ld CC=%x SC=%x.\n",
		    __func__, ha->instance, cmd, pext->SubCode));
	}

	/*
	 * Get permission to process ioctl command. Only one will proceed
	 * at a time.
	 */
	if (qla2x00_down_timeout(&ha->ioctl->access_sem,
				QLA_IOCTL_ACCESS_WAIT_TIME * HZ) != 0) {
		/* error timed out */
		DEBUG9_10(printk("%s: ERROR timeout getting ioctl "
		    "access. host no=%d.\n", __func__, pext->HbaSelect));

		pext->Status = EXT_STATUS_BUSY;
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

		kfree(pext);
		return (ret);
	}


	while (test_bit(CFG_ACTIVE, &ha->cfg_flags) || ha->dpc_active) {
		if (signal_pending(current))
			break;   /* get out */

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}

	switch (cmd) { /* switch on EXT IOCTL COMMAND CODE */

	case EXT_CC_QUERY:
		DEBUG9(printk("%s: got query command.\n", __func__));

		ret = qla2x00_query(ha, pext, 0);

		break;

	case EXT_CC_GET_DATA:
		DEBUG9(printk("%s: got get_data command.\n", __func__));

		ret = qla2x00_get_data(ha, pext, 0);

		break;

	case EXT_CC_SEND_SCSI_PASSTHRU:
		DEBUG9(printk("%s: got SCSI passthru cmd.\n", __func__));

		ret = qla2x00_scsi_passthru(ha, pext, mode);

		break;

	case EXT_CC_REG_AEN:
		ret = qla2x00_aen_reg(ha, pext, mode);

		break;

	case EXT_CC_GET_AEN:
		ret = qla2x00_aen_get(ha, pext, mode);

		break;

	case EXT_CC_WWPN_TO_SCSIADDR:
		ret = qla2x00_wwpn_to_scsiaddr(ha, pext, 0);
		break;

	case EXT_CC_SEND_ELS_PASSTHRU:
		if (IS_QLA2100(ha) || IS_QLA2200(ha))
			goto fail;
		/*FALLTHROUGH*/
	case EXT_CC_SEND_FCCT_PASSTHRU:
		ret = qla2x00_msiocb_passthru(ha, pext, cmd, mode);

		break;

	case EXT_CC_SEND_ELS_RNID:
		DEBUG9(printk("%s: got ELS RNID cmd.\n", __func__));

		ret = qla2x00_send_els_rnid(ha, pext, mode);
		break;

	case EXT_CC_SET_DATA:
		ret = qla2x00_set_host_data(ha, pext, mode);
		break;

	case INT_CC_READ_NVRAM:
		ret = qla2x00_read_nvram(ha, pext, mode);
		break;

	case INT_CC_UPDATE_NVRAM:
		ret = qla2x00_update_nvram(ha, pext, mode);
		break;

	case INT_CC_LOOPBACK:
		ret = qla2x00_send_loopback(ha, pext, mode);
		break;

	case INT_CC_READ_OPTION_ROM:
		ret = qla2x00_read_option_rom(ha, pext, mode);
		break;

	case INT_CC_UPDATE_OPTION_ROM:
		ret = qla2x00_update_option_rom(ha, pext, mode);
		break;

	case INT_CC_GET_OPTION_ROM_LAYOUT:
		ret = qla2x00_get_option_rom_layout(ha, pext, mode);
		break;

	case INT_CC_GET_VPD:
		ret = qla2x00_get_vpd(ha, pext, mode);
		break;

	case INT_CC_UPDATE_VPD:
		ret = qla2x00_update_vpd(ha, pext, mode);
		break;

        case INT_CC_GET_SFP_DATA:
		ret = qla2x00_get_sfp_data(ha, pext, mode);
		break;

	case INT_CC_PORT_PARAM:
		ret = qla2x00_update_port_param(ha, pext, mode);
		break;

	/* all others go here */
	/*
	   case EXT_CC_PLATFORM_REG:
	   break;
	 */

#if defined(CONFIG_SCSI_QLA2XXX_FAILOVER)
	/* Failover IOCTLs */
	case FO_CC_GET_PARAMS:
	case FO_CC_SET_PARAMS:
	case FO_CC_GET_PATHS:
	case FO_CC_SET_CURRENT_PATH:
	case FO_CC_RESET_HBA_STAT:
	case FO_CC_GET_HBA_STAT:
	case FO_CC_GET_LUN_DATA:
	case FO_CC_SET_LUN_DATA:
	case FO_CC_GET_TARGET_DATA:
	case FO_CC_SET_TARGET_DATA:
	case FO_CC_GET_LBTYPE:
	case FO_CC_SET_LBTYPE:
		DEBUG9(printk("%s: failover arg (%p):\n", __func__, arg));

		qla2x00_fo_ioctl(ha, cmd, pext, mode);

		break;
#endif

	default:
	fail:
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		break;

	} /* end of CC decode switch */

	/* Always try to copy values back regardless what happened before. */
	tmp_rval = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

	if (ret == 0)
		ret = tmp_rval;

	DEBUG9(printk("%s: exiting. tmp_rval(%d) ret(%d)\n",
	    __func__, tmp_rval, ret));

	up(&ha->ioctl->access_sem);

	kfree(pext);
	return (ret);
}

/*
 * qla2x00_alloc_ioctl_mem
 *	Allocates memory needed by IOCTL code.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_alloc_ioctl_mem(scsi_qla_host_t *ha)
{
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_new_ioctl_dma_mem(ha, QLA_INITIAL_IOCTLMEM_SIZE) !=
	    QLA_SUCCESS) {
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl physical memory allocation\n");

		return QLA_MEMORY_ALLOC_FAILED;
	}

	/* Allocate context memory buffer */
	ha->ioctl = kmalloc(sizeof(struct hba_ioctl), GFP_KERNEL);
	if (ha->ioctl == NULL) {
		/* error */
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl context allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl, 0, sizeof(struct hba_ioctl));

	/* Allocate AEN tracking buffer */
	ha->ioctl->aen_tracking_queue =
	    kmalloc(EXT_DEF_MAX_AEN_QUEUE * sizeof(EXT_ASYNC_EVENT), GFP_KERNEL);
	if (ha->ioctl->aen_tracking_queue == NULL) {
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl aen_queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->aen_tracking_queue, 0,
			EXT_DEF_MAX_AEN_QUEUE * sizeof(EXT_ASYNC_EVENT));

	ha->ioctl->ioctl_tq = kmalloc(sizeof(os_tgt_t), GFP_KERNEL);
	if (ha->ioctl->ioctl_tq == NULL) {
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl tgt queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->ioctl_tq, 0, sizeof(os_tgt_t));

	ha->ioctl->ioctl_lq = kmalloc(sizeof(os_lun_t), GFP_KERNEL);
	if (ha->ioctl->ioctl_lq == NULL) {
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl lun queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->ioctl_lq, 0, sizeof(os_lun_t));

	/* Pick the largest size we'll need per ha of all ioctl cmds.
	 * Use this size when freeing.
	 */
	ha->ioctl->scrap_mem = kmalloc(QLA_IOCTL_SCRAP_SIZE, GFP_KERNEL);
	if (ha->ioctl->scrap_mem == NULL) {
		printk(KERN_WARNING
		    "qla2x00: ERROR in ioctl scrap_mem allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->scrap_mem, 0, QLA_IOCTL_SCRAP_SIZE);

	ha->ioctl->scrap_mem_size = QLA_IOCTL_SCRAP_SIZE;
	ha->ioctl->scrap_mem_used = 0;
	DEBUG9(printk("%s(%ld): scrap_mem_size=%d.\n",
	    __func__, ha->host_no, ha->ioctl->scrap_mem_size));

	ha->ioctl->ioctl_lq->q_state = LUN_STATE_READY;
	ha->ioctl->ioctl_lq->q_lock = SPIN_LOCK_UNLOCKED;

	init_MUTEX(&ha->ioctl->access_sem);

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance));

 	return QLA_SUCCESS;
}

/*
 * qla2x00_get_new_ioctl_dma_mem
 *	Allocates dma memory of the specified size.
 *	This is done to replace any previously allocated ioctl dma buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_new_ioctl_dma_mem(scsi_qla_host_t *ha, uint32_t size)
{
	DEBUG9(printk("%s entered.\n", __func__));

	if (ha->ioctl_mem) {
		DEBUG9(printk("%s: ioctl_mem was previously allocated. "
		    "Dealloc old buffer.\n", __func__));

	 	/* free the memory first */
	 	pci_free_consistent(ha->pdev, ha->ioctl_mem_size, ha->ioctl_mem,
		    ha->ioctl_mem_phys);
	}

	/* Get consistent memory allocated for ioctl I/O operations. */
	ha->ioctl_mem = dma_alloc_coherent(&ha->pdev->dev, size,
	    &ha->ioctl_mem_phys, GFP_KERNEL);
	if (ha->ioctl_mem == NULL) {
		printk(KERN_WARNING
		    "%s: ERROR in ioctl physical memory allocation. "
		    "Requested length=%x.\n", __func__, size);

		ha->ioctl_mem_size = 0;
		return QLA_MEMORY_ALLOC_FAILED;
	}
	ha->ioctl_mem_size = size;

	DEBUG9(printk("%s exiting.\n", __func__));

	return QLA_SUCCESS;
}

/*
 * qla2x00_free_ioctl_mem
 *	Frees memory used by IOCTL code for the specified ha.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
qla2x00_free_ioctl_mem(scsi_qla_host_t *ha)
{
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (ha->ioctl) {
		kfree(ha->ioctl->scrap_mem);
		ha->ioctl->scrap_mem = NULL;
		ha->ioctl->scrap_mem_size = 0;

		kfree(ha->ioctl->ioctl_tq);
		ha->ioctl->ioctl_tq = NULL;

		kfree(ha->ioctl->ioctl_lq);
		ha->ioctl->ioctl_lq = NULL;

		kfree(ha->ioctl->aen_tracking_queue);
		ha->ioctl->aen_tracking_queue = NULL;

		kfree(ha->ioctl);
		ha->ioctl = NULL;
	}

	/* free memory allocated for ioctl operations */
	if (ha->ioctl_mem)
		dma_free_coherent(&ha->pdev->dev, ha->ioctl_mem_size,
		    ha->ioctl_mem, ha->ioctl_mem_phys);
	ha->ioctl_mem = NULL;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

}

/*
 * qla2x00_get_ioctl_scrap_mem
 *	Returns pointer to memory of the specified size from the scrap buffer.
 *	This can be called multiple times before the free call as long
 *	as the memory is to be used by the same ioctl command and
 *	there's still memory left in the scrap buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	ppmem = pointer to return a buffer pointer.
 *	size = size of buffer to return.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_ioctl_scrap_mem(scsi_qla_host_t *ha, void **ppmem, uint32_t size)
{
	int		ret = QLA_SUCCESS;
	uint32_t	free_mem;

	DEBUG9(printk("%s(%ld): inst=%ld entered. size=%d.\n",
	    __func__, ha->host_no, ha->instance, size));

	free_mem = ha->ioctl->scrap_mem_size - ha->ioctl->scrap_mem_used;
	if (free_mem >= size) {
		*ppmem = ha->ioctl->scrap_mem + ha->ioctl->scrap_mem_used;
		ha->ioctl->scrap_mem_used += size;
	} else {
		DEBUG10(printk("%s(%ld): no more scrap memory.\n",
		    __func__, ha->host_no));

		ret = QLA_FUNCTION_FAILED;
	}

	DEBUG9(printk("%s(%ld): exiting. ret=%d.\n",
	    __func__, ha->host_no, ret));

	return (ret);
}

/*
 * qla2x00_free_ioctl_scrap_mem
 *	Makes the entire scrap buffer free for use.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 */
void
qla2x00_free_ioctl_scrap_mem(scsi_qla_host_t *ha)
{
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	memset(ha->ioctl->scrap_mem, 0, ha->ioctl->scrap_mem_size);
	ha->ioctl->scrap_mem_used = 0;

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no));
}

/*
 * qla2x00_find_curr_ha
 *	Searches and returns the pointer to the adapter host_no specified.
 *
 * Input:
 *	host_inst = driver internal adapter instance number to search.
 *	ha = adapter state pointer of the instance requested.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_find_curr_ha(uint16_t host_inst, scsi_qla_host_t **ret_ha)
{
	int	rval = QLA_SUCCESS;
	int	found;
	struct list_head *hal;
	scsi_qla_host_t *search_ha = NULL;

	/*
 	 * Set ha context for this IOCTL by matching host_no.
	 */
	found = 0;
	read_lock(&qla_hostlist_lock);
	list_for_each(hal, &qla_hostlist) {
		search_ha = list_entry(hal, scsi_qla_host_t, list);

		if (search_ha->instance == host_inst) {
			found++;
			break;
		}
	}
	read_unlock(&qla_hostlist_lock);

	if (!found) {
 		DEBUG10(printk("%s: ERROR matching host_inst "
 		    "%d to an HBA Instance.\n", __func__, host_inst));
		rval = QLA_FUNCTION_FAILED;
	} else {
		DEBUG9(printk("%s: found matching host_inst "
		    "%d to an HBA Instance.\n", __func__, host_inst));
		*ret_ha = search_ha;
	}

	return rval;
}

/*
 * qla2x00_get_driver_specifics
 *	Returns driver specific data in the response buffer.
 *
 * Input:
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_driver_specifics(EXT_IOCTL *pext, scsi_qla_host_t *ha)
{
	int			ret = 0;
	EXT_LN_DRIVER_DATA	data;

	DEBUG9(printk("%s: entered.\n", __func__));

	if (pext->ResponseLen < sizeof(EXT_LN_DRIVER_DATA)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR ResponseLen too small.\n",
		    __func__));

		return (ret);
	}
	/* Clear out the data */
	memset(&data, 0, sizeof(EXT_LN_DRIVER_DATA));

	data.DrvVer.Major = QLA_DRIVER_MAJOR_VER;
	data.DrvVer.Minor = QLA_DRIVER_MINOR_VER;
	data.DrvVer.Patch = QLA_DRIVER_PATCH_VER;
	data.DrvVer.Beta = QLA_DRIVER_BETA_VER;

	/* This driver supports large luns */
	data.Flags |= EXT_DEF_SUPPORTS_LARGE_LUN;

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &data, sizeof(EXT_LN_DRIVER_DATA));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR copy resp buf = %d.\n",
		    __func__, ret));
		ret = -EFAULT;
	} else {
		pext->Status = EXT_STATUS_OK;
	}

	DEBUG9(printk("%s: exiting. ret=%d.\n", __func__, ret));

	return (ret);
}

/*
 * qla2x00_aen_reg
 *	IOCTL management server Asynchronous Event Tracking Enable/Disable.
 *
 * Input:
 *	ha = pointer to the adapter struct of the adapter to register.
 *	cmd = pointer to EXT_IOCTL structure containing values from user.
 *	mode = flags. not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_aen_reg(scsi_qla_host_t *ha, EXT_IOCTL *cmd, int mode)
{
	int		rval = 0;
	EXT_REG_AEN	reg_struct;

	DEBUG9(printk("%s(%ld): inst %ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	rval = copy_from_user(&reg_struct, Q64BIT_TO_PTR(cmd->RequestAdr,
	    cmd->AddrMode), sizeof(EXT_REG_AEN));
	if (rval == 0) {
		cmd->Status = EXT_STATUS_OK;
		if (reg_struct.Enable) {
			ha->ioctl->flags |= IOCTL_AEN_TRACKING_ENABLE;
		} else {
			ha->ioctl->flags &= ~IOCTL_AEN_TRACKING_ENABLE;
		}
	} else {
		DEBUG9(printk("%s(%ld): inst %ld copy error=%d.\n",
		    __func__, ha->host_no, ha->instance, rval));

		cmd->Status = EXT_STATUS_COPY_ERR;
		rval = -EFAULT;
	}

	DEBUG9(printk("%s(%ld): inst %ld reg_struct.Enable(%d) "
	    "ha->ioctl_flag(%x) cmd->Status(%d).",
	    __func__, ha->host_no, ha->instance, reg_struct.Enable,
	    ha->ioctl->flags, cmd->Status));

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (rval);
}

/*
 * qla2x00_aen_get
 *	Asynchronous Event Record Transfer to user.
 *	The entire queue will be emptied and transferred back.
 *
 * Input:
 *	ha = pointer to the adapter struct of the specified adapter.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 *
 * NOTE: Need to use hardware lock to protect the queues from updates
 *	 via isr/enqueue_aen after we get rid of io_request_lock.
 */
static int
qla2x00_aen_get(scsi_qla_host_t *ha, EXT_IOCTL *cmd, int mode)
{
	int		rval = 0;
	EXT_ASYNC_EVENT	*tmp_q;
	EXT_ASYNC_EVENT	*paen;
	uint8_t		i;
	uint8_t		queue_cnt;
	uint8_t		request_cnt;
	uint32_t	stat = EXT_STATUS_OK;
	uint32_t	ret_len = 0;
	unsigned long   cpu_flags = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	request_cnt = (uint8_t)(cmd->ResponseLen / sizeof(EXT_ASYNC_EVENT));

	if (request_cnt < EXT_DEF_MAX_AEN_QUEUE) {
		/* We require caller to alloc for the maximum request count */
		cmd->Status       = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s(%ld): inst=%ld Buffer size %ld too small. "
		    "Exiting normally.",
		    __func__, ha->host_no, ha->instance,
		    (ulong)cmd->ResponseLen));

		return (rval);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&paen,
	    sizeof(EXT_ASYNC_EVENT) * EXT_DEF_MAX_AEN_QUEUE)) {
		/* not enough memory */
		cmd->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_ASYNC_EVENT)*EXT_DEF_MAX_AEN_QUEUE));
		return (rval);
	}

	/* 1st: Make a local copy of the entire queue content. */
	tmp_q = (EXT_ASYNC_EVENT *)ha->ioctl->aen_tracking_queue;
	queue_cnt = 0;

	spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
	i = ha->ioctl->aen_q_head;

	for (; queue_cnt < EXT_DEF_MAX_AEN_QUEUE;) {
		if (tmp_q[i].AsyncEventCode != 0) {
			memcpy(&paen[queue_cnt], &tmp_q[i],
			    sizeof(EXT_ASYNC_EVENT));
			queue_cnt++;
			tmp_q[i].AsyncEventCode = 0; /* empty out the slot */
		}

		if (i == ha->ioctl->aen_q_tail) {
			/* done. */
			break;
		}

		i++;

		if (i == EXT_DEF_MAX_AEN_QUEUE) {
			i = 0;
		}
	}

	/* Empty the queue. */
	ha->ioctl->aen_q_head = 0;
	ha->ioctl->aen_q_tail = 0;

	spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

	/* 2nd: Now transfer the queue content to user buffer */
	/* Copy the entire queue to user's buffer. */
	ret_len = (uint32_t)(queue_cnt * sizeof(EXT_ASYNC_EVENT));
	if (queue_cnt != 0) {
		rval = copy_to_user(Q64BIT_TO_PTR(cmd->ResponseAdr,
		    cmd->AddrMode), paen, ret_len);
	}
	cmd->ResponseLen = ret_len;

	if (rval != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld copy FAILED. error = %d\n",
		    __func__, ha->host_no, ha->instance, rval));
		rval = -EFAULT;
		stat = EXT_STATUS_COPY_ERR;
	} else {
		stat = EXT_STATUS_OK;
	}

	cmd->Status = stat;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting. rval=%d.\n",
	     __func__, ha->host_no, ha->instance, rval));

	return (rval);
}

/*
 * qla2x00_enqueue_aen
 *
 * Input:
 *	ha = adapter state pointer.
 *	event_code = async event code of the event to add to queue.
 *	payload = event payload for the queue.
 *
 * Context:
 *	Interrupt context.
 * NOTE: Need to hold the hardware lock to protect the queues from
 *	 aen_get after we get rid of the io_request_lock.
 */
void
qla2x00_enqueue_aen(scsi_qla_host_t *ha, uint16_t event_code, void *payload)
{
	uint8_t			new_entry; /* index to current entry */
	uint16_t		*mbx;
	EXT_ASYNC_EVENT		*aen_queue;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (!(ha->ioctl->flags & IOCTL_AEN_TRACKING_ENABLE))
		return;

	aen_queue = (EXT_ASYNC_EVENT *)ha->ioctl->aen_tracking_queue;
	if (aen_queue[ha->ioctl->aen_q_tail].AsyncEventCode != 0) {
		/* Need to change queue pointers to make room. */

		/* Increment tail for adding new entry. */
		ha->ioctl->aen_q_tail++;
		if (ha->ioctl->aen_q_tail == EXT_DEF_MAX_AEN_QUEUE) {
			ha->ioctl->aen_q_tail = 0;
		}

		if (ha->ioctl->aen_q_head == ha->ioctl->aen_q_tail) {
			/*
			 * We're overwriting the oldest entry, so need to
			 * update the head pointer.
			 */
			ha->ioctl->aen_q_head++;
			if (ha->ioctl->aen_q_head == EXT_DEF_MAX_AEN_QUEUE) {
				ha->ioctl->aen_q_head = 0;
			}
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld Adding code 0x%x to aen_q %p @ %d\n",
	    __func__, ha->host_no, ha->instance, event_code, aen_queue,
	    ha->ioctl->aen_q_tail));

	new_entry = ha->ioctl->aen_q_tail;
	aen_queue[new_entry].AsyncEventCode = event_code;

		/* Update payload */
	switch (event_code) {
	case MBA_LIP_OCCURRED:
	case MBA_LOOP_UP:
	case MBA_LOOP_DOWN:
	case MBA_LIP_RESET:
	case MBA_PORT_UPDATE:
		/* empty */
		break;

	case MBA_RSCN_UPDATE:
		mbx = (uint16_t *)payload;
		aen_queue[new_entry].Payload.RSCN.AddrFormat = MSB(mbx[1]);
		/* domain */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[0] = LSB(mbx[1]);
		/* area */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[1] = MSB(mbx[2]);
		/* al_pa */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[2] = LSB(mbx[2]);

		break;

	default:
		/* Not supported */
		aen_queue[new_entry].AsyncEventCode = 0;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));
}

/*
 * qla2x00_query
 *	Handles all subcommands of the EXT_CC_QUERY command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int rval = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* All Query type ioctls are done here */
	switch(pext->SubCode) {

	case EXT_SC_QUERY_HBA_NODE:
		/* fill in HBA NODE Information */
		rval = qla2x00_query_hba_node(ha, pext, mode);
		break;

	case EXT_SC_QUERY_HBA_PORT:
		/* return HBA PORT related info */
		rval = qla2x00_query_hba_port(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_PORT:
		/* return discovered port information */
		rval = qla2x00_query_disc_port(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_TGT:
		/* return discovered target information */
		rval = qla2x00_query_disc_tgt(ha, pext, mode);
		break;

	case EXT_SC_QUERY_CHIP:
		rval = qla2x00_query_chip(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_LUN:
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;

	default:
 		DEBUG9_10(printk("%s(%ld): inst=%ld unknown SubCode %d.\n",
 		    __func__, ha->host_no, ha->instance, pext->SubCode));
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance));
	return rval;
}

/*
 * qla2x00_query_hba_node
 *	Handles EXT_SC_QUERY_HBA_NODE subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_hba_node(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	i, transfer_size;
	EXT_HBA_NODE	*ptmp_hba_node;
	uint8_t		*next_str;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_hba_node,
	    sizeof(EXT_HBA_NODE))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_NODE)));
		return (ret);
	}

	/* fill all available HBA NODE Information */
	for (i = 0; i < 8 ; i++)
		ptmp_hba_node->WWNN[i] = ha->node_name[i];

	sprintf((char *)(ptmp_hba_node->Manufacturer), "QLogic Corporation");
	sprintf((char *)(ptmp_hba_node->Model), ha->model_number);

	ptmp_hba_node->SerialNum[0] = ha->serial0;
	ptmp_hba_node->SerialNum[1] = ha->serial1;
	ptmp_hba_node->SerialNum[2] = ha->serial2;
	sprintf((char *)(ptmp_hba_node->DriverVersion), qla2x00_version_str);
	sprintf((char *)(ptmp_hba_node->FWVersion),"%2d.%02d.%02d",
	    ha->fw_major_version,
	    ha->fw_minor_version,
	    ha->fw_subminor_version);
	DEBUG9_10(printk("%s(%ld): inst=%ld fw ver=%02d.%02d.%02d.\n",
	    __func__, ha->host_no, ha->instance,
	    ha->fw_major_version, ha->fw_minor_version, ha->fw_subminor_version));

	/* Option ROM version string. */
	memset(ptmp_hba_node->OptRomVersion, 0,
	    sizeof(ptmp_hba_node->OptRomVersion));
	next_str = ptmp_hba_node->OptRomVersion;
	sprintf(next_str, "0.00");
	if (test_bit(ROM_CODE_TYPE_BIOS, &ha->code_types)) {
		sprintf(next_str, "%d.%02d", ha->bios_revision[1],
		    ha->bios_revision[0]);
	}
	/* Extended Option ROM versions. */
	ptmp_hba_node->BIValid = 0;
	memset(ptmp_hba_node->BIEfiVersion, 0,
	    sizeof(ptmp_hba_node->BIEfiVersion));
	memset(ptmp_hba_node->BIFCodeVersion, 0,
	    sizeof(ptmp_hba_node->BIFCodeVersion));
	if (test_bit(ROM_CODE_TYPE_FCODE, &ha->code_types)) {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			ptmp_hba_node->BIValid |= EXT_HN_BI_FCODE_VALID;
			ptmp_hba_node->BIFCodeVersion[0] = ha->fcode_revision[1];
			ptmp_hba_node->BIFCodeVersion[1] = ha->fcode_revision[0];
		} else {
			unsigned int barray[3];

			memset (barray, 0, sizeof(barray));
			ptmp_hba_node->BIValid |= EXT_HN_BI_FCODE_VALID;
			sscanf(ha->fcode_revision, "%u.%u.%u", &barray[0],
			    &barray[1], &barray[2]);
			ptmp_hba_node->BIFCodeVersion[0] = barray[0];
			ptmp_hba_node->BIFCodeVersion[1] = barray[1];
			ptmp_hba_node->BIFCodeVersion[2] = barray[2];
		}
	}
	if (test_bit(ROM_CODE_TYPE_EFI, &ha->code_types)) {
		ptmp_hba_node->BIValid |= EXT_HN_BI_EFI_VALID;
		ptmp_hba_node->BIEfiVersion[0] = ha->efi_revision[1];
		ptmp_hba_node->BIEfiVersion[1] = ha->efi_revision[0];
	}
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha) || IS_QLA2322(ha)) {
		ptmp_hba_node->BIValid |= EXT_HN_BI_FW_VALID;
		ptmp_hba_node->BIFwVersion[0] = ha->fw_revision[0];
		ptmp_hba_node->BIFwVersion[1] = ha->fw_revision[1];
		ptmp_hba_node->BIFwVersion[2] = ha->fw_revision[2];
		ptmp_hba_node->BIFwVersion[3] = ha->fw_revision[3];

		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld fw rev=%04d.%04d.%04d.%04d.\n",
		    __func__, ha->host_no, ha->instance,
		    ha->fw_revision[0], ha->fw_revision[1],
		    ha->fw_revision[2], ha->fw_revision[3]));
	}

	ptmp_hba_node->InterfaceType = EXT_DEF_FC_INTF_TYPE;
	ptmp_hba_node->PortCount = 1;
	ptmp_hba_node->DriverAttr = 0;

#if defined(CONFIG_SCSI_QLA2XXX_FAILOVER)
	if (qla2x00_failover_enabled(ha))
		ptmp_hba_node->DriverAttr |= DRVR_FO_ENABLED;
#endif

	/* now copy up the HBA_NODE to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_NODE))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_NODE);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_hba_node, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	qla2x00_free_ioctl_scrap_mem(ha);
	return (ret);
}

/*
 * qla2x00_query_hba_port
 *	Handles EXT_SC_QUERY_HBA_PORT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_hba_port(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	tgt_cnt, tgt, transfer_size;
	uint32_t	port_cnt;
	fc_port_t	*fcport;
	EXT_HBA_PORT	*ptmp_hba_port;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_hba_port,
	    sizeof(EXT_HBA_PORT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT)));
		return (ret);
	}

	/* reflect all HBA PORT related info */
	ptmp_hba_port->WWPN[7] = ha->port_name[7];
	ptmp_hba_port->WWPN[6] = ha->port_name[6];
	ptmp_hba_port->WWPN[5] = ha->port_name[5];
	ptmp_hba_port->WWPN[4] = ha->port_name[4];
	ptmp_hba_port->WWPN[3] = ha->port_name[3];
	ptmp_hba_port->WWPN[2] = ha->port_name[2];
	ptmp_hba_port->WWPN[1] = ha->port_name[1];
	ptmp_hba_port->WWPN[0] = ha->port_name[0];
	ptmp_hba_port->Id[0] = 0;
	ptmp_hba_port->Id[1] = ha->d_id.r.d_id[2];
	ptmp_hba_port->Id[2] = ha->d_id.r.d_id[1];
	ptmp_hba_port->Id[3] = ha->d_id.r.d_id[0];
	ptmp_hba_port->Type =  EXT_DEF_INITIATOR_DEV;

	switch (ha->current_topology) {
	case ISP_CFG_NL:
	case ISP_CFG_FL:
		ptmp_hba_port->Mode = EXT_DEF_LOOP_MODE;
		break;

	case ISP_CFG_N:
	case ISP_CFG_F:
		ptmp_hba_port->Mode = EXT_DEF_P2P_MODE;
		break;

	default:
		ptmp_hba_port->Mode = EXT_DEF_UNKNOWN_MODE;
		break;
	}

	port_cnt = 0;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET) {
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x not target dev\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7]));
			continue;
		}

		/* if removed or missing */
		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x not online\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7]));
			continue;
		}
		port_cnt++;
	}

	tgt_cnt  = 0;
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if (ha->otgt[tgt] == NULL) {
			continue;
		}
		if (ha->otgt[tgt]->fcport == NULL) {
			/* port doesn't exist */
			DEBUG9(printk("%s(%ld): tgt %d port not exist.\n",
			    __func__, ha->host_no, tgt));
			continue;
		}

		DEBUG9(printk("%s(%ld): inst=%ld found port at %d. ",
		    __func__, ha->host_no, ha->instance, tgt));
		DEBUG9(printk("ostgtid=%d, flags=%x, tgt_q=%p, cfg_id=%d.\n",
		    ha->otgt[tgt]->fcport->os_target_id,
		    ha->otgt[tgt]->fcport->flags,
		    ha->otgt[tgt]->fcport->tgt_queue,
		    ha->otgt[tgt]->fcport->cfg_id));

		tgt_cnt++;
	}

	DEBUG9_10(printk("%s(%ld): inst=%ld disc_port cnt=%d, tgt cnt=%d.\n",
	    __func__, ha->host_no, ha->instance,
	    port_cnt, tgt_cnt));
	ptmp_hba_port->DiscPortCount   = port_cnt;
	ptmp_hba_port->DiscTargetCount = tgt_cnt;

	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD) {
		ptmp_hba_port->State = EXT_DEF_HBA_LOOP_DOWN;
	} else if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags)) {

		ptmp_hba_port->State = EXT_DEF_HBA_SUSPENDED;
	} else {
		ptmp_hba_port->State = EXT_DEF_HBA_OK;
	}

	ptmp_hba_port->DiscPortNameType = EXT_DEF_USE_PORT_NAME;

	/* Return supported FC4 type depending on driver support. */
	ptmp_hba_port->PortSupportedFC4Types = EXT_DEF_FC4_TYPE_SCSI;
	ptmp_hba_port->PortActiveFC4Types = EXT_DEF_FC4_TYPE_SCSI;
	if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
		ptmp_hba_port->PortSupportedFC4Types |= EXT_DEF_FC4_TYPE_IP;
		ptmp_hba_port->PortActiveFC4Types |= EXT_DEF_FC4_TYPE_IP;
	}

	/* Return supported speed depending on adapter type */
	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		ptmp_hba_port->PortSupportedSpeed = EXT_DEF_PORTSPEED_1GBIT;
	else
		ptmp_hba_port->PortSupportedSpeed = EXT_DEF_PORTSPEED_2GBIT;

	switch (ha->link_data_rate) {
	case 0:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_1GBIT;
		break;
	case 1:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_2GBIT;
		break;
	case 3:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_4GBIT;
		break;
	case 4:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_10GBIT;
		break;
	default:
		/* unknown */
		ptmp_hba_port->PortSpeed = 0;
		break;
	}

	/* now copy up the HBA_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_hba_port, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return ret;
}

/*
 * qla2x00_query_disc_port
 *	Handles EXT_SC_QUERY_DISC_PORT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_disc_port(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	int		found;
	uint32_t	tgt, transfer_size, inst;
	fc_port_t	*fcport;
	os_tgt_t	*tq;
	EXT_DISC_PORT	*ptmp_disc_port;

	DEBUG9(printk("%s(%ld): inst=%ld entered. Port inst=%02d.\n",
	    __func__, ha->host_no, ha->instance, pext->Instance));

	inst = 0;
	found = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;

		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			/* port does not exist anymore */
			DEBUG9(printk("%s(%ld): fcport marked lost. "
			    "port=%02x%02x%02x%02x%02x%02x%02x%02x "
			    "loop_id=%02x not online.\n",
			    __func__, ha->host_no,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7],
			    fcport->loop_id));
			continue;
		}

		if (inst != pext->Instance) {
			DEBUG9(printk("%s(%ld): found fcport %02d "
			    "d_id=%02x%02x%02x. Skipping.\n",
			    __func__, ha->host_no, inst,
			    fcport->d_id.b.domain,
			    fcport->d_id.b.area,
			    fcport->d_id.b.al_pa));

			inst++;
			continue;
		}

		DEBUG9(printk("%s(%ld): inst=%ld found matching fcport %02d "
		    "online. d_id=%02x%02x%02x loop_id=%02x online.\n",
		    __func__, ha->host_no, ha->instance, inst,
		    fcport->d_id.b.domain,
		    fcport->d_id.b.area,
		    fcport->d_id.b.al_pa,
		    fcport->loop_id));

		/* Found the matching port still connected. */
		found++;
		break;
	}

	if (!found) {
		DEBUG9_10(printk("%s(%ld): inst=%ld dev not found.\n",
		    __func__, ha->host_no, ha->instance));

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_disc_port,
	    sizeof(EXT_DISC_PORT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DISC_PORT)));
		return (ret);
	}

	memcpy(ptmp_disc_port->WWNN, fcport->node_name, WWN_SIZE);
	memcpy(ptmp_disc_port->WWPN, fcport->port_name, WWN_SIZE);

	ptmp_disc_port->Id[0] = 0;
	ptmp_disc_port->Id[1] = fcport->d_id.r.d_id[2];
	ptmp_disc_port->Id[2] = fcport->d_id.r.d_id[1];
	ptmp_disc_port->Id[3] = fcport->d_id.r.d_id[0];

	/* Currently all devices on fcport list are target capable devices */
	/* This default value may need to be changed after we add non target
	 * devices also to this list.
	 */
	ptmp_disc_port->Type = EXT_DEF_TARGET_DEV;

	if (fcport->flags & FC_FABRIC_DEVICE) {
		ptmp_disc_port->Type |= EXT_DEF_FABRIC_DEV;
	}
	if (fcport->flags & FC_TAPE_PRESENT) {
		ptmp_disc_port->Type |= EXT_DEF_TAPE_DEV;
	}
	if (fcport->port_type == FCT_INITIATOR) {
		ptmp_disc_port->Type |= EXT_DEF_INITIATOR_DEV;
	}

	ptmp_disc_port->LoopID = fcport->loop_id;
	ptmp_disc_port->Status = 0;
	ptmp_disc_port->Bus    = 0;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if ((tq = ha->otgt[tgt]) == NULL) {
			continue;
		}

		if (tq->fcport == NULL)  /* dg 08/14/01 */
			continue;

		if (memcmp(fcport->port_name, tq->fcport->port_name,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			ptmp_disc_port->TargetId = tgt;
			break;
		}
	}

	/* now copy up the DISC_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_DISC_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DISC_PORT);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_disc_port, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_query_disc_tgt
 *	Handles EXT_SC_QUERY_DISC_TGT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_disc_tgt(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	tgt, transfer_size, inst;
	uint32_t	cnt, i;
	fc_port_t	*tgt_fcport;
	os_tgt_t	*tq;
	EXT_DISC_TARGET	*ptmp_disc_target;

	DEBUG9(printk("%s(%ld): inst=%ld entered for tgt inst %d.\n",
	    __func__, ha->host_no, ha->instance, pext->Instance));

	tq = NULL;
	for (tgt = 0, inst = 0; tgt < MAX_TARGETS; tgt++) {
		if (ha->otgt[tgt] == NULL) {
			continue;
		}
		/* if wrong target id then skip to next entry */
		if (inst != pext->Instance) {
			inst++;
			continue;
		}
		tq = ha->otgt[tgt];
		break;
	}

	if (tq == NULL || tgt == MAX_TARGETS) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld target dev not found. "
		    "tq=%p, tgt=%d.\n",
		    __func__, ha->host_no, ha->instance, tq, tgt));
		return (ret);
	}

	if (tq->fcport == NULL) { 	/* dg 08/14/01 */
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld target %d port not found. "
		    "tq=%p.\n",
		    __func__, ha->host_no, ha->instance, tgt, tq));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_disc_target,
	    sizeof(EXT_DISC_TARGET))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DISC_TARGET)));
		return (ret);
	}

	tgt_fcport = tq->fcport;
	if (tgt_fcport->flags & (FC_XP_DEVICE|FC_NVSXXX_DEVICE))
		memcpy(ptmp_disc_target->WWNN, tq->node_name, WWN_SIZE);
	else
		memcpy(ptmp_disc_target->WWNN, tgt_fcport->node_name, WWN_SIZE);
	memcpy(ptmp_disc_target->WWPN, tgt_fcport->port_name, WWN_SIZE);

	ptmp_disc_target->Id[0] = 0;
	ptmp_disc_target->Id[1] = tgt_fcport->d_id.r.d_id[2];
	ptmp_disc_target->Id[2] = tgt_fcport->d_id.r.d_id[1];
	ptmp_disc_target->Id[3] = tgt_fcport->d_id.r.d_id[0];

	/* All devices on ha->otgt list are target capable devices. */
	ptmp_disc_target->Type = EXT_DEF_TARGET_DEV;

	if (tgt_fcport->flags & FC_FABRIC_DEVICE) {
		ptmp_disc_target->Type |= EXT_DEF_FABRIC_DEV;
	}
	if (tgt_fcport->flags & FC_TAPE_PRESENT) {
		ptmp_disc_target->Type |= EXT_DEF_TAPE_DEV;
	}
	if (tgt_fcport->port_type & FCT_INITIATOR) {
		ptmp_disc_target->Type |= EXT_DEF_INITIATOR_DEV;
	}

	ptmp_disc_target->LoopID   = tgt_fcport->loop_id;
	ptmp_disc_target->Status   = 0;
	if (atomic_read(&tq->fcport->state) != FCS_ONLINE) {
		ptmp_disc_target->Status |= EXT_DEF_TGTSTAT_OFFLINE;
	}
	if (qla2x00_is_fcport_in_config(ha, tq->fcport)) {
		ptmp_disc_target->Status |= EXT_DEF_TGTSTAT_IN_CFG;
	}

	ptmp_disc_target->Bus      = 0;
	ptmp_disc_target->TargetId = tgt;

	cnt = 0;
	/* enumerate available LUNs under this TGT (if any) */
	if (ha->otgt[tgt] != NULL) {
		for (i = 0; i < MAX_LUNS ; i++) {
			if ((ha->otgt[tgt])->olun[i] !=0)
				cnt++;
		}
	}

	ptmp_disc_target->LunCount = cnt;

	DEBUG9(printk("%s(%ld): copying data for tgt id %d. ",
	    __func__, ha->host_no, tgt));
	DEBUG9(printk("port=%p:%02x%02x%02x%02x%02x%02x%02x%02x. "
	    "lun cnt=%d.\n",
	    tgt_fcport,
	    tgt_fcport->port_name[0],
	    tgt_fcport->port_name[1],
	    tgt_fcport->port_name[2],
	    tgt_fcport->port_name[3],
	    tgt_fcport->port_name[4],
	    tgt_fcport->port_name[5],
	    tgt_fcport->port_name[6],
	    tgt_fcport->port_name[7],
	    cnt));

	/* now copy up the DISC_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_DISC_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DISC_TARGET);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_disc_target, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_query_chip
 *	Handles EXT_SC_QUERY_CHIP subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_chip(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	transfer_size, i;
	EXT_CHIP		*ptmp_isp;
	struct Scsi_Host	*host;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

 	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_isp,
 	    sizeof(EXT_CHIP))) {
 		/* not enough memory */
 		pext->Status = EXT_STATUS_NO_MEMORY;
 		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
 		    "size requested=%ld.\n",
 		    __func__, ha->host_no, ha->instance,
 		    (ulong)sizeof(EXT_CHIP)));
 		return (ret);
 	}

	host = ha->host;
	ptmp_isp->VendorId       = ha->pdev->vendor;
	ptmp_isp->DeviceId       = ha->pdev->device;
	ptmp_isp->SubVendorId    = ha->pdev->subsystem_vendor;
	ptmp_isp->SubSystemId    = ha->pdev->subsystem_device;
	ptmp_isp->PciBusNumber   = ha->pdev->bus->number;
	ptmp_isp->PciDevFunc     = ha->pdev->devfn;
	ptmp_isp->PciSlotNumber  = PCI_SLOT(ha->pdev->devfn);
	ptmp_isp->DomainNr       = pci_domain_nr(ha->pdev->bus);
	/* These values are not 64bit architecture safe. */
	ptmp_isp->IoAddr         = 0; //(UINT32)ha->pio_address;
	ptmp_isp->IoAddrLen      = 0; //(UINT32)ha->pio_length;
	ptmp_isp->MemAddr        = 0; //(UINT32)ha->mmio_address;
	ptmp_isp->MemAddrLen     = 0; //(UINT32)ha->mmio_length;
	ptmp_isp->ChipType       = 0; /* ? */
	ptmp_isp->InterruptLevel = ha->pdev->irq;

	for (i = 0; i < 8; i++)
		ptmp_isp->OutMbx[i] = 0;

	/* now copy up the ISP to user */
	if (pext->ResponseLen < sizeof(EXT_CHIP))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_CHIP);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_isp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_get_data
 *	Handles all subcommands of the EXT_CC_GET_DATA command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_data(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int	tmp_rval = 0;

	switch(pext->SubCode) {
	case EXT_SC_GET_STATISTICS:
		tmp_rval = qla2x00_get_statistics(ha, pext, mode);
		break;

	case EXT_SC_GET_FC_STATISTICS:
		tmp_rval = qla2x00_get_fc_statistics(ha, pext, mode);
		break;

	case EXT_SC_GET_PORT_SUMMARY:
		tmp_rval = qla2x00_get_port_summary(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DRIVER:
		tmp_rval = qla2x00_query_driver(ha, pext, mode);
		break;

	case EXT_SC_QUERY_FW:
		tmp_rval = qla2x00_query_fw(ha, pext, mode);
		break;

	case EXT_SC_GET_RNID:
		tmp_rval = qla2x00_get_rnid_params(ha, pext, mode);
		break;

	case EXT_SC_GET_LUN_BY_Q:
		tmp_rval = qla2x00_get_tgt_lun_by_q(ha, pext, mode);
		break;

	case EXT_SC_GET_BEACON_STATE:
		if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
			tmp_rval = qla2x00_get_led_state(ha, pext, mode);
			break;
		}
		/*FALLTHROUGH*/

	default:
		DEBUG10(printk("%s(%ld): inst=%ld unknown SubCode %d.\n",
		    __func__, ha->host_no, ha->instance, pext->SubCode));
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	 }

	return (tmp_rval);
}

/*
 * qla2x00_get_statistics
 *	Issues get_link_status mbx cmd and returns statistics
 *	relavent to the specified adapter.
 *
 * Input:
 *	ha = pointer to adapter struct of the specified adapter.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_statistics(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	EXT_HBA_PORT_STAT	*ptmp_stat;
	int		ret = 0;
	link_stat_t	stat_buf;
	uint8_t		rval;
	uint8_t		*usr_temp, *kernel_tmp;
	uint16_t	mb_stat[1];
	uint32_t	transfer_size;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* check on loop down */
	if ((!IS_QLA24XX(ha) && !IS_QLA54XX(ha) &&
	    atomic_read(&ha->loop_state) != LOOP_READY) ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	/* Send mailbox cmd to get more. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha))
		rval = qla24xx_get_isp_stats(ha, (uint32_t *)&stat_buf,
		    sizeof(stat_buf) / 4, mb_stat);
	else
		rval = qla2x00_get_link_status(ha, ha->loop_id, &stat_buf,
		    mb_stat);
	if (rval != QLA_SUCCESS) {
		if (rval == BIT_0) {
			pext->Status = EXT_STATUS_NO_MEMORY;
		} else if (rval == BIT_1) {
			pext->Status = EXT_STATUS_MAILBOX;
			pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
		} else {
			pext->Status = EXT_STATUS_ERR;
		}

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR mailbox failed. "
		    "mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]));
		printk(KERN_WARNING
		     "%s(%ld): inst=%ld ERROR mailbox failed. mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]);

		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_stat,
	    sizeof(EXT_HBA_PORT_STAT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT_STAT)));
		return (ret);
	}

	ptmp_stat->ControllerErrorCount   =  ha->total_isp_aborts;
	ptmp_stat->DeviceErrorCount       =  ha->total_dev_errs;
	ptmp_stat->TotalIoCount           =  ha->total_ios;
	ptmp_stat->TotalMBytes            =  ha->total_bytes >> 20;
	ptmp_stat->TotalLipResets         =  ha->total_lip_cnt;
	/*
	   ptmp_stat->TotalInterrupts        =  ha->total_isr_cnt;
	 */

	ptmp_stat->TotalLinkFailures               = stat_buf.link_fail_cnt;
	ptmp_stat->TotalLossOfSync                 = stat_buf.loss_sync_cnt;
	ptmp_stat->TotalLossOfSignals              = stat_buf.loss_sig_cnt;
	ptmp_stat->PrimitiveSeqProtocolErrorCount  = stat_buf.prim_seq_err_cnt;
	ptmp_stat->InvalidTransmissionWordCount    = stat_buf.inval_xmit_word_cnt;
	ptmp_stat->InvalidCRCCount                 = stat_buf.inval_crc_cnt;

	/* now copy up the STATISTICS to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT_STAT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT_STAT);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)ptmp_stat;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_get_fc_statistics
 *	Issues get_link_status mbx cmd to the target device with
 *	the specified WWN and returns statistics relavent to the
 *	device.
 *
 * Input:
 *	ha = pointer to adapter struct of the specified device.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_fc_statistics(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	EXT_HBA_PORT_STAT	*ptmp_stat;
	EXT_DEST_ADDR		addr_struct;
	fc_port_t	*fcport;
	int		port_found;
	link_stat_t	stat_buf;
	int		ret = 0;
	uint8_t		rval;
	uint8_t		*usr_temp, *kernel_tmp;
	uint8_t		*req_name;
	uint16_t	mb_stat[1];
	uint32_t	transfer_size;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	ret = copy_from_user(&addr_struct, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy req buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		return (-EFAULT);
	}

	/* find the device's loop_id */
	port_found = 0;
	fcport = NULL;
	switch (addr_struct.DestType) {
	case EXT_DEF_DESTTYPE_WWPN:
		req_name = addr_struct.DestAddr.WWPN;
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (memcmp(fcport->port_name, req_name,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				port_found = 1;
				break;
			}
		}
		break;

	case EXT_DEF_DESTTYPE_WWNN:
	case EXT_DEF_DESTTYPE_PORTID:
	case EXT_DEF_DESTTYPE_FABRIC:
	case EXT_DEF_DESTTYPE_SCSI:
	default:
		pext->Status = EXT_STATUS_INVALID_PARAM;
		pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR Unsupported subcode "
		    "address type.\n", __func__, ha->host_no, ha->instance));
		return (ret);

		break;
	}

	if (!port_found) {
		/* not found */
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		pext->DetailStatus = EXT_DSTATUS_TARGET;
		return (ret);
	}

	/* check for suspended/lost device */
	/*
	   if (ha->fcport is suspended/lost) {
	   pext->Status = EXT_STATUS_SUSPENDED;
	   pext->DetailStatus = EXT_DSTATUS_TARGET;
	   return pext->Status;
	   }
	 */

	/* check on loop down */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		     __func__, ha->host_no, ha->instance));
		return (ret);
	}

	/* Send mailbox cmd to get more. */
	if ((rval = qla2x00_get_link_status(ha, fcport->loop_id,
	    &stat_buf, mb_stat)) != QLA_SUCCESS) {
		if (rval == BIT_0) {
			pext->Status = EXT_STATUS_NO_MEMORY;
		} else if (rval == BIT_1) {
			pext->Status = EXT_STATUS_MAILBOX;
			pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
		} else {
			pext->Status = EXT_STATUS_ERR;
		}

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR mailbox failed. "
		    "mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_stat,
	    sizeof(EXT_HBA_PORT_STAT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT_STAT)));
		return (ret);
	}

	ptmp_stat->ControllerErrorCount   =  ha->total_isp_aborts;
	ptmp_stat->DeviceErrorCount       =  ha->total_dev_errs;
	ptmp_stat->TotalIoCount           =  ha->total_ios;
	ptmp_stat->TotalMBytes            =  ha->total_bytes >> 20;
	ptmp_stat->TotalLipResets         =  ha->total_lip_cnt;
	/*
	   ptmp_stat->TotalInterrupts        =  ha->total_isr_cnt;
	 */

	ptmp_stat->TotalLinkFailures               = stat_buf.link_fail_cnt;
	ptmp_stat->TotalLossOfSync                 = stat_buf.loss_sync_cnt;
	ptmp_stat->TotalLossOfSignals              = stat_buf.loss_sig_cnt;
	ptmp_stat->PrimitiveSeqProtocolErrorCount  = stat_buf.prim_seq_err_cnt;
	ptmp_stat->InvalidTransmissionWordCount    = stat_buf.inval_xmit_word_cnt;
	ptmp_stat->InvalidCRCCount                 = stat_buf.inval_crc_cnt;

	/* now copy up the STATISTICS to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT_STAT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT_STAT);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)ptmp_stat;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_get_port_summary
 *	Handles EXT_SC_GET_PORT_SUMMARY subcommand.
 *	Returns values of devicedata and dd_entry list.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_port_summary(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	entry_cnt = 0;
	uint32_t	port_cnt = 0;
	uint32_t	top_xfr_size;
	uint32_t	usr_no_of_entries = 0;
	uint32_t	device_types;
	void		*start_of_entry_list;
	fc_port_t	*fcport;

	EXT_DEVICEDATA		*pdevicedata;
	EXT_DEVICEDATAENTRY	*pdd_entry;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pdevicedata,
	    sizeof(EXT_DEVICEDATA))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "pdevicedata requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DEVICEDATA)));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pdd_entry,
	    sizeof(EXT_DEVICEDATAENTRY))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "pdd_entry requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DEVICEDATAENTRY)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Get device types to query. */
	device_types = 0;
	ret = copy_from_user(&device_types, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(device_types));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of struct failed ret=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Get maximum number of entries allowed in response buf */
	usr_no_of_entries = pext->ResponseLen / sizeof(EXT_DEVICEDATAENTRY);

	/* reserve some spaces to be filled in later. */
	top_xfr_size = sizeof(pdevicedata->ReturnListEntryCount) +
	    sizeof(pdevicedata->TotalDevices);

	start_of_entry_list = Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode) +
	    top_xfr_size;

	/* Start copying from devices that exist. */
	ret = qla2x00_get_fcport_summary(ha, pdd_entry, start_of_entry_list,
	    device_types, usr_no_of_entries, &entry_cnt, &pext->Status);

	DEBUG9(printk("%s(%ld): after get_fcport_summary, entry_cnt=%d.\n",
	    __func__, ha->host_no, entry_cnt));

	/* If there's still space in user buffer, return devices found
	 * in config file which don't actually exist (missing).
	 */
	if (ret == 0) {
		if (!qla2x00_failover_enabled(ha)) {
			ret = qla2x00_std_missing_port_summary(ha, pdd_entry,
			    start_of_entry_list, usr_no_of_entries,
			    &entry_cnt, &pext->Status);
		} else {
			ret = qla2x00_fo_missing_port_summary(ha, pdd_entry,
			    start_of_entry_list, usr_no_of_entries,
			    &entry_cnt, &pext->Status);

		}
	}

	DEBUG9(printk(
	    "%s(%ld): after get_missing_port_summary. entry_cnt=%d.\n",
	    __func__, ha->host_no, entry_cnt));

	if (ret) {
		DEBUG9_10(printk("%s(%ld): failed getting port info.\n",
		    __func__, ha->host_no));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	pdevicedata->ReturnListEntryCount = entry_cnt;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;

		port_cnt++;
	}
	if (port_cnt > entry_cnt)
		pdevicedata->TotalDevices = port_cnt;
	else
		pdevicedata->TotalDevices = entry_cnt;

	DEBUG9(printk("%s(%ld): inst=%ld EXT_SC_GET_PORT_SUMMARY "
	    "return entry cnt=%d port_cnt=%d.\n",
	    __func__, ha->host_no, ha->instance,
	    entry_cnt, port_cnt));

	/* copy top of devicedata, which is everything other than the
	 * actual entry list data.
	 */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pdevicedata;
	ret = copy_to_user(usr_temp, kernel_tmp, top_xfr_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp "
		    "devicedata buffer=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_get_fcport_summary
 *	Returns port values in user's dd_entry list.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pdd_entry = pointer to a temporary EXT_DEVICEDATAENTRY struct
 *	pstart_of_entry_list = start of user addr of buffer for dd_entry entries
 *	max_entries = max number of entries allowed by user buffer
 *	pentry_cnt = pointer to total number of entries so far
 *	ret_status = pointer to ioctl status field
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_fcport_summary(scsi_qla_host_t *ha, EXT_DEVICEDATAENTRY *pdd_entry,
    void *pstart_of_entry_list, uint32_t device_types, uint32_t max_entries,
    uint32_t *pentry_cnt, uint32_t *ret_status)
{
	int		ret = QLA_SUCCESS;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	b;
	uint32_t	current_offset;
	uint32_t	tgt;
	uint32_t	transfer_size;
	fc_port_t	*fcport;
	os_tgt_t	*tq;
	mp_host_t	*host = NULL;
	uint16_t	idx;
	mp_device_t	*tmp_dp = NULL;
			
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (*pentry_cnt >= max_entries)
			break;
		if (fcport->port_type != FCT_TARGET) {
			/* Don't report initiators or broadcast devices. */
			DEBUG2_9_10(printk("%s(%ld): not reporting non-target "
			    "fcport %02x%02x%02x%02x%02x%02x%02x%02x. "
			    "port_type=%x.\n",
			    __func__, ha->host_no, fcport->port_name[0],
			    fcport->port_name[1], fcport->port_name[2],
			    fcport->port_name[3], fcport->port_name[4],
			    fcport->port_name[5], fcport->port_name[6],
			    fcport->port_name[7], fcport->port_type));
			continue;
		}

		if ((atomic_read(&fcport->state) != FCS_ONLINE) &&
		    !qla2x00_is_fcport_in_config(ha, fcport)) {
			/* no need to report */
			DEBUG2_9_10(printk("%s(%ld): not reporting "
			    "fcport %02x%02x%02x%02x%02x%02x%02x%02x. "
			    "state=%i, flags=%02x.\n",
			    __func__, ha->host_no, fcport->port_name[0],
			    fcport->port_name[1], fcport->port_name[2],
			    fcport->port_name[3], fcport->port_name[4],
			    fcport->port_name[5], fcport->port_name[6],
			    fcport->port_name[7], atomic_read(&fcport->state),
			    fcport->flags));
			continue;
		}

		/* copy from fcport to dd_entry */

		for (b = 0; b < 3 ; b++)
			pdd_entry->PortID[b] = fcport->d_id.r.d_id[2-b];

		if (fcport->flags & FC_FABRIC_DEVICE) {
			pdd_entry->ControlFlags = EXT_DEF_GET_FABRIC_DEVICE;
		} else {
			pdd_entry->ControlFlags = 0;
		}

		pdd_entry->TargetAddress.Bus    = 0;
		/* Retrieve 'Target' number for port */
		for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
			if ((tq = ha->otgt[tgt]) == NULL) {
				continue;
			}

			if (tq->fcport == NULL)
				continue;

			if (memcmp(fcport->port_name, tq->fcport->port_name,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				pdd_entry->TargetAddress.Target = tgt;
				if ((fcport->flags & (FC_XP_DEVICE|FC_NVSXXX_DEVICE)) &&
				    !(device_types &
					EXT_DEF_GET_TRUE_NN_DEVICE)) {
					memcpy(pdd_entry->NodeWWN,
					    tq->node_name, WWN_SIZE);
				} else {
					memcpy(pdd_entry->NodeWWN,
					    fcport->node_name, WWN_SIZE);
				}
				break;
			}
		}
		if (tgt == MAX_TARGETS) {
			if (qla2x00_failover_enabled(ha)) {
				if (((host = qla2x00_cfg_find_host(ha)) !=
				    NULL) && (fcport->flags & (FC_XP_DEVICE|FC_NVSXXX_DEVICE)) &&
					!(device_types &
					    EXT_DEF_GET_TRUE_NN_DEVICE)) {
					if ((tmp_dp =
					    qla2x00_find_mp_dev_by_portname(
						    host, fcport->port_name,
						    &idx)) != NULL)
						memcpy(pdd_entry->NodeWWN,
						    tmp_dp->nodename, WWN_SIZE);
				} else
					memcpy(pdd_entry->NodeWWN,
					    fcport->node_name, WWN_SIZE);
			} else
				memcpy(pdd_entry->NodeWWN, fcport->node_name,
				    WWN_SIZE);
		}
		memcpy(pdd_entry->PortWWN, fcport->port_name, WWN_SIZE);

		pdd_entry->TargetAddress.Lun    = 0;
		pdd_entry->DeviceFlags          = 0;
		pdd_entry->LoopID               = fcport->loop_id;
		pdd_entry->BaseLunNumber        = 0;

		DEBUG9_10(printk("%s(%ld): reporting "
		    "fcport %02x%02x%02x%02x%02x%02x%02x%02x.\n",
		    __func__, ha->host_no, fcport->port_name[0],
		    fcport->port_name[1], fcport->port_name[2],
		    fcport->port_name[3], fcport->port_name[4],
		    fcport->port_name[5], fcport->port_name[6],
		    fcport->port_name[7]));

		current_offset = *pentry_cnt * sizeof(EXT_DEVICEDATAENTRY);

		transfer_size = sizeof(EXT_DEVICEDATAENTRY);

		/* now copy up this dd_entry to user */
		usr_temp = (uint8_t *)pstart_of_entry_list + current_offset;
		kernel_tmp = (uint8_t *)pdd_entry;
	 	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
		if (ret) {
			*ret_status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp "
			    "entry list buf=%d.\n",
			    __func__, ha->host_no, ha->instance, ret));
			return (-EFAULT);
		}

		*pentry_cnt += 1;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_fo_missing_port_summary is in qla_fo.c
 */

static int
qla2x00_std_missing_port_summary(scsi_qla_host_t *ha,
    EXT_DEVICEDATAENTRY *pdd_entry, void *pstart_of_entry_list,
    uint32_t max_entries, uint32_t *pentry_cnt, uint32_t *ret_status)
{
	int		ret = QLA_SUCCESS;
	uint8_t		*usr_temp, *kernel_tmp;
	uint16_t	idx;
	uint32_t	b;
	uint32_t	current_offset;
	uint32_t	transfer_size;
	os_tgt_t	*tq;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	for (idx = 0; idx < MAX_FIBRE_DEVICES && *pentry_cnt < max_entries;
	    idx++) {
		if ((tq = TGT_Q(ha, idx)) == NULL)
			continue;

		/* Target present in configuration data but
		 * missing during device discovery*/
		if (tq->fcport == NULL) {
			DEBUG10(printk("%s: returning missing device "
			    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__,
			    tq->port_name[0],tq->port_name[1],
			    tq->port_name[2],tq->port_name[3],
			    tq->port_name[4],tq->port_name[5],
			    tq->port_name[6],tq->port_name[7]));

			/* This device was not found. Return
			 * as unconfigured.
			 */
			memcpy(pdd_entry->NodeWWN, tq->node_name, WWN_SIZE);
			memcpy(pdd_entry->PortWWN, tq->port_name, WWN_SIZE);

			for (b = 0; b < 3 ; b++)
				pdd_entry->PortID[b] = 0;

			/* assume fabric dev so api won't translate
			 * the portid from loopid */
			pdd_entry->ControlFlags = EXT_DEF_GET_FABRIC_DEVICE;

			pdd_entry->TargetAddress.Bus    = 0;
			pdd_entry->TargetAddress.Target = idx;
			pdd_entry->TargetAddress.Lun    = 0;
			pdd_entry->DeviceFlags          = 0;
			pdd_entry->LoopID               = 0;
			pdd_entry->BaseLunNumber        = 0;

			current_offset = *pentry_cnt *
			    sizeof(EXT_DEVICEDATAENTRY);

			transfer_size = sizeof(EXT_DEVICEDATAENTRY);

			/* now copy up this dd_entry to user */
			usr_temp = (uint8_t *)pstart_of_entry_list +
			    current_offset;
			kernel_tmp = (uint8_t *)pdd_entry;
			ret = copy_to_user(usr_temp, kernel_tmp,
			    transfer_size);
			if (ret) {
				*ret_status = EXT_STATUS_COPY_ERR;
				DEBUG9_10(printk("%s(%ld): inst=%ld "
				    "ERROR copy rsp list buffer.\n",
				    __func__, ha->host_no,
				    ha->instance));
				ret = -EFAULT;
				break;
			} else {
				*pentry_cnt+=1;
			}
		}
		if (ret || *ret_status)
			break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting. ret=%d.\n", __func__,
	    ha->host_no, ha->instance, ret));

	return (ret);
}

/*
 * qla2x00_query_driver
 *	Handles EXT_SC_QUERY_DRIVER subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_driver(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	transfer_size;
	EXT_DRIVER	*pdriver_prop;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pdriver_prop,
	    sizeof(EXT_DRIVER))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DRIVER)));
		return (ret);
	}

	sprintf(pdriver_prop->Version, qla2x00_version_str);
	pdriver_prop->NumOfBus = MAX_BUSES;
	pdriver_prop->TargetsPerBus = MAX_FIBRE_DEVICES;
	pdriver_prop->LunsPerTarget = MAX_LUNS;
	pdriver_prop->MaxTransferLen  = 0xffffffff;
	pdriver_prop->MaxDataSegments = ha->host->sg_tablesize;

	if (ha->flags.enable_64bit_addressing == 1)
		pdriver_prop->DmaBitAddresses = 64;
	else
		pdriver_prop->DmaBitAddresses = 32;

	if (pext->ResponseLen < sizeof(EXT_DRIVER))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DRIVER);

	/* now copy up the ISP to user */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pdriver_prop;
 	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
 	if (ret) {
 		pext->Status = EXT_STATUS_COPY_ERR;
 		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
 		    __func__, ha->host_no, ha->instance));
 		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
 	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance));

 	return (ret);
}

/*
 * qla2x00_query_fw
 *	Handles EXT_SC_QUERY_FW subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_query_fw(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
 	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	transfer_size;
 	EXT_FW		*pfw_prop;

 	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
 	    __func__, ha->host_no, ha->instance));

 	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pfw_prop,
 	    sizeof(EXT_FW))) {
 		/* not enough memory */
 		pext->Status = EXT_STATUS_NO_MEMORY;
 		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
 		    "size requested=%ld.\n",
 		    __func__, ha->host_no, ha->instance,
 		    (ulong)sizeof(EXT_FW)));
 		return (ret);
 	}

	pfw_prop->Version[0] = ha->fw_major_version;
	pfw_prop->Version[1] = ha->fw_minor_version;
	pfw_prop->Version[2] = ha->fw_subminor_version;

	transfer_size = sizeof(EXT_FW);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pfw_prop;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

static int
qla2x00_msiocb_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext, int cmd,
    int mode)
{
	int		ret = 0;
	fc_lun_t	*ptemp_fclun = NULL;	/* buf from scrap mem */
	fc_port_t	*ptemp_fcport = NULL;	/* buf from scrap mem */
	struct scsi_cmnd *pscsi_cmd = NULL;	/* buf from scrap mem */
	struct scsi_device *pscsi_dev = NULL;	/* buf from scrap mem */
	struct request *request = NULL;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* check on current topology */
	if ((ha->current_topology != ISP_CFG_F) &&
	    (ha->current_topology != ISP_CFG_FL)) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR not in F/FL mode\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	if (ha->ioctl_mem_size <= 0) {
		if (qla2x00_get_new_ioctl_dma_mem(ha,
		    QLA_INITIAL_IOCTLMEM_SIZE) != QLA_SUCCESS) {

			DEBUG9_10(printk("%s: ERROR cannot alloc DMA "
			    "buffer size=%x.\n",
			    __func__, QLA_INITIAL_IOCTLMEM_SIZE));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qla2x00_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QLA_SUCCESS) {

			DEBUG9_10(printk("%s: ERROR cannot alloc requested"
			    "DMA buffer size %x.\n",
			    __func__, pext->ResponseLen));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}

		DEBUG9(printk("%s(%ld): inst=%ld rsp buf length larger than "
		    "existing size. Additional mem alloc successful.\n",
		    __func__, ha->host_no, ha->instance));
	}

	DEBUG9(printk("%s(%ld): inst=%ld req buf verified.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi_cmd,
	    sizeof(struct scsi_cmnd))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "cmd size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_cmnd)));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi_dev,
	    sizeof(struct scsi_device))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "cmd size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_device)));
		return (ret);
	}

	pscsi_cmd->device = pscsi_dev;

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&request,
	    sizeof(struct request))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct request)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->request = request;
	pscsi_cmd->request->nr_hw_segments = 1;

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptemp_fcport,
	    sizeof(fc_port_t))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "fcport size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(fc_port_t)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptemp_fclun,
	    sizeof(fc_lun_t))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "fclun size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(fc_lun_t)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* initialize */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	if (pscsi_cmd->timeout_per_command == 0)
		pscsi_cmd->timeout_per_command  = (ql2xioctltimeout + 3) * HZ;

	switch (cmd) {
	case EXT_CC_SEND_FCCT_PASSTHRU:
		DEBUG9(printk("%s: got CT passthru cmd.\n", __func__));
		ret = qla2x00_send_fcct(ha, pext, pscsi_cmd, ptemp_fcport,
		    ptemp_fclun, mode);
		break;
	case EXT_CC_SEND_ELS_PASSTHRU:
		DEBUG9(printk("%s: got ELS passthru cmd.\n", __func__));
		if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
			ret = qla2x00_send_els_passthru(ha, pext, pscsi_cmd,
			    ptemp_fcport, ptemp_fclun, mode);
			break;
		}
		/*FALLTHROUGH */
	default:
		DEBUG9_10(printk("%s: got invalid cmd.\n", __func__));
		break;
	}

	qla2x00_free_ioctl_scrap_mem(ha);
	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_send_els_passthru
 *	Passes the ELS command down to firmware as MSIOCB and
 *	copies the response back when it completes.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_send_els_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *ptmp_fcport, fc_lun_t *ptmp_fclun,
    int mode)
{
	int		ret = 0;

	uint8_t		invalid_wwn = 0;
	uint8_t		*ptmp_stat;
	uint8_t		*pusr_req_buf;
	uint8_t		*presp_payload;
	uint32_t	payload_len;
	uint32_t	usr_req_len;

	int		found;
	uint16_t	next_loop_id;
	fc_port_t	*fcport;

	EXT_ELS_PT_REQ	*pels_pt_req;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	usr_req_len = pext->RequestLen - sizeof(EXT_ELS_PT_REQ);
	if (usr_req_len > ha->ioctl_mem_size) {
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR ReqLen too big=%x.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen));

		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pels_pt_req,
	    sizeof(EXT_ELS_PT_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "els_pt_req size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_ELS_PT_REQ)));
		return (ret);
	}

	/* copy request buffer */
	
	ret = copy_from_user(pels_pt_req, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(EXT_ELS_PT_REQ));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of struct failed (%d).\n",
		    __func__, ha->host_no, ha->instance, ret));

		return (-EFAULT);
	}

	pusr_req_buf = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode) + sizeof(EXT_ELS_PT_REQ);
	
	ret = copy_from_user(ha->ioctl_mem, pusr_req_buf, usr_req_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of request buf failed (%d).\n",
		    __func__, ha->host_no, ha->instance, ret));

		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after copy request.\n",
	    __func__, ha->host_no, ha->instance));
	
	/* check on loop down (1) */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) {

		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld before dest port validation- loop not "
		    "ready; cannot proceed.\n",
		    __func__, ha->host_no, ha->instance));

		pext->Status = EXT_STATUS_BUSY;

		return (ret);
	}

	/*********************************/
	/* Validate the destination port */
	/*********************************/

	/* first: WWN cannot be zero if no PID is specified */
	invalid_wwn = qla2x00_is_wwn_zero(pels_pt_req->WWPN);
	if (invalid_wwn && !(pels_pt_req->ValidMask & EXT_DEF_PID_VALID)) {
		/* error: both are not set. */
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR no valid WWPN/PID\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	/* second: it cannot be the local/current HBA itself */
	if (!invalid_wwn) {
		if (memcmp(ha->port_name, pels_pt_req->WWPN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {

			/* local HBA specified. */

			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR local HBA's "
			    "WWPN found.\n",
			    __func__, ha->host_no, ha->instance));

			return (ret);
		}
	} else { /* using PID */
		if (pels_pt_req->Id[1] == ha->d_id.r.d_id[2]
		    && pels_pt_req->Id[2] == ha->d_id.r.d_id[1]
		    && pels_pt_req->Id[3] == ha->d_id.r.d_id[0]) {

			/* local HBA specified. */

			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR local HBA's "
			    "PID found.\n",
			    __func__, ha->host_no, ha->instance));

			return (ret);
		}
	}

	/************************/
	/* Now find the loop ID */
	/************************/

	found = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_INITIATOR ||
		    fcport->port_type != FCT_TARGET)
			continue;

		if (!invalid_wwn) {
			/* search with WWPN */
			if (memcmp(pels_pt_req->WWPN, fcport->port_name,
			    EXT_DEF_WWN_NAME_SIZE))
				continue;
		} else {
			/* search with PID */
			if (pels_pt_req->Id[1] != fcport->d_id.r.d_id[2]
			    || pels_pt_req->Id[2] != fcport->d_id.r.d_id[1]
			    || pels_pt_req->Id[3] != fcport->d_id.r.d_id[0])
				continue;
		}

		found++;
	}

	if (!found) {
		/* invalid WWN or PID specified */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR WWPN/PID invalid.\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	/* If this is for a host device, check if we need to perform login */
	if (fcport->port_type == FCT_INITIATOR &&
	    fcport->loop_id >= ha->last_loop_id) {

		next_loop_id = 0;
		ret = qla2x00_fabric_login(ha, fcport, &next_loop_id);
		if (ret != QLA_SUCCESS) {
			/* login failed. */
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR login to "
			    "host port failed. loop_id=%02x pid=%02x%02x%02x "
			    "ret=%d.\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->loop_id, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa, ret));

			return (ret);
		}
	}

	/* queue command */
	pels_pt_req->Lid = fcport->loop_id;

	if ((ret = qla2x00_ioctl_ms_queuecommand(ha, pext, pscsi_cmd,
	    ptmp_fcport, ptmp_fclun, pels_pt_req))) {
		return (ret);
	}

	/* check on data returned */
	ptmp_stat = (uint8_t *)ha->ioctl_mem + FC_HEADER_LEN;

	if (*ptmp_stat == ELS_STAT_LS_RJT) {
		payload_len = FC_HEADER_LEN + ELS_RJT_LENGTH;

	} else if (*ptmp_stat == ELS_STAT_LS_ACC) {
		payload_len = pext->ResponseLen - sizeof(EXT_ELS_PT_REQ);

	} else {
		/* invalid. just copy the status word. */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid stat "
		    "returned =0x%x.\n",
		    __func__, ha->host_no, ha->instance, *ptmp_stat));

		payload_len = FC_HEADER_LEN + 4;
	}

	DEBUG9(printk("%s(%ld): inst=%ld data dump-\n",
	    __func__, ha->host_no, ha->instance));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)ptmp_stat,
	    pext->ResponseLen - sizeof(EXT_ELS_PT_REQ) - FC_HEADER_LEN));
	
	/* Verify response buffer to be written */
	/* The data returned include FC frame header */
	presp_payload = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode) + sizeof(EXT_ELS_PT_REQ);

	/* copy back data returned to response buffer */
	ret = copy_to_user(presp_payload, ha->ioctl_mem, payload_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_send_fcct
 *	Passes the FC CT command down to firmware as MSIOCB and
 *	copies the response back when it completes.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_send_fcct(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *ptmp_fcport, fc_lun_t *ptmp_fclun,
    int mode)
{
	int		ret = 0;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (pext->RequestLen > ha->ioctl_mem_size) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR ReqLen too big=%x.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen));

		return (ret);
	}

	/* copy request buffer */
	ret = copy_from_user(ha->ioctl_mem, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf. ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));

		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after copy request.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_mgmt_svr_login(ha) != QLA_SUCCESS) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;

		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR login to MS.\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	DEBUG9(printk("%s(%ld): success login to MS.\n",
	    __func__, ha->host_no));

	/* queue command */
	if ((ret = qla2x00_ioctl_ms_queuecommand(ha, pext, pscsi_cmd,
	    ptmp_fcport, ptmp_fclun, NULL))) {
		return (ret);
	}

	if ((CMD_COMPL_STATUS(pscsi_cmd) != 0 &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_UNDERRUN &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_OVERRUN)||
	    CMD_ENTRY_STATUS(pscsi_cmd) != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld cmd returned error=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi_cmd)));
		pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	/* sending back data returned from Management Server */
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, pext->ResponseLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

static int
qla2x00_ioctl_ms_queuecommand(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *pfcport, fc_lun_t *pfclun,
    EXT_ELS_PT_REQ *pels_pt_req)
{
	int		ret = 0;
	int		tmp_rval = 0;
	os_lun_t	*plq;
	os_tgt_t	*ptq;

	srb_t		*sp = NULL;

	/* alloc sp */
	if ((sp = qla2x00_get_new_sp(ha)) == NULL) {

		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s: ERROR cannot alloc sp %p.\n",
		    __func__, sp));

		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after alloc sp.\n",
	    __func__, ha->host_no, ha->instance));

	DEBUG9(printk("%s(%ld): ioctl_tq=%p ioctl_lq=%p.\n",
	    __func__, ha->host_no, ha->ioctl->ioctl_tq, ha->ioctl->ioctl_lq));

	/* setup sp for this command */
	ptq = ha->ioctl->ioctl_tq;
	plq = ha->ioctl->ioctl_lq;

	DEBUG9(printk("%s(%ld): pfclun=%p pfcport=%p pscsi_cmd=%p.\n",
	    __func__, ha->host_no, pfclun, pfcport, pscsi_cmd));

	sp->cmd = pscsi_cmd;
	sp->flags = SRB_IOCTL;
	sp->lun_queue = plq;
	sp->tgt_queue = ptq;
	pfclun->fcport = pfcport;
	pfclun->lun = 0;
	plq->fclun = pfclun;
	plq->fclun->fcport->ha = ha;

	DEBUG9(printk("%s(%ld): pscsi_cmd->device=%p.\n",
	    __func__, ha->host_no, pscsi_cmd->device));

	/* init scsi_cmd */
	pscsi_cmd->device->host = ha->host;
	pscsi_cmd->scsi_done = qla2x00_msiocb_done;

	/* check on loop down (2)- check again just before sending cmd out. */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) {

		DEBUG9_10(printk("%s(%ld): inst=%ld before issue cmd- loop "
		    "not ready.\n",
		    __func__, ha->host_no, ha->instance));

		pext->Status = EXT_STATUS_BUSY;

		atomic_set(&sp->ref_count, 0);
		add_to_free_queue (ha, sp);

		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld going to issue command.\n",
	    __func__, ha->host_no, ha->instance));

	tmp_rval = qla2x00_start_ms_cmd(ha, pext, sp, pels_pt_req);

	DEBUG9(printk("%s(%ld): inst=%ld after issue command.\n",
	    __func__, ha->host_no, ha->instance));

	if (tmp_rval != 0) {
		/* We waited and post function did not get called */
		DEBUG9_10(printk("%s(%ld): inst=%ld command timed out.\n",
		    __func__, ha->host_no, ha->instance));

		pext->Status = EXT_STATUS_MS_NO_RESPONSE;

		atomic_set(&sp->ref_count, 0);
		add_to_free_queue (ha, sp);

		return (ret);
	}

	return (ret);
}


/*
 * qla2x00_start_ms_cmd
 *	Allocates an MSIOCB request pkt and sends out the passthru cmd.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_start_ms_cmd(scsi_qla_host_t *ha, EXT_IOCTL *pext, srb_t *sp,
    EXT_ELS_PT_REQ *pels_pt_req)
{
#define	ELS_REQUEST_RCTL	0x22
#define ELS_REPLY_RCTL		0x23

	uint32_t	usr_req_len;
	uint32_t	usr_resp_len;

	ms_iocb_entry_t		*pkt;
	unsigned long		cpu_flags = 0;


	/* get spin lock for this operation */
	spin_lock_irqsave(&ha->hardware_lock, cpu_flags);

	/* Get MS request packet. */
	pkt = (ms_iocb_entry_t *)qla2x00_ms_req_pkt(ha, sp);
	if (pkt == NULL) {
		/* release spin lock and return error. */
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld MSIOCB PT - could not get "
		    "Request Packet.\n", __func__, ha->host_no, ha->instance));
		return (QLA_MEMORY_ALLOC_FAILED);
	}

	usr_req_len = pext->RequestLen;
	usr_resp_len = pext->ResponseLen;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		struct ct_entry_24xx *ct_pkt;
		struct els_entry_24xx *els_pkt;

		ct_pkt = (struct ct_entry_24xx *)pkt;
		els_pkt = (struct els_entry_24xx *)pkt;

		if (pels_pt_req != NULL) {
			/* ELS Passthru */
			usr_req_len -= sizeof(EXT_ELS_PT_REQ);
			usr_resp_len -= sizeof(EXT_ELS_PT_REQ);

			els_pkt->entry_type = ELS_IOCB_TYPE;
			els_pkt->entry_count = 1;
			els_pkt->nport_handle = cpu_to_le16(pels_pt_req->Lid);
			els_pkt->tx_dsd_count = __constant_cpu_to_le16(1);
			els_pkt->rx_dsd_count = __constant_cpu_to_le16(1);
			els_pkt->rx_byte_count = cpu_to_le32(usr_resp_len);
			els_pkt->tx_byte_count = cpu_to_le32(usr_req_len);
			els_pkt->sof_type = EST_SOFI3; /* assume class 3 */
			els_pkt->opcode = 0;
			els_pkt->control_flags = 0;

			if (pext->ResponseLen == 0) {
				memcpy(els_pkt->port_id, &pels_pt_req->Id[1],
				    3);
			}

			els_pkt->tx_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			els_pkt->tx_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			els_pkt->tx_len = els_pkt->tx_byte_count;
			els_pkt->rx_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			els_pkt->rx_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			els_pkt->rx_len = els_pkt->rx_byte_count;
		} else {
			/* CT Passthru */
			ct_pkt->entry_type = CT_IOCB_TYPE;
			ct_pkt->entry_count = 1;
			ct_pkt->nport_handle =
			    cpu_to_le16(ha->mgmt_svr_loop_id);
			ct_pkt->timeout = cpu_to_le16(ql2xioctltimeout);
			ct_pkt->cmd_dsd_count = __constant_cpu_to_le16(1);
			ct_pkt->rsp_dsd_count = __constant_cpu_to_le16(1);
			ct_pkt->rsp_byte_count = cpu_to_le32(usr_resp_len);
			ct_pkt->cmd_byte_count = cpu_to_le32(usr_req_len);
			ct_pkt->dseg_0_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_0_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_0_len = ct_pkt->cmd_byte_count;
			ct_pkt->dseg_1_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_1_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_1_len = ct_pkt->rsp_byte_count;
		}
	} else {
		pkt->entry_type  = MS_IOCB_TYPE;
		pkt->entry_count = 1;

		if (pels_pt_req != NULL) {
			/* process ELS passthru command */
			usr_req_len -= sizeof(EXT_ELS_PT_REQ);
			usr_resp_len -= sizeof(EXT_ELS_PT_REQ);

			/* ELS passthru enabled */
			pkt->control_flags = cpu_to_le16(BIT_15);
			SET_TARGET_ID(ha, pkt->loop_id, pels_pt_req->Lid);
			pkt->type    = 1; /* ELS frame */

			if (pext->ResponseLen != 0) {
				pkt->r_ctl = ELS_REQUEST_RCTL;
				pkt->rx_id = 0;
			} else {
				pkt->r_ctl = ELS_REPLY_RCTL;
				pkt->rx_id =
				    cpu_to_le16(pels_pt_req->Rxid);
			}
		} else {
			usr_req_len = pext->RequestLen;
			usr_resp_len = pext->ResponseLen;
			SET_TARGET_ID(ha, pkt->loop_id, ha->mgmt_svr_loop_id);
		}

		DEBUG9_10(printk("%s(%ld): inst=%ld using loop_id=%02x "
		    "req_len=%d, resp_len=%d. Initializing pkt.\n",
		    __func__, ha->host_no, ha->instance,
		    pkt->loop_id.extended, usr_req_len, usr_resp_len));

		pkt->timeout = cpu_to_le16(ql2xioctltimeout);
		pkt->cmd_dsd_count = __constant_cpu_to_le16(1);
		pkt->total_dsd_count = __constant_cpu_to_le16(2);
		pkt->rsp_bytecount = cpu_to_le32(usr_resp_len);
		pkt->req_bytecount = cpu_to_le32(usr_req_len);

		/*
		 * Loading command payload address. user request is assumed
		 * to have been copied to ioctl_mem.
		 */
		pkt->dseg_req_address[0] = cpu_to_le32(LSD(ha->ioctl_mem_phys));
		pkt->dseg_req_address[1] = cpu_to_le32(MSD(ha->ioctl_mem_phys));
		pkt->dseg_req_length = cpu_to_le32(usr_req_len);

		/* loading response payload address */
		pkt->dseg_rsp_address[0] = cpu_to_le32(LSD(ha->ioctl_mem_phys));
		pkt->dseg_rsp_address[1] =cpu_to_le32(MSD(ha->ioctl_mem_phys));
		pkt->dseg_rsp_length = cpu_to_le32(usr_resp_len);
	}

	/* set flag to indicate IOCTL MSIOCB cmd in progress */
	ha->ioctl->MSIOCB_InProgress = 1;
	ha->ioctl->ioctl_tov = pkt->timeout + 1; /* 1 second more */

	/* prepare for receiving completion. */
	qla2x00_ioctl_sem_init(ha);

	/* Time the command via our standard driver-timer */
	if ((sp->cmd->timeout_per_command / HZ) >= ql2xcmdtimermin)
		qla2x00_add_timer_to_cmd(sp,
		    (sp->cmd->timeout_per_command / HZ) - QLA_CMD_TIMER_DELTA);
	else
		sp->flags |= SRB_NO_TIMER;

	/* Issue command to ISP */
	qla2x00_isp_cmd(ha);

	ha->ioctl->cmpl_timer.expires = jiffies + ha->ioctl->ioctl_tov * HZ;
	add_timer(&ha->ioctl->cmpl_timer);

	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware_lock.\n",
	    __func__, ha->host_no, ha->instance));
	spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

	DEBUG9(printk("%s(%ld): inst=%ld sleep for completion.\n",
	    __func__, ha->host_no, ha->instance));

	down(&ha->ioctl->cmpl_sem);

	del_timer(&ha->ioctl->cmpl_timer);

	if (ha->ioctl->MSIOCB_InProgress == 1) {
	 	DEBUG9_10(printk("%s(%ld): inst=%ld timed out. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return QLA_FUNCTION_FAILED;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return QLA_SUCCESS;
}

/*
 * qla2x00_wwpn_to_scsiaddr
 *	Handles the EXT_CC_WWPN_TO_SCSIADDR command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_wwpn_to_scsiaddr(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	fc_port_t	*tgt_fcport;
	os_tgt_t	*tq;
	uint8_t		tmp_wwpn[EXT_DEF_WWN_NAME_SIZE];
	uint32_t	b, tgt, l;
	EXT_SCSI_ADDR	tmp_addr;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (pext->RequestLen != EXT_DEF_WWN_NAME_SIZE ||
	    pext->ResponseLen < sizeof(EXT_SCSI_ADDR)) {
		/* error */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid WWN buffer size %d "
		    "received.\n",
		    __func__, ha->host_no, ha->instance, pext->ResponseLen));
		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	ret = copy_from_user(tmp_wwpn, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy_from_user "
		    "failed(%d) on request buf.\n",
		    __func__, ha->host_no, ha->instance, ret));
		pext->Status = EXT_STATUS_COPY_ERR;
		return (-EFAULT);
	}

	tq = NULL;
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if (ha->otgt[tgt] == NULL) {
			continue;
		}

		tq = ha->otgt[tgt];
		if (tq->fcport == NULL) {
			break;
		}

		tgt_fcport = tq->fcport;
		if (memcmp(tmp_wwpn, tgt_fcport->port_name,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			break;
		}
	}

	if (tq == NULL || tgt >= MAX_TARGETS) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld target dev not found. "
		    "tq=%p, tgt=%x.\n", __func__, ha->host_no, ha->instance,
		    tq, tgt));
		return (ret);
	}

	if (tq->fcport == NULL) { 	/* dg 08/14/01 */
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld target port not found. "
		    "tq=%p, tgt=%x.\n",
		    __func__, ha->host_no, ha->instance, tq, tgt));
		return (ret);
	}	

	/* Currently we only have bus 0 and no translation on LUN */
	b = 0;
	l = 0;

	/*
	 * Return SCSI address. Currently no translation is done for
	 * LUN.
	 */
	tmp_addr.Bus = b;
	tmp_addr.Target = tgt;
	tmp_addr.Lun = l;
	if (pext->ResponseLen > sizeof(EXT_SCSI_ADDR))
		pext->ResponseLen = sizeof(EXT_SCSI_ADDR);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &tmp_addr, pext->ResponseLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		return (-EFAULT);
	}

	DEBUG9(printk(KERN_INFO
	    "%s(%ld): Found t%d l%d for %02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no,
	    tmp_addr.Target, tmp_addr.Lun,
	    tmp_wwpn[0], tmp_wwpn[1], tmp_wwpn[2], tmp_wwpn[3],
	    tmp_wwpn[4], tmp_wwpn[5], tmp_wwpn[6], tmp_wwpn[7]));

	pext->Status = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_ioctl_passthru_rsp_handling
 *      Handles the return status for IOCTL passthru commands.
 *
 * Input:
 *      ha = adapter state pointer.
 *      pext = EXT_IOCTL structure pointer.
 *      pscsi_cmd = pointer to scsi command.
 *
 * Returns:
 *      0 = success
 *      others = errno value
 *
 * Context:
 *      Kernel context.
 */
static inline int
qla2x00_ioctl_passthru_rsp_handling(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd)
{
	int ret = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (ha->ioctl->SCSIPT_InProgress == 1) {
		printk(KERN_WARNING
		    "qla2x00: scsi%ld ERROR passthru command timeout.\n",
		    ha->host_no);
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		ret = 1;
		return (ret);
	}

	if (CMD_COMPL_STATUS(pscsi_cmd) == (int)IOCTL_INVALID_STATUS) {
		DEBUG9(printk("%s(%ld): inst=%ld ERROR - cmd not completed.\n",
		    __func__, ha->host_no, ha->instance));
		pext->Status = EXT_STATUS_ERR;
		ret = 1;
		return (ret);
	}

	switch (CMD_COMPL_STATUS(pscsi_cmd)) {
	case CS_INCOMPLETE:
	case CS_ABORTED:
	case CS_PORT_UNAVAILABLE:
	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
	case CS_TIMEOUT:
		DEBUG9_10(printk("%s(%ld): inst=%ld cs err = %x.\n",
		__func__, ha->host_no, ha->instance,
		CMD_COMPL_STATUS(pscsi_cmd)));
		pext->Status = EXT_STATUS_BUSY;
		ret = 1;
		return (ret);
	case CS_RESET:
	case CS_QUEUE_FULL:
		pext->Status = EXT_STATUS_ERR;
		break;
	case CS_DATA_OVERRUN:
		pext->Status = EXT_STATUS_DATA_OVERRUN;
		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): inst=%ld return overrun.\n",
		    __func__, ha->host_no, ha->instance));
		break;
	case CS_DATA_UNDERRUN:
		pext->Status = EXT_STATUS_DATA_UNDERRUN;
		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): inst=%ld return underrun.\n",
		    __func__, ha->host_no, ha->instance));
		if (CMD_SCSI_STATUS(pscsi_cmd) & SS_RESIDUAL_UNDER) {
			pext->Status = EXT_STATUS_OK;
		}
		break;
	}

	if (CMD_COMPL_STATUS(pscsi_cmd) == CS_COMPLETE &&
	    CMD_SCSI_STATUS(pscsi_cmd) == 0) {
		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): Correct completion inst=%ld\n",
		    __func__, ha->host_no, ha->instance));

	} else {
		DEBUG9_10(printk(KERN_INFO "%s(%ld): inst=%ld scsi err. "
		    "host status =0x%x, scsi status = 0x%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi_cmd), CMD_SCSI_STATUS(pscsi_cmd)));

		if (CMD_SCSI_STATUS(pscsi_cmd) & SS_CHECK_CONDITION) {
			pext->Status = EXT_STATUS_SCSI_STATUS;
			pext->DetailStatus = CMD_SCSI_STATUS(pscsi_cmd) & 0xff;
		}
	}
	return (ret);
}

/*
 * qla2x00_scsi_passthru
 *	Handles all subcommands of the EXT_CC_SEND_SCSI_PASSTHRU command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_scsi_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	struct scsi_cmnd *pscsi_cmd = NULL;
	struct scsi_device *pscsi_device = NULL;
	struct request *request = NULL;

	DEBUG9(printk("%s(%ld): entered.\n",
	    __func__, ha->host_no));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi_cmd,
	    sizeof(struct scsi_cmnd))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_cmnd)));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi_device,
	    sizeof(struct scsi_device))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_device)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->device = pscsi_device;

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&request,
	    sizeof(struct request))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct request)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->request = request;
	pscsi_cmd->request->nr_hw_segments = 1;

	switch(pext->SubCode) {
	case EXT_SC_SEND_SCSI_PASSTHRU:
		DEBUG9(printk("%s(%ld): got SCSI passthru cmd.\n",
		    __func__, ha->host_no));
		ret = qla2x00_sc_scsi_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
	case EXT_SC_SEND_FC_SCSI_PASSTHRU:
		DEBUG9(printk("%s(%ld): got FC SCSI passthru cmd.\n",
		    __func__, ha->host_no));
		ret = qla2x00_sc_fc_scsi_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
	case EXT_SC_SCSI3_PASSTHRU:
		DEBUG9(printk("%s(%ld): got SCSI3 passthru cmd.\n",
		    __func__, ha->host_no));
		ret = qla2x00_sc_scsi3_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
	default:
		DEBUG9_10(printk("%s: got invalid cmd.\n", __func__));
		break;
	}

	qla2x00_free_ioctl_scrap_mem(ha);
	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no));

	return (ret);
}

/**************************************************************************
*   qla2x00_check_tgt_status
*
* Description:
*     Checks to see if the target or loop is down.
*
* Input:
*     cmd - pointer to Scsi cmd structure
*
* Returns:
*   1 - if target is present
*   0 - if target is not present
*
**************************************************************************/
static int
qla2x00_check_tgt_status(scsi_qla_host_t *ha, struct scsi_cmnd *cmd)
{
	os_lun_t        *lq;
	unsigned int	b, t, l;
	fc_port_t	*fcport;

	/* Generate LU queue on bus, target, LUN */
	b = cmd->device->channel;
	t = cmd->device->id;
	l = cmd->device->lun;

	if ((lq = GET_LU_Q(ha,t,l)) == NULL) {
		return (QLA_FUNCTION_FAILED);
	}

	fcport = lq->fclun->fcport;

	if (TGT_Q(ha, t) == NULL ||
	    l >= ha->max_luns ||
	    atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD ||
	    (!atomic_read(&ha->loop_down_timer) &&
		atomic_read(&ha->loop_state) == LOOP_DOWN) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    atomic_read(&ha->loop_state) != LOOP_READY) {

		DEBUG(printk(KERN_INFO
		    "scsi(%ld:%2d:%2d:%2d): %s connection is down\n",
		    ha->host_no,
		    b, t, l,
		    __func__));

		cmd->result = DID_NO_CONNECT << 16;
		return (QLA_FUNCTION_FAILED);
	}
	return (QLA_SUCCESS);
}

/**************************************************************************
*   qla2x00_check_port_status
*
* Description:
*     Checks to see if the port or loop is down.
*
* Input:
*     fcport - pointer to fc_port_t structure.
*
* Returns:
*   1 - if port is present
*   0 - if port is not present
*
**************************************************************************/
static int
qla2x00_check_port_status(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	if (fcport == NULL) {
		return (QLA_FUNCTION_FAILED);
	}

	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD) {
		return (QLA_FUNCTION_FAILED);
	}

	if ((atomic_read(&fcport->state) != FCS_ONLINE) ||
	    (!atomic_read(&ha->loop_down_timer) &&
		atomic_read(&ha->loop_state) == LOOP_DOWN) ||
	    (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    atomic_read(&ha->loop_state) != LOOP_READY) {

		DEBUG(printk(KERN_INFO
		    "scsi(%ld): Connection is down. fcport=%p.\n",
		    ha->host_no, fcport));

		return (QLA_BUSY);
	}

	return (QLA_SUCCESS);
}

static int
qla2x00_ioctl_scsi_queuecommand(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, struct scsi_device *pscsi_dev,
    fc_port_t *pfcport, fc_lun_t *pfclun)
{
	int		ret = 0;
	int		ret2 = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	lun = 0, tgt = 0;
#if defined(QL_DEBUG_LEVEL_9)
	uint32_t	b, t, l;
#endif
	os_lun_t	*lq = NULL;
	os_tgt_t	*tq = NULL;
	srb_t		*sp = NULL;


	DEBUG9(printk("%s(%ld): entered.\n",
	    __func__, ha->host_no));

	if ((sp = qla2x00_get_new_sp(ha)) == NULL) {

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc sp.\n",
		    __func__, ha->host_no, ha->instance));

		pext->Status = EXT_STATUS_NO_MEMORY;
		return (QLA_FUNCTION_FAILED);
	}

	switch(pext->SubCode) {
	case EXT_SC_SEND_SCSI_PASSTHRU:

		tgt = pscsi_cmd->device->id;
		lun = pscsi_cmd->device->lun;

		tq = (os_tgt_t *)TGT_Q(ha, tgt);
		lq = (os_lun_t *)LUN_Q(ha, tgt, lun);

		break;
	case EXT_SC_SEND_FC_SCSI_PASSTHRU:
		if (pfcport == NULL || pfclun == NULL) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			DEBUG9_10(printk("%s(%ld): inst=%ld received invalid "
			    "pointers. fcport=%p fclun=%p.\n",
			    __func__, ha->host_no, ha->instance, pfcport, pfclun));
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);
			return (QLA_FUNCTION_FAILED);
		}

		if (pscsi_cmd->cmd_len != 6 && pscsi_cmd->cmd_len != 0x0A &&
		    pscsi_cmd->cmd_len != 0x0C && pscsi_cmd->cmd_len != 0x10) {
			DEBUG9_10(printk(KERN_WARNING
			    "%s(%ld): invalid Cdb Length 0x%x received.\n",
			    __func__, ha->host_no,
			    pscsi_cmd->cmd_len));
			pext->Status = EXT_STATUS_INVALID_PARAM;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);
			return (QLA_FUNCTION_FAILED);
		}
		tq = ha->ioctl->ioctl_tq;
		lq = ha->ioctl->ioctl_lq;

		break;
	case EXT_SC_SCSI3_PASSTHRU:
		if (pfcport == NULL || pfclun == NULL) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			DEBUG9_10(printk("%s(%ld): inst=%ld received invalid "
			    "pointers. fcport=%p fclun=%p.\n",
			    __func__,
			    ha->host_no, ha->instance, pfcport, pfclun));
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);
			return (QLA_FUNCTION_FAILED);
		}

		tq = ha->ioctl->ioctl_tq;
		lq = ha->ioctl->ioctl_lq;

		break;
	default:
		break;
	}

	sp->ha                = ha;
	sp->cmd               = pscsi_cmd;
	sp->flags             = SRB_IOCTL;

	/* set local fc_scsi_cmd's sp pointer to sp */
	CMD_SP(pscsi_cmd)  = (void *) sp;

	if (pscsi_cmd->sc_data_direction == DMA_TO_DEVICE) {
		/* sending user data from pext->ResponseAdr to device */
		usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_from_user(kernel_tmp, usr_temp, pext->ResponseLen);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy "
			    "failed(%d) on rsp buf.\n",
			    __func__, ha->host_no, ha->instance, ret));
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);

			return (-EFAULT);
		}
	}

	pscsi_cmd->device->host    = ha->host;

	/* mark this as a special delivery and collection command */
	pscsi_cmd->scsi_done = qla2x00_scsi_pt_done;
	pscsi_cmd->device->tagged_supported = 0;
	pscsi_cmd->use_sg               = 0; /* no ScatterGather */
	pscsi_cmd->request_bufflen      = pext->ResponseLen;
	pscsi_cmd->request_buffer       = ha->ioctl_mem;
	if (pscsi_cmd->timeout_per_command == 0)
		pscsi_cmd->timeout_per_command  = ql2xioctltimeout * HZ;

	if (tq && lq) {
		if (pext->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
			pfcport = lq->fclun->fcport;
			pfclun = lq->fclun;

			if (pfcport == NULL || pfclun == NULL) {
				pext->Status = EXT_STATUS_DEV_NOT_FOUND;
				DEBUG9_10(printk("%s(%ld): inst=%ld scsi pt "
				    "rcvd invalid ptrs. fcport=%p fclun=%p.\n",
				    __func__, ha->host_no, ha->instance,
				    pfcport, pfclun));
				atomic_set(&sp->ref_count, 0);
				add_to_free_queue (ha, sp);
				return (QLA_FUNCTION_FAILED);
			}

		} else {
			if (pext->SubCode == EXT_SC_SCSI3_PASSTHRU)
				/* The LUN value is of FCP LUN format */
				tq->olun[pfclun->lun & 0xff] = lq;
			else
				tq->olun[pfclun->lun] = lq;

			tq->ha = ha;
			lq->fclun = pfclun;
		}

		sp->lun_queue = lq;
		sp->tgt_queue = tq;
		sp->fclun = pfclun;
	} else {
		/* cannot send command without a queue. force error. */
		pfcport = NULL;
		DEBUG9_10(printk("%s(%ld): error dev q not found. tq=%p lq=%p.\n",
		    __func__, ha->host_no, tq, lq));
	}

#if defined(QL_DEBUG_LEVEL_9)
	b = pscsi_cmd->device->channel;
	t = pscsi_cmd->device->id;
	l = pscsi_cmd->device->lun;

	printk("%s(%ld): ha instance=%ld tq=%p lq=%p "
	    "pfclun=%p pfcport=%p.\n",
	    __func__, ha->host_no, ha->instance, tq, lq, pfclun,
	    pfcport);
	printk("\tCDB=%02x %02x %02x %02x; b=%x t=%x l=%x.\n",
	    pscsi_cmd->cmnd[0], pscsi_cmd->cmnd[1], pscsi_cmd->cmnd[2],
	    pscsi_cmd->cmnd[3], b, t, l);
#endif

	/*
	 * Check the status of the port
	 */
	if (pext->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
		if (qla2x00_check_tgt_status(ha, pscsi_cmd)) {
			DEBUG9_10(printk("%s(%ld): inst=%ld check_tgt_status "
			    "failed.\n",
			    __func__, ha->host_no, ha->instance));
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);
			return (QLA_FUNCTION_FAILED);
		}
	} else {
		ret2 = qla2x00_check_port_status(ha, pfcport);
		if (ret2 != QLA_SUCCESS) {
			DEBUG9_10(printk("%s(%ld): inst=%ld check_port_status "
			    "failed.\n",
			    __func__, ha->host_no, ha->instance));
			if (ret2 == QLA_BUSY)
				pext->Status = EXT_STATUS_BUSY;
			else
				pext->Status = EXT_STATUS_ERR;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (ha, sp);
			return (QLA_FUNCTION_FAILED);
		}
	}

	/* set flag to indicate IOCTL SCSI PassThru in progress */
	ha->ioctl->SCSIPT_InProgress = 1;
	ha->ioctl->ioctl_tov = (int)QLA_PT_CMD_DRV_TOV;

	/* prepare for receiving completion. */
	qla2x00_ioctl_sem_init(ha);
	CMD_COMPL_STATUS(pscsi_cmd) = (int) IOCTL_INVALID_STATUS;

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld sending command.\n",
	    __func__, ha->host_no, ha->instance));

	/* Time the command via our standard driver-timer */
	if ((pscsi_cmd->timeout_per_command / HZ) >= ql2xcmdtimermin)
		qla2x00_add_timer_to_cmd(sp,
		    (pscsi_cmd->timeout_per_command / HZ) -
		    QLA_CMD_TIMER_DELTA);
	else
		sp->flags |= SRB_NO_TIMER;

	add_to_pending_queue(ha, sp);

	qla2x00_next(ha);

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no));
	return (ret);
}


/*
 * qla2x00_sc_scsi_passthru
 *	Handles EXT_SC_SEND_SCSI_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_sc_scsi_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, struct scsi_device *pscsi_device, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	i;

	uint32_t	transfer_len;

	EXT_SCSI_PASSTHRU	*pscsi_pass;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (test_bit(FAILOVER_EVENT_NEEDED, &ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
 		    __func__, ha->host_no, ha->instance));
		pext->Status = EXT_STATUS_BUSY;
 		return (ret);
 	}

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qla2x00_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QLA_SUCCESS) {
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "requested DMA buffer size %x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen));
			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi_pass,
	    sizeof(EXT_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_SCSI_PASSTHRU)));
		return (ret);
	}

	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	/* Copy request buffer */
	usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pscsi_pass;
	ret = copy_from_user(kernel_tmp, usr_temp, sizeof(EXT_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));
		return (-EFAULT);
	}

	/* set target coordinates */
	pscsi_cmd->device->id = pscsi_pass->TargetAddr.Target;
	pscsi_cmd->device->lun = pscsi_pass->TargetAddr.Lun;

	/* Verify target exists */
	if (TGT_Q(ha, pscsi_cmd->device->id) == NULL) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR tgt %d not found.\n",
		    __func__,
		    ha->host_no, ha->instance, pscsi_cmd->device->id));
		return (ret);
	}

	/* Copy over cdb */

	if (pscsi_pass->CdbLength == 6) {
		pscsi_cmd->cmd_len = 6;

	} else if (pscsi_pass->CdbLength == 10) {
		pscsi_cmd->cmd_len = 0x0A;

	} else if (pscsi_pass->CdbLength == 12) {
		pscsi_cmd->cmd_len = 0x0C;

	} else {
		printk(KERN_WARNING
		    "%s: Unsupported Cdb Length=%x.\n",
		    __func__, pscsi_pass->CdbLength);

		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	memcpy(pscsi_cmd->cmnd, pscsi_pass->Cdb, pscsi_cmd->cmd_len);

	DEBUG9(printk("%s Dump of cdb buffer:\n", __func__));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)&pscsi_cmd->cmnd[0],
	    pscsi_cmd->cmd_len));

	switch (pscsi_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pscsi_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pscsi_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pscsi_cmd->sc_data_direction = DMA_NONE;
		break;
	}

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld sending command.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_ioctl_scsi_queuecommand(ha, pext, pscsi_cmd, pscsi_device,
	    NULL, NULL)) {
		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld waiting for completion.\n",
	    __func__, ha->host_no, ha->instance));

	/* Wait for completion */
	down(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s(%ld): inst=%ld completed.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_ioctl_passthru_rsp_handling(ha, pext, pscsi_cmd))
		return (ret);

	/* copy up structure to make sense data available to user */
	pscsi_pass->SenseLength = CMD_ACTUAL_SNSLEN(pscsi_cmd);
	if (CMD_ACTUAL_SNSLEN(pscsi_cmd)) {
		for (i = 0; i < CMD_ACTUAL_SNSLEN(pscsi_cmd); i++)
			pscsi_pass->SenseData[i] = pscsi_cmd->sense_buffer[i];

		DEBUG10(printk("%s Dump of sense buffer:\n", __func__));
		DEBUG10(qla2x00_dump_buffer(
		    (uint8_t *)&pscsi_pass->SenseData[0],
		    CMD_ACTUAL_SNSLEN(pscsi_cmd)));

		usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)pscsi_pass;
		ret = copy_to_user(usr_temp, kernel_tmp,
		    sizeof(EXT_SCSI_PASSTHRU));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
			    "buffer.\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	if (pscsi_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {
		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance));

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pscsi_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pscsi_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pscsi_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): final transferlen=%d.\n",
		    __func__, ha->host_no, transfer_len));

		usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_sc_fc_scsi_passthru
 *	Handles EXT_SC_SEND_FC_SCSI_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_sc_fc_scsi_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pfc_scsi_cmd, struct scsi_device *pfc_scsi_device,
    int mode)
{
	int			ret = 0;
	int			port_found, lun_found;
	fc_lun_t		temp_fclun;
	struct list_head	*fcpl;
	fc_port_t		*fcport;
	struct list_head	*fcll;
	fc_lun_t		*fclun;
	uint8_t			*usr_temp, *kernel_tmp;
	uint32_t		i;

	uint32_t		transfer_len;

	EXT_FC_SCSI_PASSTHRU	*pfc_scsi_pass;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_10)
	if (!pfc_scsi_cmd || !pfc_scsi_device) {
		printk("%s(%ld): invalid pointer received. pfc_scsi_cmd=%p, "
		    "pfc_scsi_device=%p.\n", __func__, ha->host_no,
		    pfc_scsi_cmd, pfc_scsi_device);
		return (ret);
	}
#endif

	if (test_bit(FAILOVER_EVENT_NEEDED, &ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
		    __func__, ha->host_no, ha->instance));
		pext->Status = EXT_STATUS_BUSY;
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pfc_scsi_pass,
	    sizeof(EXT_FC_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_FC_SCSI_PASSTHRU)));
		return (ret);
	}

	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qla2x00_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QLA_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "requested DMA buffer size %x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	/* Copy request buffer */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pfc_scsi_pass;
	ret = copy_from_user(kernel_tmp, usr_temp,
	    sizeof(EXT_FC_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));

		return (-EFAULT);
	}

	if (pfc_scsi_pass->FCScsiAddr.DestType != EXT_DEF_DESTTYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Dest type. \n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	fcport = NULL;
	fclun = NULL;
 	port_found = lun_found = 0;
 	list_for_each(fcpl, &ha->fcports) {
 		fcport = list_entry(fcpl, fc_port_t, list);

		if (memcmp(fcport->port_name,
		    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN, 8) != 0) {
			continue;

		}
 		port_found++;

 		list_for_each(fcll, &fcport->fcluns) {
 			fclun = list_entry(fcll, fc_lun_t, list);

			if (fclun->lun == pfc_scsi_pass->FCScsiAddr.Lun) {
				/* Found the right LUN */
				lun_found++;
				break;
			}
		}
		break;
	}

	if (!port_found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld FC AddrFormat - DID NOT "
		    "FIND Port matching WWPN.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	/* v5.21b9 - use a temporary fclun */
	if (!lun_found) {
		fclun = &temp_fclun;
		fclun->fcport = fcport;
		fclun->lun = pfc_scsi_pass->FCScsiAddr.Lun;
	}

	/* set target coordinates */
	pfc_scsi_cmd->device->id = 0xff; /* not used. just put something there. */
	pfc_scsi_cmd->device->lun = pfc_scsi_pass->FCScsiAddr.Lun;

	DEBUG9(printk("%s(%ld): inst=%ld cmd for loopid=%04x L=%04x "
	    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no, ha->instance, fclun->fcport->loop_id,
	    pfc_scsi_cmd->device->lun,
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[0],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[1],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[2],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[3],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[4],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[5],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[6],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[7]));

	if (pfc_scsi_pass->CdbLength == 6) {
		pfc_scsi_cmd->cmd_len = 6;

	} else if (pfc_scsi_pass->CdbLength == 0x0A) {
		pfc_scsi_cmd->cmd_len = 0x0A;

	} else if (pfc_scsi_pass->CdbLength == 0x0C) {
		pfc_scsi_cmd->cmd_len = 0x0C;

	} else if (pfc_scsi_pass->CdbLength == 0x10) {
		pfc_scsi_cmd->cmd_len = 0x10;
	} else {
		printk(KERN_WARNING
		    "qla2x00_ioctl: FC_SCSI_PASSTHRU Unknown Cdb Length=%x.\n",
		    pfc_scsi_pass->CdbLength);
		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	memcpy(pfc_scsi_cmd->cmnd, pfc_scsi_pass->Cdb,
	    pfc_scsi_cmd->cmd_len);

	DEBUG9(printk("%s Dump of cdb buffer:\n", __func__));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)&pfc_scsi_cmd->cmnd[0], 16));

	switch (pfc_scsi_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pfc_scsi_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pfc_scsi_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pfc_scsi_cmd->sc_data_direction = DMA_NONE;
		break;
	}

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld queuing command.\n",
	    __func__, ha->host_no, ha->instance));

	if (qla2x00_ioctl_scsi_queuecommand(ha, pext, pfc_scsi_cmd,
	    pfc_scsi_device, fcport, fclun)) {
		return (ret);
	}

	/* Wait for comletion */
	down(&ha->ioctl->cmpl_sem);

	if (qla2x00_ioctl_passthru_rsp_handling(ha, pext, pfc_scsi_cmd))
		return (ret);

	/* Process completed command */
	DEBUG9(printk("%s(%ld): inst=%ld done. host status=0x%x, "
	    "scsi status=0x%x.\n",
	    __func__, ha->host_no, ha->instance, CMD_COMPL_STATUS(pfc_scsi_cmd),
	    CMD_SCSI_STATUS(pfc_scsi_cmd)));

	/* copy up structure to make sense data available to user */
	pfc_scsi_pass->SenseLength = CMD_ACTUAL_SNSLEN(pfc_scsi_cmd);
	if (CMD_ACTUAL_SNSLEN(pfc_scsi_cmd)) {
		DEBUG9_10(printk("%s(%ld): inst=%ld sense[0]=%x sense[2]=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    pfc_scsi_cmd->sense_buffer[0],
		    pfc_scsi_cmd->sense_buffer[2]));

		for (i = 0; i < CMD_ACTUAL_SNSLEN(pfc_scsi_cmd); i++) {
			pfc_scsi_pass->SenseData[i] =
			pfc_scsi_cmd->sense_buffer[i];
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)pfc_scsi_pass;
		ret = copy_to_user(usr_temp, kernel_tmp,
		    sizeof(EXT_FC_SCSI_PASSTHRU));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
			    "buffer.\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	if (pfc_scsi_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {

		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance));

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pfc_scsi_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pfc_scsi_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pfc_scsi_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_sc_scsi3_passthru
 *	Handles EXT_SC_SCSI3_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_sc_scsi3_passthru(scsi_qla_host_t *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi3_cmd, struct scsi_device *pscsi3_device, int mode)
{
#define MAX_SCSI3_CDB_LEN	16

	int			ret = 0;
	int			found;
	fc_lun_t		temp_fclun;
	fc_lun_t		*fclun = NULL;
	struct list_head	*fcpl;
	fc_port_t		*fcport;
	uint8_t			*usr_temp, *kernel_tmp;
	uint32_t		transfer_len;
	uint32_t		i;

	EXT_FC_SCSI_PASSTHRU	*pscsi3_pass;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_10)
	if (!pscsi3_cmd || !pscsi3_device) {
		printk("%s(%ld): invalid pointer received. pfc_scsi_cmd=%p, "
		    "pfc_scsi_device=%p.\n", __func__, ha->host_no,
		    pscsi3_cmd, pscsi3_device);
		return (ret);
	}
#endif

	if (test_bit(FAILOVER_EVENT_NEEDED, &ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
		    __func__, ha->host_no, ha->instance));
		pext->Status = EXT_STATUS_BUSY;
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pscsi3_pass,
	    sizeof(EXT_FC_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_FC_SCSI_PASSTHRU)));
		return (ret);
	}


	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qla2x00_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QLA_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot "
			    "alloc requested DMA buffer size=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	/* Copy request buffer */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pscsi3_pass;
	ret = copy_from_user(kernel_tmp, usr_temp,
	    sizeof(EXT_FC_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));
		return (-EFAULT);
	}

	if (pscsi3_pass->FCScsiAddr.DestType != EXT_DEF_DESTTYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR - wrong Dest type.\n",
		    __func__, ha->host_no, ha->instance));
		ret = EXT_STATUS_ERR;

		return (ret);
	}

	/*
	 * For this ioctl command we always assume all 16 bytes are
	 * initialized.
	 */
	if (pscsi3_pass->CdbLength != MAX_SCSI3_CDB_LEN) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Cdb Len %d.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_pass->CdbLength));
		return (ret);
	}

 	fcport = NULL;
 	found = 0;
 	list_for_each(fcpl, &ha->fcports) {
 		fcport = list_entry(fcpl, fc_port_t, list);

		if (memcmp(fcport->port_name,
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN, 8) == 0) {
			found++;
			break;
		}
	}
	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;

		DEBUG9_10(printk("%s(%ld): inst=%ld DID NOT FIND Port for WWPN "
		    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[0],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[1],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[2],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[3],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[4],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[5],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[6],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[7]));

		return (ret);
	}

	/* Use a temporary fclun to send out the command. */
	fclun = &temp_fclun;
	fclun->fcport = fcport;
	fclun->lun = pscsi3_pass->FCScsiAddr.Lun;

	/* set target coordinates */
	pscsi3_cmd->device->id = 0xff;  /* not used. just put something there. */
	pscsi3_cmd->device->lun = pscsi3_pass->FCScsiAddr.Lun;

	DEBUG9(printk("%s(%ld): inst=%ld cmd for loopid=%04x L=%04x "
	    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no, ha->instance,
	    fclun->fcport->loop_id, pscsi3_cmd->device->lun,
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[0],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[1],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[2],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[3],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[4],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[5],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[6],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[7]));

	pscsi3_cmd->cmd_len = MAX_SCSI3_CDB_LEN;
	memcpy(pscsi3_cmd->cmnd, pscsi3_pass->Cdb, pscsi3_cmd->cmd_len);

	switch (pscsi3_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pscsi3_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pscsi3_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pscsi3_cmd->sc_data_direction = DMA_NONE;
		break;
	}

 	if (pscsi3_pass->Timeout)
		pscsi3_cmd->timeout_per_command = pscsi3_pass->Timeout * HZ;

	DEBUG9(printk("%s(%ld): inst=%ld cdb buffer dump:\n",
	    __func__, ha->host_no, ha->instance));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)&pscsi3_cmd->cmnd[0], 16));

	if (qla2x00_ioctl_scsi_queuecommand(ha, pext, pscsi3_cmd,
	    pscsi3_device, fcport, fclun)) {
		return (ret);
	}

	/* Wait for comletion */
	down(&ha->ioctl->cmpl_sem);

	if (qla2x00_ioctl_passthru_rsp_handling(ha, pext, pscsi3_cmd))
		return (ret);

	/* Process completed command */
	DEBUG9(printk("%s(%ld): inst=%ld done. host status=0x%x, "
	    "scsi status=0x%x.\n",
	    __func__, ha->host_no, ha->instance, CMD_COMPL_STATUS(pscsi3_cmd),
	    CMD_SCSI_STATUS(pscsi3_cmd)));

	/* copy up structure to make sense data available to user */
	pscsi3_pass->SenseLength = CMD_ACTUAL_SNSLEN(pscsi3_cmd);
	if (CMD_ACTUAL_SNSLEN(pscsi3_cmd)) {
		DEBUG9_10(printk("%s(%ld): inst=%ld sense[0]=%x sense[2]=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_cmd->sense_buffer[0],
		    pscsi3_cmd->sense_buffer[2]));

		for (i = 0; i < CMD_ACTUAL_SNSLEN(pscsi3_cmd); i++) {
			pscsi3_pass->SenseData[i] =
			    pscsi3_cmd->sense_buffer[i];
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)pscsi3_pass;
		ret = copy_to_user(usr_temp, kernel_tmp,
		    sizeof(EXT_FC_SCSI_PASSTHRU));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
			    "buffer.\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	if (pscsi3_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {

		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance));

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pscsi3_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pscsi3_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pscsi3_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): final transferlen=%d.\n",
		    __func__, ha->host_no, transfer_len));

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance));
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_send_els_rnid
 *	IOCTL to send extended link service RNID command to a target.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_send_els_rnid(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	EXT_RNID_REQ	*tmp_rnid;
	int		ret = 0;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	uint32_t	copy_len;
	int		found;
	uint16_t	next_loop_id;
	fc_port_t	*fcport;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (ha->ioctl_mem_size < SEND_RNID_RSP_SIZE) {
		if (qla2x00_get_new_ioctl_dma_mem(ha,
		    SEND_RNID_RSP_SIZE) != QLA_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "DMA buffer. size=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    SEND_RNID_RSP_SIZE));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (pext->RequestLen != sizeof(EXT_RNID_REQ)) {
		/* parameter error */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid req length %d.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen));
		pext->Status = EXT_STATUS_INVALID_PARAM;
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&tmp_rnid,
	    sizeof(EXT_RNID_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_RNID_REQ)));
		return (ret);
	}

	ret = copy_from_user(tmp_rnid, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Find loop ID of the device */
	found = 0;
	fcport = NULL;
	switch (tmp_rnid->Addr.Type) {
	case EXT_DEF_TYPE_WWNN:
		DEBUG9(printk("%s(%ld): inst=%ld got node name.\n",
		    __func__, ha->host_no, ha->instance));

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			if (memcmp(tmp_rnid->Addr.FcAddr.WWNN,
			    fcport->node_name, EXT_DEF_WWN_NAME_SIZE))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			} else { /* FCT_INITIATOR */
				if (!fcport->d_id.b24)
					continue;
			}

			found++;
		}
		break;

	case EXT_DEF_TYPE_WWPN:
		DEBUG9(printk("%s(%ld): inst=%ld got port name.\n",
		    __func__, ha->host_no, ha->instance));

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			if (memcmp(tmp_rnid->Addr.FcAddr.WWPN,
			    fcport->port_name, EXT_DEF_WWN_NAME_SIZE))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			} else { /* FCT_INITIATOR */
				if (!fcport->d_id.b24)
					continue;
			}

			found++;
		}
		break;

	case EXT_DEF_TYPE_PORTID:
		DEBUG9(printk("%s(%ld): inst=%ld got port ID.\n",
		    __func__, ha->host_no, ha->instance));

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			/* PORTID bytes entered must already be big endian */
			if (memcmp(&tmp_rnid->Addr.FcAddr.Id[1],
			    &fcport->d_id, EXT_DEF_PORTID_SIZE_ACTUAL))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			}

			found++;
		}
		break;
	default:
		/* parameter error */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid addressing type.\n",
		    __func__, ha->host_no, ha->instance));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	if (!found || (fcport->port_type == FCT_TARGET &&
	    fcport->loop_id > ha->last_loop_id)) {
		/*
		 * No matching device or the target device is not configured;
		 * just return error.
		 */
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* check on loop down */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) || ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance));

		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* If this is for a host device, check if we need to perform login */
	if (fcport->port_type == FCT_INITIATOR &&
	    fcport->loop_id >= ha->last_loop_id) {
		next_loop_id = 0;
		ret = qla2x00_fabric_login(ha, fcport, &next_loop_id);
		if (ret != QLA_SUCCESS) {
			/* login failed. */
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR login to "
			    "host port failed. loop_id=%02x pid=%02x%02x%02x "
			    "ret=%d.\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->loop_id, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa, ret));

			qla2x00_free_ioctl_scrap_mem(ha);
			return (ret);
		}
	}

	/* Send command */
	DEBUG9(printk("%s(%ld): inst=%ld sending rnid cmd.\n",
	    __func__, ha->host_no, ha->instance));

	ret = qla2x00_send_rnid_mbx(ha, fcport->loop_id,
	    (uint8_t)tmp_rnid->DataFormat, ha->ioctl_mem_phys,
	    SEND_RNID_RSP_SIZE, &mb[0]);

	if (ret != QLA_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

                DEBUG9_10(printk("%s(%ld): inst=%ld FAILED. rval = %x.\n",
                    __func__, ha->host_no, ha->instance, mb[0]));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld rnid cmd sent ok.\n",
	    __func__, ha->host_no, ha->instance));

	/* Copy the response */
	copy_len = (pext->ResponseLen > SEND_RNID_RSP_SIZE) ?
	    SEND_RNID_RSP_SIZE : pext->ResponseLen;

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, copy_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
		    __func__, ha->host_no, ha->instance));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	if (SEND_RNID_RSP_SIZE > pext->ResponseLen) {
		pext->Status = EXT_STATUS_DATA_OVERRUN;
		DEBUG9(printk("%s(%ld): inst=%ld data overrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	}
	pext->ResponseLen = copy_len;

	qla2x00_free_ioctl_scrap_mem(ha);
	return (ret);
}

/*
 * qla2x00_get_rnid_params
 *	IOCTL to get RNID parameters of the adapter.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_rnid_params(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	int		tmp_rval = 0;
	uint32_t	copy_len;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* check on loop down */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) || ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	/* Send command */
	tmp_rval = qla2x00_get_rnid_params_mbx(ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);

	if (tmp_rval != QLA_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld cmd FAILED=%x.\n",
		    __func__, ha->host_no, ha->instance, mb[0]));
		return (ret);
	}

	/* Copy the response */
	copy_len = (pext->ResponseLen > sizeof(EXT_RNID_DATA)) ?
	    (uint32_t)sizeof(EXT_RNID_DATA) : pext->ResponseLen;
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, copy_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf\n",
		    __func__, ha->host_no, ha->instance));
		return (-EFAULT);
	}

	pext->ResponseLen = copy_len;
	if (copy_len < sizeof(EXT_RNID_DATA)) {
		pext->Status = EXT_STATUS_DATA_OVERRUN;
		DEBUG9_10(printk("%s(%ld): inst=%ld data overrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	} else if (pext->ResponseLen > sizeof(EXT_RNID_DATA)) {
		pext->Status = EXT_STATUS_DATA_UNDERRUN;
		DEBUG9_10(printk("%s(%ld): inst=%ld data underrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	}

	return (ret);
}

/*
 *qla2x00_get_led_state
 *	IOCTL to get QLA2XXX HBA LED state
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_get_led_state(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int			ret = 0;
	EXT_BEACON_CONTROL	tmp_led_state;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (pext->ResponseLen < sizeof(EXT_BEACON_CONTROL)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR ResponseLen too small.\n",
		    __func__));

		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	/* Return current state */
	if (ha->beacon_blink_led) {
		tmp_led_state.State = EXT_DEF_GRN_BLINK_ON;
	} else {
		tmp_led_state.State = EXT_DEF_GRN_BLINK_OFF;
	}

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &tmp_led_state, sizeof(EXT_BEACON_CONTROL));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);

}

/*
 * qla2x00_set_host_data
 *	IOCTL command to set host/adapter related data.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_set_host_data(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int	ret = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* switch on command subcode */
	switch (pext->SubCode) {
	case EXT_SC_SET_RNID:
		ret = qla2x00_set_rnid_params(ha, pext, mode);
		break;
	case EXT_SC_SET_BEACON_STATE:
		if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
			ret = qla2x00_set_led_state(ha, pext, mode);
			break;
		}
		/*FALLTHROUGH*/
	default:
		/* function not supported. */
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

/*
 * qla2x00_set_rnid_params
 *	IOCTL to set RNID parameters of the adapter.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_set_rnid_params(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	EXT_SET_RNID_REQ	*tmp_set;
	EXT_RNID_DATA	*tmp_buf;
	int		ret = 0;
	int		tmp_rval = 0;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	/* check on loop down */
	if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) || ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance));

		return (ret);
	}

	if (pext->RequestLen != sizeof(EXT_SET_RNID_REQ)) {
		/* parameter error */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid request length.\n",
		    __func__, ha->host_no, ha->instance));
		return(ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&tmp_set,
	    sizeof(EXT_SET_RNID_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_SET_RNID_REQ)));
		return (ret);
	}

	ret = copy_from_user(tmp_set, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	tmp_rval = qla2x00_get_rnid_params_mbx(ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);
	if (tmp_rval != QLA_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

                DEBUG9_10(printk("%s(%ld): inst=%ld read cmd FAILED=%x.\n",
                    __func__, ha->host_no, ha->instance, mb[0]));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	tmp_buf = (EXT_RNID_DATA *)ha->ioctl_mem;
	/* Now set the params. */
	memcpy(tmp_buf->IPVersion, tmp_set->IPVersion, 2);
	memcpy(tmp_buf->UDPPortNumber, tmp_set->UDPPortNumber, 2);
	memcpy(tmp_buf->IPAddress, tmp_set->IPAddress, 16);
	tmp_rval = qla2x00_set_rnid_params_mbx(ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);

	if (tmp_rval != QLA_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld set cmd FAILED=%x.\n",
		    __func__, ha->host_no, ha->instance, mb[0]));
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance));
	}

	qla2x00_free_ioctl_scrap_mem(ha);
	return (ret);
}

/*
 *qla2x00_set_led_state
 *	IOCTL to set QLA2XXX HBA LED state
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_set_led_state(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int			ret = 0;
	uint32_t		tmp_ext_stat = 0;
	uint32_t		tmp_ext_dstat = 0;
	EXT_BEACON_CONTROL	tmp_led_state;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (pext->RequestLen < sizeof(EXT_BEACON_CONTROL)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR RequestLen too small.\n",
		    __func__));
		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance));
		return (ret);
	}

	ret = copy_from_user(&tmp_led_state, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(EXT_BEACON_CONTROL));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy req buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret));
		return (-EFAULT);
	}

	if (IS_QLA23XX(ha)) {
		ret = qla2x00_set_led_23xx(ha, &tmp_led_state, &tmp_ext_stat,
		    &tmp_ext_dstat);
	} else if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		ret = qla2x00_set_led_24xx(ha, &tmp_led_state, &tmp_ext_stat,
		    &tmp_ext_dstat);
	} else {
		/* not supported */
		tmp_ext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
	}

	pext->Status       = tmp_ext_stat;
	pext->DetailStatus = tmp_ext_dstat;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

static int
qla2x00_set_led_23xx(scsi_qla_host_t *ha, EXT_BEACON_CONTROL *ptmp_led_state,
    uint32_t *pext_stat, uint32_t *pext_dstat)
{
	int			ret = 0;
	device_reg_t __iomem	*reg = ha->iobase;
	uint16_t		gpio_enable, gpio_data;
	unsigned long		cpu_flags = 0;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	if (ptmp_led_state->State != EXT_DEF_GRN_BLINK_ON &&
	    ptmp_led_state->State != EXT_DEF_GRN_BLINK_OFF) {
		*pext_stat = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Unknown Led State set "
		    "operation recieved %x.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_led_state->State));
		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		*pext_stat = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance));
		return (ret);
	}

	switch (ptmp_led_state->State) {
	case EXT_DEF_GRN_BLINK_ON:

		DEBUG9(printk("%s(%ld): inst=%ld start blinking led \n",
		    __func__, ha->host_no, ha->instance));

		DEBUG9(printk("%s(%ld): inst=%ld orig firmware options "
		    "fw_options1=0x%x fw_options2=0x%x fw_options3=0x%x.\n",
		     __func__, ha->host_no, ha->instance, ha->fw_options[1],
		     ha->fw_options[2], ha->fw_options[3]));

		ha->fw_options[1] &= ~FO1_SET_EMPHASIS_SWING;
		ha->fw_options[1] |= FO1_DISABLE_GPIO6_7;

		if (qla2x00_set_fw_options(ha, ha->fw_options) != QLA_SUCCESS) {
			*pext_stat = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware  options failed.\n",
			    __func__, ha->host_no, ha->instance));
			break;
		}

		if (ha->pio_address)
			reg = (device_reg_t *)ha->pio_address;

		/* Turn off LEDs */
		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		if (ha->pio_address) {
			gpio_enable = RD_REG_WORD_PIO(&reg->gpioe);
			gpio_data   = RD_REG_WORD_PIO(&reg->gpiod);
		} else {
			gpio_enable = RD_REG_WORD(&reg->gpioe);
			gpio_data   = RD_REG_WORD(&reg->gpiod);
		}
		gpio_enable |= GPIO_LED_MASK;

		/* Set the modified gpio_enable values */
		if (ha->pio_address)
			WRT_REG_WORD_PIO(&reg->gpioe, gpio_enable);
		else {
			WRT_REG_WORD(&reg->gpioe, gpio_enable);
			RD_REG_WORD(&reg->gpioe);
		}

		/* Clear out previously set LED colour */
		gpio_data &= ~GPIO_LED_MASK;
		if (ha->pio_address)
			WRT_REG_WORD_PIO(&reg->gpiod, gpio_data);
		else {
			WRT_REG_WORD(&reg->gpiod, gpio_data);
			RD_REG_WORD(&reg->gpiod);
		}
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

		/* Let the per HBA timer kick off the blinking process based on
		 * the following flags. No need to do anything else now.
		 */
		ha->beacon_blink_led = 1;
		ha->beacon_color_state = 0;

		/* end of if (ptmp_led_state.State == EXT_DEF_GRN_BLINK_ON)) */

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;
		break;

	case EXT_DEF_GRN_BLINK_OFF:
		DEBUG9(printk("%s(%ld): inst=%ld stop blinking led \n",
		    __func__, ha->host_no, ha->instance));

		ha->beacon_blink_led = 0;
		/* Set the on flag so when it gets flipped it will be off */
		if (IS_QLA2322(ha)) {
			ha->beacon_color_state = QLA_LED_RGA_ON;
		} else {
			ha->beacon_color_state = QLA_LED_GRN_ON;
		}
		qla23xx_blink_led(ha);	/* This turns green LED off */

		DEBUG9(printk("%s(%ld): inst=%ld orig firmware"
		    " options fw_options1=0x%x fw_options2=0x%x "
		    "fw_options3=0x%x.\n",
		    __func__, ha->host_no, ha->instance, ha->fw_options[1],
		    ha->fw_options[2], ha->fw_options[3]));

		ha->fw_options[1] &= ~FO1_SET_EMPHASIS_SWING;
		ha->fw_options[1] &= ~FO1_DISABLE_GPIO6_7;

		if (qla2x00_set_fw_options(ha, ha->fw_options) != QLA_SUCCESS) {
			*pext_stat = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware  options failed.\n",
			    __func__, ha->host_no, ha->instance));
			break;
		}

		/* end of if (ptmp_led_state.State == EXT_DEF_GRN_BLINK_OFF) */

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;
		break;
	default:
		*pext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (ret);
}

static int
qla2x00_set_led_24xx(scsi_qla_host_t *ha, EXT_BEACON_CONTROL *ptmp_led_state,
    uint32_t *pext_stat, uint32_t *pext_dstat)
{
	int			rval = 0;
	struct device_reg_24xx __iomem *reg24 =
	    (struct device_reg_24xx __iomem *)ha->iobase;
	uint32_t		gpio_data;
	uint32_t		led_state;
	unsigned long		cpu_flags = 0;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	led_state = ptmp_led_state->State;
	if (led_state != EXT_DEF_GRN_BLINK_ON &&
	    led_state != EXT_DEF_GRN_BLINK_OFF) {
		*pext_stat = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Unknown Led State set "
		    "operation recieved %x.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_led_state->State));
		return (rval);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		*pext_stat = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance));
		return (rval);
	}

	DEBUG9_10(printk("%s(%ld): inst=%ld orig firmware options "
	    "fw_options1=0x%x fw_options2=0x%x fw_options3=0x%x.\n",
	     __func__, ha->host_no, ha->instance, ha->fw_options[1],
	     ha->fw_options[2], ha->fw_options[3]));

	switch (led_state) {
	case EXT_DEF_GRN_BLINK_ON:

		DEBUG9(printk("%s(%ld): inst=%ld start blinking led \n",
		    __func__, ha->host_no, ha->instance));

		if (!ha->beacon_blink_led) {
			/* Enable firmware for update */
			ha->fw_options[1] |= ADD_FO1_DISABLE_GPIO_LED_CTRL;

			if (qla2x00_set_fw_options(ha, ha->fw_options) !=
			    QLA_SUCCESS) {
				*pext_stat = EXT_STATUS_MAILBOX;
				*pext_dstat = ha->fw_options[0];
				DEBUG9_10(printk("%s(%ld): inst=%ld set"
				    "firmware options failed.\n",
				    __func__, ha->host_no, ha->instance));
				break;
			}

			if (qla2x00_get_fw_options(ha, ha->fw_options) !=
			    QLA_SUCCESS) {
				*pext_stat = EXT_STATUS_MAILBOX;
				*pext_dstat = ha->fw_options[0];
				DEBUG9_10(printk("%s(%ld): inst=%ld get"
				    "firmware options failed.\n",
				    __func__, ha->host_no, ha->instance));
				break;
			}

			spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
			gpio_data = RD_REG_DWORD(&reg24->gpiod);

			/* Enable the gpio_data reg for update */
			gpio_data |= GPDX_LED_UPDATE_MASK;
			WRT_REG_DWORD(&reg24->gpiod, gpio_data);
			RD_REG_DWORD(&reg24->gpiod);

			spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);
		}

		ha->beacon_color_state = 0; /* so all colors blink together */

		/* Let the per HBA timer kick off the blinking process*/
		ha->beacon_blink_led = 1;

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;

		DEBUG9(printk("%s(%ld): inst=%ld LED setup to blink.\n",
		    __func__, ha->host_no, ha->instance));

		break;

	case EXT_DEF_GRN_BLINK_OFF:
		DEBUG9(printk("%s(%ld): inst=%ld stop blinking led \n",
		    __func__, ha->host_no, ha->instance));

		ha->beacon_blink_led = 0;
		ha->beacon_color_state = QLA_LED_ALL_ON;
		qla24xx_blink_led(ha); /* will flip to all off */

		/* give control back to firmware */
		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		gpio_data = RD_REG_DWORD(&reg24->gpiod);

		/* Disable the gpio_data reg for update */
		gpio_data &= ~GPDX_LED_UPDATE_MASK;
		WRT_REG_DWORD(&reg24->gpiod, gpio_data);
		RD_REG_DWORD(&reg24->gpiod);
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

		ha->fw_options[1] &= ~ADD_FO1_DISABLE_GPIO_LED_CTRL;

		if (qla2x00_set_fw_options(ha, ha->fw_options) != QLA_SUCCESS) {
			*pext_stat = EXT_STATUS_MAILBOX;
			*pext_dstat = ha->fw_options[0];
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware options failed.\n",
			    __func__, ha->host_no, ha->instance));
			break;
		}

		if (qla2x00_get_fw_options(ha, ha->fw_options) !=
		    QLA_SUCCESS) {
			*pext_stat = EXT_STATUS_MAILBOX;
			*pext_dstat = ha->fw_options[0];
			DEBUG9_10(printk("%s(%ld): inst=%ld get"
			    "firmware options failed.\n",
			    __func__, ha->host_no, ha->instance));
			break;
		}

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;

		DEBUG9(printk("%s(%ld): inst=%ld all LED blinking stopped.\n",
		    __func__, ha->host_no, ha->instance));

		break;

	default:
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld invalid state received=%x.\n",
		    __func__, ha->host_no, ha->instance, led_state));

		*pext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return (rval);
}

/*
 * qla2x00_get_tgt_lun_by_q
 *      Get list of enabled luns from all target devices attached to the HBA
 *	by searching through lun queue.
 *
 * Input:
 *      ha = pointer to adapter
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
static int
qla2x00_get_tgt_lun_by_q(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	fc_port_t        *fcport;
	int              ret = 0;
	os_tgt_t         *ostgt;
	os_lun_t         *up;
	uint16_t         lun;
	uint16_t	 tgt;
	TGT_LUN_DATA_ENTRY  *entry;
	TGT_LUN_DATA_LIST *u_list, *llist;
	uint8_t		 *u_entry;
	int		 lun_cnt, entry_size, lun_data_list_size;
	


	DEBUG9(printk("%s: entered.\n", __func__));

	entry_size = (pext->ResponseLen -
			TGT_LUN_DATA_LIST_HEADER_SIZE) / TGT_LUN_DATA_LIST_MAX_ENTRIES;

	lun_data_list_size = TGT_LUN_DATA_LIST_HEADER_SIZE + entry_size;

        lun_cnt = entry_size - (offsetof(TGT_LUN_DATA_ENTRY, Data));
        DEBUG10(printk("(%s) Lun count = %d\n", __func__, lun_cnt));

        /* Lun count must be 256 , 2048, or 4K, multiple of 256 */
        if ((lun_cnt % OLD_MAX_LUNS) != 0) {
                DEBUG2_9_10(printk("%s: Invalid lun count = %d.\n",
                    __func__, lun_cnt));

                pext->Status = EXT_STATUS_INVALID_REQUEST;
                return (ret);
        }

	llist = vmalloc(lun_data_list_size);
	if (llist == NULL) {
		DEBUG2_9_10(printk("%s: failed to alloc memory of size (%d)\n",
		    __func__, lun_data_list_size));
		pext->Status = EXT_STATUS_NO_MEMORY;
		return (-ENOMEM);
	}
	memset(llist, 0, lun_data_list_size);

	entry = &llist->DataEntry[0];

	u_list = (TGT_LUN_DATA_LIST *)Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode);
	u_entry = (uint8_t *)&u_list->DataEntry[0];

	DEBUG9(printk("%s(%ld): entry->Data size=%ld.\n",
	    __func__, ha->host_no, (ulong)sizeof(entry->Data)));

	/* Check thru this adapter's target list */
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if ((ostgt = (os_tgt_t *)TGT_Q(ha, tgt)) == NULL) {
			continue;
		}

		if (ostgt->fcport == NULL) {
			/* no port */
			DEBUG9(printk("%s(%ld): tgt %d port not exist.\n",
			    __func__, ha->host_no, tgt));
			continue;
		}

		fcport = ostgt->fcport;

		if (fcport->port_type != FCT_TARGET) {
			/* sanity check */
			DEBUG9(printk("%s(%ld): tgt %d port not target.\n",
			    __func__, ha->host_no, tgt));
			continue;
		}

		memcpy(entry->PortName, fcport->port_name,
		    EXT_DEF_WWN_NAME_SIZE);
		memcpy(entry->NodeName, fcport->node_name,
		    EXT_DEF_WWN_NAME_SIZE);
		entry->BusNumber = 0;
		entry->TargetId = tgt;

		entry->DevType = EXT_DEF_TARGET_DEV;

		if (fcport->flags & FC_FABRIC_DEVICE) {
			entry->DevType |= EXT_DEF_FABRIC_DEV;
		}
		if (fcport->flags & FC_TAPE_PRESENT) {
			entry->DevType |= EXT_DEF_TAPE_DEV;
		}
		if (fcport->port_type & FCT_INITIATOR) {
			entry->DevType |= EXT_DEF_INITIATOR_DEV;
		}

		entry->LoopId   = fcport->loop_id;

		entry->PortId[0] = 0;
		entry->PortId[1] = fcport->d_id.r.d_id[2];
		entry->PortId[2] = fcport->d_id.r.d_id[1];
		entry->PortId[3] = fcport->d_id.r.d_id[0];

		memset(entry->Data, 0, sizeof(entry->Data));

		for (lun = 0; lun < lun_cnt; lun++) {
			up = (os_lun_t *) GET_LU_Q(ha, tgt, lun);
			if (up == NULL) {
				continue;
			}
			if (up->fclun == NULL) {
				continue;
			}

			DEBUG9(printk("%s(%ld): lun %d io_cnt=%ld.\n",
			    __func__, ha->host_no, lun, up->io_cnt));

/* Disabled checking per customer request. */
#if 0
			if (up->io_cnt < 1) {
				/* not registered with OS */
				continue;
			}
#endif

			DEBUG9(printk("%s(%ld): lun %d enabled.\n",
			    __func__, ha->host_no, lun));

			entry->Data[lun] |= LUN_DATA_ENABLED;
		}

		entry->LunCount = lun;

		DEBUG9(printk("%s(%ld): tgt %d lun count=%d.\n",
		    __func__, ha->host_no, tgt, entry->LunCount));

		ret = copy_to_user(u_entry, entry,
		    sizeof(TGT_LUN_DATA_ENTRY));

		if (ret) {
			/* error */
			DEBUG9_10(printk("%s: u_entry %p copy "
			    "error. list->EntryCount=%d.\n",
			    __func__, u_entry, llist->EntryCount));
			pext->Status = EXT_STATUS_COPY_ERR;
			ret = -EFAULT;
			break;
		}

		llist->EntryCount++;

		/* Go to next target */
		u_entry += entry_size;
	}

	DEBUG9(printk("%s: final entry count = %d\n",
	    __func__, llist->EntryCount));

	if (ret == 0) {
		/* copy number of entries */
		ret = copy_to_user(&u_list->EntryCount, &llist->EntryCount,
		    sizeof(llist->EntryCount));
	}

	vfree(llist);
	DEBUG9(printk("%s: exiting. ret=%d.\n", __func__, ret));

	return ret;
}

