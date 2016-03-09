/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/moduleparam.h>

#include "qlfo.h"
#include "qlfolimits.h"
#include "qla_foln.h"

int ql2xfailover = 1;
module_param(ql2xfailover, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(ql2xfailover,
		"Driver failover support: 0 to disable; 1 to enable.");

int ql2xrecoveryTime = MAX_RECOVERYTIME;
module_param_named(recoveryTime, ql2xrecoveryTime, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(recoveryTime,
		"Recovery time in seconds before a target device is sent I/O "
		"after a failback is performed.");

int ql2xfailbackTime = MAX_FAILBACKTIME;
module_param_named(failbackTime, ql2xfailbackTime, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(failbackTime,
		"Delay in seconds before a failback is performed.");

int MaxPathsPerDevice = 0;
module_param(MaxPathsPerDevice, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(MaxPathsPerDevice,
		"Maximum number of paths to a device.  Default 8.");

int MaxRetriesPerPath = 0;
module_param(MaxRetriesPerPath, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(MaxRetriesPerPath,
		"How many retries to perform on the current path before "
		"failing over to the next path in the path list.");

int MaxRetriesPerIo = 0;
module_param(MaxRetriesPerIo, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(MaxRetriesPerIo,
		"How many total retries to do before failing the command and "
		"returning to the OS with a DID_NO_CONNECT status.");

int qlFailoverNotifyType = 0;
module_param(qlFailoverNotifyType, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(qlFailoverNotifyType,
		"Failover notification mechanism to use when a failover or "
		"failback occurs.");

int ql2xlbType = 0;
module_param(ql2xlbType, int, S_IRUGO|S_IRUSR);
MODULE_PARM_DESC(ql2xlbType,
		"Load Balance Method : (0) None (1) static load balance and "
		"Default : 0  All the luns exposed on the first active path"
		"        : 1  For static load balance across active optimised"
		"  	      controller ports"
		"	 : 2  For  LRU"
		"	 : 3  For  LST");

int ql2xexcludemodel = 0;
module_param(ql2xexcludemodel, int, 0);
MODULE_PARM_DESC(ql2xexcludemodel,
		"Exclude device models from being marked as failover capable."
		"Combine one or more of the following model numbers into "
		"an exclusion mask: "
		"0x20 - HSV210, 0x10 - DSXXX, "
		"0x04 - HSV110, 0x02 - MSA1000, 0x01 - XP128.");

int ql2xtgtemul = 1;
module_param(ql2xtgtemul, int, 0);
MODULE_PARM_DESC(ql2xtgtemul,
	"Enable/Disable target combining emulation."
	"Default : 1  Enable target failover emulation for targets "
	"created by lunid matching"
	"        : 0  Disable target failover emulation");

int ql2xautorestore = 0;
/* Bit Map Values assigend to these devices are in-sync with
 * values assigned to these devices in the cfg_device_list[]
 * table. To add other devices use the bit map value assigned
 * to it in the above mentioned device table.
 */
module_param(ql2xautorestore,int, 0);
MODULE_PARM_DESC(ql2xautorestore,
		" Enable or disable auto-restore for the specified devices. "
		" Combine one or more of the following model numbers into "
		" an mask to toggle the default condition of autorestore: "
		" MSA1000: 0x2, EVA: 0x4, EVA A/A: 0x20, MSA A/A: 0x80"
		" For Ex: passing value of 0x6 will enable autorestore for"
		" both: MSA1000 and EVA since the default condition is disable.");

int ql2xmap2actpath =  0;
module_param(ql2xmap2actpath,int, 0);
MODULE_PARM_DESC(ql2xmap2actpath,
		" Enable OS mapping to the active port for"
		"Active/Passive devices. "
		"0 to disable; 1 to enable.");

struct cfg_device_info cfg_device_list[] = {

	{"HP", "MSA CONTROLLER", BIT_7, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"HP", "MSA VOLUME", BIT_7, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"COMPAQ", "MSA1000", BIT_1, FO_NOTIFY_TYPE_SPINUP,
		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"HITACHI", "OPEN-", BIT_0, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"HP", "OPEN-", BIT_0, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"COMPAQ", "HSV110 (C)COMPAQ", 4, FO_NOTIFY_TYPE_SPINUP,
		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"HP", "HSV100", BIT_2, FO_NOTIFY_TYPE_SPINUP,
		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"DEC", "HSG80", BIT_3, FO_NOTIFY_TYPE_NONE,
		qla2x00_export_target, NULL, NULL, NULL },
	{"IBM", "DS400", BIT_4, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"COMPAQ", "HSV111 (C)COMPAQ", BIT_5, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"HP", "HSV101", BIT_5, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"HP", "HSV200", BIT_5, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
	{"HP", "HSV210", BIT_5, FO_NOTIFY_TYPE_TPGROUP_CDB,
                qla2x00_combine_by_lunid, qla2x00_get_target_ports,
                NULL, NULL, NULL},
  	{"HITACHI", "DF600", BIT_8, FO_NOTIFY_TYPE_NONE,
  		qla2x00_combine_by_lunid, NULL, NULL, NULL },
	{"HP", "NVS1000 ", BIT_9, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, qla2x00_get_target_xports,
		NULL, NULL, NULL},
	{"DataCore", "SANsymphony", BIT_10, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, NULL,
		NULL, NULL, NULL},
	{"DataCore", "SANmelody", BIT_10, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, NULL,
		NULL, NULL, NULL},
	{"INCIPNT", "NSP ", BIT_11, FO_NOTIFY_TYPE_NONE,
		qla2x00_combine_by_lunid, qla2x00_get_target_xports,
		NULL, NULL, NULL},

	/*
	 * Must be at end of list...
	 */
	{NULL, NULL }
};

/*
 * qla2x00_check_for_devices_online
 *
 *	Check fcport state of all devices to make sure online.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Return:
 *	None.
 *
 * Context:
 */
static uint8_t
qla2x00_check_for_devices_online(scsi_qla_host_t *ha)
{
	fc_port_t	*fcport;


	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;

		if ((atomic_read(&fcport->state) == FCS_ONLINE) ||
		    (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) ||
		    fcport->flags & FC_FAILBACK_DISABLE)
			continue;

		return 0;
	}

	return 1;
}

/*
 *  qla2x00_failover_cleanup
 *	Cleanup queues after a failover.
 *
 * Input:
 *	sp = command pointer
 *
 * Context:
 *	Interrupt context.
 */
void
qla2x00_failover_cleanup(srb_t *sp)
{
	sp->cmd->result = DID_BUS_BUSY << 16;
	sp->cmd->host_scribble = (unsigned char *) NULL;
	if ((sp->flags & SRB_GOT_SENSE)) {
		sp->flags &= ~SRB_GOT_SENSE;
		sp->cmd->sense_buffer[0] = 0;
	}
	/* turn-off all failover flags */
	sp->flags = sp->flags & ~(SRB_RETRY|SRB_FAILOVER|SRB_FO_CANCEL);
}

int
qla2x00_suspend_failover_targets(scsi_qla_host_t *ha)
{
	unsigned long flags;
	struct list_head *list, *temp;
	srb_t *sp;
	int count;
	os_tgt_t *tq;

	spin_lock_irqsave(&ha->list_lock, flags);
	count = ha->failover_cnt;
	list_for_each_safe(list, temp, &ha->failover_queue) {
		sp = list_entry(ha->failover_queue.next, srb_t, list);
		tq = sp->tgt_queue;
		if (!(test_bit(TQF_SUSPENDED, &tq->flags)))
			set_bit(TQF_SUSPENDED, &tq->flags);
	}
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return count;
}

srb_t *
qla2x00_failover_next_request(scsi_qla_host_t *ha)
{
	unsigned long flags;
	srb_t *sp = NULL;

	spin_lock_irqsave(&ha->list_lock, flags);
	if (!list_empty(&ha->failover_queue)) {
		sp = list_entry(ha->failover_queue.next, srb_t, list);
		__del_from_failover_queue(ha, sp);
	}
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return sp;
}

/*
 *  qla2x00_process_failover
 *	Process any command on the failover queue.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Context:
 *	Interrupt context.
 */
static void
qla2x00_process_failover(scsi_qla_host_t *ha)
{

	os_tgt_t	*tq;
	os_lun_t	*lq;
	srb_t       *sp;
	fc_port_t *fcport;
	uint32_t    t, l;
	scsi_qla_host_t *vis_ha = ha;
	int count, i;

	DEBUG2(printk(KERN_INFO "%s: hba %ld active=%ld, retry=%d, "
			"done=%ld, failover=%d, scsi retry=%d commands.\n",
			__func__,
			ha->host_no,
			ha->actthreads,
			ha->retry_q_cnt,
			ha->done_q_cnt,
			ha->failover_cnt,
			ha->scsi_retry_q_cnt));

	/* Prevent acceptance of new I/O requests for failover target. */
	count = qla2x00_suspend_failover_targets(ha);

	/*
	 * Process all the commands in the failover queue. Attempt to failover
	 * then either complete the command as is or requeue for retry.
	 */
	for (i = 0; i < count ; i++) {
		sp = qla2x00_failover_next_request(ha);
		if (!sp)
			break;

		qla2x00_extend_timeout(sp->cmd, 360);
		if (i == 0)
			vis_ha =
			    (scsi_qla_host_t *)sp->cmd->device->host->hostdata;

		tq = sp->tgt_queue;
		lq = sp->lun_queue;
		fcport = lq->fclun->fcport;

		DEBUG2(printk("%s(): pid %ld retrycnt=%d, fcport =%p, "
		    "state=0x%x, \nloop state=0x%x fclun=%p, lq fclun=%p, "
		    "lq=%p, lun=%d\n", __func__, sp->cmd->serial_number,
		    sp->cmd->retries, fcport, atomic_read(&fcport->state),
		    atomic_read(&ha->loop_state), sp->fclun, lq->fclun, lq,
		    lq->fclun->lun));
		if (sp->err_id == SRB_ERR_DEVICE && sp->fclun == lq->fclun &&
		    atomic_read(&fcport->state) == FCS_ONLINE) {
			if (!(qla2x00_test_active_lun(fcport, sp->fclun, NULL))) {
				DEBUG2(printk("scsi(%ld) %s Detected INACTIVE "
				    "Port 0x%02x \n", ha->host_no, __func__,
				    fcport->loop_id));
				sp->err_id = SRB_ERR_OTHER;
				sp->cmd->sense_buffer[2] = 0;
				sp->cmd->result = DID_BUS_BUSY << 16;
			}
		}
		if ((sp->flags & SRB_GOT_SENSE)) {
		 	 sp->flags &= ~SRB_GOT_SENSE;
		 	 sp->cmd->sense_buffer[0] = 0;
		 	 sp->cmd->result = DID_BUS_BUSY << 16;
		 	 sp->cmd->host_scribble = (unsigned char *) NULL;
		}

		/*** Select an alternate path ***/

		/* if load balancing is enabled then adjust lq->fclun */
		if (qla2x00_cfg_is_lbenable(sp->fclun))
			lq->fclun = sp->fclun;

		/*
		 * If the path has already been change by a previous request
		 * sp->fclun != lq->fclun
		 */
		if (sp->err_id != SRB_ERR_OTHER) {
			if (atomic_read(&fcport->ha->loop_state) == LOOP_DEAD)
				sp->err_id = SRB_ERR_LOOP;
			else
				sp->err_id = SRB_ERR_PORT;
		}
		if (sp->fclun != lq->fclun || (sp->err_id != SRB_ERR_OTHER &&
		    (atomic_read(&fcport->ha->loop_state) != LOOP_DEAD) &&
		    atomic_read(&fcport->state) != FCS_DEVICE_DEAD)) {
			qla2x00_failover_cleanup(sp);
		} else if (qla2x00_cfg_failover(ha,
		    lq->fclun, tq, sp) == NULL) {
			/*
			 * We ran out of paths, so just retry the status which
			 * is already set in the cmd. We want to serialize the
			 * failovers, so we make them go thur visible HBA.
			 */
			printk(KERN_INFO
			    "%s(): Ran out of paths - pid %ld - retrying\n",
			    __func__, sp->cmd->serial_number);
		} else {
			/*
			 * if load balancing is enabled then we need to flush the
			 * other requests for the same lun
			 */
			if (qla2x00_cfg_is_lbenable(sp->fclun)) {
				DEBUG2(printk("%s(): Flushing fo queue"
					" for lq=%p\n",
					__func__,
					lq));
				qla2x00_flush_failover_q(vis_ha, lq);
			}
			qla2x00_failover_cleanup(sp);

		}
		add_to_done_queue(ha, sp);
	}

	for (t = 0; t < vis_ha->max_targets; t++) {
		if ((tq = vis_ha->otgt[t]) == NULL)
			continue;
		if (test_and_clear_bit(TQF_SUSPENDED, &tq->flags)) {
			/* EMPTY */
			DEBUG2(printk("%s(): remove suspend for target %d\n",
			    __func__, t));
		}
		for (l = 0; l < vis_ha->max_luns; l++) {
			if ((lq = (os_lun_t *) tq->olun[l]) == NULL)
				continue;

			if (test_and_clear_bit(LUN_MPIO_BUSY, &lq->q_flag)) {
				/* EMPTY */
				DEBUG(printk("%s(): remove suspend for "
				    "lun %d\n", __func__, lq->fclun->lun));
			}
		}
	}
	qla2x00_restart_queues(ha, 0);

	DEBUG(printk("%s() - done", __func__));
}

int
qla2x00_search_failover_queue(scsi_qla_host_t *ha, struct scsi_cmnd *cmd)
{
	struct list_head *list, *temp;
	unsigned long flags;
	srb_t *sp;

	DEBUG3(printk("qla2xxx_eh_abort: searching sp %p in failover queue.\n",
	    CMD_SP(cmd)));

	spin_lock_irqsave(&ha->list_lock, flags);
	list_for_each_safe(list, temp, &ha->failover_queue) {
		sp = list_entry(list, srb_t, list);

		if (cmd == sp->cmd)
			goto found;

	}
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return 0;

 found:
	/* Remove srb from failover queue. */
	__del_from_failover_queue(ha, sp);
	cmd->result = DID_ABORT << 16;
	__add_to_done_queue(ha, sp);

	spin_unlock_irqrestore(&ha->list_lock, flags);
	return 1;
}

/*
 * If we are not processing a ioctl or one of
 * the ports are still MISSING or need a resync
 * then process the failover event.
 */
void
qla2x00_process_failover_event(scsi_qla_host_t *ha)
{
	if (test_bit(CFG_ACTIVE, &ha->cfg_flags))
		return;
	if (qla2x00_check_for_devices_online(ha)) {
		if (test_and_clear_bit(FAILOVER_EVENT, &ha->dpc_flags)) {
			if (ha->flags.online)
				qla2x00_cfg_event_notify(ha, ha->failover_type);
		}
	}

	/*
	 * Get any requests from failover queue
	 */
	if (test_and_clear_bit(FAILOVER_NEEDED, &ha->dpc_flags))
		qla2x00_process_failover(ha);
}

int
qla2x00_do_fo_check(scsi_qla_host_t *ha, srb_t *sp, scsi_qla_host_t *vis_ha)
{
	/*
	 * This routine checks for DID_NO_CONNECT to decide
	 * whether to failover to another path or not. We only
	 * failover on that status.
	 */
	if (sp->lun_queue->fclun->fcport->flags & FC_FAILOVER_DISABLE)
		return 0;

	if (sp->lun_queue->fclun->flags & FLF_VISIBLE_LUN)
		return 0;

	if (!qla2x00_fo_check(ha, sp))
		return 0;

	if ((sp->state != SRB_FAILOVER_STATE)) {
		/*
		 * Retry the command on this path
		 * several times before selecting a new
		 * path.
		 */
		add_to_pending_queue_head(vis_ha, sp);
		qla2x00_next(vis_ha);
	} else
		qla2x00_extend_timeout(sp->cmd, EXTEND_CMD_TIMEOUT);

	return 1;
}

void
qla2xxx_start_all_adapters(scsi_qla_host_t *ha)
{
	struct list_head *hal;
	scsi_qla_host_t *vis_ha;

	/* Try and start all visible adapters */
	read_lock(&qla_hostlist_lock);
	list_for_each(hal, &qla_hostlist) {
		vis_ha = list_entry(hal, scsi_qla_host_t, list);

		if (!list_empty(&vis_ha->pending_queue))
			qla2x00_next(vis_ha);

		DEBUG2(printk("host(%ld):Commands busy=%d "
		    "failed=%d eh_active=%d\n ",
		    vis_ha->host_no, vis_ha->host->host_busy,
		    vis_ha->host->host_failed,
		    qla2x00_is_eh_active(vis_ha->host)));
	}
	read_unlock(&qla_hostlist_lock);
}
