/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */

/*
 * QLogic ISP2x00 Multi-path LUN Support Driver
 *
 */

#include "qla_def.h"

#include <asm/uaccess.h>
#include <linux/vmalloc.h>

#include "qlfo.h"
#include "qlfolimits.h"
#include "qla_foln.h"

/*
 *  Local Function Prototypes.
 */

static uint32_t qla2x00_add_portname_to_mp_dev(mp_device_t *, uint8_t *, uint8_t *);

static mp_device_t * qla2x00_allocate_mp_dev(uint8_t *, uint8_t *);
static mp_path_t * qla2x00_allocate_path(mp_host_t *, uint16_t, fc_port_t *,
    uint16_t);
static mp_path_list_t * qla2x00_allocate_path_list(void);

static mp_host_t * qla2x00_find_host_by_portname(uint8_t *);

static mp_device_t * qla2x00_find_or_allocate_mp_dev (mp_host_t *, uint16_t,
    fc_port_t *);
static mp_path_t * qla2x00_find_or_allocate_path(mp_host_t *, mp_device_t *,
    uint16_t, uint16_t, fc_port_t *);

static lu_path_t * qla2x00_find_or_allocate_lu_path(mp_host_t *, fc_lun_t *, uint16_t);

static uint32_t qla2x00_cfg_register_failover_lun(mp_device_t *,srb_t *,
    fc_lun_t *);
static uint32_t qla2x00_send_failover_notify(mp_device_t *, uint16_t,
    mp_path_t *, mp_path_t *);
static mp_path_t * qla2x00_select_next_path(mp_host_t *, mp_device_t *,
    uint16_t, srb_t *);

static uint8_t qla2x00_update_mp_host(mp_host_t  *);
static uint32_t qla2x00_update_mp_tree (void);

static fc_lun_t *qla2x00_find_matching_lun(uint16_t, mp_device_t *, mp_path_t *);
static lu_path_t * qla2x00_find_lu_path_by_id(mp_lun_t *, uint8_t);
static mp_path_t *qla2x00_find_path_by_id(mp_device_t *, uint8_t);
static mp_device_t *qla2x00_find_mp_dev_by_id(mp_host_t *, uint16_t);
mp_device_t *qla2x00_find_mp_dev_by_nodename(mp_host_t *, uint8_t *);
mp_device_t *qla2x00_find_mp_dev_by_portname(mp_host_t *, uint8_t *,
    uint16_t *);
static mp_device_t *qla2x00_find_dp_by_pn_from_all_hosts(uint8_t *, uint16_t *);
static mp_device_t *qla2x00_find_dp_from_all_hosts(uint8_t *);

static mp_path_t *qla2x00_get_visible_path(mp_device_t *dp);
static void qla2x00_map_os_targets(mp_host_t *);
static void qla2x00_map_os_luns(mp_host_t *, mp_device_t *, uint16_t);
static uint8_t qla2x00_map_a_oslun(mp_host_t *, mp_device_t *, uint16_t, uint16_t);

static uint8_t qla2x00_is_ww_name_zero(uint8_t *);
static void qla2x00_add_path(mp_path_list_t *, mp_path_t *);
static void qla2x00_failback_single_lun(mp_device_t *, uint16_t, uint16_t);
static void qla2x00_failback_luns(mp_host_t *);
static void qla2x00_setup_new_path(mp_device_t *, mp_path_t *, fc_port_t *);
static int  qla2x00_get_wwuln_from_device(mp_host_t *, fc_lun_t *, char *,
                int , uint8_t *, uint8_t *);
#if 0
static mp_device_t  * qla2x00_is_nn_and_pn_in_device(mp_device_t *,
	uint8_t *, uint8_t *);
static mp_device_t  * qla2x00_find_mp_dev_by_nn_and_pn(mp_host_t *, uint8_t *, uint8_t *);
#endif
static mp_lun_t  * qla2x00_find_matching_lunid(char	*);
static fc_lun_t  * qla2x00_find_matching_lun_by_num(uint16_t , mp_device_t *,
	mp_path_t *);
static int qla2x00_configure_cfg_device(fc_port_t	*);
static mp_lun_t *
qla2x00_find_or_allocate_lun(mp_host_t *, uint16_t ,
    fc_port_t *, fc_lun_t *);
static void qla2x00_add_lun(mp_device_t *, mp_lun_t *);
#if 0
static int qla2x00_is_nodename_in_device(mp_device_t *, uint8_t *);
#endif
static mp_port_t	*
qla2x00_find_or_allocate_port(mp_host_t *, mp_lun_t *,
	mp_path_t *);
static mp_tport_grp_t *
qla2x00_find_or_allocate_tgt_port_grp(mp_host_t *, mp_port_t *, fc_lun_t *,
                mp_path_t *);
static mp_port_t	*
qla2x00_find_port_by_name(mp_lun_t *, mp_path_t *);
static struct _mp_path *
qla2x00_find_first_path_to_active_tpg(mp_device_t *, mp_lun_t *, int);
static struct _mp_path *
qla2x00_find_first_active_path(mp_device_t *, mp_lun_t *);
#if 0
static int
qla2x00_is_pathid_in_port(mp_port_t *, uint8_t);
#endif
int qla2x00_export_target(void *, uint16_t , fc_port_t *, uint16_t);
int
qla2x00_get_vol_access_path(fc_port_t *fcport, fc_lun_t *fclun, int modify);
int
qla2x00_get_lun_ownership(mp_host_t *host, fc_lun_t *fclun,
		uint8_t *cur_vol_path_own);

/*
 * Global data items
 */
mp_host_t  *mp_hosts_base = NULL;
DECLARE_MUTEX(mp_hosts_lock);
int   mp_config_required = 0;
static int mp_num_hosts;
static int mp_initialized;

/*
 * ENTRY ROUTINES
 */

 /*
 *  Borrowed from scsi_scan.c
 */
int16_t
qla2x00_cfg_lookup_device(unsigned char *response_data)
{
	int i = 0;
	unsigned char *pnt;
	DEBUG3(printk(KERN_INFO "Entering %s\n", __func__));
	for (i = 0; 1; i++) {
		if (cfg_device_list[i].vendor == NULL)
			return -1;
		pnt = &response_data[8];
		while (*pnt && *pnt == ' ')
			pnt++;
		if (memcmp(cfg_device_list[i].vendor, pnt,
		    strlen(cfg_device_list[i].vendor)))
			continue;
		pnt = &response_data[16];
		while (*pnt && *pnt == ' ')
			pnt++;
		if (memcmp(cfg_device_list[i].model, pnt,
		    strlen(cfg_device_list[i].model)))
			continue;
		return i;
	}
	return -1;
}

int
qla2x00_issue_scsi_inquiry(scsi_qla_host_t *ha,
	fc_port_t *fcport, fc_lun_t *fclun)
{
	int		rval;
	int		retry;
	int		ret = 0;
	uint16_t	lun = fclun->lun;
	inq_cmd_rsp_t	*inq;
	dma_addr_t	inq_dma;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;

	inq = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &inq_dma);
	if (inq == NULL) {
		printk(KERN_WARNING
		    "scsi(%ld): Memory Allocation failed - INQ\n", ha->host_no);
		ha->mem_err++;
		return BIT_0;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &inq->p.rsp24.comp_status;
		sstatus = &inq->p.rsp24.scsi_status;
	} else {
		cstatus = &inq->p.rsp.comp_status;
		sstatus = &inq->p.rsp.scsi_status;
	}

	retry = 2;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(inq, 0, sizeof(inq_cmd_rsp_t));
			inq->p.cmd24.entry_type = COMMAND_TYPE_7;
			inq->p.cmd24.entry_count = 1;
			inq->p.cmd24.nport_handle =
			    cpu_to_le16(fcport->loop_id);
			inq->p.cmd24.port_id[0] = fcport->d_id.b.al_pa;
			inq->p.cmd24.port_id[1] = fcport->d_id.b.area;
			inq->p.cmd24.port_id[2] = fcport->d_id.b.domain;
			inq->p.cmd24.lun[1] = LSB(lun);
			inq->p.cmd24.lun[2] = MSB(lun);
			host_to_fcp_swap(inq->p.cmd24.lun,
			    sizeof(inq->p.cmd24.lun));
			inq->p.cmd24.task_mgmt_flags =
			    __constant_cpu_to_le16(TMF_READ_DATA);
			inq->p.cmd24.task = TSK_SIMPLE;
			inq->p.cmd24.fcp_cdb[0] = INQUIRY;
			inq->p.cmd24.fcp_cdb[4] = INQ_DATA_SIZE;
			host_to_fcp_swap(inq->p.cmd24.fcp_cdb,
			    sizeof(inq->p.cmd24.fcp_cdb));
			inq->p.cmd24.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd24.timeout = __constant_cpu_to_le16(3);
			inq->p.cmd24.byte_count =
			    __constant_cpu_to_le32(INQ_DATA_SIZE);
			inq->p.cmd24.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_len =
			    __constant_cpu_to_le32(INQ_DATA_SIZE);
		} else {
			memset(inq, 0, sizeof(inq_cmd_rsp_t));
			inq->p.cmd.entry_type = COMMAND_A64_TYPE;
			inq->p.cmd.entry_count = 1;
			inq->p.cmd.lun = cpu_to_le16(lun);
			SET_TARGET_ID(ha, inq->p.cmd.target, fcport->loop_id);
			inq->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_READ | CF_SIMPLE_TAG);
			inq->p.cmd.scsi_cdb[0] = INQUIRY;
			inq->p.cmd.scsi_cdb[4] = INQ_DATA_SIZE;
			inq->p.cmd.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd.timeout = __constant_cpu_to_le16(3);
			inq->p.cmd.byte_count =
			    __constant_cpu_to_le32(INQ_DATA_SIZE);
			inq->p.cmd.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_length =
			    __constant_cpu_to_le32(INQ_DATA_SIZE);
		}

		DEBUG(printk("scsi(%ld:0x%x:%d) %s: Inquiry - fcport=%p, lun "
		    "(%d)\n", ha->host_no, fcport->loop_id, lun, __func__,
		    fcport, lun));

		rval = qla2x00_issue_iocb(ha, inq, inq_dma,
		    sizeof(inq_cmd_rsp_t));

		if (rval == QLA_SUCCESS && inq->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) INQ failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    inq->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE) &&
	    --retry);

	if (rval != QLA_SUCCESS || comp_status != CS_COMPLETE ||
	    (scsi_status & SS_CHECK_CONDITION)) {
		DEBUG2(printk("%s: Failed lun inquiry - inq[0]= 0x%x, comp "
		    "status 0x%x, scsi status 0x%x. loop_id=%d\n", __func__,
		    inq->inq[0], comp_status, scsi_status, fcport->loop_id));
		ret = 1;
	} else {
		fclun->device_type = inq->inq[0];
	}
	DEBUG(printk("%s(%ld): lun=%d device_type=0x%x\n",__func__, ha->host_no, lun, fclun->device_type));
	dma_pool_free(ha->s_dma_pool, inq, inq_dma);

	return (ret);
}

int
qla2x00_test_active_lun(fc_port_t *fcport, fc_lun_t *fclun, uint8_t *wait_for_transition)
{
	int		rval = 0;
	int		retry;
	scsi_qla_host_t *ha;
	uint16_t	lun = 0;
	tur_cmd_rsp_t	*tur;
	dma_addr_t	tur_dma;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;

	ha = fcport->ha;
	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG2(printk("scsi(%ld) %s leaving: Port loop_id 0x%02x is "
		    "marked DEAD\n", ha->host_no, __func__, fcport->loop_id));
		return rval;
	}

	if (fclun == NULL) {
		DEBUG2(printk("scsi(%ld) %s Bad fclun ptr on entry.\n",
		    ha->host_no, __func__));
		return rval;
	}

	lun = fclun->lun;

	tur = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &tur_dma);
	if (tur == NULL) {
		printk(KERN_WARNING
		    "scsi(%ld): Memory Allocation failed - TUR\n", ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &tur->p.rsp24.comp_status;
		sstatus = &tur->p.rsp24.scsi_status;
		sense_data = tur->p.rsp24.data;
	} else {
		cstatus = &tur->p.rsp.comp_status;
		sstatus = &tur->p.rsp.scsi_status;
		sense_data = tur->p.rsp.req_sense_data;
	}

	retry = 4;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(tur, 0, sizeof(tur_cmd_rsp_t));
			tur->p.cmd24.entry_type = COMMAND_TYPE_7;
			tur->p.cmd24.entry_count = 1;
			tur->p.cmd24.nport_handle =
			    cpu_to_le16(fcport->loop_id);
			tur->p.cmd24.port_id[0] = fcport->d_id.b.al_pa;
			tur->p.cmd24.port_id[1] = fcport->d_id.b.area;
			tur->p.cmd24.port_id[2] = fcport->d_id.b.domain;
			tur->p.cmd24.lun[1] = LSB(lun);
			tur->p.cmd24.lun[2] = MSB(lun);
			host_to_fcp_swap(tur->p.cmd24.lun,
			    sizeof(tur->p.cmd24.lun));
			tur->p.cmd24.task = TSK_SIMPLE;
			tur->p.cmd24.fcp_cdb[0] = TEST_UNIT_READY;
			host_to_fcp_swap(tur->p.cmd24.fcp_cdb,
			    sizeof(tur->p.cmd24.fcp_cdb));
			tur->p.cmd24.dseg_count = __constant_cpu_to_le16(0);
			tur->p.cmd24.timeout = __constant_cpu_to_le16(3);
			tur->p.cmd24.byte_count = __constant_cpu_to_le32(0);
		} else {
			memset(tur, 0, sizeof(tur_cmd_rsp_t));
			tur->p.cmd.entry_type = COMMAND_A64_TYPE;
			tur->p.cmd.entry_count = 1;
			tur->p.cmd.lun = cpu_to_le16(lun);
			SET_TARGET_ID(ha, tur->p.cmd.target, fcport->loop_id);
			tur->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_SIMPLE_TAG);
			tur->p.cmd.scsi_cdb[0] = TEST_UNIT_READY;
			tur->p.cmd.dseg_count = __constant_cpu_to_le16(0);
			tur->p.cmd.timeout = __constant_cpu_to_le16(3);
			tur->p.cmd.byte_count = __constant_cpu_to_le32(0);
		}

		rval = qla2x00_issue_iocb(ha, tur, tur_dma,
		    sizeof(tur_cmd_rsp_t));

		if (rval == QLA_SUCCESS && tur->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) TUR failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    tur->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

		/* Port Logged Out, so don't retry */
		if (comp_status == CS_PORT_LOGGED_OUT ||
		    comp_status == CS_PORT_CONFIG_CHG ||
		    comp_status == CS_PORT_BUSY ||
		    comp_status == CS_INCOMPLETE ||
		    comp_status == CS_PORT_UNAVAILABLE)
			break;

		DEBUG(printk("scsi(%ld:%04x:%d) %s: TEST UNIT READY - comp "
		    "status 0x%x, scsi status 0x%x, rval=%d\n", ha->host_no,
		    fcport->loop_id, lun,__func__, comp_status, scsi_status,
		    rval));

		if (scsi_status & SS_CHECK_CONDITION) {
			/* Skip past any FCP RESPONSE data. */
			if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
				host_to_fcp_swap(sense_data,
				    sizeof(tur->p.rsp24.data));
				if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
					sense_data += le32_to_cpu(
					    tur->p.rsp24.rsp_data_len);
			}

			DEBUG2(printk("%s: check status bytes = "
			    "0x%02x 0x%02x 0x%02x\n", __func__, sense_data[2],
			    sense_data[12], sense_data[13]));

			if (sense_data[2] == NOT_READY &&
			    sense_data[12] == 0x4 && sense_data[13] == 0x2)
				break;

 	     		if (fcport->flags & FC_DSXXX_DEVICE) {
				/* Wait for transition to complete */
				if (sense_data[2] == NOT_READY && sense_data[12] == 0x4 &&
				    sense_data[13] == 0xa)  {
					 rval = 1;
					 break;
				}
				/* Already switched status - active on other controller */
				if (sense_data[2] == NOT_READY && sense_data[12] == 0x4 &&
				    (sense_data[13] == 0xb || sense_data[13] == 0x00)) {
					 if (wait_for_transition)
						 *wait_for_transition = 0;
					 rval = 1;
					 break;
				}
			}
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE ||
	    (scsi_status & SS_CHECK_CONDITION)) && --retry);

	if (rval == QLA_SUCCESS && retry &&
	    (!((scsi_status & SS_CHECK_CONDITION) &&
		(sense_data[2] == NOT_READY && sense_data[12] == 0x4 &&
		    sense_data[13] == 0x2)) && comp_status == CS_COMPLETE)) {

		DEBUG2(printk("scsi(%ld) %s - Lun (0x%02x:%d) set to ACTIVE.\n",
		    ha->host_no, __func__, fcport->loop_id, lun));

		/* We found an active path */
		fclun->flags |= FLF_ACTIVE_LUN;
		rval = 1;
	} else {
		DEBUG2(printk("scsi(%ld) %s - Lun (0x%02x:%d) set to "
		    "INACTIVE.\n", ha->host_no, __func__, fcport->loop_id,
		    lun));
		/* fcport->flags &= ~(FC_MSA_PORT_ACTIVE); */
		fclun->flags &= ~(FLF_ACTIVE_LUN);
		rval = 0;
	}

	dma_pool_free(ha->s_dma_pool, tur, tur_dma);

	LEAVE(__func__);

	return rval;
}

static fc_lun_t *
qla2x00_find_data_lun(fc_port_t *fcport)
{
	scsi_qla_host_t *ha;
	fc_lun_t	*fclun, *ret_fclun;

	ha = fcport->ha;
	ret_fclun = NULL;

	/* Go thur all luns and find a good data lun */
	list_for_each_entry(fclun, &fcport->fcluns, list) {
		fclun->flags &= ~FLF_VISIBLE_LUN;
		if (fclun->device_type == 0xff)
			qla2x00_issue_scsi_inquiry(ha, fcport, fclun);
		if (fclun->device_type == 0xc)
			fclun->flags |= FLF_VISIBLE_LUN;
		else if (fclun->device_type == TYPE_DISK) {
			ret_fclun = fclun;
		}
	}
	return (ret_fclun);
}

/*
 * qla2x00_test_active_port
 *	Determines if the port is in active or standby mode. First, we
 *	need to locate a storage lun then do a TUR on it.
 *
 * Input:
 *	fcport = port structure pointer.
 *
 *
 * Return:
 *	0  - Standby or error
 *  1 - Active
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_test_active_port(fc_port_t *fcport)
{
	int		rval = 0 ;
	int		retry;
	scsi_qla_host_t *ha;
	uint16_t	lun = 0;
	fc_lun_t	*fclun;
	tur_cmd_rsp_t	*tur;
	dma_addr_t	tur_dma;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;

	ENTER(__func__);

	ha = fcport->ha;
	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG2(printk("scsi(%ld) %s leaving: Port 0x%02x is marked "
		    "DEAD\n", ha->host_no,__func__,fcport->loop_id));
		return rval;
	}

	if ((fclun = qla2x00_find_data_lun(fcport)) == NULL) {
		DEBUG2(printk(KERN_INFO "%s leaving: Couldn't find data lun\n",
		    __func__));
		return rval;
	}
	lun = fclun->lun;

	tur = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &tur_dma);
	if (tur == NULL) {
		printk(KERN_WARNING
		    "scsi(%ld): Memory Allocation failed - TUR\n",
		    ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &tur->p.rsp24.comp_status;
		sstatus = &tur->p.rsp24.scsi_status;
		sense_data = tur->p.rsp24.data;
	} else {
		cstatus = &tur->p.rsp.comp_status;
		sstatus = &tur->p.rsp.scsi_status;
		sense_data = tur->p.rsp.req_sense_data;
	}

	retry = 4;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(tur, 0, sizeof(tur_cmd_rsp_t));
			tur->p.cmd24.entry_type = COMMAND_TYPE_7;
			tur->p.cmd24.entry_count = 1;
			tur->p.cmd24.nport_handle =
			    cpu_to_le16(fcport->loop_id);
			tur->p.cmd24.port_id[0] = fcport->d_id.b.al_pa;
			tur->p.cmd24.port_id[1] = fcport->d_id.b.area;
			tur->p.cmd24.port_id[2] = fcport->d_id.b.domain;
			tur->p.cmd24.lun[1] = LSB(lun);
			tur->p.cmd24.lun[2] = MSB(lun);
			host_to_fcp_swap(tur->p.cmd24.lun,
			    sizeof(tur->p.cmd24.lun));
			tur->p.cmd24.task = TSK_SIMPLE;
			tur->p.cmd24.fcp_cdb[0] = TEST_UNIT_READY;
			host_to_fcp_swap(tur->p.cmd24.fcp_cdb,
			    sizeof(tur->p.cmd24.fcp_cdb));
			tur->p.cmd24.dseg_count = __constant_cpu_to_le16(0);
			tur->p.cmd24.timeout = __constant_cpu_to_le16(3);
			tur->p.cmd24.byte_count = __constant_cpu_to_le32(0);
		} else {
			memset(tur, 0, sizeof(tur_cmd_rsp_t));
			tur->p.cmd.entry_type = COMMAND_A64_TYPE;
			tur->p.cmd.entry_count = 1;
			tur->p.cmd.lun = cpu_to_le16(lun);
			SET_TARGET_ID(ha, tur->p.cmd.target, fcport->loop_id);
			tur->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_SIMPLE_TAG);
			tur->p.cmd.scsi_cdb[0] = TEST_UNIT_READY;
			tur->p.cmd.dseg_count = __constant_cpu_to_le16(0);
			tur->p.cmd.timeout = __constant_cpu_to_le16(3);
			tur->p.cmd.byte_count = __constant_cpu_to_le32(0);
		}

		rval = qla2x00_issue_iocb(ha, tur, tur_dma,
		    sizeof(tur_cmd_rsp_t));

		if (rval == QLA_SUCCESS && tur->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) TUR failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    tur->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

 		/* Port Logged Out, so don't retry */
		if (comp_status == CS_PORT_LOGGED_OUT ||
		    comp_status == CS_PORT_CONFIG_CHG ||
		    comp_status == CS_PORT_BUSY ||
		    comp_status == CS_INCOMPLETE ||
		    comp_status == CS_PORT_UNAVAILABLE)
			break;

		DEBUG(printk("scsi(%ld:%04x:%d) %s: TEST UNIT READY - comp "
		    "status 0x%x, scsi status 0x%x, rval=%d\n", ha->host_no,
		    fcport->loop_id, lun,__func__, comp_status, scsi_status,
		    rval));
		if (scsi_status & SS_CHECK_CONDITION) {
			/* Skip past any FCP RESPONSE data. */
			if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
				host_to_fcp_swap(sense_data,
				    sizeof(tur->p.rsp24.data));
				if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
					sense_data += le32_to_cpu(
					    tur->p.rsp24.rsp_data_len);
			}

			DEBUG2(printk("%s: check status bytes = "
			    "0x%02x 0x%02x 0x%02x\n", __func__, sense_data[2],
			    sense_data[12], sense_data[13]));

			if (sense_data[2] == NOT_READY &&
			    sense_data[12] == 0x4 && sense_data[13] == 0x2)
				break;
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE ||
	    (scsi_status & SS_CHECK_CONDITION)) && --retry);

	if (rval == QLA_SUCCESS && retry &&
	    (!((scsi_status & SS_CHECK_CONDITION) &&
		(sense_data[2] == NOT_READY && sense_data[12] == 0x4 &&
		    sense_data[13] == 0x2)) && comp_status == CS_COMPLETE)) {
		DEBUG2(printk("scsi(%ld) %s - Port (0x%04x) set to ACTIVE.\n",
		    ha->host_no, __func__, fcport->loop_id));
		/* We found an active path */
       		fcport->flags |= FC_MSA_PORT_ACTIVE;
		rval = 1;
	} else {
		DEBUG2(printk("scsi(%ld) %s - Port (0x%04x) set to INACTIVE.\n",
		    ha->host_no, __func__, fcport->loop_id));
       		fcport->flags &= ~(FC_MSA_PORT_ACTIVE);
	}

	dma_pool_free(ha->s_dma_pool, tur, tur_dma);

	LEAVE(__func__);

	return rval;
}

/*
 * Enable Auto Restore enables auto failback capability.
 */
static inline void
qla2x00_enable_auto_restore(fc_port_t *fcport)
{
	if (fcport->cfg_id == -1) {
	 	DEBUG2(printk("%s(%ld) this device: loop_id=0x%x is not in"
			" the cfg_device_list[] database\n", __func__,
			fcport->ha->host_no, fcport->loop_id));
		return;
	}

	if (fcport->flags & (FC_MSA_DEVICE | FC_EVA_DEVICE)) {
		DEBUG2(printk("%s(%ld) support disabled for MSA/EVA"
		    		" Active/Passive device\n", __func__,
				fcport->ha->host_no));
		return;
	}

	if (cfg_device_list[fcport->cfg_id].flags & ql2xautorestore) {
		if (fcport->flags & FC_FAILBACK_DISABLE)
			fcport->flags &= ~FC_FAILBACK_DISABLE;
		else
			fcport->flags |= FC_FAILBACK_DISABLE;
	 	DEBUG2(printk("%s(%ld): enabled autorestore for loop_id=0x%x "
			 "fcport_flags=0x%x\n", __func__, fcport->ha->host_no,
			  fcport->loop_id, fcport->flags));
	}

}


void
qla2x00_set_device_flags(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	if (fcport->cfg_id == -1)
		return;

	fcport->flags &= ~(FC_XP_DEVICE|FC_MSA_DEVICE|FC_EVA_DEVICE|
				FC_DSXXX_DEVICE | FC_AA_EVA_DEVICE |
				FC_DFXXX_DEVICE | FC_AA_MSA_DEVICE |
				FC_NVSXXX_DEVICE| FC_SYMXXX_DEVICE);
	if ((cfg_device_list[fcport->cfg_id].flags & BIT_0)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is an XP device\n", ha->host_no,
		    fcport->loop_id);
		fcport->flags |= FC_XP_DEVICE;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_1)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is a MSA1000 device\n",
		    ha->host_no, fcport->loop_id);
		fcport->flags |= FC_MSA_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_2)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is a EVA device\n", ha->host_no,
		    fcport->loop_id);
		fcport->flags |= FC_EVA_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_4)) {
                printk(KERN_INFO
                    "scsi(%ld) :Loop id 0x%04x is an DSXXX device\n",
                         ha->host_no, fcport->loop_id);
                fcport->flags |= FC_DSXXX_DEVICE;
        } else if ((cfg_device_list[fcport->cfg_id].flags & BIT_5)) {
                printk(KERN_INFO
                    "scsi(%ld) :Loop id 0x%04x is an EVA_XL (AA) device\n",
                         ha->host_no, fcport->loop_id);
                fcport->flags |= FC_AA_EVA_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
        } else if ((cfg_device_list[fcport->cfg_id].flags & BIT_7)) {
                printk(KERN_INFO
                    "scsi(%ld) :Loop id 0x%04x is an MSA (AA) device\n",
                         ha->host_no, fcport->loop_id);
                fcport->flags |= FC_AA_MSA_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
        } else if ((cfg_device_list[fcport->cfg_id].flags & BIT_8)) {
                printk(KERN_INFO
                    "scsi(%ld) :Loop id 0x%04x is an DF700 device\n",
                           ha->host_no, fcport->loop_id);
                fcport->flags |= FC_DFXXX_DEVICE;
 		fcport->fo_target_port = qla2x00_get_vol_access_path;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_9)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is an NVS1000 device\n",
		    ha->host_no, fcport->loop_id);
		fcport->flags |= FC_NVSXXX_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_11)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is an NSP 202 device\n",
		    ha->host_no, fcport->loop_id);
		fcport->flags |= FC_NVSXXX_DEVICE;
		fcport->flags |= FC_FAILBACK_DISABLE;
	} else if ((cfg_device_list[fcport->cfg_id].flags & BIT_10)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x is an SYMXXX device\n",
		    ha->host_no, fcport->loop_id);
		fcport->flags |= FC_SYMXXX_DEVICE;
	}

	if ((cfg_device_list[fcport->cfg_id].flags & 8)) {
		printk(KERN_INFO
		    "scsi(%ld) :Loop id 0x%04x has FAILOVERS disabled.\n",
		    ha->host_no, fcport->loop_id);
		fcport->flags |= FC_FAILOVER_DISABLE;
	}

	   /* Enable Failback for the devices specified
	    * on the cmd line.
	    */
	   qla2x00_enable_auto_restore(fcport);
}


static int
qla2x00_configure_cfg_device(fc_port_t *fcport)
{
	int id = fcport->cfg_id;
	int exclude = 0;

	DEBUG3(printk("Entering %s - id= %d\n", __func__, fcport->cfg_id));

	if (fcport->cfg_id == -1)
		return 0;

	/* Set any notify options */
	if (cfg_device_list[id].notify_type != FO_NOTIFY_TYPE_NONE) {
		fcport->notify_type = cfg_device_list[id].notify_type;
	}

	DEBUG3(printk("%s - Configuring device \n", __func__));

	fcport->fo_combine = cfg_device_list[id].fo_combine;

	/* For some device we fake target port group support.
	 * This points to vendor specific implementation -
	 * for ex: qla2x00_get_vol_access_path() etc.
	 * So it may be already set.
	 */
 	if (fcport->fo_target_port == NULL)
	fcport->fo_target_port = cfg_device_list[id].fo_target_port;

	/* Disable failover capability if needed  and return */
	if (ql2xexcludemodel) {
		if ((ql2xexcludemodel & BIT_0)  &&
		    (fcport->flags & FC_XP_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_1) &&
		    (fcport->flags & FC_MSA_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_2) &&
		    (fcport->flags & FC_EVA_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_4) &&
		    (fcport->flags & FC_DSXXX_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_5) &&
		    (fcport->flags & FC_AA_EVA_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_7) &&
		    (fcport->flags & FC_AA_MSA_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_8) &&
			(fcport->flags & FC_DFXXX_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_9) &&
			(fcport->flags & FC_NVSXXX_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_10) &&
			(fcport->flags & FC_SYMXXX_DEVICE)) {
			exclude++;
		} else if ((ql2xexcludemodel & BIT_11) &&
			(fcport->flags & FC_NVSXXX_DEVICE)) {
			/* Support for NSP Device */
			exclude++;
		}
		if (exclude) {
			printk(KERN_INFO
			    "scsi(%ld): Excluding Loopid 0x%04x as a "
			    "failover capable device.\n",
			    fcport->ha->host_no, fcport->loop_id);

			fcport->flags |= FC_FAILOVER_DISABLE;
			fcport->fo_combine = qla2x00_export_target;
			fcport->fo_target_port = NULL;
		}
	}

	DEBUG3(printk("Exiting %s - id= %d\n", __func__, fcport->cfg_id));

	return 1;
}


/*
 * qla2x00_get_lbtype
 *
 * get the lbtype and set in the dp
 */
static void
qla2x00_get_lbtype(scsi_qla_host_t *ha)
{
        int rval;
        int lbtype, i;
        uint8_t *propbuf;
        uint8_t nn[WWN_SIZE];
        mp_device_t     *dp;    /* virtual device pointer */

        if (!ql2xdevconf)
                return;

        propbuf = kmalloc(LINESIZE, GFP_KERNEL);
        if (!propbuf)
                return;

        for (lbtype = 0; lbtype <= LB_LRU_BYTES; lbtype++) {
                for (i = 0; i < 256; i++) {
                        sprintf(propbuf, "scsi-lbtype-%d-key%d-tgtname", lbtype,i);
                        rval = qla2x00_get_prop_xstr(ha, propbuf, nn, WWN_SIZE);
                        if (rval != WWN_SIZE) {
                                continue;
                        }
                        if ((dp = qla2x00_find_dp_from_all_hosts(nn)) != NULL) {
                                dp->lbtype = lbtype;
                        }
                }
        }
        kfree(propbuf);
}

/*
 * qla2x00_cfg_init
 *      Initialize configuration structures to handle an instance of
 *      an HBA, QLA2x000 card.
 *
 * Input:
 *      ha = adapter state pointer.
 *
 * Returns:
 *      qla2x00 local function return status code.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_cfg_init(scsi_qla_host_t *ha)
{
	int	rval;

	ENTER("qla2x00_cfg_init");
	set_bit(CFG_ACTIVE, &ha->cfg_flags);
	mp_initialized = 1;
	/* First HBA, initialize the failover global properties */
	qla2x00_fo_init_params(ha);

	down(&mp_hosts_lock);
	/*
	 * If the user specified a device configuration then it is use as the
	 * configuration. Otherwise, we wait for path discovery.
	 */
	if (mp_config_required)
		qla2x00_cfg_build_path_tree(ha);

	/* Get all the LB Type */
   	qla2x00_get_lbtype(ha);

	rval = qla2x00_cfg_path_discovery(ha);
	up(&mp_hosts_lock);
	clear_bit(CFG_ACTIVE, &ha->cfg_flags);

	LEAVE("qla2x00_cfg_init");
	return rval;
}

/*
 * qla2x00_cfg_path_discovery
 *      Discover the path configuration from the device configuration
 *      for the specified host adapter and build the path search tree.
 *      This function is called after the lower level driver has
 *      completed its port and lun discovery.
 *
 * Input:
 *      ha = adapter state pointer.
 *
 * Returns:
 *      qla2x00 local function return status code.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_cfg_path_discovery(scsi_qla_host_t *ha)
{
	int		rval = QLA_SUCCESS;
	mp_host_t	*host;

	ENTER("qla2x00_cfg_path_discovery");

	set_bit(CFG_ACTIVE, &ha->cfg_flags);
	/* Initialize the path tree for this adapter */
	host = qla2x00_find_host_by_portname(ha->port_name);
	if (mp_config_required) {
		if (host == NULL) {
			DEBUG4(printk("cfg_path_discovery: host not found, "
			    "port port_name = "
			    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    ha->port_name[0], ha->port_name[1],
			    ha->port_name[2], ha->port_name[3],
			    ha->port_name[4], ha->port_name[5],
			    ha->port_name[6], ha->port_name[7]));
			rval = QLA_FUNCTION_FAILED;
		} else if (ha->instance != host->instance) {
			DEBUG4(printk("cfg_path_discovery: host instance "
				"don't match - instance=%ld.\n",
				ha->instance));
			rval = QLA_FUNCTION_FAILED;
		}
	} else if (host == NULL) {
		/* New host adapter so allocate it */
		DEBUG3(printk("%s: found new ha inst %ld. alloc host.\n",
		    __func__, ha->instance));
		if ((host = qla2x00_alloc_host(ha)) == NULL) {
			printk(KERN_INFO
				"qla2x00(%d): Couldn't allocate "
				"host - ha = %p.\n",
				(int)ha->instance, ha);
			rval = QLA_FUNCTION_FAILED;
		}
	}

	/* Fill in information about host */
	if (host != NULL) {
		host->flags |= MP_HOST_FLAG_NEEDS_UPDATE;
		host->flags |= MP_HOST_FLAG_LUN_FO_ENABLED;
		host->fcports = &ha->fcports;

		/* Check if multipath is enabled */
		DEBUG3(printk("%s: updating mp host for ha inst %ld.\n",
		    __func__, ha->instance));
		if (!qla2x00_update_mp_host(host)) {
			rval = QLA_FUNCTION_FAILED;
		}
		host->flags &= ~MP_HOST_FLAG_LUN_FO_ENABLED;
	}

	if (rval != QLA_SUCCESS) {
		/* EMPTY */
		DEBUG4(printk("qla2x00_path_discovery: Exiting FAILED\n"));
	} else {
		LEAVE("qla2x00_cfg_path_discovery");
	}
	clear_bit(CFG_ACTIVE, &ha->cfg_flags);

	return rval;
}

/*
 * qla2x00_cfg_event_notifiy
 *      Callback for host driver to notify us of configuration changes.
 *
 * Input:
 *      ha = adapter state pointer.
 *      i_type = event type
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_cfg_event_notify(scsi_qla_host_t *ha, uint32_t i_type)
{
	mp_host_t	*host;			/* host adapter pointer */

	ENTER("qla2x00_cfg_event_notify");

	set_bit(CFG_ACTIVE, &ha->cfg_flags);
	switch (i_type) {
		case MP_NOTIFY_RESET_DETECTED:
			DEBUG(printk("scsi%ld: MP_NOTIFY_RESET_DETECTED "
					"- no action\n",
					ha->host_no));
				break;
		case MP_NOTIFY_PWR_LOSS:
			DEBUG(printk("scsi%ld: MP_NOTIFY_PWR_LOSS - "
					"update tree\n",
					ha->host_no));
			/*
			 * Update our path tree in case we are
			 * losing the adapter
			 */
			down(&mp_hosts_lock);
			qla2x00_update_mp_tree();
			up(&mp_hosts_lock);
			break;
		case MP_NOTIFY_LOOP_UP:
			DEBUG(printk("scsi%ld: MP_NOTIFY_LOOP_UP - "
					"update host tree\n",
					ha->host_no));
			/* Adapter is back up with new configuration */
			if ((host = qla2x00_cfg_find_host(ha)) != NULL) {
				host->flags |= MP_HOST_FLAG_NEEDS_UPDATE;
				host->fcports = &ha->fcports;
				set_bit(CFG_FAILOVER, &ha->cfg_flags);
				down(&mp_hosts_lock);
				qla2x00_update_mp_tree();
				up(&mp_hosts_lock);
				clear_bit(CFG_FAILOVER, &ha->cfg_flags);
			}
			break;
		case MP_NOTIFY_LOOP_DOWN:
		case MP_NOTIFY_BUS_RESET:
			DEBUG(printk("scsi%ld: MP_NOTIFY_OTHERS - "
					"no action\n",
					ha->host_no));
			break;
		default:
			break;

	}
	clear_bit(CFG_ACTIVE, &ha->cfg_flags);

	LEAVE("qla2x00_cfg_event_notify");

	return QLA_SUCCESS;
}

void
qla2x00_cfg_select_route(srb_t *sp)
{
	mp_lun_t *mplun;
	struct list_head *list, *temp;
	fc_lun_t 	*tmp_fclun, *fclun;
 	lu_path_t   	*lun_path;
	int		i;

	DEBUG3(printk("qla2x00_cfg_select_route() sp=%p, fclun=%p\n",
			sp, sp->fclun));

	if ((fclun = sp->fclun) == NULL)
		return;

	mplun = (mp_lun_t *)fclun->mplun;
	if (mplun != NULL)
	{
		DEBUG3(printk("qla2x00_cfg_select_route(%ld) pid=%ld mplun=%p, fclun=%p, "
			"lun %d, port= %02x, active cnt=%d, pathid=%d, dest ha =%ld, type=%d, %d\n",
			sp->ha->host_no, sp->cmd->serial_number,fclun->mplun,fclun,mplun->number,
			fclun->fcport->loop_id,
			mplun->act_cnt,mplun->active,
			fclun->fcport->ha->host_no, mplun->dp->lbtype,
						mplun->load_balance_type));
		switch (mplun->load_balance_type) {
			case	LB_RR:
				i = 0;
#ifdef NOT_TESTED
 				list_for_each_safe(list, temp, &mplun->active_list) {
 					lun_path = list_entry(list, lu_path_t, next_active);
					tmp_fclun = lun_path->fclun;
					if (mplun->active == i) {
						fclun = tmp_fclun;
						DEBUG3(printk("%s:RR - selecting"
							" fclun %p, index %d ...\n",
							__func__,fclun,mplun->active));
						/* next path */
						mplun->active = lun_path->path_id;
						break;
					}
					i++;
				}
				/* point to next path */
				if (mplun->active > mplun->act_cnt)
					mplun->active = 0;
#endif
				break;

			case	LB_LRU:
 				list_for_each_safe(list, temp, &mplun->active_list) {
 					lun_path = list_entry(list, lu_path_t, next_active);
					tmp_fclun = lun_path->fclun;
					if (tmp_fclun == fclun)
						continue;
					DEBUG3(printk("%s:LRU -  selecting fclun"
					" %p, path_id=%d, cmp= %ld < %ld ...\n",
					__func__,tmp_fclun,lun_path->path_id,
					tmp_fclun->io_cnt,fclun->io_cnt));
					if (tmp_fclun->io_cnt < fclun->io_cnt) {
						fclun = tmp_fclun;
						mplun->active = lun_path->path_id;
					DEBUG3(printk("%s:LRU -  CHANGED to pathid=%d"
					" fclun %p, cmp= %ld < %ld port %02x...\n",
					__func__,lun_path->path_id,tmp_fclun,
					tmp_fclun->io_cnt,fclun->io_cnt,tmp_fclun->fcport->loop_id));
					}
				}
				break;

			case	LB_LST:
 				list_for_each_safe(list, temp, &mplun->active_list) {
 					lun_path = list_entry(list, lu_path_t, next_active);
					tmp_fclun = lun_path->fclun;
					if (tmp_fclun == fclun)
						continue;
					DEBUG3(printk("%s:LST -  selecting fclun %p, path_id=%d,"
							" cmp= %ld < %ld ...\n",
					__func__,tmp_fclun,lun_path->path_id,
					tmp_fclun->io_cnt,fclun->io_cnt));
					if (time_before(tmp_fclun->s_time,
					    fclun->s_time)) {
						fclun = tmp_fclun;
						mplun->active = lun_path->path_id;
						DEBUG3(printk("%s:LST -  SELECTED pathid=%d"
							" fclun %p, cmp= %ld < %ld port %02x...\n",
							__func__,lun_path->path_id,tmp_fclun,
						tmp_fclun->io_cnt,fclun->io_cnt,
						tmp_fclun->fcport->loop_id));
					}
				}
				break;

			default:
				DEBUG3(printk("%s: -  Selected default: fclun %p ...\n",__func__,fclun));
				return ;
		}
	}
	/* if we change fclun ptrs then update everything */
	if (fclun != sp->fclun) {
		sp->lun_queue->fclun = fclun;
		DEBUG3(printk("%s:Changing to fclun %p from %p...\n",__func__,
			fclun,sp->fclun));
		sp->fclun = fclun;
		sp->ha = fclun->fcport->ha;
	}
}

static int
qla2x00_chg_lun_to_preferred_path(scsi_qla_host_t *ha, mp_lun_t *mplun, int id)
{
	mp_device_t 	 *dp;
	lu_path_t   	 *lu_path;
	mp_path_t 	 *path, *old_path;
	fc_lun_t	*fclun;

  	if (mplun == NULL) {
		return 0;
	}

	DEBUG(printk("scsi%ld: %s : mplun %d preferred via configuration - id "
	    "%d \n", ha->host_no, __func__, mplun->number, id));
	dp = mplun->dp;
 	if ((path = qla2x00_find_path_by_id(dp, id)) == NULL)
		return 0;
	/* get fclun for this path */
	if ((fclun = mplun->paths[id]) == NULL)
		return 0;

 	if (path->port == NULL)
		return 0;

	if ((fclun->flags & FLF_VISIBLE_LUN)) {
	DEBUG2(printk("scsi%ld: %s : mplun %d Skipping "
		"controller lun in conf\n"
	    , ha->host_no, __func__, mplun->number));
		return 0;
	}

 	/* Is this path on an active controller? */
	/* Is this path on an active controller? */
	if ((path->port->flags & FC_EVA_DEVICE)  &&
   		(fclun->flags & FLF_ACTIVE_LUN)) {
		return 0;
	}

	if ((path->port->flags & FC_MSA_DEVICE)  &&
       	   (path->port->flags & FC_MSA_PORT_ACTIVE)) {
		return 0;
	}
	/* Is this path on the OPT controller? */
	if (path->port->fo_target_port) {
		lu_path = qla2x00_find_lu_path_by_id(mplun,id);
		if (lu_path == NULL)
			return 0;
		if (lu_path->asym_acc_state == TPG_ACT_OPT)
			return 0;
		old_path = qla2x00_find_first_path_to_active_tpg(dp, mplun, 0);
	} else {
		old_path = qla2x00_find_first_active_path(dp, mplun);
	}
	if (old_path == NULL)
		return 0;
	DEBUG(printk("scsi%ld: %s : mplun %d SWITCHING from id=%d to "
	    "preferred path id=%d\n", ha->host_no, __func__, mplun->number,
	    old_path->id, id));

	qla2x00_send_failover_notify(dp, mplun->number, path, old_path);
	return 1;
}

static int
qla2x00_set_preferred_path(mp_lun_t *mplun, int order, int flag)
{
	mp_device_t 	 *dp;
	lu_path_t   	 *lun_path;
	struct list_head *list, *temp;
	int 		 paths_cnt = 0, path_id, path_order;
	mp_path_t 	 *path, *oldpath;
 	int 		id;
	fc_lun_t	*fclun;

	DEBUG(printk("%s entered\n",__func__));

  	if (mplun == NULL) {
		return 0;
	}

	dp = mplun->dp;
	path_id = PATH_INDEX_INVALID;
	if (mplun->asymm_support == TGT_PORT_GRP_UNSUPPORTED) {
		/* We always have the first path */
		if ((fclun = mplun->paths[0]) != NULL) {
		     if (!(fclun->fcport->flags & FC_AA_EVA_DEVICE) &&
			  !(fclun->fcport->flags & FC_DFXXX_DEVICE))
				return 0;
		}
	}

  	id = mplun->pref_path_id;
 	/* we have a preferred setting from the qla2xxx.conf file, so use it */
 	if (flag) {
 		path = qla2x00_find_path_by_id(dp, mplun->config_pref_id);
  		if (path) {
 			if (id != PATH_INDEX_INVALID) {
 			oldpath = qla2x00_find_path_by_id(dp,
 			    id);
 				if (oldpath) {
 				oldpath->lun_data.data[
 				    mplun->number] &=
 					~LUN_DATA_PREFERRED_PATH;
 				DEBUG2(printk("%s Removing "
 				    "previous preferred "
 				    "setting for id=%d\n",
 				    __func__, id));
 				}
 			}
  			path_id = path->id;
			path->lun_data.data[mplun->number] |=
                                    LUN_DATA_PREFERRED_PATH;
  			DEBUG2(printk( "%s: Found (preferred config) preferred lun lun=%d,"
  				" pathid=%d\n", __func__, mplun->number,
  				  path->id));
 		} else {
  			printk( KERN_INFO "%s: Could use conf preferred setting lun=%d,"
  				" pathid=%d\n", __func__, mplun->number, id);
 			goto set_preferred_def;
 		}
 		goto set_preferred_end;
 	}

	switch (mplun->load_balance_type) {

		case LB_STATIC:	/* distrubute luns across all active-optmisied paths */
  			if (id != PATH_INDEX_INVALID) {
 				if ((path = qla2x00_find_path_by_id(dp, id))) {
  					path->lun_data.data[mplun->number] &= ~LUN_DATA_PREFERRED_PATH;
  					DEBUG2(printk("%s Removing previous preferred setting for id=%d\n",
  				   		__func__, id));
 				}
 			}
			/* Determine how many active paths we have */
			paths_cnt = 0;
			list_for_each_safe(list, temp, &mplun->active_list) {
				lun_path = list_entry(list, lu_path_t, next_active);
				paths_cnt++;
			}

			if (paths_cnt == 0) {
 				printk(KERN_INFO "%s no active_path\n",__func__);
				goto set_preferred_def;
				// return 0;
			} else
				DEBUG5(printk("%s active_path_cnt=%d\n",__func__, paths_cnt));

			path_order = order % paths_cnt;
			paths_cnt = 0;
			list_for_each_safe(list, temp, &mplun->active_list) {
				lun_path = list_entry(list, lu_path_t, next_active);
				if (paths_cnt == path_order) {
					path_id = lun_path->path_id;
 					if ((path = qla2x00_find_path_by_id(dp, path_id))) {
  						DEBUG2(printk( "%s: 1. Found preferred lun lun=%d,"
  							" pathid=%d\n", __func__, mplun->number,
  					  		path->id));
						path->lun_data.data[mplun->number] |=
						    LUN_DATA_PREFERRED_PATH;
 					} else
  						printk(KERN_INFO "%s could not find path=%p for id=%d\n",
  				   		__func__, path,path_id);
					break;
				}
				paths_cnt++;
			}

			break;

		case LB_NONE:
		case LB_LRU:
		case LB_LST:
		case LB_RR:
		case LB_LRU_BYTES:
set_preferred_def:
			/* default is first active path */
			path = qla2x00_find_first_path_to_active_tpg(dp, mplun, 1);
			if (path) {
				if (id != PATH_INDEX_INVALID) {
					oldpath = qla2x00_find_path_by_id(dp,
					    id);
					if (oldpath) {
						oldpath->lun_data.data[
						    mplun->number] &=
							~LUN_DATA_PREFERRED_PATH;
						DEBUG2(printk("%s Removing "
						    "previous preferred "
						    "setting for id=%d\n",
						    __func__, id));
					}
				}
				path_id = path->id;
				path->lun_data.data[mplun->number] |=
                                    LUN_DATA_PREFERRED_PATH;
				DEBUG2(printk( "%s: Found preferred lun lun=%d,"
				    " pathid=%d\n", __func__, mplun->number,
				    path->id));
				break;
			} else {
				DEBUG(printk("%s could not find an active path=%p\n",
				   __func__, path));
			}
		default:
			path = qla2x00_find_first_active_path(dp, mplun);
			if (path) {
				path_id = path->id;

				path->lun_data.data[mplun->number] |=
                                    LUN_DATA_PREFERRED_PATH;

				DEBUG2(printk( "%s: Found preferred lun lun=%d,"
					" pathid=%d\n", __func__, mplun->number,
					  path->id));
			}
	}

set_preferred_end:
	dp->path_list->current_path[mplun->number] = path_id;
	mplun->pref_path_id = path_id;
	DEBUG2(printk("%s lun=%d path_id=%d lb_type=%d order=%d "
	    "paths_cnt=%d\n",__func__, mplun->number, path_id,
	    mplun->load_balance_type, order, paths_cnt));
	DEBUG3(printk("%s leaving\n", __func__));

	return 1;
}


int
qla2x00_cfg_remap(scsi_qla_host_t *halist)
{
	scsi_qla_host_t *ha;

	mp_initialized = 1;
	read_lock(&qla_hostlist_lock);
	list_for_each_entry(ha, &qla_hostlist, list) {
		DEBUG2(printk("Entering %s ...\n",__func__));
		/* Find the host that was specified */
		set_bit(CFG_FAILOVER, &ha->cfg_flags);
		qla2x00_cfg_path_discovery(ha);
		clear_bit(CFG_FAILOVER, &ha->cfg_flags);

	}
	read_unlock(&qla_hostlist_lock);
	mp_initialized = 0;
	DEBUG2(printk("Exiting %s ...\n",__func__));

	return QLA_SUCCESS;
}

/*
 *  qla2x00_allocate_mp_port
 *      Allocate an fc_mp_port, clear the memory, and log a system
 *      error if the allocation fails. After fc_mp_port is allocated
 *
 */
static mp_port_t *
qla2x00_allocate_mp_port(uint8_t *portname)
{
	mp_port_t   *port;
	int	i;

	DEBUG3(printk("%s: entered.\n", __func__));

	port = kmalloc(sizeof(mp_port_t), GFP_KERNEL);
	if (!port)
		return NULL;
	memset(port, 0, sizeof(*port));

	DEBUG(printk("%s: mp_port_t allocated at %p\n",
		    __func__, port));

	/*
	 * Since this is the first port, it goes at
	 * index zero.
	 */
	if (portname)
	{
		DEBUG3(printk("%s: copying port name %02x%02x%02x"
		    "%02x%02x%02x%02x%02x.\n",
		    __func__, portname[0], portname[1],
		    portname[2], portname[3], portname[4],
		    portname[5], portname[6], portname[7]));
		memcpy(&port->portname[0], portname, PORT_NAME_SIZE);
	}
	for (i = 0; i < MAX_HOSTS; i++) {
		port->path_list[i] = PATH_INDEX_INVALID;
	}
	port->fo_cnt = 0;


	DEBUG3(printk("%s: exiting.\n", __func__));

	return port;
}

static mp_port_t	*
qla2x00_find_port_by_name(mp_lun_t *mplun,
	mp_path_t *path)
{
	mp_port_t	*port = NULL;
	mp_port_t	*temp_port;
	struct list_head *list, *temp;

	list_for_each_safe(list, temp, &mplun->ports_list) {
		temp_port = list_entry(list, mp_port_t, list);
		if (memcmp(temp_port->portname, path->portname, WWN_SIZE) == 0) {
			port = temp_port;
			break;
		}
	}
	return port;
}


static mp_port_t	*
qla2x00_find_or_allocate_port(mp_host_t *host, mp_lun_t *mplun,
	mp_path_t *path)
{
	mp_port_t	*port = NULL;
	struct list_head *list, *temp;
	unsigned long	instance = host->instance;

	DEBUG3(printk("%s entered\n",__func__));

	if (instance == MAX_HOSTS - 1) {
		printk(KERN_INFO "%s: Fail no room\n", __func__);
		return NULL;
	}

	if (mplun == NULL) {
		return NULL;
	}

	list_for_each_safe(list, temp, &mplun->ports_list) {
		port = list_entry(list, mp_port_t, list);
		if (memcmp(port->portname, path->portname, WWN_SIZE) == 0) {
			if (port->path_list[instance] == PATH_INDEX_INVALID) {
			   DEBUG(printk("scsi%ld %s: Found matching mp port %02x%02x%02x"
			    "%02x%02x%02x%02x%02x.\n",
			    instance, __func__, port->portname[0], port->portname[1],
			    port->portname[2], port->portname[3],
			    port->portname[4], port->portname[5],
			    port->portname[6], port->portname[7]));
				port->path_list[instance] = path->id;
				port->hba_list[instance] = host->ha;
				port->cnt++;
				DEBUG(printk("%s: adding portname - port[%d] = "
			    "%p at index = %d with path id %d\n",
			    __func__, (int)instance ,port,
				(int)instance, path->id));
			}
			return port;
		}
	}
	port = qla2x00_allocate_mp_port(path->portname);
	if (port) {
		port->cnt++;
		DEBUG(printk("%s: allocate and adding portname - port[%d] = "
			    "%p at index = %d with path id %d\n",
			    __func__, (int)instance, port,
				(int)instance, path->id));
		port->path_list[instance] = path->id;
		port->hba_list[instance] = host->ha;
		/* add port to list */
		list_add_tail(&port->list, &mplun->ports_list);
		port->flags = MP_NO_REL_TPORT_ID;
	}
	DEBUG3(printk("%s exit port=%p\n",__func__,port));
	return port;
}

/* Find or allocates target port group and adds mp_port to it so. */
static mp_tport_grp_t *
qla2x00_find_or_allocate_tgt_port_grp(mp_host_t *host, mp_port_t *port,
	fc_lun_t *fclun, mp_path_t *path)
{
	uint8_t rel_tport_id[2];
	uint8_t tpg_id[2];
	uint16_t len;
	char	wwulnbuf[WWULN_SIZE];
	mp_tport_grp_t	*tport_grp = NULL;
	mp_lun_t *mplun = fclun->mplun;
	struct list_head *list, *temp;
	unsigned long	instance = host->instance;
	uint8_t	cur_vol_path_own;
	int	ret;

	DEBUG3(printk("%s entered\n",__func__));

	if (instance == MAX_HOSTS - 1) {
		printk(KERN_INFO "%s: Fail no room\n", __func__);
		return NULL;
	}

	if (mplun == NULL) {
		return NULL;
	}
	DEBUG(printk("%s(%ld) entered\n",__func__,instance));
	if (fclun->asymm_support != TGT_PORT_GRP_UNSUPPORTED) {
	len = qla2x00_get_wwuln_from_device(host, fclun,
		&wwulnbuf[0], WWULN_SIZE, &rel_tport_id[0] , &tpg_id[0]);

	DEBUG5(printk("scsi(%ld): tpg_id[0]:0x%x tpg_id[1]:0x%x "
	    "rtport_id[0]:0x%x rtport_id[1]:0x%x loop_id=0x%x lun=%d\n",
	    instance, tpg_id[0], tpg_id[1], rel_tport_id[0], rel_tport_id[1],
	    fclun->fcport->loop_id, fclun->lun));

	/* if fail to do the inq then exit */
	if (len == 0) {
		return tport_grp;
		}
	} else {
		/* These targets do not support TPG as of know.
		 * But we creates dummy TPG for these targets to
		 * re-use the existing infrastructure of TPG.
		 * Using the Vol Preferred Path Priority as the TPG ID.
		 * Rel TPG ID is immaterial. Set it to Zero for right
		 * know unless there is need for it to be unique.
		 */
		if ((fclun->fcport->flags & FC_DFXXX_DEVICE)) {
			memset(rel_tport_id, 0, sizeof(rel_tport_id));
			memset(tpg_id, 0, sizeof(tpg_id));
			/* Using Vol Pref Path Priority as TPG_ID */
			ret = qla2x00_get_lun_ownership(
					host, fclun, &cur_vol_path_own);
			 if (ret == -1) {
				return tport_grp;
			 } else
			   	tpg_id[1] = ret;
		}
	}

	DEBUG5(printk("scsi(%ld): tpg_id[0]:0x%x tpg_id[1]:0x%x "
	    "rtport_id[0]:0x%x rtport_id[1]:0x%x  loop_id=0x%x lun=%d\n",
	    instance, tpg_id[0], tpg_id[1], rel_tport_id[0], rel_tport_id[1],
	    fclun->fcport->loop_id, fclun->lun));

	list_for_each_safe(list, temp, &mplun->tport_grps_list) {
		tport_grp = list_entry(list, mp_tport_grp_t, list);
		if (memcmp(tport_grp->tpg_id, &tpg_id[0], sizeof(tpg_id))
				 == 0) {
			if (port->flags & MP_NO_REL_TPORT_ID) {
			   DEBUG(printk("scsi%ld %s: Adding mp port"
			    " %02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    instance, __func__, port->portname[0],
			    port->portname[1], port->portname[2],
			    port->portname[3],
			    port->portname[4], port->portname[5],
			    port->portname[6], port->portname[7]));
			   DEBUG(printk("%s(%ld): tpg_id[0]=0x%0x tpg_id[1]=0x%0x\n",
				 __func__,instance,tpg_id[0],tpg_id[1]));
			   /* add port to list */
			   memcpy(&port->rel_tport_id[0],&rel_tport_id[0],
					 sizeof(rel_tport_id));
			   if (tport_grp->ports_list[path->id] == NULL) {
				tport_grp->ports_list[path->id] = port;
				DEBUG(printk("Updated tpg ports_list[%d]= %p\n",
					 path->id, port));
			   }
			   port->flags &= ~MP_NO_REL_TPORT_ID;
			} else {
				DEBUG(printk("%s: found an existing tport_grp=%p tpg_id[0]:0x%x"
					" tpg_id[1]:0x%x\n", __func__, tport_grp, tpg_id[0],
					 tpg_id[1]));
			}

			return tport_grp;
		}
	}

	/* allocate the target port group */
	tport_grp = kmalloc(sizeof(mp_tport_grp_t), GFP_KERNEL);
	if (tport_grp == NULL)
		return NULL;

	memset(tport_grp, 0, sizeof(*tport_grp));
	memcpy(&tport_grp->tpg_id[0], &tpg_id[0], sizeof(tpg_id));
	list_add_tail(&tport_grp->list,&mplun->tport_grps_list);

	DEBUG(printk("scsi(%ld): allocated tpg_id[1]:0x%x rtport_id[1]:0x%x"
		 " loop_id=0x%x lun=%d\n", instance, tpg_id[1], rel_tport_id[1],
		   fclun->fcport->loop_id, fclun->lun));

	memcpy(&port->rel_tport_id[0], &rel_tport_id[0], sizeof(rel_tport_id));
	port->flags &= ~MP_NO_REL_TPORT_ID;
	/* Add port to tgt port group list */
	if (tport_grp->ports_list[path->id] == NULL) {
		tport_grp->ports_list[path->id] = port;
		DEBUG2(printk("Updated tpg ports_list[%d]= %p \n",
			path->id, port));
	}

	DEBUG(printk("%s(%ld): Adding mp port"
	" %02x%02x%02x%02x%02x%02x%02x%02x to it.\n",__func__, instance,
	port->portname[0], port->portname[1], port->portname[2],
	port->portname[3], port->portname[4], port->portname[5],
	port->portname[6], port->portname[7]));

	DEBUG3(printk("%s leaving\n",__func__));

	return tport_grp;

}

/*
 * qla2x00_cfg_failover_port
 *      Failover all the luns on the specified target to
 *		the new path.
 *
 * Inputs:
 *      ha = pointer to host adapter
 *      fp - pointer to new fc_lun (failover lun)
 *      tgt - pointer to target
 *
 * Returns:
 *
 */
static fc_lun_t *
qla2x00_cfg_failover_port(mp_host_t *host, mp_device_t *dp,
	mp_path_t *new_path, fc_port_t *old_fcport, srb_t *sp)
{
	uint16_t	l;
	fc_port_t	*fcport;
	fc_lun_t	*fclun;
	fc_lun_t	*new_fclun = NULL;
	os_lun_t 	 *up;
	mp_path_t	*vis_path;
	mp_host_t 	*vis_host;

	fcport = new_path->port;
	if (!qla2x00_test_active_port(fcport))  {
		DEBUG2(printk("%s(%ld): %s - port not ACTIVE "
		"to failover: port = %p, loop id= 0x%x\n",
		__func__,
		host->ha->host_no, __func__, fcport, fcport->loop_id));
		return new_fclun;
	}

	/* Log the failover to console */
	printk(KERN_INFO
		"qla2x00%d: FAILOVER all LUNS on device %d to WWPN "
		"%02x%02x%02x%02x%02x%02x%02x%02x -> "
		"%02x%02x%02x%02x%02x%02x%02x%02x, reason=0x%x\n",
		(int) host->instance,
		(int) dp->dev_id,
		old_fcport->port_name[0], old_fcport->port_name[1],
		old_fcport->port_name[2], old_fcport->port_name[3],
		old_fcport->port_name[4], old_fcport->port_name[5],
		old_fcport->port_name[6], old_fcport->port_name[7],
		fcport->port_name[0], fcport->port_name[1],
		fcport->port_name[2], fcport->port_name[3],
		fcport->port_name[4], fcport->port_name[5],
		fcport->port_name[6], fcport->port_name[7], sp->err_id);
		 printk(KERN_INFO
		"qla2x00: FROM HBA %d to HBA %d\n",
		(int)old_fcport->ha->instance,
		(int)fcport->ha->instance);

	/* we failover all the luns on this port */
	list_for_each_entry(fclun, &fcport->fcluns, list) {
		l = fclun->lun;
		if ((fclun->flags & FLF_VISIBLE_LUN)) {
			continue;
		}
		dp->path_list->current_path[l] = new_path->id;
		if ((vis_path =
		    qla2x00_get_visible_path(dp)) == NULL) {
			printk(KERN_INFO
		    "qla2x00(%d): No visible "
			    "path for target %d, "
			    "dp = %p\n",
			    (int)host->instance,
		    dp->dev_id, dp);
		    continue;
		}

		vis_host = vis_path->host;
		up = (os_lun_t *) GET_LU_Q(vis_host->ha,
		    dp->dev_id, l);
		if (up == NULL) {
		DEBUG2(printk("%s: instance %d: No lun queue"
		    "for target %d, lun %d.. \n",
			__func__,(int)vis_host->instance,dp->dev_id,l));
			continue;
		}

		up->fclun = fclun;
		fclun->fcport->cur_path = new_path->id;

		DEBUG2(printk("%s: instance %d: Mapping target %d:0x%x,"
		    "lun %d to path id %d\n",
			__func__,(int)vis_host->instance,dp->dev_id,
			fclun->fcport->loop_id, l,
		    fclun->fcport->cur_path));

			/* issue reset to data luns only */
			if (fclun->device_type == TYPE_DISK) {
				new_fclun = fclun;
				/* send a reset lun command as well */
			printk(KERN_INFO
			    "scsi(%ld:0x%x:%d) sending reset lun \n",
					fcport->ha->host_no,
					fcport->loop_id, l);
				qla2x00_lun_reset(fcport->ha, fcport, l);
			}
		}
	return new_fclun;
}

int
qla2x00_cfg_is_lbenable(fc_lun_t *fclun)
{
	mp_lun_t *mplun;

	if (fclun == NULL)
		return 0;
	/* Check for non-lunid storages */
	mplun = (mp_lun_t *)fclun->mplun;
	if (mplun == NULL)
		return 0;

	DEBUG2(printk( "%s(): load balancing type for path= %d, path cnt=%d\n",
				__func__,
				mplun->load_balance_type,mplun->act_cnt));
	if (mplun->load_balance_type >= LB_LRU) {
		if (mplun->act_cnt > 1)
			return 1;
	}
	return 0;
}

/*
 * qla2x00_cfg_failover
 *      A problem has been detected with the current path for this
 *      lun.  Select the next available path as the current path
 *      for this device.
 *
 * Inputs:
 *      ha = pointer to host adapter
 *      fp - pointer to failed fc_lun (failback lun)
 *      tgt - pointer to target
 *
 * Returns:
 *      pointer to new fc_lun_t, or NULL if failover fails.
 */
fc_lun_t *
qla2x00_cfg_failover(scsi_qla_host_t *ha, fc_lun_t *fp,
    os_tgt_t *tgt, srb_t *sp)
{
	mp_host_t	*host;			/* host adapter pointer */
	mp_device_t	*dp;			/* virtual device pointer */
	mp_path_t	*new_path;		/* new path pointer */
	fc_lun_t	*new_fp = NULL;
	fc_port_t	*fcport, *new_fcport;
	struct osl_fo_info *osl_fo;

	ENTER("qla2x00_cfg_failover");
	DEBUG2(printk("%s entered\n",__func__));

	set_bit(CFG_ACTIVE, &ha->cfg_flags);
	if ((host = qla2x00_cfg_find_host(ha)) != NULL) {
		if (test_bit(TQF_USED_ID, &tgt->flags))
			dp = qla2x00_find_mp_dev_by_id(host, tgt->id);
		else
			dp = qla2x00_find_mp_dev_by_nodename(host,
			    tgt->node_name);
		if (dp) {
			DEBUG3(printk("qla2x00_cfg_failover: dp = %p\n", dp));
			/*
			 * Point at the next path in the path list if there is
			 * one, and if it hasn't already been failed over by
			 * another I/O. If there is only one path continuer
			 * to point at it.
			 */
			new_path = qla2x00_select_next_path(host, dp,
				fp->lun, sp);
			if (new_path == NULL) {
			DEBUG2(printk("cfg_failover: Bad new path=%p"
					" fp lun= %p\n",
				new_path, fp));
				goto cfg_failover_done;
			}
			new_fp = qla2x00_find_matching_lun(fp->lun,
					dp, new_path);
			if (new_fp == NULL) {
			DEBUG2(printk("cfg_failover: Bad fp - new path=%p, new pathid=%d"
					" new fp lun= %p\n",
				new_path, new_path->id, new_fp));
				goto cfg_failover_done;
			}
			DEBUG2(printk("cfg_failover: new path=%p, new pathid=%d"
					" new fp lun= %p\n",
				new_path, new_path->id, new_fp));

			fcport = fp->fcport;
			if ((fcport->flags & FC_MSA_DEVICE)) {
				/*
				 * "select next path" has already
				 * send out the switch path notify
				 * command, so inactive old path
				 */
       				fcport->flags &= ~(FC_MSA_PORT_ACTIVE);
				if (qla2x00_cfg_failover_port(host, dp,
						new_path, fcport, sp) == NULL) {
					osl_fo = (struct osl_fo_info *)
						sp->lun_queue->fo_ptr;
					osl_fo->fo_retry_cnt[new_path->id]++;

					DEBUG2(printk(KERN_INFO
					    "scsi(%ld): Fail to failover "
					    "device - fcport = %p path_id=%d\n",
					    host->ha->host_no, fcport,
					    new_path->id));
					goto cfg_failover_done;
				}
			} else if ((fcport->flags & FC_EVA_DEVICE) || fcport->fo_target_port) {
				new_fcport = new_path->port;
				if (qla2x00_test_active_lun(
					new_fcport, new_fp, NULL)) {
					qla2x00_cfg_register_failover_lun(dp,
						sp, new_fp);
				 	 /* send a reset lun command as well */
					 if (fcport->flags &
					     (FC_EVA_DEVICE |
						 FC_AA_EVA_DEVICE)) {
						 printk(KERN_INFO
						     "scsi(%ld:0x%x:%d) sending"
						     "reset lun \n",
						     new_fcport->ha->host_no,
						     new_fcport->loop_id,
						     new_fp->lun);
						 qla2x00_lun_reset(
						     new_fcport->ha,
						     new_fcport, new_fp->lun);
					 }
				} else {
					osl_fo = (struct osl_fo_info *)
						sp->lun_queue->fo_ptr;
					osl_fo->fo_retry_cnt[new_path->id]++;

					DEBUG2(printk(
						"scsi(%ld): %s Fail to failover lun "
						"old fclun= %p, new fclun= %p\n",
						host->ha->host_no,
						 __func__,fp, new_fp));
					goto cfg_failover_done;
				}
			} else { /*default */
				        DEBUG2(printk(
				        	"scsi(%ld): %s Default failover lun "
				        	"old fclun= %p, new fclun= %p\n",
				        	host->ha->host_no,
				        	 __func__,fp, new_fp));
				new_fp = qla2x00_find_matching_lun(fp->lun, dp,
				    new_path);
				qla2x00_cfg_register_failover_lun(dp, sp,
				    new_fp);
			}

		} else {
			printk(KERN_INFO
				"qla2x00(%d): Couldn't find device "
				"to failover: dp = %p\n",
				host->instance, dp);
		}
	}

cfg_failover_done:
	clear_bit(CFG_ACTIVE, &ha->cfg_flags);

	LEAVE("qla2x00_cfg_failover");

	return new_fp;
}

/*
 * IOCTL support
 */
#define CFG_IOCTL
#if defined(CFG_IOCTL)
/*
 * qla2x00_cfg_get_paths
 *      Get list of paths EXT_FO_GET_PATHS.
 *
 * Input:
 *      ha = pointer to adapter
 *      bp = pointer to buffer
 *      cmd = Pointer to kernel copy of EXT_IOCTL.
 *
 * Return;
 *      0 on success or errno.
 *	driver ioctl errors are returned via cmd->Status.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_cfg_get_paths(EXT_IOCTL *cmd, FO_GET_PATHS *bp, int mode)
{
	int	cnt, lun_count, u_size;
	int	rval = 0;
	uint16_t	idx;

	FO_PATHS_INFO	*paths,	*u_paths;
	FO_PATH_ENTRY	*entry;
	EXT_DEST_ADDR   *sap = &bp->HbaAddr;
	mp_host_t	*host = NULL;	/* host adapter pointer */
	mp_device_t	*dp;		/* virtual device pointer */
	mp_path_t	*path;		/* path pointer */
	mp_path_list_t	*path_list;	/* path list pointer */
	scsi_qla_host_t *ha;


	DEBUG9(printk("%s: entered.\n", __func__));

	u_size = cmd->ResponseLen;
	if (!u_size) {
		DEBUG2_9_10(printk(KERN_INFO "%s: User did not set reponse len %d.\n",
		    __func__, u_size));

		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	/* Determine total lun count */
	lun_count = u_size - (offsetof(FO_PATHS_INFO, CurrentPathIndex)) -
	    (sizeof(paths->PathEntry)) - sizeof(paths->Reserved5);
	DEBUG10(printk("(%s)Lun count = %ld\n", __func__, lun_count));

	if ((lun_count % OLD_MAX_LUNS) != 0) {
		/* Invlaid lun count */
		DEBUG2_9_10(printk(KERN_INFO "%s: Got invalid lun count = %d.\n",
		    __func__, lun_count));
		cmd->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	u_paths = (FO_PATHS_INFO *)Q64BIT_TO_PTR(cmd->ResponseAdr, cmd->AddrMode);
	ha = qla2x00_get_hba((int)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk(KERN_INFO "%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance));

		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (rval);
	}
	DEBUG9(printk("%s(%ld): found matching ha inst %d.\n",
	    __func__, ha->host_no, bp->HbaInstance));

	if (qla2x00_failover_enabled(ha)) {
		if ((host = qla2x00_cfg_find_host(ha)) == NULL) {
			cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
			cmd->DetailStatus = EXT_DSTATUS_HBA_INST;
			DEBUG4(printk("%s: cannot find target (%ld)\n",
			    __func__, ha->instance));
			DEBUG9_10(printk("%s: cannot find host inst(%ld).\n",
			    __func__, ha->instance));

			return rval;
		}
	}

	/* Allocate as much as API has allocated */
	paths = (FO_PATHS_INFO *)vmalloc(u_size);
	if (paths == NULL) {
		DEBUG4(printk("%s: failed to allocate memory of size (%d)\n",
		    __func__, u_size));
		DEBUG9_10(printk("%s: failed allocate memory size(%d).\n",
		    __func__, u_size));

		cmd->Status = EXT_STATUS_NO_MEMORY;

		return -ENOMEM;
	}
	memset(paths, 0, u_size);

	DEBUG9(printk("%s(%ld): found matching ha inst %d.\n",
	    __func__, ha->host_no, bp->HbaInstance));

	if (!qla2x00_failover_enabled(ha)) {
		/* non-fo case. There's only one path. */

		mp_path_list_t	*ptmp_plist;
#define STD_MAX_PATH_CNT	1
#define STD_VISIBLE_INDEX	0
		int found;
		fc_port_t *fcport = NULL;

		DEBUG9(printk("%s: non-fo case.\n", __func__));

		if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_plist,
		    sizeof(mp_path_list_t))) {
			/* not enough memory */
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld scrap not big enough. "
			    "lun_mask requested=%ld.\n",
			    __func__, ha->host_no, ha->instance,
			    (ulong)sizeof(mp_path_list_t)));
			cmd->Status = EXT_STATUS_NO_MEMORY;

			vfree(paths);

			return -ENOMEM;
		}

		found = 0;
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (memcmp(fcport->node_name, sap->DestAddr.WWNN,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				found++;
				break;
			}
		}

		if (found) {
			DEBUG9(printk("%s: found fcport:"
			    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
			    __func__,
			    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
			    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
			    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
			    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7]));

			paths->HbaInstance         = bp->HbaInstance;
			paths->PathCount           = STD_MAX_PATH_CNT;
			paths->VisiblePathIndex    = STD_VISIBLE_INDEX;

			/* Copy current path, which is the first one (0). */
			memcpy(paths->CurrentPathIndex,
			    ptmp_plist->current_path, lun_count);

			entry = &((PATH_ENTRY(paths,
			    lun_count))[STD_VISIBLE_INDEX]);

			entry->Visible     = 1;
			entry->HbaInstance = bp->HbaInstance;

			memcpy(entry->PortName, fcport->port_name,
			    EXT_DEF_WWP_NAME_SIZE);

			/* Copy data to user */
			if (rval == 0)
				rval = copy_to_user(&u_paths->PathCount,
				    &paths->PathCount, 4);
			if (rval == 0)
				rval = copy_to_user(&u_paths->CurrentPathIndex,
				    &paths->CurrentPathIndex, lun_count);
			if (rval == 0)
				rval = copy_to_user(
				    (PATH_ENTRY(u_paths, lun_count)),
				    (PATH_ENTRY(paths, lun_count)),
				    sizeof(paths->PathEntry));

			if (rval) { /* if any of the above failed */
				DEBUG9_10(printk("%s: data copy failed.\n",
				    __func__));

				cmd->Status = EXT_STATUS_COPY_ERR;
			}
		} else {
			cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
			cmd->DetailStatus = EXT_DSTATUS_TARGET;

			DEBUG10(printk("%s: cannot find fcport "
			    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
			    __func__,
			    sap->DestAddr.WWNN[0],
			    sap->DestAddr.WWNN[1],
			    sap->DestAddr.WWNN[2],
			    sap->DestAddr.WWNN[3],
			    sap->DestAddr.WWNN[4],
			    sap->DestAddr.WWNN[5],
			    sap->DestAddr.WWNN[6],
			    sap->DestAddr.WWNN[7]));
			DEBUG4(printk("%s: cannot find fcport "
			    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
			    __func__,
			    sap->DestAddr.WWNN[0],
			    sap->DestAddr.WWNN[1],
			    sap->DestAddr.WWNN[2],
			    sap->DestAddr.WWNN[3],
			    sap->DestAddr.WWNN[4],
			    sap->DestAddr.WWNN[5],
			    sap->DestAddr.WWNN[6],
			    sap->DestAddr.WWNN[7]));
		}

		qla2x00_free_ioctl_scrap_mem(ha);
		/* end of non-fo case. */

	} else if (sap->DestType != EXT_DEF_DESTTYPE_WWNN &&
	    sap->DestType != EXT_DEF_DESTTYPE_WWPN) {
		/* Scan for mp_dev by nodename or portname *ONLY* */

		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;

		DEBUG4(printk("%s: target can be accessed by NodeName only.",
		    __func__));
		DEBUG9_10(printk("%s: target can be accessed by NodeName or "
		    " PortName only. Got type %d.\n",
		    __func__, sap->DestType));

	} else if ((sap->DestType == EXT_DEF_DESTTYPE_WWNN &&
	    (dp = qla2x00_find_mp_dev_by_nodename(host,
	    sap->DestAddr.WWNN)) != NULL) ||
	    (sap->DestType == EXT_DEF_DESTTYPE_WWPN &&
	    (dp = qla2x00_find_mp_dev_by_portname(host,
	    sap->DestAddr.WWPN, &idx)) != NULL)) {

		DEBUG9(printk("%s(%ld): Found mp_dev. nodename="
		    "%02x%02x%02x%02x%02x%02x%02x%02x portname="
		    "%02x%02x%02x%02x%02x%02x%02x%02x.\n.",
		    __func__, host->ha->host_no,
		    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7],
		    sap->DestAddr.WWPN[0], sap->DestAddr.WWPN[1],
		    sap->DestAddr.WWPN[2], sap->DestAddr.WWPN[3],
		    sap->DestAddr.WWPN[4], sap->DestAddr.WWPN[5],
		    sap->DestAddr.WWPN[6], sap->DestAddr.WWPN[7]));

		path_list = dp->path_list;

		paths->HbaInstance 	   = bp->HbaInstance;
		paths->PathCount           = path_list->path_cnt;
		paths->VisiblePathIndex    = path_list->visible;

		/* copy current paths */
		memcpy(paths->CurrentPathIndex, path_list->current_path,
		    lun_count);

		path = path_list->last;
		for (cnt = 0; cnt < path_list->path_cnt; cnt++) {
			entry = &((PATH_ENTRY(paths, lun_count))[path->id]);

			entry->Visible     = (path->id == path_list->visible);
			entry->HbaInstance = path->host->instance;
			DEBUG9(printk("%s: entry %d ha %d path id %d, pn="
			    "%02x%02x%02x%02x%02x%02x%02x%02x. visible=%d.\n",
			    __func__, cnt, path->host->instance, path->id,
			    path->portname[0], path->portname[1],
			    path->portname[2], path->portname[3],
			    path->portname[4], path->portname[5],
			    path->portname[6], path->portname[7],
			    entry->Visible));

			memcpy(entry->PortName,
			    path->portname,
			    EXT_DEF_WWP_NAME_SIZE);

			path = path->next;
		}
		DEBUG9(printk("%s: path cnt=%d, visible path=%d.\n",
		    __func__, path_list->path_cnt, path_list->visible));

		/* copy data to user */
		if (rval == 0)
			rval = copy_to_user(&u_paths->PathCount,
			    &paths->PathCount, 4);
		if (rval == 0)
			rval = copy_to_user(&u_paths->CurrentPathIndex,
			    &paths->CurrentPathIndex, lun_count);
		if (rval == 0)
			rval = copy_to_user((PATH_ENTRY(u_paths, lun_count)),
			    (PATH_ENTRY(paths, lun_count)),
			    sizeof(paths->PathEntry));

		if (rval != 0) {  /* if any of the above failed */
			DEBUG9_10(printk("%s: u_paths %p copy"
			    " error. paths->PathCount=%d.\n",
			    __func__, u_paths, paths->PathCount));
			cmd->Status = EXT_STATUS_COPY_ERR;
		}

	} else {

		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;

		DEBUG9_10(printk("%s: DestType=%x.\n",
		    __func__, sap->DestType));
		DEBUG9_10(printk("%s: return DEV_NOT_FOUND for node=%02x%02x"
		    "%02x%02x%02x%02x%02x%02x port=%02x%02x%02x%02x%02x%02x"
		    "%02x%02x.\n",
		    __func__,
		    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7],
		    sap->DestAddr.WWPN[0], sap->DestAddr.WWPN[1],
		    sap->DestAddr.WWPN[2], sap->DestAddr.WWPN[3],
		    sap->DestAddr.WWPN[4], sap->DestAddr.WWPN[5],
		    sap->DestAddr.WWPN[6], sap->DestAddr.WWPN[7]));

		DEBUG4(printk("%s: return DEV_NOT_FOUND for node=%02x%02x"
		    "%02x%02x%02x%02x%02x%02x port=%02x%02x%02x%02x%02x%02x"
		    "%02x%02x.\n",
		    __func__,
		    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7],
		    sap->DestAddr.WWPN[0], sap->DestAddr.WWPN[1],
		    sap->DestAddr.WWPN[2], sap->DestAddr.WWPN[3],
		    sap->DestAddr.WWPN[4], sap->DestAddr.WWPN[5],
		    sap->DestAddr.WWPN[6], sap->DestAddr.WWPN[7]));
	}

	vfree(paths);

	DEBUG9(printk("%s: exiting. rval=%d.\n", __func__, rval));

	return rval;

} /* qla2x00_cfg_get_paths */

/*
 * qla2x00_cfg_set_current_path
 *      Set the current failover path EXT_FO_GET_PATHS IOCTL call.
 *
 * Input:
 *      ha = pointer to adapter
 *      bp = pointer to buffer
 *      cmd = Pointer to kernel copy of EXT_IOCTL.
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_cfg_set_current_path(EXT_IOCTL *cmd, FO_SET_CURRENT_PATH *bp, int mode)
{
	uint8_t         orig_id, new_id;
	uint16_t	idx;
	mp_host_t       *host, *new_host;
	mp_device_t     *dp;
	mp_path_list_t  *path_list;
	EXT_DEST_ADDR   *sap = &bp->HbaAddr;
	uint32_t        rval = 0;
	scsi_qla_host_t *ha;
	mp_path_t       *new_path, *old_path;
	fc_lun_t	*fclun;
	int		skip_set = 0;

	DEBUG9(printk("%s: entered.\n", __func__));

	/* First find the adapter with the instance number. */
	ha = qla2x00_get_hba((int)bp->HbaInstance);
	if (!ha) {
		DEBUG2_9_10(printk(KERN_INFO "%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance));

		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (rval);
	}

	if (!qla2x00_failover_enabled(ha)) {
		/* non-failover mode. nothing to be done. */
		DEBUG9_10(printk("%s(%ld): non-failover driver mode.\n",
		    __func__, ha->host_no));

		return 0;
	}

	if ((host = qla2x00_cfg_find_host(ha)) == NULL) {
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_HBA_INST;
		DEBUG4(printk("%s: cannot find adapter.\n",
		    __func__));
		DEBUG9_10(printk("%s(%ld): cannot find mphost.\n",
		    __func__, ha->host_no));
		return (rval);
	}

	set_bit(CFG_ACTIVE, &ha->cfg_flags);
	sap = &bp->HbaAddr;
	/* Scan for mp_dev by nodename *ONLY* */
	if (sap->DestType != EXT_DEF_DESTTYPE_WWNN &&
	    sap->DestType != EXT_DEF_DESTTYPE_WWPN) {
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;
		DEBUG4(printk("%s: target can be accessed by NodeName only.",
		    __func__));
		DEBUG9_10(printk("%s(%ld): target can be accessed by NodeName "
		    " or PortName only.\n",
		    __func__, ha->host_no));
	} else if ((sap->DestType == EXT_DEF_DESTTYPE_WWNN &&
	    (dp = qla2x00_find_mp_dev_by_nodename(host,
	    sap->DestAddr.WWNN)) != NULL) ||
	    (sap->DestType == EXT_DEF_DESTTYPE_WWPN &&
	    (dp = qla2x00_find_mp_dev_by_portname(host,
	    sap->DestAddr.WWPN, &idx)) != NULL)) {

		if (sap->DestType == EXT_DEF_DESTTYPE_WWNN) {
			DEBUG9_10(printk("%s(%ld): found mpdev with matching "
			    " NodeName.\n",
			    __func__, ha->host_no));
		} else {
			DEBUG9_10(printk("%s(%ld): found mpdev with matching "
			    " PortName.\n",
			    __func__, ha->host_no));
		}

		path_list = dp->path_list;

		if (bp->NewCurrentPathIndex < MAX_PATHS_PER_DEVICE &&
		    sap->Lun < MAX_LUNS &&
		    bp->NewCurrentPathIndex < path_list->path_cnt) {

			orig_id = path_list->current_path[sap->Lun];

			DEBUG(printk("%s: dev no  %d, lun %d, "
			    "newindex %d, oldindex %d "
			    "nn=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    __func__, dp->dev_id, sap->Lun,
			    bp->NewCurrentPathIndex, orig_id,
			    host->nodename[0], host->nodename[1],
			    host->nodename[2], host->nodename[3],
			    host->nodename[4], host->nodename[5],
			    host->nodename[6], host->nodename[7]));
			old_path = qla2x00_find_path_by_id(dp, orig_id);

			if (orig_id == PATH_INDEX_INVALID) {
				cmd->Status = EXT_STATUS_INVALID_PARAM;
				cmd->DetailStatus =
				EXT_DSTATUS_PATH_INDEX;
				skip_set++;
			/* Make sure original lun is not a controller lun */
			} else if ((fclun = qla2x00_find_matching_lun(sap->Lun,
					dp, old_path)) != NULL) {
				if ((fclun->flags & FLF_VISIBLE_LUN)) {
					cmd->Status = EXT_STATUS_INVALID_PARAM;
					cmd->DetailStatus =
						EXT_DSTATUS_PATH_INDEX;
					skip_set++;
				}
			}
			if (!skip_set && bp->NewCurrentPathIndex != orig_id) {
				/* Acquire the update spinlock. */

				/* Set the new current path. */
				new_id = path_list-> current_path[sap->Lun] =
				    bp->NewCurrentPathIndex;

				/* Release the update spinlock. */
				old_path = qla2x00_find_path_by_id(
				    dp, orig_id);
				new_path = qla2x00_find_path_by_id(dp, new_id);
				new_host = new_path->host;

				/* remap the lun */
				qla2x00_map_a_oslun(new_host, dp,
				    dp->dev_id, sap->Lun);

				qla2x00_send_failover_notify(dp,
				    sap->Lun, old_path, new_path);
			} else {
				/* EMPTY */
				DEBUG4(printk("%s: path index not changed.\n",
				    __func__));
				DEBUG9(printk("%s(%ld): path id not changed.\n",
				    __func__, ha->host_no));
			}
		} else {
			cmd->Status = EXT_STATUS_INVALID_PARAM;
			cmd->DetailStatus = EXT_DSTATUS_PATH_INDEX;
			DEBUG4(printk("%s: invalid index for device.\n",
			    __func__));
			DEBUG9_10(printk("%s: invalid index for device.\n",
			    __func__));
		}
	} else {
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;
		DEBUG4(printk("%s: cannot find device.\n",
		    __func__));
		DEBUG9_10(printk("%s: DestType=%x.\n",
		    __func__, sap->DestType));
		DEBUG9_10(printk("%s: return DEV_NOT_FOUND for node=%02x%02x"
		    "%02x%02x%02x%02x%02x%02x port=%02x%02x%02x%02x%02x%02x"
		    "%02x%02x.\n",
		    __func__,
		    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7],
		    sap->DestAddr.WWPN[0], sap->DestAddr.WWPN[1],
		    sap->DestAddr.WWPN[2], sap->DestAddr.WWPN[3],
		    sap->DestAddr.WWPN[4], sap->DestAddr.WWPN[5],
		    sap->DestAddr.WWPN[6], sap->DestAddr.WWPN[7]));
	}
	clear_bit(CFG_ACTIVE, &ha->cfg_flags);

	DEBUG9(printk("%s: exiting. rval = %d.\n", __func__, rval));

	return rval;
}
#endif

/*
 * MP SUPPORT ROUTINES
 */

/*
 * qla2x00_add_mp_host
 *	Add the specified host the host list.
 *
 * Input:
 *	node_name = pointer to node name
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
mp_host_t *
qla2x00_add_mp_host(uint8_t *node_name)
{
	mp_host_t   *host, *temp;

	host = kmalloc(sizeof(mp_host_t), GFP_KERNEL);
	if (!host)
		return NULL;
	memset(host, 0, sizeof(*host));
	memcpy(host->nodename, node_name, WWN_SIZE);
	host->next = NULL;

	/* add to list */
	if (mp_hosts_base == NULL) {
		mp_hosts_base = host;
	} else {
		temp = mp_hosts_base;
		while (temp->next != NULL)
			temp = temp->next;
		temp->next = host;
	}

	mp_num_hosts++;
	return host;
}

/*
 * qla2x00_alloc_host
 *      Allocate and initialize an mp host structure.
 *
 * Input:
 *      ha = pointer to base driver's adapter structure.
 *
 * Returns:
 *      Pointer to host structure or null on error.
 *
 * Context:
 *      Kernel context.
 */
mp_host_t   *
qla2x00_alloc_host(scsi_qla_host_t *ha)
{
	mp_host_t	*host, *temp;

	ENTER("qla2x00_alloc_host");

	host = kmalloc(sizeof(mp_host_t), GFP_KERNEL);
	if (!host)
		return NULL;

	memset(host, 0, sizeof(*host));
	host->ha = ha;
	memcpy(host->nodename, ha->node_name, WWN_SIZE);
	memcpy(host->portname, ha->port_name, WWN_SIZE);
	host->next = NULL;
	host->flags = MP_HOST_FLAG_NEEDS_UPDATE;
	host->instance = ha->instance;
	/* host->MaxLunsPerTarget = qla_fo_params.MaxLunsPerTarget; */

	if (qla2x00_fo_enabled(host->ha, host->instance)) {
		host->flags |= MP_HOST_FLAG_FO_ENABLED;
		DEBUG4(printk("%s: Failover enabled.\n",
		    __func__));
	} else {
		/* EMPTY */
		DEBUG4(printk("%s: Failover disabled.\n",
		    __func__));
	}
	/* add to list */
	if (mp_hosts_base == NULL) {
		mp_hosts_base = host;
	} else {
		temp = mp_hosts_base;
		while (temp->next != NULL)
			temp = temp->next;
		temp->next = host;
	}
	mp_num_hosts++;

	DEBUG4(printk("%s: Alloc host @ %p\n", __func__, host));
	return host;
}

/*
 * qla2x00_add_portname_to_mp_dev
 *      Add the specific port name to the list of port names for a
 *      multi-path device.
 *
 * Input:
 *      dp = pointer ti virtual device
 *      portname = Port name to add to device
 *      nodename = Node name to add to device
 *
 * Returns:
 *      qla2x00 local function return status code.
 *
 * Context:
 *      Kernel context.
 */
static uint32_t
qla2x00_add_portname_to_mp_dev(mp_device_t *dp, uint8_t *portname, uint8_t *nodename)
{
	uint16_t	index;
	uint32_t	rval = QLA_SUCCESS;

	ENTER("qla2x00_add_portname_to_mp_dev");

	/* Look for an empty slot and add the specified portname.   */
	for (index = 0; index < MAX_NUMBER_PATHS; index++) {
		if (qla2x00_is_ww_name_zero(&dp->portnames[index][0])) {
			DEBUG4(printk("%s: adding portname to dp = "
			    "%p at index = %d\n",
			    __func__, dp, index));
			memcpy(&dp->portnames[index][0], portname, WWN_SIZE);
			break;
		}
	}
	if (index == MAX_NUMBER_PATHS) {
		rval = QLA_FUNCTION_FAILED;
		DEBUG4(printk("%s: Fail no room\n", __func__));
	} else {
		/* EMPTY */
		DEBUG4(printk("%s: Exit OK\n", __func__));
	}

	LEAVE("qla2x00_add_portname_to_mp_dev");

	return rval;
}


/*
 *  qla2x00_allocate_mp_dev
 *      Allocate an fc_mp_dev, clear the memory, and log a system
 *      error if the allocation fails. After fc_mp_dev is allocated
 *
 *  Inputs:
 *      nodename  = pointer to nodename of new device
 *      portname  = pointer to portname of new device
 *
 *  Returns:
 *      Pointer to new mp_device_t, or NULL if the allocation fails.
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t *
qla2x00_allocate_mp_dev(uint8_t  *nodename, uint8_t *portname)
{
	mp_device_t   *dp;            /* Virtual device pointer */

	ENTER("qla2x00_allocate_mp_dev");
	DEBUG3(printk("%s: entered.\n", __func__));

	dp = kmalloc(sizeof(mp_device_t), GFP_KERNEL);
	if (!dp) {
		DEBUG4(printk("%s: Allocate failed.\n", __func__));
		return NULL;
	}
	memset(dp, 0, sizeof(*dp));

	DEBUG3(printk("%s: mp_device_t allocated at %p\n", __func__, dp));

	/*
	 * Copy node name into the mp_device_t.
	 */
	if (nodename) {
		DEBUG3(printk("%s: copying node name %02x%02x%02x"
		    "%02x%02x%02x%02x%02x.\n",
		    __func__, nodename[0], nodename[1],
		    nodename[2], nodename[3], nodename[4],
		    nodename[5], nodename[6], nodename[7]));
		memcpy(dp->nodename, nodename, WWN_SIZE);
	}

	/*
	 * Since this is the first port, it goes at
	 * index zero.
	 */
	if (portname)
	{
		DEBUG3(printk("%s: copying port name %02x%02x%02x"
		    "%02x%02x%02x%02x%02x.\n",
		    __func__, portname[0], portname[1],
		    portname[2], portname[3], portname[4],
		    portname[5], portname[6], portname[7]));
		memcpy(&dp->portnames[0][0], portname, PORT_NAME_SIZE);
	}

	/* Allocate an PATH_LIST for the fc_mp_dev. */
	if ((dp->path_list = qla2x00_allocate_path_list()) == NULL) {
		DEBUG4(printk("%s: allocate path_list Failed.\n",
		    __func__));
		kfree(dp);
		dp = NULL;
	} else {
		DEBUG4(printk("%s: mp_path_list_t allocated at %p\n",
		    __func__, dp->path_list));
		/* EMPTY */
		DEBUG4(printk("qla2x00_allocate_mp_dev: Exit Okay\n"));
	}

	DEBUG3(printk("%s: exiting.\n", __func__));
	LEAVE("qla2x00_allocate_mp_dev");

	return dp;
}

/*
 *  qla2x00_allocate_path
 *      Allocate a PATH.
 *
 *  Inputs:
 *     host   Host adapter for the device.
 *     path_id  path number
 *     port   port for device.
 *      dev_id  device number
 *
 *  Returns:
 *      Pointer to new PATH, or NULL if the allocation failed.
 *
 * Context:
 *      Kernel context.
 */
static mp_path_t *
qla2x00_allocate_path(mp_host_t *host, uint16_t path_id,
    fc_port_t *port, uint16_t dev_id)
{
	mp_path_t	*path;
	uint16_t	lun;

	ENTER("qla2x00_allocate_path");

	path = kmalloc(sizeof(mp_path_t), GFP_KERNEL);
	if (!path) {
		DEBUG4(printk("%s: Failed\n", __func__));
		return 0;
	}
	memset(path, 0, sizeof(*path));

	DEBUG3(printk("%s(%ld): allocated path %p at path id %d.\n",
	    __func__, host->ha->host_no, path, path_id));

	/* Copy the supplied information into the MP_PATH.  */
	path->host = host;

	if (!(port->flags & FC_CONFIG) && port->loop_id != FC_NO_LOOP_ID) {
		path->port = port;
		DEBUG3(printk("%s(%ld): assigned port pointer %p "
			    "to path id %d.\n",
		    __func__, host->ha->host_no, port, path_id));
	}

	path->id = path_id;
	port->cur_path = path->id;
	path->mp_byte = port->mp_byte;
	path->next = NULL;
	memcpy(path->portname, port->port_name, WWN_SIZE);

	DEBUG3(printk("%s(%ld): path id %d copied portname "
	    "%02x%02x%02x%02x%02x%02x%02x%02x. enabling all LUNs.\n",
	    __func__, host->ha->host_no, path->id,
	    port->port_name[0], port->port_name[1],
	    port->port_name[2], port->port_name[3],
	    port->port_name[4], port->port_name[5],
	    port->port_name[6], port->port_name[7]));

	for (lun = 0; lun < MAX_LUNS; lun++) {
		path->lun_data.data[lun] |= LUN_DATA_ENABLED;
	}

	return path;
}


/*
 *  qla2x00_allocate_path_list
 *      Allocate a PATH_LIST
 *
 *  Input:
 * 		None
 *
 *  Returns:
 *      Pointer to new PATH_LIST, or NULL if the allocation fails.
 *
 * Context:
 *      Kernel context.
 */
static mp_path_list_t *
qla2x00_allocate_path_list(void)
{
	mp_path_list_t	*path_list;
	uint16_t		i;
	uint16_t		l;

	path_list = kmalloc(sizeof(mp_path_list_t), GFP_KERNEL);
	if (!path_list) {
		DEBUG4(printk("%s: Alloc pool failed for MP_PATH_LIST.\n",
		    __func__));
		return NULL;
	}
	memset(path_list, 0, sizeof(*path_list));

	DEBUG4(printk("%s: allocated at %p\n", __func__, path_list));

	path_list->visible = PATH_INDEX_INVALID;
	/* Initialized current path */
	for (i = 0; i < MAX_LUNS_PER_DEVICE; i++) {
		l = (i & LUN_MASK);
		path_list->current_path[l] = PATH_INDEX_INVALID;
	}
	path_list->last = NULL;

	return path_list;
}

/*
 *  qla2x00_cfg_find_host
 *      Look through the existing multipath tree, and find
 *      a host adapter to match the specified ha.
 *
 *  Input:
 *      ha = pointer to host adapter
 *
 *  Return:
 *      Pointer to new host, or NULL if no match found.
 *
 * Context:
 *      Kernel context.
 */
mp_host_t *
qla2x00_cfg_find_host(scsi_qla_host_t *ha)
{
	mp_host_t     *host = NULL;	/* Host found and null if not */
	mp_host_t     *tmp_host;

	ENTER("qla2x00_cfg_find_host");

	for (tmp_host = mp_hosts_base; (tmp_host); tmp_host = tmp_host->next) {
		if (tmp_host->ha == ha) {
			host = tmp_host;
			DEBUG3(printk("%s: Found host =%p, instance %d\n",
			    __func__, host, host->instance));
			break;
		}
	}

	LEAVE("qla2x00_cfg_find_host");

	return host;
}

/*
 *  qla2x00_find_host_by_portname
 *      Look through the existing multipath tree, and find
 *      a host adapter to match the specified portname.
 *
 *  Input:
 *      name = portname to match.
 *
 *  Return:
 *      Pointer to new host, or NULL if no match found.
 *
 * Context:
 *      Kernel context.
 */
mp_host_t *
qla2x00_find_host_by_portname(uint8_t *name)
{
	mp_host_t     *host;		/* Host found and null if not */

	for (host = mp_hosts_base; (host); host = host->next) {
		if (memcmp(host->portname, name, WWN_SIZE) == 0)
			break;
	}
	return host;
}

/*
 * qla2x00_found_hidden_path
 *	This is called only when the port trying to figure out whether
 *	to bind to this mp_device has mpbyte of zero. It doesn't matter
 *	if the path we check on is first path or not because if
 *	more than one path has mpbyte zero and not all are zero, it is
 *	invalid and unsupported configuration which we don't handle.
 *
 * Input:
 *	dp = mp_device pointer
 *
 * Returns:
 *	1 - first path in dp is hidden.
 *	0 - no hidden path.
 *
 * Context:
 *	Kernel context.
 */
static inline uint8_t
qla2x00_found_hidden_path(mp_device_t *dp)
{
	uint8_t		ret = 0;
	mp_path_list_t	*path_list = dp->path_list;
#ifdef QL_DEBUG_LEVEL_2
	mp_path_t	*tmp_path;
	uint8_t		cnt = 0;
#endif

	/* Sanity check */
	if (path_list == NULL) {
		/* ERROR? Just print debug and return */
		DEBUG2_3(printk("%s: ERROR No path list found on dp.\n",
		    __func__));
		return (0);
	}

	if (path_list->last != NULL &&
	    path_list->last->mp_byte & MP_MASK_HIDDEN) {
		ret = 1;
	}

#ifdef QL_DEBUG_LEVEL_2
	/* If any path is visible, return 0 right away, otherwise check
	 * through to make sure all existing paths in this mpdev are hidden.
	 */
	for (tmp_path = path_list->last; tmp_path && cnt < path_list->path_cnt;
	    tmp_path = tmp_path->next, cnt++) {
		if (!(tmp_path->mp_byte & MP_MASK_HIDDEN)) {
			printk("%s: found visible path.\n", __func__);
		}
	}
#endif

	return (ret);
}


/*
 * qla2x00_get_lun_ownership()
 *	Issue Vendor Specific SCSI Inquiry page code 0xe0 command for
 *	Ownership assignment query.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fcport = FC port structure pointer.
 *
 * Return:
 *	QLA2X00_FUNCTION_FAILED  - Failed to get the pref_path_priority
 *      Otherwise : pref_path_priority
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_lun_ownership(mp_host_t *host, fc_lun_t *fclun,
		uint8_t *cur_vol_path_own)
{
	int		rval = 0;
	int		retry;
	scsi_qla_host_t *ha;
	uint16_t	next_loopid;
	evpd_inq_cmd_rsp_t *inq;
	dma_addr_t	inq_dma;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	int		vol_pref_path_priority;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;

	if (atomic_read(&fclun->fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG(printk("%s leaving: Port is marked DEAD\n",__func__));
		return rval;
	}

	ha = host->ha;
	inq = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &inq_dma);
	if (inq == NULL) {
		printk(KERN_WARNING
		    "scsi(%ld): Memory Allocation failed - INQ\n",
		    ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &inq->p.rsp24.comp_status;
		sstatus = &inq->p.rsp24.scsi_status;
		sense_data = inq->p.rsp24.data;
	} else {
		cstatus = &inq->p.rsp.comp_status;
		sstatus = &inq->p.rsp.scsi_status;
		sense_data = inq->p.rsp.req_sense_data;
	}

	retry = 2;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(inq, 0, sizeof(evpd_inq_cmd_rsp_t));
			inq->p.cmd24.entry_type = COMMAND_TYPE_7;
			inq->p.cmd24.entry_count = 1;
			inq->p.cmd24.nport_handle =
			    cpu_to_le16(fclun->fcport->loop_id);
			inq->p.cmd24.port_id[0] = fclun->fcport->d_id.b.al_pa;
			inq->p.cmd24.port_id[1] = fclun->fcport->d_id.b.area;
			inq->p.cmd24.port_id[2] = fclun->fcport->d_id.b.domain;
			inq->p.cmd24.lun[1] = LSB(fclun->lun);
			inq->p.cmd24.lun[2] = MSB(fclun->lun);
			host_to_fcp_swap(inq->p.cmd24.lun,
			    sizeof(inq->p.cmd24.lun));
			inq->p.cmd24.task_mgmt_flags =
			    __constant_cpu_to_le16(TMF_READ_DATA);
			inq->p.cmd24.task = TSK_SIMPLE;
			inq->p.cmd24.fcp_cdb[0] = INQUIRY;
			inq->p.cmd24.fcp_cdb[1] = INQ_EVPD_SET;
			inq->p.cmd24.fcp_cdb[2] = VOL_OWNERSHIP_VPD_PAGE;
			inq->p.cmd24.fcp_cdb[4] = VITAL_PRODUCT_DATA_SIZE;
			host_to_fcp_swap(inq->p.cmd24.fcp_cdb,
			    sizeof(inq->p.cmd24.fcp_cdb));
			inq->p.cmd24.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd24.timeout = __constant_cpu_to_le16(10);
			inq->p.cmd24.byte_count =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
			inq->p.cmd24.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_len =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
		} else {
			memset(inq, 0, sizeof(evpd_inq_cmd_rsp_t));
			inq->p.cmd.entry_type = COMMAND_A64_TYPE;
			inq->p.cmd.entry_count = 1;
			inq->p.cmd.lun = cpu_to_le16(fclun->lun);
			SET_TARGET_ID(ha, inq->p.cmd.target,
			    fclun->fcport->loop_id);
			inq->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_READ | CF_SIMPLE_TAG);
			inq->p.cmd.scsi_cdb[0] = INQUIRY;
			inq->p.cmd.scsi_cdb[1] = INQ_EVPD_SET;
			inq->p.cmd.scsi_cdb[2] = VOL_OWNERSHIP_VPD_PAGE;
			inq->p.cmd.scsi_cdb[4] = VITAL_PRODUCT_DATA_SIZE;
			inq->p.cmd.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd.timeout = __constant_cpu_to_le16(10);
			inq->p.cmd.byte_count =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
			inq->p.cmd.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_length =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
		}

		rval = qla2x00_issue_iocb(ha, inq, inq_dma,
		    sizeof(evpd_inq_cmd_rsp_t));

		if (rval == QLA_SUCCESS && inq->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) INQ failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    inq->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

		DEBUG2(printk("%s: lun (%d) inquiry page 0x83-  (lun ownership) comp status "
		    "0x%x, scsi status 0x%x, rval=%d\n",__func__, fclun->lun,
		    comp_status, scsi_status, rval));

		/* if port not logged in then try and login */
		if (fclun->lun == 0 && comp_status == CS_PORT_LOGGED_OUT &&
		    atomic_read(&fclun->fcport->state) != FCS_DEVICE_DEAD) {
			if (fclun->fcport->flags & FC_FABRIC_DEVICE) {
				/* login and update database */
 				next_loopid = 0;
 				qla2x00_fabric_login(ha, fclun->fcport,
 				    &next_loopid);
			} else {
				/* Loop device gone but no LIP... */
				rval = QLA_FUNCTION_FAILED;
				break;
 			}
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE) &&
	    --retry);

	if (rval == QLA_SUCCESS &&
		 inq->inq[1] == VOL_OWNERSHIP_VPD_PAGE &&
		 (inq->inq[4] & VOL_OWNERSHIP_BIT_VALID)) {

		*cur_vol_path_own = (inq->inq[4]& VOL_OWNERSHIP_BIT) >> 6;
		vol_pref_path_priority = ((inq->inq[4]& VOL_OWNERSHIP_BIT))?
					PREFERRED_PATH_PRIORITY : SECONDARY_PATH_PRIORITY;

	} else {
		if (scsi_status & SS_CHECK_CONDITION) {
			/* Skip past any FCP RESPONSE data. */
			if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
				host_to_fcp_swap(sense_data, sizeof(inq->p.rsp24.data));
				if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
					sense_data += le32_to_cpu(
					    inq->p.rsp24.rsp_data_len);
			}

			/*
			 * ILLEGAL REQUEST - 0x05
			 * INVALID FIELD IN CDB - 24 : 00
			 */
			if (sense_data[2] == 0x05 && sense_data[12] == 0x24 &&
			    sense_data[13] == 0x00) {
				DEBUG(printk(KERN_INFO
				    "%s Lun(%d) does not support Inquiry Page "
				    "Code-0x83\n", __func__, fclun->lun));
			} else {
				DEBUG(printk(KERN_INFO "%s Lun(%d) does not support "
				    "Inquiry Page Code-0x83\n",	__func__,fclun->lun));

				DEBUG(printk(KERN_INFO
				    "Unhandled check condition sense_data[2]=0x%x "
				    "sense_data[12]=0x%x sense_data[13]=0x%x\n",
				    sense_data[2], sense_data[12], sense_data[13]));
			}
			rval = 0;
		} else {
	 		/* Unable to issue Inquiry Page 0x83 */
	 		DEBUG2(printk(KERN_INFO
	 		    "%s Failed to issue Inquiry Page 0x83 -- lun (%d) cs=0x%x "
	 		    "ss=0x%x, rval=%d\n", __func__, fclun->lun, comp_status,
	 		    scsi_status, rval));
			rval = 0;
  		}
		*cur_vol_path_own = 0;
		vol_pref_path_priority = SECONDARY_PATH_PRIORITY;
	}

	dma_pool_free(ha->s_dma_pool, inq, inq_dma);

	return 	vol_pref_path_priority;
}

/*
 * qla2x00_get_wwuln_from_device
 *	Issue SCSI inquiry page code 0x83 command for LUN WWLUN_NAME.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fcport = FC port structure pointer.
 *
 * Return:
 *	0  - Failed to get the lun_wwlun_name
 *      Otherwise : wwlun_size
 *
 * Context:
 *	Kernel context.
 */

static int
qla2x00_get_wwuln_from_device(mp_host_t *host, fc_lun_t *fclun, char *evpd_buf,
    int wwlun_size , uint8_t *rel_tport_id, uint8_t *tpg_id)
{

	int		rval = 0;
	int		retry;
	scsi_qla_host_t *ha;
	uint16_t	next_loopid;
	evpd_inq_cmd_rsp_t *inq;
	dma_addr_t	inq_dma;
	uint16_t        page_length = 0;
        uint16_t        next_desc = 0;
        uint16_t        hdr;
        uint32_t        iden_len = 0;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;

	if (atomic_read(&fclun->fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG(printk("%s leaving: Port is marked DEAD\n",__func__));
		return rval;
	}

	memset(evpd_buf, 0 ,wwlun_size);
	ha = host->ha;

	inq = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &inq_dma);
	if (inq == NULL) {
		printk(KERN_WARNING
		    "scsi(%ld): Memory Allocation failed - INQ\n",
		    ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &inq->p.rsp24.comp_status;
		sstatus = &inq->p.rsp24.scsi_status;
		sense_data = inq->p.rsp24.data;
	} else {
		cstatus = &inq->p.rsp.comp_status;
		sstatus = &inq->p.rsp.scsi_status;
		sense_data = inq->p.rsp.req_sense_data;
	}

	retry = 2;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(inq, 0, sizeof(evpd_inq_cmd_rsp_t));
			inq->p.cmd24.entry_type = COMMAND_TYPE_7;
			inq->p.cmd24.entry_count = 1;
			inq->p.cmd24.nport_handle =
			    cpu_to_le16(fclun->fcport->loop_id);
			inq->p.cmd24.port_id[0] = fclun->fcport->d_id.b.al_pa;
			inq->p.cmd24.port_id[1] = fclun->fcport->d_id.b.area;
			inq->p.cmd24.port_id[2] = fclun->fcport->d_id.b.domain;
			inq->p.cmd24.lun[1] = LSB(fclun->lun);
			inq->p.cmd24.lun[2] = MSB(fclun->lun);
			host_to_fcp_swap(inq->p.cmd24.lun,
			    sizeof(inq->p.cmd24.lun));
			inq->p.cmd24.task_mgmt_flags =
			    __constant_cpu_to_le16(TMF_READ_DATA);
			inq->p.cmd24.task = TSK_SIMPLE;
			inq->p.cmd24.fcp_cdb[0] = INQUIRY;
			inq->p.cmd24.fcp_cdb[1] = INQ_EVPD_SET;
			inq->p.cmd24.fcp_cdb[2] = INQ_DEV_IDEN_PAGE;
			inq->p.cmd24.fcp_cdb[4] = VITAL_PRODUCT_DATA_SIZE;
			host_to_fcp_swap(inq->p.cmd24.fcp_cdb,
			    sizeof(inq->p.cmd24.fcp_cdb));
			inq->p.cmd24.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd24.timeout = __constant_cpu_to_le16(10);
			inq->p.cmd24.byte_count =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
			inq->p.cmd24.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(struct sts_entry_24xx)));
			inq->p.cmd24.dseg_0_len =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
		} else {
			memset(inq, 0, sizeof(evpd_inq_cmd_rsp_t));
			inq->p.cmd.entry_type = COMMAND_A64_TYPE;
			inq->p.cmd.entry_count = 1;
			inq->p.cmd.lun = cpu_to_le16(fclun->lun);
			SET_TARGET_ID(ha, inq->p.cmd.target,
			    fclun->fcport->loop_id);
			inq->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_READ | CF_SIMPLE_TAG);
			inq->p.cmd.scsi_cdb[0] = INQUIRY;
			inq->p.cmd.scsi_cdb[1] = INQ_EVPD_SET;
			inq->p.cmd.scsi_cdb[2] = INQ_DEV_IDEN_PAGE;
			inq->p.cmd.scsi_cdb[4] = VITAL_PRODUCT_DATA_SIZE;
			inq->p.cmd.dseg_count = __constant_cpu_to_le16(1);
			inq->p.cmd.timeout = __constant_cpu_to_le16(10);
			inq->p.cmd.byte_count =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
			inq->p.cmd.dseg_0_address[0] = cpu_to_le32(
			    LSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_address[1] = cpu_to_le32(
			    MSD(inq_dma + sizeof(sts_entry_t)));
			inq->p.cmd.dseg_0_length =
			    __constant_cpu_to_le32(VITAL_PRODUCT_DATA_SIZE);
		}

		rval = qla2x00_issue_iocb(ha, inq, inq_dma,
		    sizeof(evpd_inq_cmd_rsp_t));

		if (rval == QLA_SUCCESS && inq->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) INQ failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    inq->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

		DEBUG5(printk("%s: lun (%d) inquiry page 0x83-  comp status "
		    "0x%x, scsi status 0x%x, rval=%d\n",__func__, fclun->lun,
		    comp_status, scsi_status, rval));

		/* if port not logged in then try and login */
		if (fclun->lun == 0 && comp_status == CS_PORT_LOGGED_OUT &&
		    atomic_read(&fclun->fcport->state) != FCS_DEVICE_DEAD) {
			if (fclun->fcport->flags & FC_FABRIC_DEVICE) {
				/* login and update database */
 				next_loopid = 0;
 				qla2x00_fabric_login(ha, fclun->fcport,
 				    &next_loopid);
			} else {
				/* Loop device gone but no LIP... */
				rval = QLA_FUNCTION_FAILED;
				break;
 			}
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE) &&
	    --retry);

	if (rval == QLA_SUCCESS && inq->inq[1] == INQ_DEV_IDEN_PAGE) {
		if (inq->inq[7] <= WWLUN_SIZE) {
			memcpy(evpd_buf, &inq->inq[8], inq->inq[7]);
			DEBUG(printk("%s : Lun(%d)  WWLUN size %d\n",__func__,
			    fclun->lun, inq->inq[7]));
		} else {
			memcpy(evpd_buf, &inq->inq[8], WWLUN_SIZE);
			printk(KERN_INFO "%s : Lun(%d)  WWLUN may not be "
			    "complete, Buffer too small need: %d provided: "
			    "%d\n",__func__, fclun->lun, inq->inq[7],
			    WWLUN_SIZE);
		}
		rval = inq->inq[7];		/* lun wwlun_size */
		DEBUG3(qla2x00_dump_buffer(evpd_buf, rval));

		/* Copy the other identifiers for devices which
                 * support report target port group cmd */
                if (fclun->fcport->fo_target_port == NULL)
                        goto out;
                if (rel_tport_id == NULL || tpg_id == NULL)
                        goto out;

                /* page length of identifier descriptor list */
                hdr = 4;
                page_length = (inq->inq[2] << 8 | inq->inq[3]);
                page_length = page_length + hdr;
                /* identifier descriptor next to logical unit */
                next_desc = hdr + (inq->inq[7] + hdr);

                DEBUG5(printk("%s next_desc =%d page_length=%d\n",
			__func__,next_desc,page_length));
		while (next_desc < page_length) {
			iden_len = inq->inq[next_desc + hdr -1];
                        DEBUG5(printk("%s iden len =%d code_set=0x%x type=0x%x\n",__func__,iden_len,
				(inq->inq[next_desc] & 0x0f),(inq->inq[next_desc + 1] & 0x3f)));

                        if ((inq->inq[next_desc] & 0x0f) == CODE_SET_BINARY &&
				(((inq->inq[next_desc + 1] & 0x3f) ==
				 (ASSOCIATION_LOGICAL_DEVICE << 4 |
                                          TYPE_REL_TGT_PORT)) ||
				((inq->inq[next_desc + 1] & 0x3f) ==
				 (ASSOCIATION_TARGET_PORT << 4 |
                                          TYPE_REL_TGT_PORT)))) {
                                iden_len = inq->inq[next_desc + hdr -1];
                                rel_tport_id[0] =
                                        inq->inq[next_desc + hdr + iden_len -2];
                                rel_tport_id[1] =
                                        inq->inq[next_desc + hdr + iden_len -1];
			       DEBUG(printk("%s rel_tport_id[0]=0x%x"
					" rel_tport_id[1]=0x%x\n", __func__,
					rel_tport_id[0], rel_tport_id[1]));
                        }
                        if ((inq->inq[next_desc] & 0x0f) == CODE_SET_BINARY &&
				(((inq->inq[next_desc + 1] & 0x3f) ==
				 (ASSOCIATION_LOGICAL_DEVICE << 4 |
                                          TYPE_TPG_GROUP)) ||
				((inq->inq[next_desc + 1] & 0x3f) ==
				 (ASSOCIATION_TARGET_PORT << 4 |
                                          TYPE_TPG_GROUP)))) {

                                iden_len = inq->inq[next_desc + hdr -1];
                                tpg_id[0] = inq->inq[next_desc + hdr + iden_len -2];
                                tpg_id[1] = inq->inq[next_desc + hdr + iden_len -1];
                                DEBUG(printk("%s tpg_id[0]=0x%x "
                                        "tpg_id[1]=0x%x\n",__func__,
                                        tpg_id[0],tpg_id[1]));
                        }
                        /* increment to the next identifier descriptor */
                        next_desc += iden_len + hdr;
                }
	} else if (scsi_status & SS_CHECK_CONDITION) {
		/* Skip past any FCP RESPONSE data. */
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			host_to_fcp_swap(sense_data, sizeof(inq->p.rsp24.data));
			if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
				sense_data += le32_to_cpu(
				    inq->p.rsp24.rsp_data_len);
		}

		/*
		 * ILLEGAL REQUEST - 0x05
		 * INVALID FIELD IN CDB - 24 : 00
		 */
		if (sense_data[2] == 0x05 && sense_data[12] == 0x24 &&
		    sense_data[13] == 0x00) {
			DEBUG(printk(KERN_INFO
			    "%s Lun(%d) does not support Inquiry Page "
			    "Code-0x83\n", __func__, fclun->lun));
		} else {
			DEBUG(printk(KERN_INFO "%s Lun(%d) does not support "
			    "Inquiry Page Code-0x83\n",	__func__,fclun->lun));

			DEBUG(printk(KERN_INFO
			    "Unhandled check condition sense_data[2]=0x%x "
			    "sense_data[12]=0x%x sense_data[13]=0x%x\n",
			    sense_data[2], sense_data[12], sense_data[13]));
		}
		rval = 0;
	} else {
 		/* Unable to issue Inquiry Page 0x83 */
 		DEBUG2(printk(KERN_INFO
 		    "%s Failed to issue Inquiry Page 0x83 -- lun (%d) cs=0x%x "
 		    "ss=0x%x, rval=%d\n", __func__, fclun->lun, comp_status,
 		    scsi_status, rval));
		rval = 0;
  	}
out:

	dma_pool_free(ha->s_dma_pool, inq, inq_dma);

	LEAVE(__func__);

	return rval;
}

/*
 * qla2x00_find_matching_lunid
 *      Find the lun in the lun list that matches the
 *  specified wwu lun number.
 *
 * Input:
 *      buf  = buffer that contains the wwuln
 *      host = host to search for lun
 *
 * Returns:
 *      NULL or pointer to lun
 *
 * Context:
 *      Kernel context.
 * (dg)
 */
static mp_lun_t  *
qla2x00_find_matching_lunid(char	*buf)
{
	int		devid = 0;
	mp_host_t	*temp_host;  /* temporary pointer */
	mp_device_t	*temp_dp;  /* temporary pointer */
	mp_lun_t *lun;

	//printk("%s: entered.\n", __func__);

	for (temp_host = mp_hosts_base; (temp_host);
	    temp_host = temp_host->next) {
		for (devid = 0; devid < MAX_MP_DEVICES; devid++) {
			temp_dp = temp_host->mp_devs[devid];

			if (temp_dp == NULL)
				continue;

			for (lun = temp_dp->luns; lun != NULL ;
					lun = lun->next) {

				if (lun->siz > WWULN_SIZE)
					lun->siz = WWULN_SIZE;

				if (memcmp(lun->wwuln, buf, lun->siz) == 0)
					return lun;
			}
		}
	}
	return NULL;

}

void
qla2x00_update_lu_path_state(scsi_qla_host_t *ha, rpt_tport_grp_rsp_t *tpg,
	fc_lun_t *fclun,
	uint16_t	tpg_count,
	uint8_t		*tpg_id,
	uint8_t		asym_acc_state)
{
	struct list_head *list, *temp;
	lu_path_t	*lu_path = NULL;
	mp_lun_t *mplun;

	/* update the lu_path state */
	mplun = fclun->mplun;
	list_for_each_safe(list, temp, &mplun->lu_paths) {
		lu_path = list_entry(list, lu_path_t, list);

		if (lu_path->tpg_id[0] != tpg_id[0] || lu_path->tpg_id[1] != tpg_id[1])
			continue;

		if (lu_path->fclun != fclun)
			continue;

		/* copy the tgt port group state */
		if (tpg != NULL)
			lu_path->asym_acc_state =
			   tpg->list.tport_grp[tpg_count].state.asym_acc_state;
		else
			lu_path->asym_acc_state = asym_acc_state;

		/* FIXMEdg: Is this really needed ?????  */
		if (lu_path->asym_acc_state == TPG_ACT_OPT) {
			fclun->flags |= FLF_ACTIVE_LUN;

			DEBUG(printk("%s(%ld) Set lun %d to active path %d, "
			    "state =%d fclun_flags=0x%x loop_id=0x%02x\n",
			    __func__, ha->instance, fclun->lun,
			    lu_path->path_id, lu_path->asym_acc_state,
			    lu_path->fclun->flags,
			    lu_path->fclun->fcport->loop_id));
		}
		DEBUG2(printk("%s(%ld): index=%d lun %d Update state of "
		    "lu_path %d tpg_id=0x%x rel_tport_id=0x%x, tpg state=%d \n",
		    __func__, ha->instance, tpg_count, fclun->lun,
		    lu_path->path_id, lu_path->tpg_id[1],
		    lu_path->rel_tport_id[1],lu_path->asym_acc_state));
	}
}


int
qla2x00_get_vol_access_path(fc_port_t *fcport, fc_lun_t *fclun, int modify)
{
	int		rval = QLA_FUNCTION_FAILED;
	uint8_t		tpg_id[2];
	uint16_t	lun = 0;
	scsi_qla_host_t *ha;
	mp_lun_t *mplun;
	struct list_head *list, *temp;
	mp_tport_grp_t *tport_grp = NULL;
	mp_host_t *host;
	uint16_t	tpg_count;
	int		vol_pref_path_priority = -1;
	uint8_t		cur_vol_path_own, asym_acc_state = 0;

	ENTER(__func__);
	DEBUG(printk(KERN_INFO "%s  entered\n",__func__));

	ha = fcport->ha;
	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG2(printk("scsi(%ld) %s leaving: lun %d, Port 0x%02x is marked "
			"DEAD\n", ha->host_no,__func__,fclun->lun, fcport->loop_id));
			return rval;
	}

	lun = fclun->lun;
	mplun = fclun->mplun;
	if (fclun->mplun == NULL) {
		DEBUG2(printk("%s mplun does not exist for fclun=%p\n",
				__func__,fclun));
		return rval;
	}
	if ((host = qla2x00_cfg_find_host(fcport->ha)) == NULL) {
		DEBUG2(printk("%s mp_host does not exist for fclun=%p\n",
				__func__,fclun));
		return rval;
	}

	if ((fclun->fcport->flags & FC_DFXXX_DEVICE)) {
		vol_pref_path_priority = qla2x00_get_lun_ownership(
					host, fclun, &cur_vol_path_own);
	}
	if (vol_pref_path_priority == -1) {
		DEBUG2(printk("%s failed to get the vol_pref_path_priority\n",
				__func__));
		return rval;
	}
	DEBUG2(printk("scsi(%ld) %s port 0x%02x lun %d access: vol_pref_path 0x%x, cureent 0x%x\n",
			ha->host_no,__func__,fcport->loop_id,
			fclun->lun,vol_pref_path_priority,
			cur_vol_path_own));

	memset(&tpg_id[0], 0, sizeof(tpg_id));
	tpg_id[1] = vol_pref_path_priority;
	/* find matching tpg_id and copy the asym_acc_state */
	for (tpg_count = 0; tpg_count < TGT_PORT_GRP_COUNT; tpg_count++) {
		list_for_each_safe(list, temp, &mplun->tport_grps_list) {
			tport_grp = list_entry(list, mp_tport_grp_t,
					 list);
			if (memcmp(tport_grp->tpg_id, &tpg_id[0],
				 sizeof(tpg_id)) != 0)
					continue;
			/* copy the tgt port group state */
			if (mp_initialized) {
				if (vol_pref_path_priority ==
					PREFERRED_PATH_PRIORITY)
					asym_acc_state = TPG_ACT_OPT;
				if (vol_pref_path_priority ==
						SECONDARY_PATH_PRIORITY)
					asym_acc_state =
						TPG_ACT_NON_OPT;

			} else {
				/* Volume owned by the controller */
				if (cur_vol_path_own == 1)
					asym_acc_state = TPG_ACT_OPT;
				/* Volume owned by the alternate controller */
				if (cur_vol_path_own == 0)
					asym_acc_state = TPG_ACT_NON_OPT;
			}
			tport_grp->asym_acc_state = asym_acc_state;
			DEBUG(printk("%s Update target port state =%d for"
					" mplun %p\n", __func__,
					tport_grp->asym_acc_state,mplun));
		}
		if (modify) {
			qla2x00_update_lu_path_state(ha, NULL, fclun,
				0, &tpg_id[0], asym_acc_state);
		}
	}
	LEAVE(__func__);

	return rval;
}

int
qla2x00_get_target_ports(fc_port_t *fcport, fc_lun_t *fclun, int modify)
{
	int		rval = 0;
	int		retry;
	uint16_t	tpg_count;
	uint8_t		tpg_id[2];
	uint16_t	lun = 0;
	dma_addr_t	tpg_dma;
	scsi_qla_host_t *ha;
	mp_lun_t *mplun;
	rpt_tport_grp_rsp_t *tpg;
	struct list_head *list, *temp;
	mp_tport_grp_t *tport_grp = NULL;
	tgt_port_grp_desc_0 *tpg_rtpg_0 = NULL;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;

	ENTER(__func__);
	DEBUG(printk(KERN_INFO "%s  entered\n",__func__));

	ha = fcport->ha;
	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG2(printk("scsi(%ld) %s leaving: Port 0x%02x is marked "
			"DEAD\n", ha->host_no,__func__,fcport->loop_id));
			return rval;
	}

	lun = fclun->lun;
	mplun = fclun->mplun;
	if (fclun->mplun == NULL) {
		DEBUG(printk("%s mplun does not exist for fclun=%p\n",
				__func__,fclun));
		return rval;
	}

	/* LUN 0 on EVA/MSA device is a controller lun and does not support ALUA */
	if (fclun->asymm_support == TGT_PORT_GRP_UNSUPPORTED)  {
		//qla2x00_test_active_lun(fcport, fclun);
		printk("%s(%ld): for lun=%d does not suuport ALUA \n",__func__,
				ha->instance,lun);
		rval = 1;
		return rval;
	}

	tpg = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &tpg_dma);
	if (tpg == NULL) {
		printk(KERN_WARNING
				"scsi(%ld): Memory Allocation failed - TPG\n",
				ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &tpg->p.rsp24.comp_status;
		sstatus = &tpg->p.rsp24.scsi_status;
		sense_data = tpg->p.rsp24.data;
	} else {
		cstatus = &tpg->p.rsp.comp_status;
		sstatus = &tpg->p.rsp.scsi_status;
		sense_data = tpg->p.rsp.req_sense_data;
	}

	retry = 2;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(tpg, 0, sizeof(rpt_tport_grp_rsp_t));
			tpg->p.cmd24.entry_type = COMMAND_TYPE_7;
			tpg->p.cmd24.entry_count = 1;
			tpg->p.cmd24.nport_handle =
			    cpu_to_le16(fcport->loop_id);
			tpg->p.cmd24.port_id[0] = fcport->d_id.b.al_pa;
			tpg->p.cmd24.port_id[1] = fcport->d_id.b.area;
			tpg->p.cmd24.port_id[2] = fcport->d_id.b.domain;
			tpg->p.cmd24.lun[1] = LSB(lun);
			tpg->p.cmd24.lun[2] = MSB(lun);
			host_to_fcp_swap(tpg->p.cmd24.lun,
			    sizeof(tpg->p.cmd24.lun));
			tpg->p.cmd24.task = TSK_SIMPLE;
			tpg->p.cmd24.task_mgmt_flags =
			    __constant_cpu_to_le16(TMF_READ_DATA);
			tpg->p.cmd24.fcp_cdb[0] = SCSIOP_MAINTENANCE_IN;
			tpg->p.cmd24.fcp_cdb[1] = SCSISA_TARGET_PORT_GROUPS;
			tpg->p.cmd24.fcp_cdb[8] =
			    (sizeof(rpt_tport_grp_data_t) >> 8) & 0xff;
			tpg->p.cmd24.fcp_cdb[9] =
			    sizeof(rpt_tport_grp_data_t) & 0xff;
			host_to_fcp_swap(tpg->p.cmd24.fcp_cdb,
			    sizeof(tpg->p.cmd24.fcp_cdb));
			tpg->p.cmd24.dseg_count = __constant_cpu_to_le16(1);
			tpg->p.cmd24.timeout = __constant_cpu_to_le16(10);
			tpg->p.cmd24.byte_count =
			    __constant_cpu_to_le32(sizeof(rpt_tport_grp_data_t));
			tpg->p.cmd24.dseg_0_address[0] = cpu_to_le32(
			    LSD(tpg_dma + sizeof(struct sts_entry_24xx)));
			tpg->p.cmd24.dseg_0_address[1] = cpu_to_le32(
			    MSD(tpg_dma + sizeof(struct sts_entry_24xx)));
			tpg->p.cmd24.dseg_0_len =
			    __constant_cpu_to_le32(sizeof(rpt_tport_grp_data_t));
		} else {
			memset(tpg, 0, sizeof(rpt_tport_grp_rsp_t));
			tpg->p.cmd.entry_type = COMMAND_A64_TYPE;
			tpg->p.cmd.entry_count = 1;
			tpg->p.cmd.lun = cpu_to_le16(lun);
			SET_TARGET_ID(ha, tpg->p.cmd.target, fcport->loop_id);
			tpg->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_READ | CF_SIMPLE_TAG);
			tpg->p.cmd.scsi_cdb[0] = SCSIOP_MAINTENANCE_IN;
			tpg->p.cmd.scsi_cdb[1] = SCSISA_TARGET_PORT_GROUPS;
			tpg->p.cmd.scsi_cdb[8] = (sizeof(rpt_tport_grp_data_t) >> 8)
			    & 0xff;
			tpg->p.cmd.scsi_cdb[9] = sizeof(rpt_tport_grp_data_t) & 0xff;
			tpg->p.cmd.dseg_count = __constant_cpu_to_le16(1);
			tpg->p.cmd.timeout = __constant_cpu_to_le16(10);
			tpg->p.cmd.byte_count =
			    __constant_cpu_to_le32(sizeof(rpt_tport_grp_data_t));
			tpg->p.cmd.dseg_0_address[0] = cpu_to_le32(
			    LSD(tpg_dma + sizeof(sts_entry_t)));
			tpg->p.cmd.dseg_0_address[1] = cpu_to_le32(
			    MSD(tpg_dma + sizeof(sts_entry_t)));
			tpg->p.cmd.dseg_0_length =
			    __constant_cpu_to_le32(sizeof(rpt_tport_grp_data_t));
		}

		rval = qla2x00_issue_iocb(ha, tpg, tpg_dma,
		    sizeof(rpt_tport_grp_rsp_t));

		if (rval == QLA_SUCCESS && tpg->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) TPG failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    tpg->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

		DEBUG5(printk("%s: lun (%d) Report Target Port group "
			" comp status 0x%x, scsi status 0x%x, rval=%d\n",
			__func__, lun, comp_status, scsi_status, rval));
		/* Port Logged Out, so don't retry */
		if (comp_status == CS_PORT_LOGGED_OUT ||
		    comp_status == CS_PORT_CONFIG_CHG ||
		    comp_status == CS_PORT_BUSY ||
		    comp_status == CS_INCOMPLETE ||
		    comp_status == CS_PORT_UNAVAILABLE)
				break;

		DEBUG(printk("scsi(%ld:%04x:%d) %s: Report Target Port group"
		    " - comp status 0x%x, scsi status 0x%x, rval=%d\n",
		    ha->host_no, fcport->loop_id, lun,__func__, comp_status,
		    scsi_status, rval));

                if (rval != QLA_SUCCESS ||
		    comp_status != CS_COMPLETE ||
		    scsi_status & SS_CHECK_CONDITION) {

			/* Device underrun, treat as OK. */
			if (comp_status == CS_DATA_UNDERRUN &&
			    scsi_status & SS_RESIDUAL_UNDER) {

				rval = QLA_SUCCESS;
				comp_status = CS_COMPLETE;
				break;
			}
		}

		if ((scsi_status & SS_CHECK_CONDITION)) {
			/* Skip past any FCP RESPONSE data. */
			if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
				host_to_fcp_swap(sense_data,
				    sizeof(tpg->p.rsp24.data));
				if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
					sense_data += le32_to_cpu(
					    tpg->p.rsp24.rsp_data_len);
			}

			DEBUG2(printk("%s: check status bytes = "
			    "0x%02x 0x%02x 0x%02x\n", __func__,
			    sense_data[2], sense_data[12], sense_data[13]));
			/* add checking for extended sense key for adaptec */
			if (sense_data[2] == NOT_READY)
				break;
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE ||
			(scsi_status & SS_CHECK_CONDITION)) && --retry);

	if (rval == QLA_SUCCESS && retry &&
		(!((scsi_status & SS_CHECK_CONDITION) &&
		(sense_data[2] == NOT_READY)) && comp_status == CS_COMPLETE)) {
		memset(&tpg_id[0], 0, sizeof(tpg_id));
		/* find matching tpg_id and copy the asym_acc_state */
		for (tpg_count = 0; tpg_count < TGT_PORT_GRP_COUNT;
				tpg_count++) {
			/* In our original design, we assume there are two relative target port
			 * groups per target port, but some storages (ie. MSA1500) only has one relative
			 * target port per target port group, so we have a different structure definitions
			 * for each type and use the appropriate one depending on how many ports the storage
			 * has.
			 *  tpg  = dual relative port devices
			 *  tpg_rtgp_0 = single relative port devices
			 */
			if (tpg->list.tport_grp[0].tgt_port_count == 1) {
			    	if (tpg_rtpg_0 == NULL)
					tpg_rtpg_0 = (tgt_port_grp_desc_0 *)
						&tpg->list.tport_grp[tpg_count];
				memcpy(&tpg_id[0], &tpg_rtpg_0->tgt_port_grp[0],
					sizeof(tpg_id));
			} else {
			    memcpy(&tpg_id[0],
			       &tpg->list.tport_grp[tpg_count].tgt_port_grp[0],
			       sizeof(tpg_id));

			}
			DEBUG2(printk("%s tpg_id[0]=0x%x tpg_id[1]=0x%x\n",
				__func__,tpg_id[0], tpg_id[1]));


			list_for_each_safe(list, temp, &mplun->tport_grps_list) {
				tport_grp = list_entry(list, mp_tport_grp_t,
						 list);
				if (memcmp(tport_grp->tpg_id, &tpg_id[0],
					 sizeof(tpg_id)) != 0)
						continue;
				/* copy the tgt port group state */
				if (tpg_rtpg_0 != NULL) {
					tport_grp->asym_acc_state =
					tpg_rtpg_0->state.asym_acc_state;
				} else {
					tport_grp->asym_acc_state =
					  tpg->list.tport_grp[tpg_count].state.
						asym_acc_state;
				}
				DEBUG2(printk("%s Update target port state =%d for mplun %p\n",
					__func__,tport_grp->asym_acc_state,mplun));
			}
			if (modify) {
				if (tpg_rtpg_0 != NULL)
					qla2x00_update_lu_path_state(ha, NULL,
					    fclun,
					    tpg_count, &tpg_id[0],
					    tpg_rtpg_0->state.asym_acc_state);
				else
					qla2x00_update_lu_path_state(ha, tpg,
					    fclun,
					    tpg_count, &tpg_id[0],
					    0);
			}
			if (tpg_rtpg_0 != NULL)
				tpg_rtpg_0++;

		}
		rval = 1;
	} else {
		DEBUG2(printk(KERN_INFO "%s Failed to issue Report tgt port"
			" group -- lun (%d) cs=0x%x ss=0x%x, rval=%d\n",
			__func__, lun, comp_status, scsi_status, rval));
		rval = 0;
	}

	dma_pool_free(ha->s_dma_pool, tpg, tpg_dma);

	LEAVE(__func__);

	return rval;
}

int
qla2x00_get_target_xports(fc_port_t *fcport, fc_lun_t *fclun, int modify)
{
	int		rval = 0;
	int		retry;
	uint16_t	tpg_count;
	uint16_t	lun = 0;
	dma_addr_t	tpg_dma;
	scsi_qla_host_t *ha;
	mp_lun_t *mplun;
	rtpg_param_data_rsp_t *tpg;
	struct list_head *list, *temp;
	mp_tport_grp_t *tport_grp = NULL;
	tpg_desc_t *tport_grp_desc_end = NULL;
	tpg_desc_t *tport_grp_desc = NULL;
	rel_tport_desc_t *rel_tport;
	uint16_t	comp_status = 0;
	uint16_t	scsi_status = 0;
	uint16_t	*cstatus, *sstatus;
	uint8_t		*sense_data;
	uint32_t	rtpg_size;
	int		expected_rtpg_siz;
	int		max_port_count;
	int		i;

	ENTER(__func__);
	DEBUG(printk(KERN_INFO "%s  entered\n",__func__));

	ha = fcport->ha;
	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD) {
		DEBUG2(printk("scsi(%ld) %s leaving: Port 0x%02x is marked "
			"DEAD\n", ha->host_no,__func__,fcport->loop_id));
			return rval;
	}

	lun = fclun->lun;
	mplun = fclun->mplun;
	if (fclun->mplun == NULL) {
		DEBUG(printk("%s mplun does not exist for fclun=%p\n",
				__func__,fclun));
		return rval;
	}

	/* LUN 0 on EVA/MSA device is a controller lun and does not support ALUA */
	if (fclun->asymm_support == TGT_PORT_GRP_UNSUPPORTED)  {
		//qla2x00_test_active_lun(fcport, fclun);
		printk("%s(%ld): for lun=%d does not suuport ALUA \n",__func__,
				ha->instance,lun);
		rval = 1;
		return rval;
	}

	/* We can handle RTPG parameters up to this size */
	expected_rtpg_siz = 4000;
	tpg = dma_alloc_coherent(&ha->pdev->dev,
	    sizeof(rtpg_param_data_rsp_t) + expected_rtpg_siz, &tpg_dma,
	    GFP_KERNEL);
	if (tpg == NULL) {
		printk(KERN_WARNING
				"scsi(%ld): Memory Allocation failed - TPG\n",
				ha->host_no);
		ha->mem_err++;
		return rval;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		cstatus = &tpg->p.rsp24.comp_status;
		sstatus = &tpg->p.rsp24.scsi_status;
		sense_data = tpg->p.rsp24.data;
	} else {
		cstatus = &tpg->p.rsp.comp_status;
		sstatus = &tpg->p.rsp.scsi_status;
		sense_data = tpg->p.rsp.req_sense_data;
	}

	retry = 2;
	do {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			memset(tpg, 0, sizeof(rtpg_param_data_rsp_t));
			tpg->p.cmd24.entry_type = COMMAND_TYPE_7;
			tpg->p.cmd24.entry_count = 1;
			tpg->p.cmd24.nport_handle =
			    cpu_to_le16(fcport->loop_id);
			tpg->p.cmd24.port_id[0] = fcport->d_id.b.al_pa;
			tpg->p.cmd24.port_id[1] = fcport->d_id.b.area;
			tpg->p.cmd24.port_id[2] = fcport->d_id.b.domain;
			tpg->p.cmd24.lun[1] = LSB(lun);
			tpg->p.cmd24.lun[2] = MSB(lun);
			host_to_fcp_swap(tpg->p.cmd24.lun,
			    sizeof(tpg->p.cmd24.fcp_cdb));
			tpg->p.cmd24.task = TSK_SIMPLE;
			tpg->p.cmd24.task_mgmt_flags =
			    __constant_cpu_to_le16(TMF_READ_DATA);
			tpg->p.cmd24.fcp_cdb[0] = SCSIOP_MAINTENANCE_IN;
			tpg->p.cmd24.fcp_cdb[1] = SCSISA_TARGET_PORT_GROUPS;
			tpg->p.cmd24.fcp_cdb[8] =
			    (expected_rtpg_siz >> 8) & 0xff;
			tpg->p.cmd24.fcp_cdb[9] = expected_rtpg_siz & 0xff;
			host_to_fcp_swap(tpg->p.cmd24.fcp_cdb,
			    sizeof(tpg->p.cmd24.fcp_cdb));
			tpg->p.cmd24.dseg_count = __constant_cpu_to_le16(1);
			tpg->p.cmd24.timeout = __constant_cpu_to_le16(10);
			tpg->p.cmd24.byte_count =
			    cpu_to_le32(expected_rtpg_siz);
			tpg->p.cmd24.dseg_0_address[0] = cpu_to_le32(
			    LSD(tpg_dma + sizeof(struct sts_entry_24xx)));
			tpg->p.cmd24.dseg_0_address[1] = cpu_to_le32(
			    MSD(tpg_dma + sizeof(struct sts_entry_24xx)));
			tpg->p.cmd24.dseg_0_len =
			    cpu_to_le32(expected_rtpg_siz);
		} else {
			memset(tpg, 0, sizeof(rpt_tport_grp_rsp_t));
			tpg->p.cmd.entry_type = COMMAND_A64_TYPE;
			tpg->p.cmd.entry_count = 1;
			tpg->p.cmd.lun = cpu_to_le16(lun);
			SET_TARGET_ID(ha, tpg->p.cmd.target, fcport->loop_id);
			tpg->p.cmd.control_flags =
			    __constant_cpu_to_le16(CF_READ | CF_SIMPLE_TAG);
			tpg->p.cmd.scsi_cdb[0] = SCSIOP_MAINTENANCE_IN;
			tpg->p.cmd.scsi_cdb[1] = SCSISA_TARGET_PORT_GROUPS;
			tpg->p.cmd.scsi_cdb[8] =
			    (expected_rtpg_siz >> 8) & 0xff;
			tpg->p.cmd.scsi_cdb[9] = expected_rtpg_siz & 0xff;
			tpg->p.cmd.dseg_count = __constant_cpu_to_le16(1);
			tpg->p.cmd.timeout = __constant_cpu_to_le16(10);
			tpg->p.cmd.byte_count = cpu_to_le32(expected_rtpg_siz);
			tpg->p.cmd.dseg_0_address[0] = cpu_to_le32(
			    LSD(tpg_dma + sizeof(sts_entry_t)));
			tpg->p.cmd.dseg_0_address[1] = cpu_to_le32(
			    MSD(tpg_dma + sizeof(sts_entry_t)));
			tpg->p.cmd.dseg_0_length =
			    cpu_to_le32(expected_rtpg_siz);
		}

		rval = qla2x00_issue_iocb(ha, tpg, tpg_dma,
		    sizeof(rpt_tport_grp_rsp_t));

		if (rval == QLA_SUCCESS && tpg->p.rsp.entry_status != 0) {
			DEBUG(printk("%s(%ld) TPG failed to complete IOCB "
			    "-- error status (%x).\n", __func__, ha->host_no,
			    tpg->p.rsp.entry_status));
			continue;
		}

		comp_status = le16_to_cpup(cstatus);
		scsi_status = le16_to_cpup(sstatus);

		DEBUG5(printk("%s: lun (%d) Report Target Port group "
			" comp status 0x%x, scsi status 0x%x, rval=%d\n",
			__func__, lun, comp_status, scsi_status, rval));
		/* Port Logged Out, so don't retry */
		if (comp_status == CS_PORT_LOGGED_OUT ||
		    comp_status == CS_PORT_CONFIG_CHG ||
		    comp_status == CS_PORT_BUSY ||
		    comp_status == CS_INCOMPLETE ||
		    comp_status == CS_PORT_UNAVAILABLE)
				break;

		DEBUG(printk("scsi(%ld:%04x:%d) %s: Report Target Port group"
		    " - comp status 0x%x, scsi status 0x%x, rval=%d\n",
		    ha->host_no, fcport->loop_id, lun,__func__, comp_status,
		    scsi_status, rval));

                if (rval != QLA_SUCCESS ||
		    comp_status != CS_COMPLETE ||
		    scsi_status & SS_CHECK_CONDITION) {

			/* Device underrun, treat as OK. */
			if (comp_status == CS_DATA_UNDERRUN &&
			    scsi_status & SS_RESIDUAL_UNDER) {

				rval = QLA_SUCCESS;
				comp_status = CS_COMPLETE;
				break;
			}
		}

		if ((scsi_status & SS_CHECK_CONDITION)) {
			/* Skip past any FCP RESPONSE data. */
			if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
				host_to_fcp_swap(sense_data,
				    sizeof(tpg->p.rsp24.data));
				if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
					sense_data += le32_to_cpu(
					    tpg->p.rsp24.rsp_data_len);
			}

			DEBUG2(printk("%s: check status bytes = "
			    "0x%02x 0x%02x 0x%02x\n", __func__,
			    sense_data[2], sense_data[12], sense_data[13]));
			/* add checking for extended sense key for adaptec */
			if (sense_data[2] == NOT_READY)
				break;
		}
	} while ((rval != QLA_SUCCESS || comp_status != CS_COMPLETE ||
			(scsi_status & SS_CHECK_CONDITION)) && --retry);

	if (rval == QLA_SUCCESS && retry &&
		(!((scsi_status & SS_CHECK_CONDITION) &&
		(sense_data[2] == NOT_READY)) && comp_status == CS_COMPLETE)) {

		/* check for size match */
		rtpg_size = be32_to_cpu(tpg->data.len);
		if (rtpg_size >  expected_rtpg_siz) {
			printk(KERN_INFO
			    "scsi(%ld:%04x:%d) %s: Buffer too big - size 0x%x "
			    "> 0x%x \n", ha->host_no, fcport->loop_id, lun,
			    __func__, rtpg_size, expected_rtpg_siz);
			rtpg_size = expected_rtpg_siz;
		}

		tport_grp_desc = (tpg_desc_t *)&tpg->data.tpg_desc_entry[0];
		max_port_count = tport_grp_desc->tgt_port_count;
		tport_grp_desc_end = (tpg_desc_t *) ((ulong)tport_grp_desc +
		    (ulong)rtpg_size);

		DEBUG5(printk("%s: Dump of RTPG parameter data [siz]= 0x%x, "
		    "%d start address=%p max_port_count=%d, ending "
		    "address=%p\n", __func__,  rtpg_size, rtpg_size,
		    &tpg->data, max_port_count, tport_grp_desc_end));
		DEBUG5(qla2x00_dump_buffer((uint8_t *)&tpg->data, rtpg_size));

		/* find matching tpg_id and update the asym_acc_state */
		for (tpg_count = 0; tpg_count < 10 ; tpg_count++) {
			rel_tport = &tport_grp_desc->rel_tgt_port_entry[0];
			DEBUG5(printk("%s: Next TPG descr data:  tpg_index=%d, "
			    "tpg_desc id=0x%x:0x%x max_port_count=%d, "
			    "tport_grp_desc=%p, rel_tport=%p\n", __func__,
			    tpg_count, tport_grp_desc->tpg_id[0],
			    tport_grp_desc->tpg_id[1], max_port_count,
			    tport_grp_desc, rel_tport));
			if ((ulong) rel_tport >= (ulong) tport_grp_desc_end) {
				DEBUG2(printk("Done\n"));
				break;
			}
			/*
			 * Search our list for this entry and if match update
			 * state info.
			 */
			i = 0;
			list_for_each_safe(list, temp,
			    &mplun->tport_grps_list) {
				tport_grp = list_entry(list, mp_tport_grp_t,
				    list);
				/* matching TPG descriptors */
				if (tport_grp->tpg_id[0] ==
				    tport_grp_desc->tpg_id[0] &&
				    tport_grp->tpg_id[1] ==
				    tport_grp_desc->tpg_id[1]) {
					/* copy the tgt port group state */
					tport_grp->asym_acc_state =
					    tport_grp_desc->state.asym_acc_state;
					DEBUG2(printk("%s Found Matching TPG - "
					    "Updating TPG state =%d for mplun "
					    "%p\n", __func__,
					    tport_grp->asym_acc_state,mplun));
					if (modify) {
						qla2x00_update_lu_path_state(
						    ha, NULL, fclun, tpg_count,
						    &tport_grp->tpg_id[0],
						    tport_grp->asym_acc_state);
					}
				}

				DEBUG2(printk("%s: TPG[%d] : our_tpg[%d]= "
				    "0x%x:0x%x, tpg= 0x%x:0x%x, last rel_tport "
				    "[%p]= 0x%x,0x%x\n", __func__, tpg_count,
				    i, tport_grp->tpg_id[0],
				    tport_grp->tpg_id[1],
				    tport_grp_desc->tpg_id[0],
				    tport_grp_desc->tpg_id[1], rel_tport,
				    rel_tport->rel_port_id[0],
				    rel_tport->rel_port_id[1]));
				i++;
			}

			/* Skip rel ports in the TPG descriptor */
			for (i = 0; i < max_port_count ; i++ , rel_tport++)
				;
			/* next descriptor */
			tport_grp_desc = (tpg_desc_t *) rel_tport;
		}
		rval = 1;
	} else {
		DEBUG2(printk(KERN_INFO "%s Failed to issue Report tgt port"
			" group -- lun (%d) cs=0x%x ss=0x%x, rval=%d\n",
			__func__, lun, comp_status, scsi_status, rval));
		rval = 0;
	}

	dma_free_coherent(&ha->pdev->dev,
	    sizeof(rtpg_param_data_rsp_t) + expected_rtpg_siz, tpg, tpg_dma);

	LEAVE(__func__);

	return rval;
}


#if 0
/*
 * qla2x00_find_mp_dev_by_nn_and_pn
 *      Find the mp_dev for the specified target name.
 *
 * Input:
 *      host = host adapter pointer.
 *      name  = Target name
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t  *
qla2x00_find_mp_dev_by_nn_and_pn(mp_host_t *host,
	uint8_t *portname, uint8_t *nodename)
{
	int id;
	int idx;
	mp_device_t *dp;

	for (id= 0; id < MAX_MP_DEVICES; id++) {
		if ((dp = host->mp_devs[id]) == NULL)
			continue;

		for (idx = 0; idx < MAX_PATHS_PER_DEVICE; idx++) {
			if (memcmp(&dp->nodenames[idx][0], nodename, WWN_SIZE) == 0 &&
				memcmp(&dp->portnames[idx][0], portname, WWN_SIZE) == 0 ) {
					DEBUG3(printk("%s: Found matching device @ index %d:\n",
			    		__func__, id));
					return dp;
			}
		}
	}

	return NULL;
}

/*
 * qla2x00_is_nn_and_pn_in_device
 *      Find the mp_dev for the specified target name.
 *
 * Input:
 *      host = host adapter pointer.
 *      name  = Target name
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t  *
qla2x00_is_nn_and_pn_in_device(mp_device_t *dp,
	uint8_t *portname, uint8_t *nodename)
{
	int idx;

	for (idx = 0; idx < MAX_PATHS_PER_DEVICE; idx++) {
		if (memcmp(&dp->nodenames[idx][0], nodename, WWN_SIZE) == 0 &&
			memcmp(&dp->portnames[idx][0], portname, WWN_SIZE) == 0 ) {
				DEBUG3(printk("%s: Found matching device @ index %d:\n",
			    __func__, id));
				return dp;
		}
	}

	return NULL;
}
#endif

/*
 *  qla2x00_export_target
 *      Look through the existing multipath control tree, and find
 *      an mp_lun_t with the supplied world-wide lun number.  If
 *      one cannot be found, allocate one.
 *
 *  Input:
 *      host      Adapter to add device to.
 *      dev_id    Index of device on adapter.
 *      port      port database information.
 *
 *  Returns:
 *      Pointer to new mp_device_t, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      If the MP HOST does not already point to the mp_device_t,
 *      a pointer is added at the proper port offset.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_export_target(void *vhost, uint16_t dev_id,
	fc_port_t *fcport, uint16_t pathid)
{
	mp_host_t	*host = (mp_host_t *) vhost;
	mp_path_t 	*path;
	mp_device_t *dp = NULL;
	int		names_valid; /* Node name and port name are not zero */
	int		node_found;  /* Found matching node name. */
	int		port_found;  /* Found matching port name. */
	mp_device_t	*temp_dp;
	int		i;
	uint16_t	new_id = dev_id;
	uint16_t	idx;

	DEBUG3(printk("%s(%ld): Entered. host=%p, fcport =%p, dev_id = %d\n",
	    __func__, host->ha->host_no, host, fcport, dev_id));

	temp_dp = qla2x00_find_mp_dev_by_id(host,dev_id);

	/* if Device already known at this port. */
	if (temp_dp != NULL) {
		node_found = qla2x00_is_nodename_equal(temp_dp->nodename,
		    fcport->node_name);
		port_found = qla2x00_is_portname_in_device(temp_dp,
		    fcport->port_name);
		/* found */
		if (node_found && port_found)
			dp = temp_dp;

	}


	/* Sanity check the port information  */
	names_valid = (!qla2x00_is_ww_name_zero(fcport->node_name) &&
	    !qla2x00_is_ww_name_zero(fcport->port_name));

	/*
	 * If the optimized check failed, loop through each known
	 * device on this known adapter looking for the node name.
	 */
	if (dp == NULL && names_valid) {
		if ((temp_dp = qla2x00_find_mp_dev_by_portname(host,
	    		fcport->port_name, &idx)) == NULL) {
			/* find a good index */
			for (i = dev_id; i < MAX_MP_DEVICES; i++)
				if (host->mp_devs[i] == NULL) {
					new_id = i;
					break;
				}
		} else if (temp_dp != NULL) { /* found dp */
			if (qla2x00_is_nodename_equal(temp_dp->nodename,
			    fcport->node_name)) {
				new_id = temp_dp->dev_id;
				dp = temp_dp;
			}
		}
	}

	/* If we couldn't find one, allocate one. */
	if (dp == NULL &&
	    ((fcport->flags & FC_CONFIG) || !mp_config_required)) {

		DEBUG2(printk("%s(%d): No match for WWPN. Creating new mpdev \n"
		"node %02x%02x%02x%02x%02x%02x%02x%02x "
		"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		 __func__, host->instance,
		fcport->node_name[0], fcport->node_name[1],
		fcport->node_name[2], fcport->node_name[3],
		fcport->node_name[4], fcport->node_name[5],
		fcport->node_name[6], fcport->node_name[7],
		fcport->port_name[0], fcport->port_name[1],
		fcport->port_name[2], fcport->port_name[3],
		fcport->port_name[4], fcport->port_name[5],
		fcport->port_name[6], fcport->port_name[7]));
		dp = qla2x00_allocate_mp_dev(fcport->node_name,
		    	fcport->port_name);

		DEBUG2(printk("%s(%ld): (2) mp_dev[%d] update"
		" with dp %p\n ",
		__func__, host->ha->host_no, new_id, dp));
		host->mp_devs[new_id] = dp;
		dp->dev_id = new_id;
		dp->use_cnt++;
	}

	/*
	* We either have found or created a path list. Find this
	* host's path in the path list or allocate a new one
	* and add it to the list.
	*/
	if (dp == NULL) {
		/* We did not create a mp_dev for this port. */
		fcport->mp_byte |= MP_MASK_UNCONFIGURED;
		DEBUG2(printk("%s: Device NOT found or created at "
	    	" dev_id=%d.\n",
	    	__func__, dev_id));
		return 0;
	}

	path = qla2x00_find_or_allocate_path(host, dp, dev_id,
		pathid, fcport);
	if (path == NULL) {
		DEBUG2(printk("%s:Path NOT found or created.\n",
	    	__func__));
		return 0;
	}

	return 1;
}


static int
qla2x00_add_path_to_active_list(mp_lun_t *lun, lu_path_t *lun_path)
{
	struct list_head *list, *temp;
 	lu_path_t   	 *nwlun_path = NULL;
	fc_lun_t	*fclun;
	unsigned long	flags;
	unsigned long	cpu_flags = 0;

	spin_lock_irqsave(&lun->mplock, cpu_flags);
	list_for_each_safe(list, temp, &lun->active_list) {
 		nwlun_path = list_entry(list, lu_path_t, next_active);
		if (nwlun_path == lun_path) {
	DEBUG2(printk("%s: ** Already in active list-lun %d fclun %p pathid=%d loop id %02x -act cnt= %d, dp->lbtype=%d\n",
		__func__,lun_path->fclun->lun,
		lun_path->fclun,lun_path->path_id,lun_path->fclun->fcport->loop_id,lun->act_cnt,lun->dp->lbtype));

			if ((fclun = lun_path->fclun) != NULL) {
				spin_lock(&fclun->fcport->ha->hardware_lock);
				fclun->s_time = 0;
				fclun->io_cnt = 0;
				spin_unlock(&fclun->fcport->ha->hardware_lock);
			}
			spin_unlock_irqrestore(&lun->mplock, cpu_flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&lun->mplock, cpu_flags);

	DEBUG2(printk("%s: +++ Adding lun %d fclun %p pathid=%d loop id %02x... to active list -count %d\n",
		__func__,lun_path->fclun->lun,
		lun_path->fclun,lun_path->path_id,lun_path->fclun->fcport->loop_id,lun->act_cnt));
	spin_lock_irqsave(&lun->mplock, cpu_flags);
	list_add_tail(&lun_path->next_active, &lun->active_list);
	lun->act_cnt++;
	spin_unlock_irqrestore(&lun->mplock, cpu_flags);

	/* reset service time, so it can be retries
	   once it gets restored */
	if ((fclun = lun_path->fclun) != NULL) {
		spin_lock_irqsave(&fclun->fcport->ha->hardware_lock, flags);
		fclun->s_time = 0;
		fclun->io_cnt = 0;
		spin_unlock_irqrestore(&fclun->fcport->ha->hardware_lock, flags);
	}
	return 1;
}

static void
qla2x00_change_active_path(mp_lun_t *lun, fc_lun_t  *fclun, srb_t *sp)
{
	struct list_head *list, *temp;
 	lu_path_t   	 *lun_path;
	fc_lun_t	*tmp_fclun = NULL;
	unsigned long	cpu_flags = 0;

	spin_lock_irqsave(&lun->mplock, cpu_flags);
	list_for_each_safe(list, temp, &lun->active_list) {
		lun_path = list_entry(list, lu_path_t, next_active);
		tmp_fclun = lun_path->fclun;
		if (tmp_fclun != fclun) {
			DEBUG2(printk("%s: -+-+ Changing to fclun %p, path_id=%d, loop_id %02x io_cnt= %ld s_time = %ld ...\n",
			__func__,tmp_fclun,lun_path->path_id,tmp_fclun->fcport->loop_id,
			tmp_fclun->io_cnt,tmp_fclun->s_time));
			sp->lun_queue->fclun = tmp_fclun;
			lun->active = lun_path->path_id;
			break;
		}
	}
	spin_unlock_irqrestore(&lun->mplock, cpu_flags);
}

int
qla2x00_del_fclun_from_active_list(mp_lun_t *lun, fc_lun_t  *fclun, srb_t *sp)
{
	struct list_head *list, *temp;
 	lu_path_t   	 *lun_path;
	unsigned long	cpu_flags = 0;
	int 	switch_paths = 0;

	DEBUG(printk("%s\n",__func__));
	spin_lock_irqsave(&lun->mplock, cpu_flags);
	list_for_each_safe(list, temp, &lun->active_list) {
 		lun_path = list_entry(list, lu_path_t, next_active);
	DEBUG(printk("%s: active list entry: lun %d mplun->fclun %p fclun=%p "
			"pathid=%d loop id %02x... to active list -count %d\n",
		__func__,lun_path->fclun->lun,
		lun_path->fclun,fclun,lun_path->path_id,
		lun_path->fclun->fcport->loop_id,lun->act_cnt));
		if (lun_path->fclun == fclun) {
	DEBUG2(printk("%s: ---- Removing lun %d fclun %p pathid=%d loop id %02x... to active list -count %d\n",
		__func__,lun_path->fclun->lun,
		lun_path->fclun,lun_path->path_id,lun_path->fclun->fcport->loop_id,lun->act_cnt));
			list_del_init(list);
			if (lun->act_cnt > 0)
				lun->act_cnt--;
			switch_paths++;
			break;
		}
	}
	spin_unlock_irqrestore(&lun->mplock, cpu_flags);
	if (switch_paths)
			qla2x00_change_active_path(lun, fclun, sp);
	if (lun->act_cnt == 0)
		return 1;
	return 0;
}

/*
 *  qla2x00_combine_by_lunid
 *      Look through the existing multipath control tree, and find
 *      an mp_lun_t with the supplied world-wide lun number.  If
 *      one cannot be found, allocate one.
 *
 *  Input:
 *      host      Adapter to add device to.
 *      dev_id    Index of device on adapter.
 *      port      port database information.
 *
 *  Returns:
 *      Pointer to new mp_device_t, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      If the MP HOST does not already point to the mp_device_t,
 *      a pointer is added at the proper port offset.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_combine_by_lunid(void *vhost, uint16_t dev_id,
	fc_port_t *fcport, uint16_t pathid)
{
	mp_host_t	*host = (mp_host_t *) vhost;
	int fail = 0;
	mp_path_t 	*path;
	mp_device_t *dp = NULL;
	fc_lun_t	*fclun;
	mp_lun_t  *lun;
	int		names_valid; /* Node name and port name are not zero */
	mp_host_t	*temp_host;  /* pointer to temporary host */
	mp_device_t	*temp_dp;
	mp_port_t	*port;
	mp_tport_grp_t  *tpg;
	lu_path_t	*lu_path = NULL;
	uint16_t	l;

	ENTER("qla2x00_combine_by_lunid");
	DEBUG3(printk("Entering %s\n", __func__));

	/*
	 * Currently, not use because we create common nodename for
	 * the gui, so we can use the normal common namename processing.
	 */
	if (fcport->flags & FC_CONFIG) {
		/* Search for device if not found create one */

		temp_dp = qla2x00_find_mp_dev_by_id(host,dev_id);

		/* if Device already known at this port. */
		if (temp_dp != NULL) {
			DEBUG(printk("%s: Found an existing "
		    	"dp %p-  host %p inst=%d, fcport =%p, path id = %d\n",
		    	__func__, temp_dp, host, host->instance, fcport,
		    	pathid));
			if (qla2x00_is_portname_in_device(temp_dp,
		    		 fcport->port_name)) {

				DEBUG2(printk("%s: mp dev %02x%02x%02x%02x%02x%02x"
			    "%02x%02x exists on %p. dev id %d. path cnt=%d.\n",
			    __func__,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7],
			    temp_dp, dev_id, temp_dp->path_list->path_cnt));
				dp = temp_dp;
			}

		}

		/*
	 	* If the optimized check failed, loop through each known
	 	* device on each known adapter looking for the node name
	 	* and port name.
	 	*/
		if (dp == NULL) {
			/*
			 * Loop through each potential adapter for the
			 * specified target (dev_id). If a device is
			 * found then add this port or use it.
			 */
			for (temp_host = mp_hosts_base; (temp_host);
				temp_host = temp_host->next) {
				/* user specifies the target via dev_id */
				temp_dp = temp_host->mp_devs[dev_id];
				if (temp_dp == NULL) {
					continue;
				}
				if (qla2x00_is_portname_in_device(temp_dp,
		    			fcport->port_name)) {
					dp = temp_dp;
				} else {
					qla2x00_add_portname_to_mp_dev(
				    	temp_dp, fcport->port_name,
					fcport->node_name);
					dp = temp_dp;
					host->mp_devs[dev_id] = dp;
					dp->use_cnt++;
				}
				break;
			}
		}

		/* Sanity check the port information  */
		names_valid = (!qla2x00_is_ww_name_zero(fcport->node_name) &&
	    	!qla2x00_is_ww_name_zero(fcport->port_name));

		if (dp == NULL && names_valid &&
	    	((fcport->flags & FC_CONFIG) || !mp_config_required)) {

			DEBUG2(printk("%s(%ld): No match. adding new mpdev on "
		    	"dev_id %d. node %02x%02x%02x%02x%02x%02x%02x%02x "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no, dev_id,
		    	fcport->node_name[0], fcport->node_name[1],
		    	fcport->node_name[2], fcport->node_name[3],
		    	fcport->node_name[4], fcport->node_name[5],
		    	fcport->node_name[6], fcport->node_name[7],
		    	fcport->port_name[0], fcport->port_name[1],
		    	fcport->port_name[2], fcport->port_name[3],
		    	fcport->port_name[4], fcport->port_name[5],
		    	fcport->port_name[6], fcport->port_name[7]));
			dp = qla2x00_allocate_mp_dev(fcport->node_name,
					fcport->port_name);

			host->mp_devs[dev_id] = dp;
			dp->dev_id = dev_id;
			dp->use_cnt++;
		}

		/*
	 	* We either have found or created a path list. Find this
	 	* host's path in the path list or allocate a new one
	 	* and add it to the list.
	 	*/
		if (dp == NULL) {
			/* We did not create a mp_dev for this port. */
			fcport->mp_byte |= MP_MASK_UNCONFIGURED;
			DEBUG2(printk("%s: Device NOT found or created at "
		    	" dev_id=%d.\n",
		    	__func__, dev_id));
			return 0;
		}

		/*
	 	* Find the path in the current path list, or allocate
	 	* a new one and put it in the list if it doesn't exist.
	 	* Note that we do NOT set bSuccess to 0 in the case
	 	* of failure here.  We must tolerate the situation where
	 	* the customer has more paths to a device than he can
	 	* get into a PATH_LIST.
	 	*/
		path = qla2x00_find_or_allocate_path(host, dp, dev_id,
	    	pathid, fcport);
		if (path == NULL) {
			DEBUG2(printk("%s:Path NOT found or created.\n",
		    	__func__));
			return 0;
		}

		/*
		 * Set the PATH flag to match the device flag of whether this
		 * device needs a relogin.  If any device needs relogin, set
		 * the relogin countdown.
	 	*/
		path->config = 1;
	} else {
		if (mp_initialized && fcport->flags & FC_MSA_DEVICE) {
			 qla2x00_test_active_port(fcport);
		}
		list_for_each_entry(fclun, &fcport->fcluns, list) {
			if (mp_initialized &&
			    fcport->flags & FC_EVA_DEVICE) {
			     qla2x00_test_active_lun(fcport, fclun, NULL);
			}
			lun = qla2x00_find_or_allocate_lun(host, dev_id,
			    fcport, fclun);

			if (lun == NULL) {
				fail++;
				continue;
			}
			/*
 			* Find the path in the current path list, or allocate
 			* a new one and put it in the list if it doesn't exist.
 			*/
			dp = lun->dp;
			if (fclun->mplun == NULL) {
				fclun->mplun = lun;
				lun->asymm_support = fclun->asymm_support;
			}
			path = qla2x00_find_or_allocate_path(host, dp,
			    dp->dev_id, pathid, fcport);
			if (path == NULL || dp == NULL) {
				fail++;
				continue;
			}

			/* set up the path at lun level */
			lu_path = qla2x00_find_or_allocate_lu_path(host,
					fclun, path->id);
			if (lu_path == NULL) {
				fail++;
				continue;
			}

			/* set the lun active flag */
			/* Kludge: HSV210(EVA-AA) reports controller lun as
			 * Disk Type.  Controller lun on HSV210 does not
			 * support TgtPortGrp. Mark this lun as active for OS
			 * to scan beyond Lun Zero.
			 */
			if (mp_initialized &&
			    fcport->flags & (FC_AA_EVA_DEVICE |
				FC_AA_MSA_DEVICE | FC_NVSXXX_DEVICE)) {
			     qla2x00_test_active_lun(path->port, fclun, NULL);
			}

			/* Add fclun to path list */
			if (lun->paths[path->id] == NULL) {
				lun->paths[path->id] = fclun;
				DEBUG2(printk("Updated path[%d]= %p for lun %p\n",
					path->id, fclun, lun));
				lun->path_cnt++;
			}

			/*
			 * if we have a visible lun then make
			 * the target visible as well
			 */
			l = lun->number;
			if (fclun->flags & FLF_VISIBLE_LUN) {
				if (dp->path_list->visible ==
				    PATH_INDEX_INVALID) {
					dp->path_list->visible = path->id;
					DEBUG2(printk("%s: dp %p setting "
					    "visible id to %d\n",
					    __func__,dp,path->id));
				}
				dp->path_list->current_path[l] = path->id;

				path->lun_data.data[l] |=
				    LUN_DATA_PREFERRED_PATH;

				DEBUG2(printk("%s: Found a controller path 0x%x "
				    "- lun %d\n", __func__, path->id,l));
				printk("%s: Found a controller path 0x%x "
				    "- lun %d\n", __func__, path->id,l);
			} else if (mp_initialized && path->config) {
			 	if (path->lun_data.data[l] &
			    		LUN_DATA_PREFERRED_PATH) {
					/*
				 	* If this is not the first path added, if this
				 	* is the preferred path, so make it the
				 	* current path.
				 	*/
					dp->path_list->current_path[l] = path->id;
  					lun->config_pref_id = path->id;
				}
			} else if (mp_initialized &&
				   ((fcport->fo_target_port == NULL))) {
	   			/*
				 * Whenever a port or lun is "active" then
				 * force it to be a preferred path.
 	   			 */
	   			if (qla2x00_find_first_active_path(dp, lun)
					== path) {
	   				dp->path_list->current_path[l] =
					    path->id;
					path->lun_data.data[l] |=
					   LUN_DATA_PREFERRED_PATH;
					DEBUG2(printk(
					"%s: Found (find first) preferred lun at loopid=0x%02x, lun=%d, pathid=%d\n",
	    			__func__, fcport->loop_id, l, path->id));
				} else if (fcport->flags & (FC_MSA_DEVICE
					| FC_EVA_DEVICE)) {
	   				dp->path_list->current_path[l] =
					    0;
					path->lun_data.data[l] |=
					    LUN_DATA_PREFERRED_PATH;
					DEBUG2(printk(
					"%s: Setting first path as preferred lun at loopid=0x%02x, lun=%d, pathid=%d\n",
	    			__func__, fcport->loop_id, l, path->id));
				}
			}

			port = qla2x00_find_or_allocate_port(host, lun, path);
			if (port == NULL) {
				fail++;
				continue;
			}

			if (fcport->fo_target_port) {
			        if ((fcport->fo_target_port ==
						qla2x00_get_target_ports) &&
					(fclun->asymm_support ==
						 TGT_PORT_GRP_UNSUPPORTED)) {
					DEBUG(printk("%s lun = %d does not support"
						" ALUA\n",__func__,fclun->lun));
					printk("%s lun = %d does not support"
						" ALUA\n",__func__,fclun->lun);
					memcpy(&lu_path->rel_tport_id[0], &port->rel_tport_id[0],
					sizeof(port->rel_tport_id));
				} else {
					tpg = qla2x00_find_or_allocate_tgt_port_grp(
							host, port, fclun,path);
					if (tpg == NULL) {
						fail++;
						continue;
					}
					if (lu_path->flags & LPF_TPG_UNKNOWN) {
						memcpy(&lu_path->tpg_id[0], &tpg->tpg_id[0],
						sizeof(tpg->tpg_id));
						memcpy(&lu_path->rel_tport_id[0], &port->rel_tport_id[0],
						sizeof(port->rel_tport_id));
					}
					if (mp_initialized) {
					   /* set the tgt port grp state */
					    fcport->fo_target_port(fcport,fclun,1);
					}
				}
                        }

			/*
			 * create active path list for load balancing:
			 * 	- All paths ACT_OPT and NON_ACT_OPT
			 */
			if (lun->load_balance_type >= LB_LRU) {
				if (!(fclun->flags & FLF_VISIBLE_LUN)) {
					if ((fclun->flags & FLF_ACTIVE_LUN) ||
						fcport->fo_target_port) {
						/* all path s ACT_OPT and NON_ACT_OPT */
						qla2x00_add_path_to_active_list(lun,
						    lu_path);
					}
					if ((lu_path->flags & LPF_TPG_UNKNOWN))
						lu_path->flags &= ~LPF_TPG_UNKNOWN;
				}
			} else {
				/* create active path list for set preferred paths */
				if ((lu_path->flags & LPF_TPG_UNKNOWN) &&
				    !(fclun->flags & FLF_VISIBLE_LUN)) {
					if (fcport->fo_target_port) {
		 				if (lu_path->asym_acc_state ==
						    TPG_ACT_OPT) {
						DEBUG2(printk("%s(%d): Setting "
						    "TPG_ACT_OPT loopid=0x%02x "
						    "lu_path tpg_id=0x%x "
						    "rel_tport_id=0x%x lun=%d "
						    "fclun_flags=%d\n",
						    __func__, host->instance,
						    fclun->fcport->loop_id,
						    lu_path->tpg_id[1],
						    lu_path->rel_tport_id[1],
						    l, fclun->flags));
							qla2x00_add_path_to_active_list(lun,
							    lu_path);
						}
					} else if (fclun->flags & FLF_ACTIVE_LUN) {
						qla2x00_add_path_to_active_list(lun,
						    lu_path);
					}
					lu_path->flags &= ~LPF_TPG_UNKNOWN;

					DEBUG(printk("%s(%d): lu_path tpg_id=0x%x "
					    "rel_tport_id=0x%x lun=%d\n fclun_flags=%d",
					    __func__, host->instance,
					    lu_path->tpg_id[1],
					    lu_path->rel_tport_id[1],l, fclun->flags));
				}
			}

         } /* end of list_for_each_entry() */
	}

	if (fail)
		return 0;
	return 1;
}

#if 0
/*
 *  qla2x00_find_or_allocate_mp_dev
 *      Look through the existing multipath control tree, and find
 *      an mp_device_t with the supplied world-wide node name.  If
 *      one cannot be found, allocate one.
 *
 *  Input:
 *      host      Adapter to add device to.
 *      dev_id    Index of device on adapter.
 *      port      port database information.
 *
 *  Returns:
 *      Pointer to new mp_device_t, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      If the MP HOST does not already point to the mp_device_t,
 *      a pointer is added at the proper port offset.
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t *
qla2x00_find_or_allocate_mp_dev(mp_host_t *host, uint16_t dev_id,
    fc_port_t *port)
{
	mp_device_t	*dp = NULL;  /* pointer to multi-path device   */
	int		node_found;  /* Found matching node name. */
	int		port_found;  /* Found matching port name. */
	int		names_valid; /* Node name and port name are not zero */
	mp_host_t	*temp_host;  /* pointer to temporary host */

	uint16_t	j;
	mp_device_t	*temp_dp;

	ENTER("qla2x00_find_or_allocate_mp_dev");

	DEBUG3(printk("%s(%ld): entered. host=%p, port =%p, dev_id = %d\n",
	    __func__, host->ha->host_no, host, port, dev_id));

	temp_dp = qla2x00_find_mp_dev_by_id(host,dev_id);

	DEBUG3(printk("%s: temp dp =%p\n", __func__, temp_dp));
	/* if Device already known at this port. */
	if (temp_dp != NULL) {
		node_found = qla2x00_is_nodename_equal(temp_dp->nodename,
		    port->node_name);
		port_found = qla2x00_is_portname_in_device(temp_dp,
		    port->port_name);

		if (node_found && port_found) {
			DEBUG3(printk("%s: mp dev %02x%02x%02x%02x%02x%02x"
			    "%02x%02x exists on %p. dev id %d. path cnt=%d.\n",
			    __func__,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7],
			    temp_dp, dev_id, temp_dp->path_list->path_cnt));
			dp = temp_dp;

			/*
			 * Copy the LUN configuration data
			 * into the mp_device_t.
			 */
		}
	}


	/* Sanity check the port information  */
	names_valid = (!qla2x00_is_ww_name_zero(port->node_name) &&
	    !qla2x00_is_ww_name_zero(port->port_name));

	/*
	 * If the optimized check failed, loop through each known
	 * device on each known adapter looking for the node name.
	 */
	if (dp == NULL && names_valid) {
		DEBUG3(printk("%s: Searching each adapter for the device...\n",
		    __func__));

		/* Check for special cases. */
		if (port->flags & FC_CONFIG) {
			/* Here the search is done only for ports that
			 * are found in config file, so we can count on
			 * mp_byte value when binding the paths.
			 */
			DEBUG3(printk("%s(%ld): mpbyte=%02x process configured "
			    "portname=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__, host->ha->host_no, port->mp_byte,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7]));
			DEBUG3(printk("%s(%ld): nodename %02x%02x%02x%02x%02x"
			    "%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->node_name[0], port->node_name[1],
			    port->node_name[2], port->node_name[3],
			    port->node_name[4], port->node_name[5],
			    port->node_name[6], port->node_name[7]));

			if (port->mp_byte == 0) {
				DEBUG3(printk("%s(%ld): port visible.\n",
				    __func__, host->ha->host_no));

				/* This device in conf file is set to visible */
				for (temp_host = mp_hosts_base; (temp_host);
				    temp_host = temp_host->next) {
					/* Search all hosts with given tgt id
					 * for any previously created dp with
					 * matching node name.
					 */
					temp_dp = temp_host->mp_devs[dev_id];
					if (temp_dp == NULL) {
						continue;
					}

					node_found =
					    qla2x00_is_nodename_equal(
					    temp_dp->nodename, port->node_name);

					if (node_found &&
					    qla2x00_found_hidden_path(
					    temp_dp)) {
						DEBUG3(printk(
						    "%s(%ld): found "
						    "mpdev of matching "
						    "node %02x%02x%02x"
						    "%02x%02x%02x%02x"
						    "%02x w/ hidden "
						    "paths. dp=%p "
						    "dev_id=%d.\n",
						    __func__,
						    host->ha->host_no,
						    port->port_name[0],
						    port->port_name[1],
						    port->port_name[2],
						    port->port_name[3],
						    port->port_name[4],
						    port->port_name[5],
						    port->port_name[6],
						    port->port_name[7],
						    temp_dp, dev_id));
						/*
						 * Found the mpdev.
						 * Treat this same as default
						 * case by adding this port
						 * to this mpdev which has same
						 * nodename.
						 */
						qla2x00_add_portname_to_mp_dev(
						    temp_dp, port->port_name, port->node_name);
						dp = temp_dp;
						host->mp_devs[dev_id] = dp;
						dp->use_cnt++;

						break;
					}
				}

			} else if (port->mp_byte & MP_MASK_OVERRIDE) {
				/* Bind on port name */
				DEBUG3(printk(
				    "%s(%ld): port has override bit.\n",
				    __func__, host->ha->host_no));

				temp_dp = qla2x00_find_dp_by_pn_from_all_hosts(
				    port->port_name, &j);

				if (temp_dp) {
					/* Found match */
					DEBUG3(printk("%s(%ld): update mpdev "
					    "on Matching port %02x%02x%02x"
					    "%02x%02x%02x%02x%02x "
					    "dp %p dev_id %d\n",
					    __func__, host->ha->host_no,
					    port->port_name[0],
					    port->port_name[1],
					    port->port_name[2],
					    port->port_name[3],
					    port->port_name[4],
					    port->port_name[5],
					    port->port_name[6],
					    port->port_name[7],
					    temp_dp, j));
					/*
					 * Bind this port to this mpdev of the
					 * matching port name.
					 */
					dp = temp_dp;
					host->mp_devs[j] = dp;
					dp->use_cnt++;
				}
			} else {
				DEBUG3(printk("%s(%ld): default case.\n",
				    __func__, host->ha->host_no));
				/* Default case. Search and bind/add this
				 * port to the mp_dev with matching node name
				 * if it is found.
				 */
				dp = qla2x00_default_bind_mpdev(host, port);
			}

		} else {
			DEBUG3(printk("%s(%ld): process discovered port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7]));
			DEBUG3(printk("%s(%ld): nodename %02x%02x%02x%02x%02x"
			    "%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->node_name[0], port->node_name[1],
			    port->node_name[2], port->node_name[3],
			    port->node_name[4], port->node_name[5],
			    port->node_name[6], port->node_name[7]));

			/* Here we try to find the mp_dev pointer for the
			 * current port in the current host, which would
			 * have been created if the port was specified in
			 * the config file.  To be sure the mp_dev we found
			 * really is for the current port, we check the
			 * node name to make sure it matches also.
			 * When we find a previously created mp_dev pointer
			 * for the current port, just return the pointer.
			 * We proceed to add this port to an mp_dev of
			 * the matching node name only if it is not found in
			 * the mp_dev list already created and ConfigRequired
			 * is not set.
			 */
			temp_dp = qla2x00_find_mp_dev_by_portname(host,
			    port->port_name, &j);

			if (temp_dp && qla2x00_is_nodename_equal(
			    temp_dp->nodename, port->node_name)) {
				/* Found match. This mpdev port was created
				 * from config file entry.
				 */
				DEBUG3(printk("%s(%ld): update mpdev "
				    "on Matching port %02x%02x%02x"
				    "%02x%02x%02x%02x%02x "
				    "dp %p dev_id %d\n",
				    __func__, host->ha->host_no,
				    port->port_name[0],
				    port->port_name[1],
				    port->port_name[2],
				    port->port_name[3],
				    port->port_name[4],
				    port->port_name[5],
				    port->port_name[6],
				    port->port_name[7],
				    temp_dp, j));

				dp = temp_dp;
			} else if (!mp_config_required) {

				DEBUG3(printk("%s(%ld): default case.\n",
				    __func__, host->ha->host_no));
				/* Default case. Search and bind/add this
				 * port to the mp_dev with matching node name
				 * if it is found.
				 */
				dp = qla2x00_default_bind_mpdev(host, port);
			}
		}
	}

	/* If we couldn't find one, allocate one. */
	if (dp == NULL &&
	    ((port->flags & FC_CONFIG) || !mp_config_required)) {

		DEBUG3(printk("%s(%ld): No match. adding new mpdev on "
		    "dev_id %d. node %02x%02x%02x%02x%02x%02x%02x%02x "
		    "port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    __func__, host->ha->host_no, dev_id,
		    port->node_name[0], port->node_name[1],
		    port->node_name[2], port->node_name[3],
		    port->node_name[4], port->node_name[5],
		    port->node_name[6], port->node_name[7],
		    port->port_name[0], port->port_name[1],
		    port->port_name[2], port->port_name[3],
		    port->port_name[4], port->port_name[5],
		    port->port_name[6], port->port_name[7]));
		dp = qla2x00_allocate_mp_dev(port->node_name, port->port_name);

#ifdef QL_DEBUG_LEVEL_2
		if (host->mp_devs[dev_id] != NULL) {
			printk(KERN_WARNING
			    "qla2x00: invalid/unsupported configuration found. "
			    "overwriting target id %d.\n",
			    dev_id);
		}
#endif
		host->mp_devs[dev_id] = dp;
		dp->dev_id = dev_id;
		dp->use_cnt++;
	}

	DEBUG3(printk("%s(%ld): exiting. return dp=%p.\n",
	    __func__, host->ha->host_no, dp));
	LEAVE("qla2x00_find_or_allocate_mp_dev");

	return dp;
}
#endif

/*
 * qla2x00_default_bind_mpdev
 *
 * Input:
 *	host = mp_host of current adapter
 *	port = fc_port of current port
 *
 * Returns:
 *	mp_device pointer
 *	NULL - not found.
 *
 * Context:
 *	Kernel context.
 */
static inline mp_device_t *
qla2x00_default_bind_mpdev(mp_host_t *host, fc_port_t *port)
{
	/* Default search case */
	int		devid = 0;
	mp_device_t	*temp_dp = NULL;  /* temporary pointer */
	mp_host_t	*temp_host;  /* temporary pointer */

	DEBUG3(printk("%s: entered.\n", __func__));

	for (temp_host = mp_hosts_base; (temp_host);
	    temp_host = temp_host->next) {
		for (devid = 0; devid < MAX_MP_DEVICES; devid++) {
			temp_dp = temp_host->mp_devs[devid];

			if (temp_dp == NULL)
				continue;

			if (qla2x00_is_nodename_equal(temp_dp->nodename,
			    port->node_name)) {
				DEBUG3(printk(
				    "%s: Found matching dp @ host %p id %d:\n",
				    __func__, temp_host, devid));
				break;
			}
		}
		if (temp_dp != NULL) {
			/* found a match. */
			break;
		}
	}

	if (temp_dp) {
		DEBUG3(printk("%s(%ld): update mpdev "
		    "on Matching node at dp %p. "
		    "dev_id %d adding new port %p-%02x"
		    "%02x%02x%02x%02x%02x%02x%02x\n",
		    __func__, host->ha->host_no,
		    temp_dp, devid, port,
		    port->port_name[0], port->port_name[1],
		    port->port_name[2], port->port_name[3],
		    port->port_name[4], port->port_name[5],
		    port->port_name[6], port->port_name[7]));

		if (!qla2x00_is_portname_in_device(temp_dp,
		    port->port_name)) {
		qla2x00_add_portname_to_mp_dev(temp_dp,
			    port->port_name, port->node_name);
		}

		/*
		 * Set the flag that we have
		 * found the device.
		 */
		host->mp_devs[devid] = temp_dp;
		temp_dp->use_cnt++;

		/* Fixme(dg)
		 * Copy the LUN info into
		 * the mp_device_t
		 */
	}

	return (temp_dp);
}

/*
 *  qla2x00_find_or_allocate_mp_dev
 *      Look through the existing multipath control tree, and find
 *      an mp_device_t with the supplied world-wide node name.  If
 *      one cannot be found, allocate one.
 *
 *  Input:
 *      host      Adapter to add device to.
 *      dev_id    Index of device on adapter.
 *      port      port database information.
 *
 *  Returns:
 *      Pointer to new mp_device_t, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      If the MP HOST does not already point to the mp_device_t,
 *      a pointer is added at the proper port offset.
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t *
qla2x00_find_or_allocate_mp_dev(mp_host_t *host, uint16_t dev_id,
    fc_port_t *port)
{
	mp_device_t	*dp = NULL;  /* pointer to multi-path device   */
	uint8_t		node_found;  /* Found matching node name. */
	uint8_t		port_found;  /* Found matching port name. */
	uint8_t		names_valid; /* Node name and port name are not zero */
	mp_host_t	*temp_host;  /* pointer to temporary host */

	uint16_t	j;
	mp_device_t	*temp_dp;

	ENTER("qla2x00_find_or_allocate_mp_dev");

	DEBUG3(printk("%s(%ld): entered. host=%p, port =%p, dev_id = %d\n",
	    __func__, host->ha->host_no, host, port, dev_id));

	temp_dp = qla2x00_find_mp_dev_by_id(host,dev_id);

	DEBUG3(printk("%s: temp dp =%p\n", __func__, temp_dp));
	/* if Device already known at this port. */
	if (temp_dp != NULL) {
		node_found = qla2x00_is_nodename_equal(temp_dp->nodename,
		    port->node_name);
		port_found = qla2x00_is_portname_in_device(temp_dp,
		    port->port_name);

		if (node_found && port_found) {
			DEBUG3(printk("%s: mp dev %02x%02x%02x%02x%02x%02x"
			    "%02x%02x exists on %p. dev id %d. path cnt=%d.\n",
			    __func__,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7],
			    temp_dp, dev_id, temp_dp->path_list->path_cnt));
			dp = temp_dp;

			/*
			 * Copy the LUN configuration data
			 * into the mp_device_t.
			 */
		}
	}

	/* Sanity check the port information  */
	names_valid = (!qla2x00_is_ww_name_zero(port->node_name) &&
	    !qla2x00_is_ww_name_zero(port->port_name));

	/*
	 * If the optimized check failed, loop through each known
	 * device on each known adapter looking for the node name.
	 */
	if (dp == NULL && names_valid) {
		DEBUG3(printk("%s: Searching each adapter for the device...\n",
		    __func__));

		/* Check for special cases. */
		if (port->flags & FC_CONFIG) {
			/* Here the search is done only for ports that
			 * are found in config file, so we can count on
			 * mp_byte value when binding the paths.
			 */
			DEBUG3(printk("%s(%ld): mpbyte=%02x process configured "
			    "portname=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__, host->ha->host_no, port->mp_byte,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7]));
			DEBUG3(printk("%s(%ld): nodename %02x%02x%02x%02x%02x"
			    "%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->node_name[0], port->node_name[1],
			    port->node_name[2], port->node_name[3],
			    port->node_name[4], port->node_name[5],
			    port->node_name[6], port->node_name[7]));

			if (port->mp_byte == 0) {
				DEBUG3(printk("%s(%ld): port visible.\n",
				    __func__, host->ha->host_no));

				/* This device in conf file is set to visible */
				for (temp_host = mp_hosts_base; (temp_host);
				    temp_host = temp_host->next) {
					/* Search all hosts with given tgt id
					 * for any previously created dp with
					 * matching node name.
					 */
					temp_dp = temp_host->mp_devs[dev_id];
					if (temp_dp == NULL) {
						continue;
					}

					node_found =
					    qla2x00_is_nodename_equal(
					    temp_dp->nodename, port->node_name);

					if (node_found &&
					    qla2x00_found_hidden_path(
					    temp_dp)) {
						DEBUG3(printk(
						    "%s(%ld): found "
						    "mpdev of matching "
						    "node %02x%02x%02x"
						    "%02x%02x%02x%02x"
						    "%02x w/ hidden "
						    "paths. dp=%p "
						    "dev_id=%d.\n",
						    __func__,
						    host->ha->host_no,
						    port->port_name[0],
						    port->port_name[1],
						    port->port_name[2],
						    port->port_name[3],
						    port->port_name[4],
						    port->port_name[5],
						    port->port_name[6],
						    port->port_name[7],
						    temp_dp, dev_id));
						/*
						 * Found the mpdev.
						 * Treat this same as default
						 * case by adding this port
						 * to this mpdev which has same
						 * nodename.
						 */
					if (!qla2x00_is_portname_in_device(
					    temp_dp, port->port_name)) {
						qla2x00_add_portname_to_mp_dev(
						    temp_dp, port->port_name,
						    port->node_name);
					}

						dp = temp_dp;
						host->mp_devs[dev_id] = dp;
						dp->use_cnt++;

						break;
					} else {
						port->flags |=
						    FC_FAILOVER_DISABLE;
					}
				}

			} else if (port->mp_byte & MP_MASK_OVERRIDE) {
				/* Bind on port name */
				DEBUG3(printk(
				    "%s(%ld): port has override bit.\n",
				    __func__, host->ha->host_no));

				temp_dp = qla2x00_find_dp_by_pn_from_all_hosts(
				    port->port_name, &j);

				if (temp_dp) {
					/* Found match */
					DEBUG3(printk("%s(%ld): update mpdev "
					    "on Matching port %02x%02x%02x"
					    "%02x%02x%02x%02x%02x "
					    "dp %p dev_id %d\n",
					    __func__, host->ha->host_no,
					    port->port_name[0],
					    port->port_name[1],
					    port->port_name[2],
					    port->port_name[3],
					    port->port_name[4],
					    port->port_name[5],
					    port->port_name[6],
					    port->port_name[7],
					    temp_dp, j));
					/*
					 * Bind this port to this mpdev of the
					 * matching port name.
					 */
					dp = temp_dp;
					host->mp_devs[j] = dp;
					dp->use_cnt++;
				}
			} else {
				DEBUG3(printk("%s(%ld): default case.\n",
				    __func__, host->ha->host_no));
				/* Default case. Search and bind/add this
				 * port to the mp_dev with matching node name
				 * if it is found.
				 */
				dp = qla2x00_default_bind_mpdev(host, port);
			}

		} else {
			DEBUG3(printk("%s(%ld): process discovered port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7]));
			DEBUG3(printk("%s(%ld): nodename %02x%02x%02x%02x%02x"
			    "%02x%02x%02x.\n",
			    __func__, host->ha->host_no,
			    port->node_name[0], port->node_name[1],
			    port->node_name[2], port->node_name[3],
			    port->node_name[4], port->node_name[5],
			    port->node_name[6], port->node_name[7]));

			/* Here we try to find the mp_dev pointer for the
			 * current port in the current host, which would
			 * have been created if the port was specified in
			 * the config file.  To be sure the mp_dev we found
			 * really is for the current port, we check the
			 * node name to make sure it matches also.
			 * When we find a previously created mp_dev pointer
			 * for the current port, just return the pointer.
			 * We proceed to add this port to an mp_dev of
			 * the matching node name only if it is not found in
			 * the mp_dev list already created and ConfigRequired
			 * is not set.
			 */
			temp_dp = qla2x00_find_mp_dev_by_portname(host,
			    port->port_name, &j);

			if (temp_dp && qla2x00_is_nodename_equal(
			    temp_dp->nodename, port->node_name)) {
				/* Found match. This mpdev port was created
				 * from config file entry.
				 */
				DEBUG3(printk("%s(%ld): found mpdev "
				    "created for current port %02x%02x%02x"
				    "%02x%02x%02x%02x%02x "
				    "dp %p dev_id %d\n",
				    __func__, host->ha->host_no,
				    port->port_name[0],
				    port->port_name[1],
				    port->port_name[2],
				    port->port_name[3],
				    port->port_name[4],
				    port->port_name[5],
				    port->port_name[6],
				    port->port_name[7],
				    temp_dp, j));

				dp = temp_dp;
			} else if (!mp_config_required) {

				DEBUG3(printk("%s(%ld): default case.\n",
				    __func__, host->ha->host_no));
				/* Default case. Search and bind/add this
				 * port to the mp_dev with matching node name
				 * if it is found.
				 */
				dp = qla2x00_default_bind_mpdev(host, port);
			}
		}
	}

	/* If we couldn't find one, allocate one. */
	if (dp == NULL &&
	    ((port->flags & FC_CONFIG) || !mp_config_required)) {

		DEBUG3(printk("%s(%ld): No match. adding new mpdev on "
		    "dev_id %d. node %02x%02x%02x%02x%02x%02x%02x%02x "
		    "port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    __func__, host->ha->host_no, dev_id,
		    port->node_name[0], port->node_name[1],
		    port->node_name[2], port->node_name[3],
		    port->node_name[4], port->node_name[5],
		    port->node_name[6], port->node_name[7],
		    port->port_name[0], port->port_name[1],
		    port->port_name[2], port->port_name[3],
		    port->port_name[4], port->port_name[5],
		    port->port_name[6], port->port_name[7]));
		dp = qla2x00_allocate_mp_dev(port->node_name, port->port_name);

#ifdef QL_DEBUG_LEVEL_2
		if (host->mp_devs[dev_id] != NULL) {
			printk(KERN_WARNING
			    "qla2x00: invalid/unsupported configuration found. "
			    "overwriting target id %d.\n",
			    dev_id);
		}
#endif
		host->mp_devs[dev_id] = dp;
		dp->dev_id = dev_id;
		dp->use_cnt++;
	}

	DEBUG3(printk("%s(%ld): exiting. return dp=%p.\n",
	    __func__, host->ha->host_no, dp));
	LEAVE("qla2x00_find_or_allocate_mp_dev");

	return dp;
}


/*
 *  qla2x00_find_or_allocate_path
 *      Look through the path list for the supplied device, and either
 *      find the supplied adapter (path) for the adapter, or create
 *      a new one and add it to the path list.
 *
 *  Input:
 *      host      Adapter (path) for the device.
 *      dp       Device and path list for the device.
 *      dev_id    Index of device on adapter.
 *      port     Device data from port database.
 *
 *  Returns:
 *      Pointer to new PATH, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      1. If the PATH_LIST does not already point to the PATH,
 *         a new PATH is added to the PATH_LIST.
 *      2. If the new path is found to be a second visible path, it is
 *         marked as hidden, and the device database is updated to be
 *         hidden as well, to keep the miniport synchronized.
 *
 * Context:
 *      Kernel context.
 */
/* ARGSUSED */
static mp_path_t *
qla2x00_find_or_allocate_path(mp_host_t *host, mp_device_t *dp,
    uint16_t dev_id, uint16_t pathid, fc_port_t *port)
{
	mp_path_list_t	*path_list = dp->path_list;
	mp_path_t		*path;
	uint8_t			id;


	ENTER("qla2x00_find_or_allocate_path");

	DEBUG4(printk("%s: host =%p, port =%p, dp=%p, dev id = %d\n",
	    __func__, host, port, dp, dev_id));
	/*
	 * Loop through each known path in the path list.  Look for
	 * a PATH that matches both the adapter and the port name.
	 */
	path = qla2x00_find_path_by_name(host, path_list, port->port_name);


	if (path != NULL) {
		DEBUG3(printk("%s: Found an existing "
		    "path %p-  host %p inst=%d, port =%p, path id = %d\n",
		    __func__, path, host, host->instance, path->port,
		    path->id));
		DEBUG3(printk("%s: Luns for path_id %d, instance %d\n",
		    __func__, path->id, host->instance));
		DEBUG3(qla2x00_dump_buffer(
		    (char *)&path->lun_data.data[0], 64));

		/* If we found an existing path, look for any changes to it. */
		if (path->port == NULL) {
			DEBUG3(printk("%s: update path %p w/ port %p, path id="
			    "%d, path mp_byte=0x%x port mp_byte=0x%x.\n",
			    __func__, path, port, path->id,
			    path->mp_byte, port->mp_byte));
			path->port = port;
			port->mp_byte = path->mp_byte;
		} else {
			DEBUG3(printk("%s: update path %p port %p path id %d, "
			    "path mp_byte=0x%x port mp_byte=0x%x.\n",
			    __func__, path, path->port, path->id,
			    path->mp_byte, port->mp_byte));

			if ((path->mp_byte & MP_MASK_HIDDEN) &&
			    !(port->mp_byte & MP_MASK_HIDDEN)) {

				DEBUG3(printk("%s: Adapter(%p) "
				    "Device (%p) Path (%d) "
				    "has become visible.\n",
				    __func__, host, dp, path->id));

				path->mp_byte &= ~MP_MASK_HIDDEN;
			}

			if (!(path->mp_byte & MP_MASK_HIDDEN) &&
			    (port->mp_byte & MP_MASK_HIDDEN)) {

				DEBUG3(printk("%s(%ld): Adapter(%p) "
				    "Device (%p) Path (%d) "
				    "has become hidden.\n",
				    __func__, host->ha->host_no, host,
				    dp, path->id));

				path->mp_byte |= MP_MASK_HIDDEN;
			}
		}

	} else {
		/*
		 * If we couldn't find an existing path, and there is still
		 * room to add one, allocate one and put it in the list.
		 */
		if (path_list->path_cnt < MAX_PATHS_PER_DEVICE &&
			path_list->path_cnt < qla_fo_params.MaxPathsPerDevice) {

			if (port->flags & FC_CONFIG) {
				/* Use id specified in config file. */
				id = pathid;
				DEBUG3(printk("%s(%ld): using path id %d from "
				    "config file.\n",
				    __func__, host->ha->host_no, id));
			} else {
				/* Assign one. */
				id = path_list->path_cnt;
				DEBUG3(printk(
				    "%s(%ld): assigning path id %d.\n",
				    __func__, host->ha->host_no, id));
			}

			/* Update port with bitmask info */
			path = qla2x00_allocate_path(host, id, port, dev_id);
			if (path) {
#if defined(QL_DEBUG_LEVEL_3)
				printk("%s: allocated new path %p, adding path "
				    "id %d, mp_byte=0x%x\n", __func__, path,
				    id, path->mp_byte);
				if (path->port)
					printk("port=%p-"
					   "%02x%02x%02x%02x%02x%02x%02x%02x\n",
					   path->port,
					   path->port->port_name[0],
					   path->port->port_name[1],
					   path->port->port_name[2],
					   path->port->port_name[3],
					   path->port->port_name[4],
					   path->port->port_name[5],
					   path->port->port_name[6],
					   path->port->port_name[7]);
#endif
				qla2x00_add_path(path_list, path);

				/*
				 * Reconcile the new path against the existing
				 * ones.
				 */
				qla2x00_setup_new_path(dp, path, port);
			}
		} else {
			/* EMPTY */
			DEBUG4(printk("%s: Err exit, no space to add path.\n",
			    __func__));
		}

	}

	LEAVE("qla2x00_find_or_allocate_path");

	return path;
}

static lu_path_t *
qla2x00_find_or_allocate_lu_path(mp_host_t *host, fc_lun_t *fclun,
	uint16_t pathid)
{
	mp_lun_t		*mplun = NULL;
	struct list_head	*list, *temp;
	lu_path_t		*lu_path = NULL;
	fc_port_t		*fcport = fclun->fcport;

	DEBUG3(printk("%s entered\n",__func__));

	if (fclun->mplun == NULL) {
		DEBUG(printk("%s mplun does not exist for fclun=%p\n",
				__func__,fclun));
		goto failed;
	}
	mplun = fclun->mplun;
	/*
	 * Loop through each known path in the lun_path list.  Look for
	 * a PATH that matches fclun. */
	list_for_each_safe(list, temp, &mplun->lu_paths) {
		lu_path = list_entry(list, lu_path_t, list);
		if (lu_path->fclun == fclun) {
			DEBUG2(printk("%s found an existing path lu_path=%p"
					" lu_path_id=%d fclun=%p\n",__func__,
					lu_path, lu_path->path_id, fclun));
			goto found_lu_path;
		}
	}

	lu_path = kmalloc(sizeof(lu_path_t), GFP_KERNEL);
	if (lu_path == NULL) {
		DEBUG4(printk("%s: Failed\n", __func__));
		goto failed;
	}
	memset(lu_path, 0, sizeof(*lu_path));

	DEBUG(printk("%s(%ld): allocated lu_path %p at path id lun=%d %d.\n",
	    __func__, host->ha->host_no, lu_path, pathid, fclun->lun));

	/* Copy the supplied information into the lu_path. */
	lu_path->host = host;
	lu_path->hba_instance = host->instance;
	lu_path->path_id = pathid;
	lu_path->fclun = fclun;
	lu_path->flags = LPF_TPG_UNKNOWN;
	fclun->path_id = pathid;
	memcpy(lu_path->portname, fcport->port_name, WWN_SIZE);
	list_add_tail(&lu_path->list,&mplun->lu_paths);

	DEBUG3(printk("%s(%ld): path id %d copied portname "
	    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, host->ha->host_no, pathid,
	    fcport->port_name[0], fcport->port_name[1],
	    fcport->port_name[2], fcport->port_name[3],
	    fcport->port_name[4], fcport->port_name[5],
	    fcport->port_name[6], fcport->port_name[7]));

	DEBUG3(printk("%s leaving\n",__func__));

found_lu_path :
	return lu_path;
failed :
	return NULL;

}

static mp_device_t  *
qla2x00_find_dp_from_all_hosts(uint8_t *nn)
{
	mp_device_t		*temp_dp = NULL;
	mp_host_t	*temp_host;  /* temporary pointer */

	DEBUG3(printk("%s: entered.\n", __func__));

	for (temp_host = mp_hosts_base; (temp_host);
	    temp_host = temp_host->next) {
		temp_dp = qla2x00_find_mp_dev_by_nodename(temp_host, nn);
		if (temp_dp) {
			return temp_dp;
		}
	}

	DEBUG3(printk("%s: exiting.\n", __func__));

	return temp_dp;
}
/*
 *  qla2x00_find_or_allocate_lun
 *      Look through the existing multipath control tree, and find
 *      an mp_lun_t with the supplied world-wide lun number.  If
 *      one cannot be found, allocate one.
 *
 *  Input:
 *      host      Adapter (lun) for the device.
 *      fclun     Lun data from port database.
 *
 *  Returns:
 *      Pointer to new LUN, or NULL if the allocation fails.
 *
 *  Side Effects:
 *      1. If the LUN_LIST does not already point to the LUN,
 *         a new LUN is added to the LUN_LIST.
 *      2. If the DEVICE_LIST does not already point to the DEVICE,
 *         a new DEVICE is added to the DEVICE_LIST.
 *
 * Context:
 *      Kernel context.
 */
/* ARGSUSED */
static mp_lun_t *
qla2x00_find_or_allocate_lun(mp_host_t *host, uint16_t dev_id,
    fc_port_t *port, fc_lun_t *fclun)
{
	mp_lun_t		*lun = NULL;
	mp_device_t		*dp = NULL;
	mp_device_t		*temp_dp = NULL;
	uint16_t		len;
	uint16_t		idx;
	uint16_t		new_id = dev_id;
	char			wwulnbuf[WWULN_SIZE];
	int			new_dev = 0;
	int			i;


	ENTER("qla2x00_find_or_allocate_lun");
	DEBUG(printk("Entering %s\n", __func__));

	if (fclun == NULL)
		return NULL;

	DEBUG2(printk("%s: "
		    " lun num=%d fclun %p mplun %p hba inst=%d, port =%p, dev id = %d\n",
		    __func__, fclun->lun, fclun, fclun->mplun, host->instance, port,
		    dev_id));
	/*
	 * Perform inquiry page 83 to get the wwuln or
	 * use what was specified by the user.
	 */
	if ((port->flags & FC_CONFIG)) {
			if ((len = fclun->mplen) != 0)
				memcpy(wwulnbuf, fclun->mpbuf, len);
	} else {
		len = qla2x00_get_wwuln_from_device(host, fclun,
			&wwulnbuf[0], WWULN_SIZE, NULL, NULL);
		/* if fail to do the inq then exit */
		if (len == 0) {
			return lun;
		}
	}

	if (len != 0)
		lun = qla2x00_find_matching_lunid(wwulnbuf);

	/*
	 * If this is a visible "controller" lun and
	 * it is already exists on somewhere world wide
 	 * then allocate a new device, so it can be
	 * exported it to the OS.
	 */
	if ((fclun->flags & FLF_VISIBLE_LUN) &&
		lun != NULL) {
		if (fclun->mplun == NULL) {
			lun = NULL;
			new_dev++;
		DEBUG2(printk("%s: Creating visible lun "
		    "lun %p num %d fclun %p mplun %p inst=%d, port =%p, dev id = %d\n",
		    __func__, lun, fclun->lun, fclun, fclun->mplun, host->instance, port,
		    dev_id));
		} else {
			lun = fclun->mplun;
			return lun;
		}
	}
	else if ((lun == NULL) && ql2xmap2actpath &&
	    (((port->flags & FC_MSA_DEVICE) &&
		!(port->flags & FC_MSA_PORT_ACTIVE)) ||
	      ((port->flags & FC_EVA_DEVICE) &&
	   	!(fclun->flags & FLF_ACTIVE_LUN)))) {
		DEBUG2(printk("%s: Skipping MSA/EVA lun "
		    "lun %p num %d fclun %p mplun %p inst=%d, port =%p, dev id = %d\n",
		    __func__, lun, fclun->lun, fclun, fclun->mplun, host->instance, port,
		    dev_id));
		return NULL;
	}

	if (lun != NULL) {
		DEBUG(printk("%s: Found an existing "
		    "lun %p num %d fclun %p host %p inst=%d, port =%p, dev id = %d\n",
		    __func__, lun, fclun->lun, fclun, host, host->instance, port,
		    dev_id));
		if ((dp = lun->dp) == NULL) {
			printk("NO dp pointer in alloacted lun\n");
			return NULL;
		}
		DEBUG(printk("%s(%ld): lookup portname for lun->dp = "
		    	"dev_id %d. dp=%p node %02x%02x%02x%02x%02x%02x%02x%02x "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no, dp->dev_id, dp,
		    	port->node_name[0], port->node_name[1],
		    	port->node_name[2], port->node_name[3],
		    	port->node_name[4], port->node_name[5],
		    	port->node_name[6], port->node_name[7],
		    	port->port_name[0], port->port_name[1],
		    	port->port_name[2], port->port_name[3],
		    	port->port_name[4], port->port_name[5],
		    	port->port_name[6], port->port_name[7]));

#if 1
		if (qla2x00_is_portname_in_device(dp,
		    port->port_name)) {

				DEBUG(printk("%s: Found portname %02x%02x%02x%02x%02x%02x"
			    "%02x%02x match in mp_dev[%d] = %p\n",
			    __func__,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7],
			    dp->dev_id, dp));
			if (host->mp_devs[dp->dev_id] == NULL) {
				host->mp_devs[dp->dev_id] = dp;
				dp->use_cnt++;
			}
		} else {
			DEBUG(printk("%s(%ld): MP_DEV no-match on portname. adding new port - "
		    	"dev_id %d. node %02x%02x%02x%02x%02x%02x%02x%02x "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no, dev_id,
		    	port->node_name[0], port->node_name[1],
		    	port->node_name[2], port->node_name[3],
		    	port->node_name[4], port->node_name[5],
		    	port->node_name[6], port->node_name[7],
		    	port->port_name[0], port->port_name[1],
		    	port->port_name[2], port->port_name[3],
		    	port->port_name[4], port->port_name[5],
		    	port->port_name[6], port->port_name[7]));

			qla2x00_add_portname_to_mp_dev(dp,
		    	port->port_name, port->node_name);

			DEBUG2(printk("%s(%ld): (1) Added portname and mp_dev[%d] update"
		    	" with dp %p\n ",
		    	__func__, host->ha->host_no, dp->dev_id, dp));
			for (i = dev_id; i < MAX_MP_DEVICES; i++)
				if (host->mp_devs[i] == NULL) {
					new_id = i;
					break;
			  	}
			if (host->mp_devs[dp->dev_id] == NULL) {
				host->mp_devs[dp->dev_id] = dp;
				dp->use_cnt++;
			} else if (host->mp_devs[dp->dev_id] != dp) {
				DEBUG2(printk("%s(%d) Targets coming up in "
				    "different order, using a new slot: "
				    "old_dev_id=%d old_dp=%p new_dev_id=%d "
				    "new_dp=%p\n", __func__, host->instance,
				    dp->dev_id,  host->mp_devs[dp->dev_id],
				    new_id, dp));
				host->mp_devs[new_id] = dp;
				dp->use_cnt++;
			}
		}
#else
		if ((temp_dp = qla2x00_find_mp_dev_by_portname(host,
			    	port->port_name, &idx)) == NULL) {
			DEBUG(printk("%s(%ld): MP_DEV no-match on portname. adding new port on "
		    	"dev_id %d. node %02x%02x%02x%02x%02x%02x%02x%02x "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no, dev_id,
		    	port->node_name[0], port->node_name[1],
		    	port->node_name[2], port->node_name[3],
		    	port->node_name[4], port->node_name[5],
		    	port->node_name[6], port->node_name[7],
		    	port->port_name[0], port->port_name[1],
		    	port->port_name[2], port->port_name[3],
		    	port->port_name[4], port->port_name[5],
		    	port->port_name[6], port->port_name[7]));

			qla2x00_add_portname_to_mp_dev(dp,
		    	port->port_name, port->node_name);

			DEBUG(printk("%s(%ld): (1) Added portname and mp_dev[%d] update"
		    	" with dp %p\n ",
		    	__func__, host->ha->host_no, dp->dev_id, dp));
			if (host->mp_devs[dp->dev_id] == NULL) {
				host->mp_devs[dp->dev_id] = dp;
				dp->use_cnt++;
			}
		} else if (dp == temp_dp) {
			DEBUG3(printk("%s(%ld): MP_DEV %p match with portname @ "
		    	" mp_dev[%d]. "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no, temp_dp, idx,
		    	port->port_name[0], port->port_name[1],
		    	port->port_name[2], port->port_name[3],
		    	port->port_name[4], port->port_name[5],
		    	port->port_name[6], port->port_name[7]));

			host->mp_devs[idx] = temp_dp;
			dp->use_cnt++;
		}
#endif
	} else {
		DEBUG(printk("%s: MP_lun %d not found "
		    "for fclun %p inst=%d, port =%p, dev id = %d\n",
		    __func__, fclun->lun, fclun, host->instance, port,
		    dev_id));

			if ((dp = qla2x00_find_mp_dev_by_portname(host,
			    	port->port_name, &idx)) == NULL || new_dev) {
				DEBUG2(printk("%s(%ld): No match for WWPN. Creating new mpdev \n"
		    	"node %02x%02x%02x%02x%02x%02x%02x%02x "
		    	"port %02x%02x%02x%02x%02x%02x%02x%02x\n",
		    	__func__, host->ha->host_no,
		    	port->node_name[0], port->node_name[1],
		    	port->node_name[2], port->node_name[3],
		    	port->node_name[4], port->node_name[5],
		    	port->node_name[6], port->node_name[7],
		    	port->port_name[0], port->port_name[1],
		    	port->port_name[2], port->port_name[3],
		    	port->port_name[4], port->port_name[5],
		    	port->port_name[6], port->port_name[7]));
			dp = qla2x00_allocate_mp_dev(port->node_name,
						port->port_name);
			if (dp == NULL) {
				return lun;
			}
			if (ql2xlbType != 0 && ql2xlbType <= LB_LST) {
				dp->lbtype = ql2xlbType;
			}
			DEBUG2(printk(KERN_INFO "scsi%ld: Setting "
		    	"lbType=%d\n", host->ha->host_no, dp->lbtype));
			/* find a good index */
			for (i = dev_id; i < MAX_MP_DEVICES; i++)
				if (host->mp_devs[i] == NULL) {
					new_id = i;
					break;
				}
			} else if (dp != NULL) { /* found dp */
				new_id = dp->dev_id;
				DEBUG2(printk("%s: 2. Found portname already in device %02x%02x%02x%02x%02x%02x"
			    "%02x%02x match in mp_dev[%d] = %p\n",
			    __func__,
			    port->port_name[0], port->port_name[1],
			    port->port_name[2], port->port_name[3],
			    port->port_name[4], port->port_name[5],
			    port->port_name[6], port->port_name[7],
			    dp->dev_id, dp));
			}

			/*
			 * if we have a controller lun then assign it to a different dev
			 * and point to the failover dev as well by nodename matching.
			 */
 			if (ql2xtgtemul && (fclun->flags & FLF_VISIBLE_LUN)) {
				DEBUG2(printk("%s(%ld): (2) mp_dev[%d] Setting dev IGNORE flag."
		    		" dp %p , new_dev = %d\n ",
		    		__func__, host->ha->host_no, new_id, dp, new_dev));
				temp_dp = qla2x00_find_dp_from_all_hosts(port->node_name);
				/* bind together for old GUI */
				if (temp_dp) {
					dp->mpdev = temp_dp;
				DEBUG2(printk("%s: 10. Found nodename %02x%02x%02x%02x%02x%02x"
			    "%02x%02x already in mp_dev[%d] = %p - binding.\n",
			    __func__,
			    port->node_name[0], port->node_name[1],
			    port->node_name[2], port->node_name[3],
			    port->node_name[4], port->node_name[5],
			    port->node_name[6], port->node_name[7],
			    temp_dp->dev_id, temp_dp));
				}
			}

			if (dp != NULL) {
			DEBUG2(printk("%s(%ld): (2) mp_dev[%d] update"
		    	" with dp %p\n ",
		    	__func__, host->ha->host_no, new_id, dp));
				host->mp_devs[new_id] = dp;
				dp->dev_id = new_id;
				dp->use_cnt++;
				lun = kmalloc(sizeof(mp_lun_t), GFP_KERNEL);
				if (lun != NULL) {
					memset(lun, 0, sizeof(*lun));
					DEBUG(printk("Added lun %p to dp %p lun number %d\n",
					lun, dp, fclun->lun));
					DEBUG(qla2x00_dump_buffer(wwulnbuf, len));
					memcpy(lun->wwuln, wwulnbuf, len);
					lun->siz = len;
					lun->number = fclun->lun;
					lun->dp = dp;
					qla2x00_add_lun(dp, lun);
					INIT_LIST_HEAD(&lun->ports_list);
					INIT_LIST_HEAD(&lun->lu_paths);
					INIT_LIST_HEAD(&lun->active_list);
				    	INIT_LIST_HEAD(&lun->tport_grps_list);
					spin_lock_init(&lun->mplock);
 					lun->pref_path_id = PATH_INDEX_INVALID;
					lun->config_pref_id =
					    PATH_INDEX_INVALID;
					lun->act_cnt = 0;
					lun->active = 0;
					lun->load_balance_type =
						    dp->lbtype;
				}
			} else
				printk(KERN_WARNING
			    	"qla2x00: Couldn't get memory for dp. \n");
	}

	DEBUG(printk("Exiting %s\n", __func__));
	LEAVE("qla2x00_find_or_allocate_lun");

	return lun;
}


static uint32_t
qla2x00_cfg_register_failover_lun(mp_device_t *dp, srb_t *sp, fc_lun_t *new_lp)
{
	uint32_t	status = QLA_SUCCESS;
	os_tgt_t	*tq;
	os_lun_t	*lq;
	fc_lun_t 	*old_lp;

	DEBUG2(printk(KERN_INFO "%s: NEW fclun = %p, sp = %p\n",
	    __func__, new_lp, sp));

	/*
	 * Fix lun descriptors to point to new fclun which is a new fcport.
	 */
	if (new_lp == NULL) {
		DEBUG2(printk(KERN_INFO "%s: Failed new lun %p\n",
		    __func__, new_lp));
		return QLA_FUNCTION_FAILED;
	}

	tq = sp->tgt_queue;
	lq = sp->lun_queue;
	if (tq == NULL) {
		DEBUG2(printk(KERN_INFO "%s: Failed to get old tq %p\n",
		    __func__, tq));
		return QLA_FUNCTION_FAILED;
	}
	if (lq == NULL) {
		DEBUG2(printk(KERN_INFO "%s: Failed to get old lq %p\n",
		    __func__, lq));
		return QLA_FUNCTION_FAILED;
	}
	old_lp = lq->fclun;
	lq->fclun = new_lp;

	/* Log the failover to console */
	printk(KERN_INFO
		"qla2x00: FAILOVER device %d from "
		"%02x%02x%02x%02x%02x%02x%02x%02x -> "
		"%02x%02x%02x%02x%02x%02x%02x%02x - "
		"LUN %02x, reason=0x%x\n",
		dp->dev_id,
		old_lp->fcport->port_name[0], old_lp->fcport->port_name[1],
		old_lp->fcport->port_name[2], old_lp->fcport->port_name[3],
		old_lp->fcport->port_name[4], old_lp->fcport->port_name[5],
		old_lp->fcport->port_name[6], old_lp->fcport->port_name[7],
		new_lp->fcport->port_name[0], new_lp->fcport->port_name[1],
		new_lp->fcport->port_name[2], new_lp->fcport->port_name[3],
		new_lp->fcport->port_name[4], new_lp->fcport->port_name[5],
		new_lp->fcport->port_name[6], new_lp->fcport->port_name[7],
		new_lp->lun, sp->err_id);
	printk(KERN_INFO
		"qla2x00: FROM HBA %d to HBA %d\n",
		(int)old_lp->fcport->ha->instance,
		(int)new_lp->fcport->ha->instance);

	DEBUG3(printk("%s: NEW fclun = %p , port =%p, "
	    "loop_id =0x%x, instance %ld\n",
	    __func__,
	    new_lp, new_lp->fcport,
	    new_lp->fcport->loop_id,
	    new_lp->fcport->ha->instance));

	return status;
}


/*
 * qla2x00_send_failover_notify
 *      A failover operation has just been done from an old path
 *      index to a new index.  Call lower level driver
 *      to perform the failover notification.
 *
 * Inputs:
 *      device           Device being failed over.
 *      lun                LUN being failed over.
 *      newpath           path that was failed over too.
 *      oldpath           path that was failed over from.
 *
 * Return:
 *      Local function status code.
 *
 * Context:
 *      Kernel context.
 */
/* ARGSUSED */
static uint32_t
qla2x00_send_failover_notify(mp_device_t *dp,
    uint16_t lun, mp_path_t *newpath, mp_path_t *oldpath)
{
	fc_lun_t	*old_lp, *new_lp;
	uint32_t	status = QLA_SUCCESS;

	ENTER("qla2x00_send_failover_notify");

	if ((old_lp = qla2x00_find_matching_lun(lun, dp, oldpath)) == NULL) {
		DEBUG2(printk(KERN_INFO "%s: Failed to get old lun %p, %d\n",
		    __func__, old_lp,lun));
		return QLA_FUNCTION_FAILED;
	}
	if ((new_lp = qla2x00_find_matching_lun(lun, dp, newpath)) == NULL) {
		DEBUG2(printk(KERN_INFO "%s: Failed to get new lun %p,%d\n",
		    __func__, new_lp,lun));
		return QLA_FUNCTION_FAILED;
	}

	/*
	 * If the target is the same target, but a new HBA has been selected,
	 * send a third party logout if required.
	 */
	if ((qla_fo_params.FailoverNotifyType &
			 FO_NOTIFY_TYPE_LOGOUT_OR_LUN_RESET ||
			qla_fo_params.FailoverNotifyType &
			 FO_NOTIFY_TYPE_LOGOUT_OR_CDB) &&
			qla2x00_is_portname_equal(
				oldpath->portname, newpath->portname)) {

		status = qla2x00_send_fo_notification(old_lp, new_lp);
		if (status == QLA_SUCCESS) {
			/* EMPTY */
			DEBUG4(printk("%s: Logout succeded\n",
			    __func__));
		} else {
			/* EMPTY */
			DEBUG4(printk("%s: Logout Failed\n",
			    __func__));
		}
	} else if ((qla_fo_params.FailoverNotifyType &
			 FO_NOTIFY_TYPE_LUN_RESET) ||
			(qla_fo_params.FailoverNotifyType &
			 FO_NOTIFY_TYPE_LOGOUT_OR_LUN_RESET)) {

		/*
		 * If desired, send a LUN reset as the
		 * failover notification type.
		 */
		if (newpath->lun_data.data[lun] & LUN_DATA_ENABLED) {
			status = qla2x00_send_fo_notification(old_lp, new_lp);
			if (status == QLA_SUCCESS) {
				/* EMPTY */
				DEBUG4(printk("%s: LUN reset succeeded.\n",
				    __func__));
			} else {
				/* EMPTY */
				DEBUG4(printk("%s: Failed reset LUN.\n",
				    __func__));
			}
		}

	} else if (qla_fo_params.FailoverNotifyType == FO_NOTIFY_TYPE_CDB ||
			qla_fo_params.FailoverNotifyType ==
			FO_NOTIFY_TYPE_LOGOUT_OR_CDB) {

		if (newpath->lun_data.data[lun] & LUN_DATA_ENABLED) {
			status = qla2x00_send_fo_notification(old_lp, new_lp);
			if (status == QLA_SUCCESS) {
				/* EMPTY */
				DEBUG4(printk("%s: Send CDB succeeded.\n",
				    __func__));
			} else {
				/* EMPTY */
				DEBUG4(printk("%s: Send CDB Error "
				    "lun=(%d).\n", __func__, lun));
			}
		}
	} else if (qla_fo_params.FailoverNotifyType == FO_NOTIFY_TYPE_SPINUP ||
			old_lp->fcport->notify_type == FO_NOTIFY_TYPE_SPINUP) {

			status = qla2x00_send_fo_notification(old_lp, new_lp);
			if (status == QLA_SUCCESS) {
				/* EMPTY */
				DEBUG(printk("%s: Send CDB succeeded.\n",
				    __func__));
			} else {
				/* EMPTY */
				DEBUG(printk("%s: Send CDB Error "
				    "lun=(%d).\n", __func__, lun));
			}
	} else if (qla_fo_params.FailoverNotifyType == FO_NOTIFY_TYPE_TPGROUP_CDB ||
                   old_lp->fcport->notify_type == FO_NOTIFY_TYPE_TPGROUP_CDB) {

			status = qla2x00_send_fo_notification(old_lp, new_lp);
			if (status == QLA_SUCCESS) {
				DEBUG(printk("%s: Set Tgt Port Group CDB succeeded.\n",
					__func__));
			} else {
				DEBUG(printk("%s: Set Tgt Port Group CDB Error "
                                                "lun=(%d).\n", __func__, lun));
			}

	 } else {
		/* EMPTY */
		DEBUG4(printk("%s: failover disabled or no notify routine "
		    "defined.\n", __func__));
	}

	return status;
}

static mp_path_t *
qla2x00_find_host_from_port(mp_device_t *dp,
		mp_host_t *host,
		mp_port_t *port)
{
	unsigned long	instance;
	uint8_t 	id;
	int		i;
	mp_path_t	*path = NULL;

	/* get next host instance */
	instance = host->instance;
	for (i = 0 ; i < port->cnt ; i++) {
		instance = instance + 1;
		DEBUG3(printk("%s: Finding new instance %d, max %d, cnt %d\n",
			__func__, (int)instance, port->cnt, i));
		/* Handle wrap-around */
		if (instance == port->cnt)
			instance = 0;
		if (port->hba_list[instance] == NULL)
			continue;
		if (port->hba_list[instance] != host->ha)
			break;
	}
	/* Found a different hba then return the path to it */
	if (i != port->cnt) {
		id = port->path_list[instance];
		DEBUG2(printk("%s: Changing to new host - pathid=%d\n",
			__func__, id));
		path = qla2x00_find_path_by_id(dp, id);
		/* Make sure this is a good port */
		if (path) {
			if (atomic_read(&path->port->state) ==
			    FCS_DEVICE_DEAD) {
				DEBUG2(printk("qla(%d) %s - Port (0x%04x) "
				    "DEAD.\n", path->host->instance, __func__,
				    path->port->loop_id));
				path = NULL;
			}
		}
	}
	return (path);
}

static inline mp_tport_grp_t *
qla2x00_find_tgt_port_grp_by_state(mp_lun_t *mplun, uint8_t asym_acc_state)
{
        mp_tport_grp_t  *tport_grp = NULL, *tmp_tpg;
	struct list_head *list, *temp;

	list_for_each_safe(list, temp, &mplun->tport_grps_list) {
		tmp_tpg = list_entry(list, mp_tport_grp_t, list);
               if (tmp_tpg->asym_acc_state == asym_acc_state) {
                       tport_grp = tmp_tpg;
			break;
		}
	}
	return tport_grp;
}

/*
 * Find_best_port
 * This routine tries to locate the best port to the target that
 * doesn't require issuing a target notify command.
 */
/* ARGSUSED */
static mp_path_t *
qla2x00_find_best_port(mp_device_t *dp,
		mp_path_t *orig_path,
		mp_port_t *port,
		fc_lun_t *fclun)
{
	mp_path_t	*path = NULL;
	mp_path_t	*new_path;
	mp_port_t	*temp_port;
	int		i;
	fc_lun_t 	*new_fp;
	struct list_head *list, *temp;
	mp_lun_t *mplun = (mp_lun_t *)fclun->mplun;
	unsigned long	instance;
	uint16_t	id;

	list_for_each_safe(list, temp, &mplun->ports_list) {
		temp_port = list_entry(list, mp_port_t, list);
		if (port == temp_port) {
			continue;
		}
		/* Search for an active matching lun on any HBA,
		   but starting with the orig HBA */
		instance = orig_path->host->instance;
		for (i = 0 ; i < temp_port->cnt ; instance++) {
			if (instance == MAX_HOSTS)
				instance = 0;
			id = temp_port->path_list[instance];
			DEBUG(printk(
			"qla%d %s: i=%d, Checking temp port=%p, pathid=%d\n",
				(int)instance,__func__, i, temp_port, id));
			if (id == PATH_INDEX_INVALID)
				continue;
			i++; /* found a valid hba entry */
			new_fp = mplun->paths[id];
			DEBUG(printk(
			"qla%d %s: Checking fclun %p, for pathid=%d\n",
				(int)instance,__func__, new_fp, id));
			if (new_fp == NULL)
				continue;
			new_path = qla2x00_find_path_by_id(dp, id);
			if (new_path != NULL) {
			DEBUG(printk(
			"qla%d %s: Found new path new_fp=%p, "
			"path=%p, flags=0x%x\n",
				(int)new_path->host->instance,__func__, new_fp,
				new_path, new_path->port->flags));


			if (atomic_read(&new_path->port->state) ==
			    FCS_DEVICE_DEAD) {
				DEBUG2(printk("qla(%d) %s - Port (0x%04x) "
				    "DEAD.\n", (int)new_path->host->instance,
				    __func__, new_path->port->loop_id));
				continue;
			}

			/* Is this path on an active controller? */
			if ((new_path->port->flags & FC_EVA_DEVICE)  &&
	   			!(new_fp->flags & FLF_ACTIVE_LUN)) {
			 DEBUG2(printk("qla(%d) %s - EVA Port (0x%04x) INACTIVE.\n",
			(int)new_path->host->instance, __func__,
			new_path->port->loop_id));
				continue;
			}

			if ((new_path->port->flags & FC_MSA_DEVICE)  &&
       			   !(new_path->port->flags & FC_MSA_PORT_ACTIVE)) {
			 DEBUG2(printk("qla(%d) %s - MSA Port (0x%04x) INACTIVE.\n",
			(int)new_path->host->instance, __func__,
			new_path->port->loop_id));
				continue;
			}
			/* Is this path on the same active controller? */
			/* FixME:Luns on the same Tgt port grp have the same asym access state */
			if (new_path->port->fo_target_port) {
				lu_path_t *new_lu_path;
				/* find lu_path for the current fclun */
				new_lu_path = qla2x00_find_lu_path_by_id(mplun,new_fp->path_id);
				if (new_lu_path->asym_acc_state != TPG_ACT_OPT) {
					 DEBUG(printk("qla(%d) %s - Port (0x%04x)"
						" does not belong to the active tgt port grp.\n",
						(int)new_path->host->instance, __func__,
						new_path->port->loop_id));
					continue;
				} else {
					DEBUG2(printk("qla(%d) %s - Port (0x%04x) Found path %d belonging"
						   " to the active tgt port grp\n",
						(int)new_path->host->instance,__func__,
						 new_path->port->loop_id,new_lu_path->path_id));
				}
			}

			/* found a good path */
			DEBUG2(printk("qla%d %s: *** Changing from port %p to "
			    "new port %p - pathid=%d\n", (int)instance,
			    __func__, port, temp_port, new_path->id));

			 return (new_path);
			}
		}
	}

	return (path);
}

int
qla2x00_find_all_active_fcports(uint16_t lun)
{
	scsi_qla_host_t *ha;
	fc_port_t *fcport;
	fc_lun_t *fclun;
	uint8_t		wait_for_transition = 1;
	int	bad = 0;

	DEBUG2(printk(KERN_INFO
	    "%s: Scanning for active ports...\n", __func__));

	read_lock(&qla_hostlist_lock);
	list_for_each_entry(ha, &qla_hostlist, list) {
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_TARGET)
				continue;

			if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
			    atomic_read(&fcport->ha->loop_state) == LOOP_DEAD)
				continue;

			if (fcport->flags & (FC_EVA_DEVICE | FC_MSA_DEVICE)) {
				list_for_each_entry(fclun, &fcport->fcluns,
				    list) {
					if (fclun->flags & FLF_VISIBLE_LUN)
						continue;
					if (lun != fclun->lun)
						continue;

					qla2x00_test_active_lun(fcport, fclun, NULL);
				}
			}
			if ((fcport->flags & FC_MSA_DEVICE))
				qla2x00_test_active_port(fcport);
			 /* FixMe - Add support for devices which support tgt port grp ??*/
			if (fcport->fo_target_port) {
				DEBUG(printk("%s(%ld) issue report tgt port group\n",__func__,ha->host_no));
				list_for_each_entry(fclun, &fcport->fcluns,
				    list) {
					if (fclun->flags & FLF_VISIBLE_LUN)
						continue;
					if (lun != fclun->lun)
						continue;

					/* For DSXXX device do a quick check to see if
					 * implicit failover is taking place.
					 */
					if (wait_for_transition) {
						if (qla2x00_wait_for_tpg_ready(fclun)
							== QLA_FUNCTION_FAILED) {
						DEBUG2(printk("%s(%ld) lun=%d"
							"Waiting for transition state - failed\n",
								__func__,ha->host_no, lun));
							bad =1;
							break;  /* don't waste time on the other luns */
						}
						wait_for_transition = 0;
					}

                                        /* set the tgt port grp state */
					fcport->fo_target_port(fcport, fclun, 1);
				}
			}
		}
	}
	read_unlock(&qla_hostlist_lock);

	DEBUG2(printk(KERN_INFO
	    "%s: Done Scanning ports...\n", __func__));
	return bad;
}

void
qla2x00_find_all_active_ports(srb_t *sp)
{
	scsi_qla_host_t *ha;
	fc_port_t *fcport;
	fc_lun_t *fclun;
	uint16_t lun;
	uint8_t		wait_for_transition = 1;

	DEBUG2(printk(KERN_INFO
	    "%s: Scanning for active ports...\n", __func__));

	lun = sp->lun_queue->fclun->lun;

	read_lock(&qla_hostlist_lock);
	list_for_each_entry(ha, &qla_hostlist, list) {
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_TARGET)
				continue;

			if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
			    atomic_read(&fcport->ha->loop_state) == LOOP_DEAD)
				continue;

			if (fcport->flags & (FC_EVA_DEVICE | FC_MSA_DEVICE)) {
				list_for_each_entry(fclun, &fcport->fcluns,
				    list) {
					if (fclun->flags & FLF_VISIBLE_LUN)
						continue;
					if (lun != fclun->lun)
						continue;

					qla2x00_test_active_lun(fcport, fclun, NULL);
				}
			}
			if ((fcport->flags & FC_MSA_DEVICE))
				qla2x00_test_active_port(fcport);
			 /* FixMe - Add support for devices which support tgt port grp ??*/
			if (fcport->fo_target_port) {
				DEBUG(printk("%s(%ld) issue report tgt port group\n",__func__,ha->host_no));
				list_for_each_entry(fclun, &fcport->fcluns,
				    list) {
					if (fclun->flags & FLF_VISIBLE_LUN)
						continue;
					if (lun != fclun->lun)
						continue;

					/* For DSXXX device do a quick check to see if
					 * implicit failover is taking place.
					 */
					if ((fcport->flags & (FC_DSXXX_DEVICE|
					    		FC_AA_MSA_DEVICE))
						&& wait_for_transition) {
						if (qla2x00_wait_for_tpg_ready(fclun)
							== QLA_FUNCTION_FAILED) {
						DEBUG2(printk("%s(%ld) lun=%d"
							"Waiting for transition state - failed\n",
								__func__,ha->host_no, lun));
							break;  /* don't waste time on the other luns */
						}
						wait_for_transition = 0;
					}

                                        /* set the tgt port grp state */
					if (fcport->flags & FC_AA_MSA_DEVICE)
						fcport->fo_target_port(fcport, fclun, 0);
					else
						fcport->fo_target_port(fcport, fclun, 1);
				}
			}
		}
	}
	read_unlock(&qla_hostlist_lock);

	DEBUG2(printk(KERN_INFO
	    "%s: Done Scanning ports...\n", __func__));
}

/*
 * qla2x00_smart_failover
 *      This routine tries to be smart about how it selects the
 *	next path. It selects the next path base on whether the
 *	loop went down or the port went down. If the loop went
 *	down it will select the next HBA. Otherwise, it will select
 *	the next port.
 *
 * Inputs:
 *      device           Device being failed over.
 *      sp               Request that initiated failover.
 *      orig_path           path that was failed over from.
 *
 * Return:
 *      next path	next path to use.
 *	flag 		1 - Don't send notify command
 *	 		0 - Send notify command
 *
 * Context:
 *      Kernel context.
 */
/* ARGSUSED */
static mp_path_t *
qla2x00_smart_path(mp_device_t *dp,
	mp_path_t *orig_path, srb_t *sp, int *flag)
{
	mp_path_t	*path = NULL;
	fc_lun_t *fclun;
	mp_port_t *port;
	mp_host_t *host= orig_path->host;

	DEBUG2(printk("Entering %s - sp err = %d, instance =%d\n",
		__func__, sp->err_id, (int)host->instance));

	qla2x00_find_all_active_ports(sp);

	if (sp != NULL) {
		fclun = sp->lun_queue->fclun;
		if (fclun == NULL) {
			printk( KERN_INFO
			"scsi%d %s: couldn't find fclun %p pathid=%d\n",
				(int)host->instance,__func__, fclun, orig_path->id);
			return (orig_path->next);
		}
		port = qla2x00_find_port_by_name(
			(mp_lun_t *)fclun->mplun, orig_path);
		if (port == NULL) {
			printk( KERN_INFO
			"scsi%d %s: couldn't find MP port %p pathid=%d\n",
				(int)host->instance,__func__, port, orig_path->id);
			return (orig_path->next);
		}

		/* Change to next HOST if loop went down */
		if (sp->err_id == SRB_ERR_LOOP) {
			path = qla2x00_find_host_from_port(dp,
					host, port);
			if (path != NULL) {
				port->fo_cnt++;
				*flag = 1;
		  		/* if we used all the hbas then
			   	try and get another port */
		  		if (port->fo_cnt > port->cnt) {
					port->fo_cnt = 0;
					*flag = 0;
					path =
					  qla2x00_find_best_port(dp,
						orig_path, port, fclun);
					if (path)
						*flag = 1;
		   		}
			}
		} else {
			path = qla2x00_find_best_port(dp,
				orig_path, port, fclun);
			if (path)
				*flag = 1;
		}
	}
	/* Default path is next path*/
	if (path == NULL)
		path = orig_path->next;

	DEBUG3(printk("Exiting %s\n", __func__));
	return path;
}

void
qla2x00_flush_failover_target(scsi_qla_host_t *ha, os_tgt_t *tq)
{
	os_lun_t	*lq;
	uint16_t	l;

	for (l = 0; l < ha->max_luns; l++) {
		if ((lq = (os_lun_t *) tq->olun[l]) == NULL)
			continue;
		qla2x00_flush_failover_q(ha, lq);
       }
}

/*
 *  qla2x00_select_next_path
 *      A problem has been detected with the current path for this
 *      device.  Try to select the next available path as the current
 *      path for this device.  If there are no more paths, the same
 *      path will still be selected.
 *
 *  Inputs:
 *      dp           pointer of device structure.
 *      lun                LUN to failover.
 *
 *  Return Value:
 *      	new path or same path
 *
 * Context:
 *      Kernel context.
 */
static mp_path_t *
qla2x00_select_next_path(mp_host_t *host, mp_device_t *dp, uint16_t lun,
	srb_t *sp)
{
	mp_path_t	*path = NULL;
	mp_path_list_t	*path_list;
	mp_path_t	*orig_path;
	uint16_t	id;
	uint32_t	status;
	mp_host_t *new_host;
	int	skip_notify = 0;
	fc_port_t	*fcport;
  	scsi_qla_host_t *vis_ha;
	fc_lun_t	*new_fp = NULL;


	ENTER("qla2x00_select_next_path:");

	path_list = dp->path_list;
	if (path_list == NULL)
		return NULL;

	/* Get current path */
	id = path_list->current_path[lun];

	/* Get path for current path id  */
	if ((orig_path = qla2x00_find_path_by_id(dp, id)) != NULL) {
		/* select next path */
		 /* FixMe - Add support for devices which
			support tgt port grp ??*/
       		if ((fcport = orig_path->port) != NULL) {
		    path = orig_path->next;
			/* if path cnt == 1 and MSA device then see if
			we can fix it by sending a notify  */
		    if ((fcport->flags & (FC_MSA_DEVICE |
					 FC_EVA_DEVICE)) &&
			!mp_initialized &&
			path_list->path_cnt == 1) {
			if (!qla2x00_test_active_port(fcport))  {
				path = orig_path;
				/* flush all for this target */
				vis_ha =
			    	(scsi_qla_host_t *)sp->cmd->device->host->hostdata;
				qla2x00_flush_failover_target(
					vis_ha, sp->tgt_queue);
				qla2x00_spinup(fcport->ha,
						fcport, lun);
		    		skip_notify = 1;
			}
		    }
		    if (!skip_notify && ((fcport->flags &
		    		(FC_MSA_DEVICE|FC_EVA_DEVICE)) ||
			fcport->fo_target_port)) {
			path = qla2x00_smart_path(dp, orig_path, sp,
			    &skip_notify);
		    }
		} else
			path = orig_path->next;

		new_host = path->host;

		/* FIXME may need to check for HBA being reset */
		DEBUG3(printk("%s: lun %d orig path = %p new path = %p "
		    "curr idx = %d, new idx = %d, skip_notify=%d\n",
		    __func__, lun, orig_path, path, orig_path->id, path->id,
		    skip_notify));
		DEBUG3(printk("  FAILOVER: device nodename: "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    dp->nodename[0], dp->nodename[1],
		    dp->nodename[2], dp->nodename[3],
		    dp->nodename[4], dp->nodename[5],
		    dp->nodename[6], dp->nodename[7]));
		DEBUG3(printk(" Original  - host nodename: "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    orig_path->host->nodename[0],
		    orig_path->host->nodename[1],
		    orig_path->host->nodename[2],
		    orig_path->host->nodename[3],
		    orig_path->host->nodename[4],
		    orig_path->host->nodename[5],
		    orig_path->host->nodename[6],
		    orig_path->host->nodename[7]));
		DEBUG3(printk("   portname: "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    orig_path->port->port_name[0],
		    orig_path->port->port_name[1],
		    orig_path->port->port_name[2],
		    orig_path->port->port_name[3],
		    orig_path->port->port_name[4],
		    orig_path->port->port_name[5],
		    orig_path->port->port_name[6],
		    orig_path->port->port_name[7]));
		DEBUG3(printk(" New  - host nodename: "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    new_host->nodename[0], new_host->nodename[1],
		    new_host->nodename[2], new_host->nodename[3],
		    new_host->nodename[4], new_host->nodename[5],
		    new_host->nodename[6], new_host->nodename[7]));
		DEBUG3(printk("   portname: "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    path->port->port_name[0],
		    path->port->port_name[1],
		    path->port->port_name[2],
		    path->port->port_name[3],
		    path->port->port_name[4],
		    path->port->port_name[5],
		    path->port->port_name[6],
		    path->port->port_name[7]));

		path_list->current_path[lun] = path->id;
		if (path != orig_path) {
			if (path->port) {
				if (path->port->flags & FC_AA_MSA_DEVICE) {
					new_fp = qla2x00_find_matching_lun(lun,
					    dp, path);
					if (new_fp != NULL) {
						/*
						 * Check lun before issuing
						 * reset
						 */
						if (qla2x00_test_active_lun(
						    path->port, new_fp,
						    NULL)) {
							DEBUG2(printk(KERN_INFO
							    "scsi(%ld:0x%x:%d) "
							    "sending reset "
							    "lun\n",
							    path->port->ha->host_no,
							    path->port->loop_id, lun));
							qla2x00_lun_reset(
							    path->port->ha,
							    path->port, lun);
						}
					}
				}
				if (!skip_notify) {
					status = qla2x00_send_failover_notify(
					    dp, lun, path, orig_path);
				}
			}
		}
	}

	LEAVE("qla2x00_select_next_path:");

	return  path ;
}


/*
 *  qla2x00_update_mp_host
 *      Update the multipath control information from the port
 *      database for that adapter.
 *
 *  Input:
 *      host      Adapter to update. Devices that are new are
 *                      known to be attached to this adapter.
 *
 *  Returns:
 *      1 if updated successfully; 0 if error.
 *
 */
static uint8_t
qla2x00_update_mp_host(mp_host_t  *host)
{
	uint8_t		success = 1;
	uint16_t	dev_id;
	fc_port_t 	*fcport;
	scsi_qla_host_t *ha = host->ha;
	int		order;
	mp_device_t	*temp_dp;
	mp_lun_t 	*lun;

	ENTER("qla2x00_update_mp_host");

	/*
	 * We make sure each port is attached to some virtual device.
	 */
	dev_id = 0;
	fcport = NULL;
 	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;

		DEBUG3(printk("%s(%ld): checking fcport list. update port "
		    "%p-%02x%02x%02x%02x%02x%02x%02x%02x dev_id %d "
		    "to ha inst %ld.\n",
		    __func__, ha->host_no,
		    fcport,
		    fcport->port_name[0], fcport->port_name[1],
		    fcport->port_name[2], fcport->port_name[3],
		    fcport->port_name[4], fcport->port_name[5],
		    fcport->port_name[6], fcport->port_name[7],
		    dev_id, ha->instance));

		qla2x00_configure_cfg_device(fcport);
		success |= qla2x00_update_mp_device(host, fcport, dev_id, 0);
		dev_id++;
	}
	if (mp_initialized) {
		for (dev_id = 0; dev_id < MAX_MP_DEVICES; dev_id++) {
			temp_dp = host->mp_devs[dev_id];

			if (temp_dp == NULL)
				continue;

			for (order = 0, lun = temp_dp->luns; lun != NULL ;
				lun = lun->next, order++) {
  				if (lun->config_pref_id != PATH_INDEX_INVALID) {
					qla2x00_chg_lun_to_preferred_path(ha, lun, lun->config_pref_id);
 					qla2x00_set_preferred_path(lun, order, 1);
  				} else
 					qla2x00_set_preferred_path(lun, order, 0);
			}
		}
	}

	if (success) {
		DEBUG2(printk(KERN_INFO "%s: Exit OK\n", __func__));
		qla2x00_map_os_targets(host);
	} else {
		/* EMPTY */
		DEBUG2(printk(KERN_INFO "%s: Exit FAILED\n", __func__));
	}

	DEBUG2(printk("%s: inst %ld exiting.\n", __func__, ha->instance));
	LEAVE("qla2x00_update_mp_host");

	return success;
}

/*
 *  qla2x00_update_mp_device
 *      Update the multipath control information from the port
 *      database for that adapter.
 *
 *  Inputs:
 *		host   Host adapter structure
 *      port   Device to add to the path tree.
 *		dev_id  Device id
 *
 *  Synchronization:
 *      The Adapter Lock should have already been acquired
 *      before calling this routine.
 *
 *  Return
 *      1 if updated successfully; 0 if error.
 *
 */
uint8_t
qla2x00_update_mp_device(mp_host_t *host,
    fc_port_t *port, uint16_t dev_id, uint16_t pathid)
{
	uint8_t		success = 1;
	mp_device_t *dp;
	mp_path_t  *path;

	ENTER("qla2x00_update_mp_device");

	DEBUG3(printk("%s(%ld): entered. host %p inst=%d, port =%p-%02x%02x"
	    "%02x%02x%02x%02x%02x%02x, dev id = %d\n",
	    __func__, host->ha->host_no, host, host->instance, port,
	    port->port_name[0], port->port_name[1],
	    port->port_name[2], port->port_name[3],
	    port->port_name[4], port->port_name[5],
	    port->port_name[6], port->port_name[7],
	    dev_id));

	if (!qla2x00_is_ww_name_zero(port->port_name)) {
		if (port->fo_combine) {
			return (port->fo_combine(host, dev_id, port, pathid));
		}

		/* Only export tape devices */
		if (port->flags & FC_TAPE_PRESENT) {
			return qla2x00_export_target(host, dev_id, port, pathid);
		}

		/*
		 * Search for a device with a matching node name,
		* portname or create one.
		 */
		dp = qla2x00_find_or_allocate_mp_dev(host, dev_id, port);

		/*
		 * We either have found or created a path list. Find this
		 * host's path in the path list or allocate a new one
		 * and add it to the list.
		 */
		if (dp == NULL) {
			/* We did not create a mp_dev for this port. */
			port->mp_byte |= MP_MASK_UNCONFIGURED;
			DEBUG4(printk("%s: Device NOT found or created at "
			    " dev_id=%d.\n",
			    __func__, dev_id));
			return 0;
		}

		/*
		 * Find the path in the current path list, or allocate
		 * a new one and put it in the list if it doesn't exist.
		 * Note that we do NOT set bSuccess to 0 in the case
		 * of failure here.  We must tolerate the situation where
		 * the customer has more paths to a device than he can
		 * get into a PATH_LIST.
		 */

		path = qla2x00_find_or_allocate_path(host, dp, dev_id,
		    pathid, port);
		if (path == NULL) {
			DEBUG4(printk("%s:Path NOT found or created.\n",
			    __func__));
			return 0;
		}

		/* Set the PATH flag to match the device flag
		 * of whether this device needs a relogin.  If any
		 * device needs relogin, set the relogin countdown.
		 */
		if (port->flags & FC_CONFIG)
			path->config = 1;

		if (atomic_read(&port->state) != FCS_ONLINE) {
			path->relogin = 1;
			if (host->relogin_countdown == 0)
				host->relogin_countdown = 30;
		} else {
			path->relogin = 0;
		}

	} else {
		/* EMPTY */
		DEBUG4(printk("%s: Failed portname empty.\n",
		    __func__));
	}

	DEBUG3(printk("%s(%ld): exiting.\n",
	    __func__, host->ha->host_no));
	LEAVE("qla2x00_update_mp_device");

	return success;
}

/*
 * qla2x00_update_mp_tree
 *      Get port information from each adapter, and build or rebuild
 *      the multipath control tree from this data.  This is called
 *      from init and during port database notification.
 *
 * Input:
 *      None
 *
 * Return:
 *      Local function return code.
 *
 */
static uint32_t
qla2x00_update_mp_tree(void)
{
	mp_host_t	*host;
	uint32_t	rval = QLA_SUCCESS;

	ENTER("qla2x00_update_mp_tree:");

	/* Loop through each adapter and see what needs updating. */
	for (host = mp_hosts_base; (host) ; host = host->next) {

		DEBUG4(printk("%s: hba(%d) flags (%x)\n",
		    __func__, host->instance, host->flags));
		/* Clear the countdown; it may be reset in the update. */
		host->relogin_countdown = 0;

		/* Override the NEEDS_UPDATE flag if disabled. */
		if (host->flags & MP_HOST_FLAG_DISABLE ||
		    list_empty(host->fcports))
			host->flags &= ~MP_HOST_FLAG_NEEDS_UPDATE;

		if (host->flags & MP_HOST_FLAG_NEEDS_UPDATE) {

			/*
			 * Perform the actual updates.  If this succeeds, clear
			 * the flag that an update is needed, and failback all
			 * devices that are visible on this path to use this
			 * path.  If the update fails, leave set the flag that
			 * an update is needed, and it will be picked back up
			 * during the next timer routine.
			 */
			if (qla2x00_update_mp_host(host)) {
				host->flags &= ~MP_HOST_FLAG_NEEDS_UPDATE;

				qla2x00_failback_luns(host);
			} else
				rval = QLA_FUNCTION_FAILED;

		}

	}

	if (rval != QLA_SUCCESS) {
		/* EMPTY */
		DEBUG4(printk("%s: Exit FAILED.\n", __func__));

	} else {
		/* EMPTY */
		DEBUG4(printk("%s: Exit OK.\n", __func__));
	}
	return rval;
}



/*
 * qla2x00_find_matching_lun_by_num
 *      Find the lun in the path that matches the
 *  specified lun number.
 *
 * Input:
 *      lun  = lun number
 *      newpath = path to search for lun
 *
 * Returns:
 *      NULL or pointer to lun
 *
 * Context:
 *      Kernel context.
 * (dg)
 */
static fc_lun_t  *
qla2x00_find_matching_lun_by_num(uint16_t lun_no, mp_device_t *dp,
	mp_path_t *newpath)
{
	int found;
	fc_lun_t *lp = NULL;	/* lun ptr */
	fc_port_t *fcport;		/* port ptr */
	mp_lun_t  *lun;

	/* Use the lun list if we have one */
	if (dp->luns) {
		for (lun = dp->luns; lun != NULL ; lun = lun->next) {
			if (lun_no == lun->number) {
				lp = lun->paths[newpath->id];
				break;
			}
		}
	} else {
	if ((fcport = newpath->port) != NULL) {
			found = 0;
			list_for_each_entry(lp, &fcport->fcluns, list) {
				if (lun_no == lp->lun) {
					found++;
				break;
			}
		}
			if (!found)
				lp = NULL;
		}
	}
	return lp;
}

static fc_lun_t  *
qla2x00_find_matching_lun(uint16_t lun, mp_device_t *dp,
	mp_path_t *newpath)
{
	fc_lun_t *lp;

	lp = qla2x00_find_matching_lun_by_num(lun, dp, newpath);

	return lp;
}

/*
 * qla2x00_find_path_by_name
 *      Find the path specified portname from the pathlist
 *
 * Input:
 *      host = host adapter pointer.
 * 	pathlist =  multi-path path list
 *      portname  	portname to search for
 *
 * Returns:
 * pointer to the path or NULL
 *
 * Context:
 *      Kernel context.
 */
mp_path_t *
qla2x00_find_path_by_name(mp_host_t *host, mp_path_list_t *plp,
    uint8_t *portname)
{
	mp_path_t  *path = NULL;		/* match if not NULL */
	mp_path_t  *tmp_path;
	int cnt;

	if ((tmp_path = plp->last) != NULL) {
		for (cnt = 0; (tmp_path) && cnt < plp->path_cnt; cnt++) {
			if (tmp_path->host == host &&
				qla2x00_is_portname_equal(
					tmp_path->portname, portname)) {

				path = tmp_path;
				break;
			}
			tmp_path = tmp_path->next;
		}
	}
	return path ;
}

/*
* qla2x00_find_lu_path_by_id
 *      Find the path for the specified path id.
 *
 * Input:
 * 	mp_lun 		multi-path lun
 * 	id 		path id
 *
 * Returns:
 *      pointer to the lu_path or NULL
 *
 * Context:
 *      Kernel context.
 */
static lu_path_t *
qla2x00_find_lu_path_by_id(mp_lun_t *mplun, uint8_t path_id)
{
	struct list_head *list, *temp;
	lu_path_t  *tmp_path = NULL;
	lu_path_t	*lu_path = NULL;

	list_for_each_safe(list, temp, &mplun->lu_paths) {
		tmp_path = list_entry(list, lu_path_t, list);
		if (tmp_path->path_id == path_id) {
			lu_path = tmp_path;
			break;
		}
	}
	return lu_path ;
}


/*
 * qla2x00_find_path_by_id
 *      Find the path for the specified path id.
 *
 * Input:
 * 	dp 		multi-path device
 * 	id 		path id
 *
 * Returns:
 *      pointer to the path or NULL
 *
 * Context:
 *      Kernel context.
 */
static mp_path_t *
qla2x00_find_path_by_id(mp_device_t *dp, uint8_t id)
{
	mp_path_t  *path = NULL;
	mp_path_t  *tmp_path;
	mp_path_list_t		*path_list;
	int cnt;

	path_list = dp->path_list;
	tmp_path = path_list->last;
	for (cnt = 0; (tmp_path) && cnt < path_list->path_cnt; cnt++) {
		if (tmp_path->id == id) {
			path = tmp_path;
			break;
		}
		tmp_path = tmp_path->next;
	}
	return path ;
}

/*
 * qla2x00_find_mp_dev_by_id
 *      Find the mp_dev for the specified target id.
 *
 * Input:
 *      host = host adapter pointer.
 *      tgt  = Target id
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t  *
qla2x00_find_mp_dev_by_id(mp_host_t *host, uint16_t id)
{
	if (id < MAX_MP_DEVICES)
		return host->mp_devs[id];
	else
		return NULL;
}

/*
 * qla2x00_find_mp_dev_by_nodename
 *      Find the mp_dev for the specified target name.
 *
 * Input:
 *      host = host adapter pointer.
 *      name  = Target name
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
mp_device_t  *
qla2x00_find_mp_dev_by_nodename(mp_host_t *host, uint8_t *name)
{
	int id;
	mp_device_t *dp;

	ENTER("qla2x00_find_mp_dev_by_nodename");

	for (id= 0; id < MAX_MP_DEVICES; id++) {
		if ((dp = host->mp_devs[id]) == NULL)
			continue;

		if (dp->mpdev) {
			DEBUG2(printk("%s: IGNORE device @ index %d: mpdev=%p\n",
			    __func__, id,dp->mpdev));
			if (qla2x00_is_nodename_equal(dp->mpdev->nodename, name)) {
				DEBUG2(printk("%s: Found matching device @ index %d:\n",
			    	__func__, id));
				return dp->mpdev;
			}
		}
DEBUG3(printk("%s mpdev_nodename=%0x nodename_from_gui=%0x",__func__,dp->nodename[7],name[7]));
		if (qla2x00_is_nodename_equal(dp->nodename, name)) {
			DEBUG3(printk("%s: Found matching device @ index %d:\n",
			    __func__, id));
			return dp;
		}
	}

	LEAVE("qla2x00_find_mp_dev_by_name");

	return NULL;
}

/*
 * qla2x00_find_mp_dev_by_portname
 *      Find the mp_dev for the specified target name.
 *
 * Input:
 *      host = host adapter pointer.
 *      name  = port name
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
mp_device_t  *
qla2x00_find_mp_dev_by_portname(mp_host_t *host, uint8_t *name, uint16_t *pidx)
{
	int		id;
	mp_device_t	*dp = NULL;

	DEBUG3(printk("%s: entered.\n", __func__));

	for (id= 0; id < MAX_MP_DEVICES; id++) {
		if ((dp = host->mp_devs[id]) == NULL)
			continue;

		if (qla2x00_is_portname_in_device(dp, name)) {
			DEBUG3(printk("%s: Found matching device @ index %d:\n",
			    __func__, id));
			*pidx = id;
			return dp;
		}
	}

	DEBUG3(printk("%s: exiting.\n", __func__));

 	return NULL;
 }

/*
 * qla2x00_find_dp_by_pn_from_all_hosts
 *      Search through all mp hosts to find the mp_dev for the
 *	specified port name.
 *
 * Input:
 *      pn  = port name
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
static mp_device_t  *
qla2x00_find_dp_by_pn_from_all_hosts(uint8_t *pn, uint16_t *pidx)
{
	int		id;
	mp_device_t	*ret_dp = NULL;
	mp_device_t	*temp_dp = NULL;  /* temporary pointer */
	mp_host_t	*temp_host;  /* temporary pointer */

	DEBUG3(printk("%s: entered.\n", __func__));

	for (temp_host = mp_hosts_base; (temp_host);
	    temp_host = temp_host->next) {
		for (id= 0; id < MAX_MP_DEVICES; id++) {
			temp_dp = temp_host->mp_devs[id];

			if (temp_dp == NULL)
				continue;

			if (qla2x00_is_portname_in_device(temp_dp, pn)) {
				DEBUG3(printk(
				    "%s: Found matching dp @ host %p id %d:\n",
				    __func__, temp_host, id));
				ret_dp = temp_dp;
				*pidx = id;
				break;
			}
		}
		if (ret_dp != NULL) {
			/* found a match. */
			break;
		}
	}

	DEBUG3(printk("%s: exiting.\n", __func__));

	return ret_dp;
}

/*
 * qla2x00_get_visible_path
 * Find the the visible path for the specified device.
 *
 * Input:
 *      dp = device pointer
 *
 * Returns:
 *      NULL or path
 *
 * Context:
 *      Kernel context.
 */
static mp_path_t *
qla2x00_get_visible_path(mp_device_t *dp)
{
	uint16_t	id;
	mp_path_list_t	*path_list;
	mp_path_t	*path;

	path_list = dp->path_list;
	/* if we don't have a visible path skip it */
	if ((id = path_list->visible) == PATH_INDEX_INVALID) {
		return NULL;
	}

	if ((path = qla2x00_find_path_by_id(dp,id))== NULL)
		return NULL;

	return path ;
}

/*
 * qla2x00_map_os_targets
 * Allocate the luns and setup the OS target.
 *
 * Input:
 *      host = host adapter pointer.
 *
 * Returns:
 *      None
 *
 * Context:
 *      Kernel context.
 */
static void
qla2x00_map_os_targets(mp_host_t *host)
{
	scsi_qla_host_t *ha = host->ha;
	mp_path_t	*path;
	mp_device_t 	*dp;
	os_tgt_t	*tgt;
	int		t;

	ENTER("qla2x00_map_os_targets ");

	for (t = 0; t < MAX_TARGETS; t++) {
		dp = host->mp_devs[t];
		if (dp != NULL) {
			DEBUG3(printk("%s: (%d) found a dp=%p, "
			    "host=%p, ha=%p\n",
			    __func__, t, dp, host,ha));

			if ((path = qla2x00_get_visible_path(dp)) == NULL) {
				DEBUG( printk(KERN_INFO
				    "qla_cfg(%d): No visible path "
				    "for target %d, dp = %p\n",
				    host->instance, t, dp));
				continue;
			}

			/* if not the visible path skip it */
			if (path->host == host) {
				if (TGT_Q(ha, t) == NULL) {
					if ((tgt = qla2x00_tgt_alloc(ha, t)) == NULL) {
						printk(KERN_WARNING
						    "%s(%ld): Unable to allocate "
						    "target structure, skipping "
						    "device target %d\n",
						    __func__, ha->host_no, t);
						continue;
					}
					memcpy(tgt->node_name, dp->nodename,
					    WWN_SIZE);
					memcpy(tgt->port_name, path->portname,
					    WWN_SIZE);
					tgt->fcport = path->port;
					tgt->id = dp->dev_id;
					if (path->port)
						if (path->port->flags &
						    FC_NVSXXX_DEVICE)
							set_bit(TQF_USED_ID,
							    &tgt->flags);
				}
				if (path->port)
					path->port->os_target_id = t;
				DEBUG3(printk("%s(%ld): host instance =%d, "
				    "device= %p, tgt=%d has VISIBLE path,"
				    "path id=%d\n",
				    __func__, ha->host_no,
				    host->instance,
				    dp, t, path->id));
			} else {
			/* EMPTY */
				DEBUG3(printk("%s(%ld): host instance =%d, "
				    "device= %p, tgt=%d has HIDDEN "
				    "path, path id=%d\n",
				    __func__, ha->host_no,
				    host->instance, dp, t,
					path->id));
				continue;
			}
			qla2x00_map_os_luns(host, dp, t);
		} else {
			if ((tgt= TGT_Q(ha,t)) != NULL) {
				qla2x00_tgt_free(ha,t);
			}
		}
	}

	LEAVE("qla2x00_map_os_targets ");
}

static void
qla2x00_map_or_failover_oslun(mp_host_t *host, mp_device_t *dp,
	uint16_t t, uint16_t lun_no)
{
	int	i;

	/*
	 * if this is initization time and we couldn't map the
	 * lun then try and find a usable path.
	 */
	if (qla2x00_map_a_oslun(host, dp, t, lun_no) &&
		(host->flags & MP_HOST_FLAG_LUN_FO_ENABLED)) {
		/* find a path for us to use */
		for (i = 0; i < dp->path_list->path_cnt; i++) {
			qla2x00_select_next_path(host, dp, lun_no, NULL);
			if (!qla2x00_map_a_oslun(host, dp, t, lun_no))
				break;
		}
	}
}

/*
 * qla2x00_map_os_luns
 *      Allocate the luns for the OS target.
 *
 * Input:
 *      dp = pointer to device
 *      t  = OS target number.
 *
 * Returns:
 *      None
 *
 * Context:
 *	Kernel context.
 */
static void
qla2x00_map_os_luns(mp_host_t *host, mp_device_t *dp, uint16_t t)
{
	uint16_t lun_no;
	mp_lun_t	*lun;
	os_lun_t *up;

	DEBUG3(printk("Entering %s..\n",__func__));

	/* if we are using lun binding then scan for the discovered luns */
	if (dp->luns) {
		for (lun = dp->luns; lun != NULL ; lun = lun->next) {
			lun_no = lun->number;
			DEBUG2(printk("%s: instance %d: Mapping target %d, lun %d..\n",
				__func__,host->instance,t,lun->number));
			qla2x00_map_or_failover_oslun(host, dp,
				t, lun_no);
			up = (os_lun_t *) GET_LU_Q(host->ha, t, lun_no);
			if (up == NULL) {
				DEBUG2(printk("%s: instance %d: No LUN_Q for target %d, lun %d..\n",
					__func__,host->instance,t,lun->number));
				continue;
			}
			if (up->fclun == NULL) {
			DEBUG2(printk("%s: instance %d: No FCLUN for target %d, lun %d.. lp=%p \n",
				__func__,host->instance,t,lun->number,up));
				continue;
			}
			DEBUG2(printk("%s: instance %d: Mapping target %d, lun %d.. to path id %d\n",
				__func__,host->instance,t,lun->number,
			    up->fclun->fcport->cur_path));
		}
	} else {
		for (lun_no = 0; lun_no < MAX_LUNS; lun_no++) {
			qla2x00_map_or_failover_oslun(host, dp,
				t, lun_no);
		}
	}
	DEBUG3(printk("Exiting %s..\n",__func__));
}

/*
 * qla2x00_map_a_osluns
 *      Map the OS lun to the current path
 *
 * Input:
 *      host = pointer to host
 *      dp = pointer to device
 *      lun  = OS lun number.
 *
 * Returns:
 *      None
 *
 * Context:
 *	Kernel context.
 */

static uint8_t
qla2x00_map_a_oslun(mp_host_t *host, mp_device_t *dp, uint16_t t, uint16_t lun)
{
	fc_port_t	*fcport;
	fc_lun_t	*fclun;
	os_lun_t	*lq;
	uint16_t	id;
	mp_path_t	*path, *vis_path;
	mp_host_t 	*vis_host;
	uint8_t		status = 0;

	if ((id = dp->path_list->current_path[lun]) != PATH_INDEX_INVALID) {
		path = qla2x00_find_path_by_id(dp,id);
		if (path) {
			fcport = path->port;
			if (fcport) {

				/* Always map all luns if they are enabled */
			 	fcport->cur_path = id;
				fclun = qla2x00_find_matching_lun(lun,dp,path);
				if (fclun &&
					(path->lun_data.data[lun] &
					 LUN_DATA_ENABLED)) {
		DEBUG(printk( "qla2x00(%d): Current path for lun %d/%p is path id %d\n",
		    host->instance,
		    lun, fclun, id));
		DEBUG3(printk( "qla2x00(%d): Lun is enable \n", host->instance));

					/*
					 * Mapped lun on the visible path
					 */
					if ((vis_path =
					    qla2x00_get_visible_path(dp)) ==
					    NULL) {

						printk(KERN_INFO
						    "qla2x00(%d): No visible "
						    "path for target %d, "
						    "dp = %p\n",
						    host->instance,
						    t, dp);

						return 0;
					}
					vis_host = vis_path->host;

					/* ra 11/30/01 */
					/*
					 * Always alloc LUN 0 so kernel
					 * will scan past LUN 0.
					 */
					if (lun != 0 &&
					    (EXT_IS_LUN_BIT_SET(
						&(fcport->lun_mask), lun))) {

						/* mask this LUN */
						return 0;
					}

					if ((lq = qla2x00_lun_alloc(
							vis_host->ha,
							t, lun)) != NULL) {

						lq->fclun = fclun;
						((struct osl_fo_info *)
						 lq->fo_ptr)->path_cnt =
						     dp->path_list->path_cnt;
					}
		DEBUG(printk( "qla2x00(%d): lun allocated %p for lun %d\n",
			 host->instance,lq,lun));
				}
			}
			else
				status = 1;
		}
	}
	return status;
}

/*
 * qla2x00_is_ww_name_zero
 *
 * Input:
 *      ww_name = Pointer to WW name to check
 *
 * Returns:
 *      1 if name is 0 else 0
 *
 * Context:
 *      Kernel context.
 */
static uint8_t
qla2x00_is_ww_name_zero(uint8_t *nn)
{
	int cnt;

	/* Check for zero node name */
	for (cnt = 0; cnt < WWN_SIZE ; cnt++, nn++) {
		if (*nn != 0)
			break;
	}
	/* if zero return 1 */
	if (cnt == WWN_SIZE)
		return 1;
	else
		return 0;
}

/*
 * qla2x00_add_path
 * Add a path to the pathlist
 *
 * Input:
 * pathlist -- path list of paths
 * path -- path to be added to list
 *
 * Returns:
 *      None
 *
 * Context:
 *      Kernel context.
 */
static void
qla2x00_add_path(mp_path_list_t *pathlist, mp_path_t *path)
{
	mp_path_t *last = pathlist->last;

	ENTER("qla2x00_add_path");
	DEBUG3(printk("%s: entered for path id %d.\n",
	    __func__, path->id));

	DEBUG3(printk("%s: pathlist =%p, path =%p, cnt = %d\n",
	    __func__, pathlist, path, pathlist->path_cnt));
	if (last == NULL) {
		last = path;
	} else {
		path->next = last->next;
	}

	last->next = path;
	pathlist->last = path;
	pathlist->path_cnt++;

	DEBUG3(printk("%s: exiting. path cnt=%d.\n",
	    __func__, pathlist->path_cnt));
	LEAVE("qla2x00_add_path");
}

static void
qla2x00_add_lun(mp_device_t *dp, mp_lun_t *lun)
{
	mp_lun_t 	*cur_lun;

	ENTER("qla2x00_add_lun");

	/* Insert new entry into the list of luns */
	lun->next = NULL;

	cur_lun = dp->luns;
	if (cur_lun == NULL) {
		dp->luns = lun;
	} else {
		/* add to tail of list */
		while (cur_lun->next != NULL)
			cur_lun = cur_lun->next;

		cur_lun->next = lun;
	}
	LEAVE("qla2x00_add_lun");
}

/*
 * qla2x00_is_portname_in_device
 *	Search for the specified "portname" in the device list.
 *
 * Input:
 *	dp = device pointer
 *	portname = portname to searched for in device
 *
 * Returns:
 *      qla2x00 local function return status code.
 *
 * Context:
 *      Kernel context.
 */
int
qla2x00_is_portname_in_device(mp_device_t *dp, uint8_t *portname)
{
	int idx;

 	if (dp->mpdev) {
 		for (idx = 0; idx < MAX_PATHS_PER_DEVICE; idx++) {
 			if (memcmp(&dp->mpdev->portnames[idx][0], portname, WWN_SIZE) == 0)
 				return 1;
 		}
 	}
	for (idx = 0; idx < MAX_PATHS_PER_DEVICE; idx++) {
		if (memcmp(&dp->portnames[idx][0], portname, WWN_SIZE) == 0)
			return 1;
	}
	return 0;
}


/*
 *  qla2x00_set_lun_data_from_bitmask
 *      Set or clear the LUN_DATA_ENABLED bits in the LUN_DATA from
 *      a LUN bitmask provided from the miniport driver.
 *
 *  Inputs:
 *      lun_data = Extended LUN_DATA buffer to set.
 *      lun_mask = Pointer to lun bit mask union.
 *
 *  Return Value: none.
 */
void
qla2x00_set_lun_data_from_bitmask(mp_lun_data_t *lun_data,
    lun_bit_mask_t *lun_mask)
{
	uint16_t lun;

	ENTER("qla2x00_set_lun_data_from_bitmask");

	for (lun = 0; lun < MAX_LUNS; lun++) {
		/* our bit mask is inverted */
		if (!(EXT_IS_LUN_BIT_SET(lun_mask,lun)))
			lun_data->data[lun] |= LUN_DATA_ENABLED;
		else
			lun_data->data[lun] &= ~LUN_DATA_ENABLED;

		DEBUG5(printk("%s: lun data[%d] = 0x%x\n",
		    __func__, lun, lun_data->data[lun]));
	}

	LEAVE("qla2x00_set_lun_data_from_bitmask");

	return;
}

static void
qla2x00_failback_single_lun(mp_device_t *dp, uint16_t lun, uint16_t new)
{
	mp_path_list_t   *pathlist;
	mp_path_t        *new_path, *old_path;
	uint16_t 	old;
	mp_host_t  *host;
	os_lun_t *lq;
	os_tgt_t *tq;
	mp_path_t	*vis_path;
	mp_host_t 	*vis_host;
	fc_port_t 	*new_fcport;
 	fc_lun_t	*fclun;
 	int		skip_notify = 0;

	/* Failback and update statistics. */
	if ((pathlist = dp->path_list) == NULL)
		return;

	old = pathlist->current_path[lun];
	pathlist->current_path[lun] = new;

	if ((new_path = qla2x00_find_path_by_id(dp, new)) == NULL)
		return;
	if ((old_path = qla2x00_find_path_by_id(dp, old)) == NULL)
		return;

	/* An fclun should exist for the failbacked lun */
	if ((fclun = qla2x00_find_matching_lun(lun, dp, new_path)) == NULL)
		return;
	if (qla2x00_find_matching_lun(lun, dp, old_path) == NULL)
		return;

	if ((vis_path = qla2x00_get_visible_path(dp)) == NULL) {
		DEBUG2(printk(KERN_INFO
		    "No visible path for target %d, dp = %p\n", dp->dev_id,
		    dp));
		return;
	}
	vis_host = vis_path->host;
	tq = TGT_Q(vis_host->ha, dp->dev_id);
	if (tq == NULL) {
		DEBUG2(printk(KERN_INFO
		    "%s(): **** DP dev_id derives a NULL TGT_Q\n", __func__));
		return;
	}

 	if ((new_fcport = new_path->port) == NULL)
 		return;

	DEBUG2(printk(KERN_INFO
	    "qla2x00(%d): Suspending I/O to target %d, dp = %p, lun=%d\n",
	    vis_host->instance, dp->dev_id, dp, lun));

	set_bit(TQF_SUSPENDED, &tq->flags);
	/* Log to console and to event log. */
	printk(KERN_INFO
		"qla2x00: FAILBACK device %d -> "
		"%02x%02x%02x%02x%02x%02x%02x%02x LUN %02x\n",
		dp->dev_id,
		dp->nodename[0], dp->nodename[1],
		dp->nodename[2], dp->nodename[3],
		dp->nodename[4], dp->nodename[5],
		dp->nodename[6], dp->nodename[7],
		lun);

	printk(KERN_INFO
		"qla2x00: FROM HBA %d to HBA %d \n",
		old_path->host->instance,
		new_path->host->instance);

	host = new_path->host;

 	if (new_fcport->flags & (FC_AA_EVA_DEVICE |
 				FC_AA_MSA_DEVICE)) {
 		/* Update lun path info if necessary */
 		if (qla2x00_find_all_active_fcports(lun)) {
			DEBUG2(printk(KERN_INFO
	    		"qla2x00(%d): FAILBACk failed for target %d, dp = %p, lun=%d\n",
	    		vis_host->instance, dp->dev_id, dp, lun));
			clear_bit(TQF_SUSPENDED, &tq->flags);
			return;
		}

 		/* Check if path has already moved */
 		if (new_fcport->fo_target_port) {
 			lu_path_t *new_lu_path;
 			mp_lun_t *mplun;
 			/* find lu_path for the current fclun */
 			mplun = (mp_lun_t *)fclun->mplun;
 			new_lu_path = qla2x00_find_lu_path_by_id(
 				mplun,fclun->path_id);
 			if (new_lu_path->asym_acc_state == TPG_ACT_OPT) {
 				skip_notify++;
 			}
 		}
 	}
	/* Clear the reservation if any. */
	if (new_fcport != NULL) {
		if (new_fcport->flags &
		    (FC_EVA_DEVICE | FC_AA_EVA_DEVICE | FC_AA_MSA_DEVICE |
			FC_NVSXXX_DEVICE | FC_SYMXXX_DEVICE)) {
			printk(KERN_INFO
			    "scsi(%ld:0x%x:%d) sending lun reset.\n",
			    new_fcport->ha->host_no, new_fcport->loop_id, lun);
			qla2x00_lun_reset(new_fcport->ha, new_fcport, lun);
		}
	}

	/* Send a failover notification. */
 	if (!skip_notify)
 		qla2x00_send_failover_notify(dp, lun, new_path, old_path);

	/* remap the lun */
	qla2x00_map_a_oslun(host, dp, dp->dev_id, lun);

	/* 7/16
	 * Reset counts on the visible path
	 */
	if ((vis_path = qla2x00_get_visible_path(dp)) == NULL) {
		printk(KERN_INFO
			"qla2x00(%d): No visible path for "
			"target %d, dp = %p\n",
			host->instance,
			dp->dev_id, dp);
		return;
	}

	DEBUG2(printk(KERN_INFO
	    "qla2x00(%d): Resuming I/O to target %d, dp = %p, lun=%d\n",
	    vis_host->instance, dp->dev_id, dp, lun));
	clear_bit(TQF_SUSPENDED, &tq->flags);

	vis_host = vis_path->host;
	if ((lq = qla2x00_lun_alloc(vis_host->ha, dp->dev_id, lun)) != NULL) {
		((struct osl_fo_info *) lq->fo_ptr)->path_cnt =
		    dp->path_list->path_cnt;
		qla2x00_delay_lun(vis_host->ha, lq, ql2xrecoveryTime);
		qla2x00_flush_failover_q(vis_host->ha, lq);
		qla2x00_reset_lun_fo_counts(vis_host->ha, lq);
	}
}

#if 0
static void
qla2x00_failback_single_lun(mp_device_t *dp, uint8_t lun, uint8_t new)
{
	mp_path_list_t   *pathlist;
	mp_path_t        *new_path, *old_path;
	uint8_t 	old;
	mp_host_t  *new_host;
	os_lun_t *lq;
	mp_path_t	*vis_path;
	mp_host_t 	*vis_host;
	int		status;

	/* Failback and update statistics. */
	if ((pathlist = dp->path_list) == NULL)
		return;

	old = pathlist->current_path[lun];
	/* pathlist->current_path[lun] = new; */

	if ((new_path = qla2x00_find_path_by_id(dp, new)) == NULL)
		return;
	if ((old_path = qla2x00_find_path_by_id(dp, old)) == NULL)
		return;

	/* An fclun should exist for the failbacked lun */
	if (qla2x00_find_matching_lun(lun, dp, new_path) == NULL)
		return;
	if (qla2x00_find_matching_lun(lun, dp, old_path) == NULL)
		return;

	if ((vis_path = qla2x00_get_visible_path(dp)) == NULL) {
		printk(KERN_INFO
			"No visible path for "
			"target %d, dp = %p\n",
			dp->dev_id, dp);
		return;
	}
	vis_host = vis_path->host;
	/* Schedule the recovery before we move the luns */
	if ((lq = (os_lun_t *)
		LUN_Q(vis_host->ha, dp->dev_id, lun)) == NULL ) {
		printk(KERN_INFO
			"qla2x00(%d): No visible lun for "
			"target %d, dp = %p, lun=%d\n",
			vis_host->instance,
			dp->dev_id, dp, lun);
		return;
  	}

	qla2x00_delay_lun(vis_host->ha, lq, ql2xrecoveryTime);

	/* Log to console and to event log. */
	printk(KERN_INFO
		"qla2x00: FAILBACK device %d -> "
		"%02x%02x%02x%02x%02x%02x%02x%02x LUN %02x\n",
		dp->dev_id,
		dp->nodename[0], dp->nodename[1],
		dp->nodename[2], dp->nodename[3],
		dp->nodename[4], dp->nodename[5],
		dp->nodename[6], dp->nodename[7],
		lun);

	printk(KERN_INFO
		"qla2x00: FROM HBA %d to HBA %d \n",
		old_path->host->instance,
		new_path->host->instance);


	/* Send a failover notification. */
	status = qla2x00_send_failover_notify(dp, lun,
			new_path, old_path);

	new_host = 	new_path->host;

	/* remap the lun */
	if (status == QLA_SUCCESS) {
		pathlist->current_path[lun] = new;
		qla2x00_map_a_oslun(new_host, dp, dp->dev_id, lun);
		qla2x00_flush_failover_q(vis_host->ha, lq);
		qla2x00_reset_lun_fo_counts(vis_host->ha, lq);
	}
}
#endif

/*
*  qla2x00_failback_luns
*      This routine looks through the devices on an adapter, and
*      for each device that has this adapter as the visible path,
*      it forces that path to be the current path.  This allows us
*      to keep some semblance of static load balancing even after
*      an adapter goes away and comes back.
*
*  Arguments:
*      host          Adapter that has just come back online.
*
*  Return:
*	None.
*/
static void
qla2x00_failback_luns(mp_host_t  *host)
{
	uint16_t          dev_no;
	uint16_t          l;
	uint16_t          lun;
	int i;
	mp_device_t      *dp;
	mp_path_list_t   *path_list;
	mp_path_t        *path;
	fc_lun_t	*new_fp;

	ENTER("qla2x00_failback_luns");

	for (dev_no = 0; dev_no < MAX_MP_DEVICES; dev_no++) {
		dp = host->mp_devs[dev_no];

		if (dp == NULL)
			continue;

		if (dp->mpdev)
			dp = dp->mpdev;

		path_list = dp->path_list;
		for (path = path_list->last, i= 0;
			i < path_list->path_cnt;
			i++, path = path->next) {

			if (path->host != host)
				continue;

			if (path->port == NULL)
				continue;

			if (atomic_read(&path->port->state) == FCS_DEVICE_DEAD)
				continue;

		        if ((path->port->flags & FC_FAILBACK_DISABLE))
				continue;

			/*
			 * Failback all the paths for this host,
			 * the luns could be preferred across all paths
			 */
			DEBUG(printk("%s(%d): Lun Data for device %p, "
			    "id=%d, path id=%d\n",
			    __func__, host->instance, dp, dp->dev_id,
			    path->id));
			DEBUG4(qla2x00_dump_buffer(
			    (char *)&path->lun_data.data[0], 64));
			DEBUG4(printk("%s(%d): Perferrred Path data:\n",
			    __func__, host->instance));
			DEBUG4(qla2x00_dump_buffer(
			    (char *)&path_list->current_path[0], 64));

			for (lun = 0; lun < MAX_LUNS_PER_DEVICE; lun++) {
				l = (lun & LUN_MASK);

				/*
				 * if this is the preferred lun and not
				 * the current path then failback lun.
				 */
				DEBUG4(printk("%s: target=%d, cur path id =%d, "
				    "lun data[%d] = %d)\n",
				    __func__, dp->dev_id, path->id,
				    lun, path->lun_data.data[lun]));

				if ((path->lun_data.data[l] &
						LUN_DATA_PREFERRED_PATH) &&
					/* !path->relogin && */
					path_list->current_path[l] !=
						path->id) {
					/* No point in failing back a
					   disconnected lun */
					new_fp = qla2x00_find_matching_lun(
							l, dp, path);

					if (new_fp == NULL)
						continue;
					/* Skip a disconect lun */
					if (new_fp->device_type & 0x20)
						continue;

					qla2x00_failback_single_lun(
							dp, l, path->id);
				}
			}
		}

	}

	LEAVE("qla2x00_failback_luns");

	return;
}

static struct _mp_path *
qla2x00_find_first_path_to_active_tpg(mp_device_t *dp, mp_lun_t *mplun, int any_grp)
{
	mp_tport_grp_t	*tport_grp = NULL;
	mp_path_t 	*path = NULL;
	mp_path_list_t  *plp = dp->path_list;
	mp_path_t  	*tmp_path;
	fc_port_t 	*fcport;
	mp_port_t 	*mp_port;
	int 		cnt;

	/* Find an Active Optimised Tgt port group */
	tport_grp = qla2x00_find_tgt_port_grp_by_state(mplun, TPG_ACT_OPT);
	if (tport_grp == NULL) {
		/* Find an Active Non Optimised Tgt port group */
		if (any_grp)
			tport_grp = qla2x00_find_tgt_port_grp_by_state(mplun, TPG_ACT_NON_OPT);
		if (tport_grp == NULL)
			return path;
	}
	DEBUG(printk("%s found active tpg asym_state=%d tpg_id=%d\n",__func__,
			tport_grp->asym_acc_state,  tport_grp->tpg_id[1]));
	/* Find first active path to this tgt port grp */
	if ((tmp_path = plp->last) != NULL) {
		tmp_path = tmp_path->next;
		for (cnt = 0; (tmp_path) && cnt < plp->path_cnt;
		    tmp_path = tmp_path->next, cnt++) {
			fcport = tmp_path->port;
			if (fcport == NULL)
				continue;
			mp_port = tport_grp->ports_list[tmp_path->id];
			if (mp_port == NULL)
				continue;
			if (memcmp(fcport->port_name, mp_port->portname,
					WWN_SIZE) == 0) {
				path = tmp_path;
				break;
			}
		}
	}
	return path;


}

static struct _mp_path *
qla2x00_find_first_active_path(mp_device_t *dp, mp_lun_t *lun)
{
	mp_path_t *path= NULL;
	mp_path_list_t  *plp = dp->path_list;
	mp_path_t  *tmp_path;
	fc_port_t 	*fcport;
	fc_lun_t 	*fclun;
	int cnt;

	if ((tmp_path = plp->last) != NULL) {
		tmp_path = tmp_path->next;
		for (cnt = 0; (tmp_path) && cnt < plp->path_cnt;
		    tmp_path = tmp_path->next, cnt++) {
			fcport = tmp_path->port;
			if (fcport != NULL) {
				if ((fcport->flags & FC_EVA_DEVICE) ||
					fcport->fo_target_port) {
					fclun = lun->paths[tmp_path->id];
					if (fclun == NULL)
						continue;
					if (fclun->flags & FLF_ACTIVE_LUN) {
						path = tmp_path;
						break;
					}
				} else {
					if ((fcport->flags &
					    FC_MSA_PORT_ACTIVE)) {
						path = tmp_path;
						break;
					}
				}
			}
		}
	}
	return path;
}

/*
 *  qla2x00_setup_new_path
 *      Checks the path against the existing paths to see if there
 *      are any incompatibilities.  It then checks and sets up the
 *      current path indices.
 *
 *  Inputs:
 *      dp   =  pointer to device
 *      path = new path
 *
 *  Returns:
 *      None
 */
static void
qla2x00_setup_new_path(mp_device_t *dp, mp_path_t *path, fc_port_t *fcport)
{
	mp_path_list_t  *path_list = dp->path_list;
	mp_path_t       *tmp_path, *first_path;
	mp_host_t       *first_host;
	mp_host_t       *tmp_host;

	uint16_t	lun;
	uint16_t	l;
	uint16_t	path_id;

	ENTER("qla2x00_setup_new_path");
	DEBUG(printk("qla2x00_setup_new_path: path %p path id %d\n",
		path, path->id));
	if (path->port) {
		DEBUG(printk("qla2x00_setup_new_path: port %p loop id 0x%x\n",
		path->port, fcport->loop_id));
	}

	/* If this is a visible path, and there is not already a
	 * visible path, save it as the visible path.  If there
	 * is already a visible path, log an error and make this
	 * path invisible.
	 */
	if (!(path->mp_byte & (MP_MASK_HIDDEN | MP_MASK_UNCONFIGURED))) {

		/* No known visible path */
		if (path_list->visible == PATH_INDEX_INVALID) {
			DEBUG3(printk("%s: No know visible path - make this "
			    "path visible\n",
			    __func__));

			path_list->visible = path->id;
			path->mp_byte &= ~MP_MASK_HIDDEN;
		} else {
			DEBUG3(printk("%s: Second visible path found- make "
			    "this one hidden\n",
			    __func__));

			path->mp_byte |= MP_MASK_HIDDEN;
		}
		if (path->port)
			path->port->mp_byte = path->mp_byte;
	}

	/*
	 * If this is not the first path added, and the setting for
	 * MaxLunsPerTarget does not match that of the first path
	 * then disable qla_cfg for all adapters.
	 */
	first_path = qla2x00_find_path_by_id(dp, 0);

	if (first_path != NULL) {
		first_host = first_path->host;
		if ((path->id != 0) &&
			(first_host->MaxLunsPerTarget !=
			 path->host->MaxLunsPerTarget)) {

			for (tmp_path = path_list->last, path_id = 0;
				(tmp_path) && path_id <= path->id; path_id++) {

				tmp_host = tmp_path->host;
				if (!(tmp_host->flags &
						MP_HOST_FLAG_DISABLE)) {

					DEBUG4(printk("%s: 2nd visible "
					    "path (%p)\n",
					    __func__, tmp_host));

					tmp_host->flags |= MP_HOST_FLAG_DISABLE;
				}
			}
		}
	}

	if ((!(fcport->flags & (FC_MSA_DEVICE | FC_EVA_DEVICE)) && fcport->fo_target_port == NULL) ||
	    fcport->flags & FC_FAILOVER_DISABLE) {

		/*
		 * For each LUN, evaluate whether the new path that is added is
		 * better than the existing path.  If it is, make it the
		 * current path for the LUN.
		 */
		for (lun = 0; lun < MAX_LUNS_PER_DEVICE; lun++) {
			l = (lun & LUN_MASK);

			/*
			 * If this is the first path added, it is the only
			 * available path, so make it the current path.
			 */
			DEBUG4(printk("%s: lun_data 0x%x, LUN %d\n",
			    __func__, path->lun_data.data[l], lun));

			if (first_path == path) {
				path_list->current_path[l] = 0;
                                path->lun_data.data[l] |=
                                    LUN_DATA_PREFERRED_PATH;
			} else if (path->lun_data.data[l] &
			    LUN_DATA_PREFERRED_PATH) {
				/*
				 * If this is not the first path added, if this
				 * is the preferred path, so make it the
				 * current path.
				 */
				path_list->current_path[l] = path->id;
			}
		}
	}

	LEAVE("qla2x00_setup_new_path");

	return;
}

/*
 * qla2x00_cfg_mem_free
 *     Free all configuration structures.
 *
 * Input:
 *      ha = adapter state pointer.
 *
 * Context:
 *      Kernel context.
 */
void
qla2x00_cfg_mem_free(scsi_qla_host_t *ha)
{
	mp_lun_t        *cur_lun, *next_lun;
	mp_lun_t        *tmp_lun;
	mp_device_t *dp;
	mp_path_list_t  *path_list;
	mp_path_t       *tmp_path, *path;
	mp_host_t       *host, *temp;
	mp_port_t	*temp_port;
	struct list_head *list, *temp_list;
	int	id, cnt, tid;
	mp_tport_grp_t  *tport_grp;
	lu_path_t	*lu_path;

	if ((host = qla2x00_cfg_find_host(ha)) != NULL) {
		if (mp_num_hosts == 0)
			return;

		for (id= 0; id < MAX_MP_DEVICES; id++) {
			if ((dp = host->mp_devs[id]) == NULL)
				continue;
			if ((path_list = dp->path_list) == NULL)
				continue;
			if ((tmp_path = path_list->last) == NULL)
				continue;
			for (cnt = 0; cnt < path_list->path_cnt; cnt++) {
				path = tmp_path;
				tmp_path = tmp_path->next;
				DEBUG(printk(KERN_INFO
						"host%d - Removing path[%d] "
						"= %p\n",
						host->instance,
						cnt, path));
				kfree(path);
			}
			kfree(path_list);
			host->mp_devs[id] = NULL;
			/* remove dp from other hosts */
			for (temp = mp_hosts_base; (temp); temp = temp->next) {
				for (tid= 0; tid < MAX_MP_DEVICES; tid++)
					if (temp->mp_devs[tid] == dp) {
					DEBUG(printk(KERN_INFO
						"host%d - Removing host[%d] = "
						"%p\n",
						host->instance,
						temp->instance,temp));
					temp->mp_devs[tid] = NULL;
					}
			}
			/* Free all the lun struc's attached
			 * to this mp_device */
			for (cur_lun = dp->luns; (cur_lun);
					cur_lun = next_lun) {
				DEBUG(printk(KERN_INFO
						"host%d - Removing lun:%p "
						"attached to device:%p\n",
						host->instance,
						cur_lun,dp));
				list_for_each_safe(list, temp_list,
					&cur_lun->ports_list) {
					temp_port = list_entry(list,
							mp_port_t, list);
					list_del_init(&temp_port->list);
					DEBUG(printk(KERN_INFO
						"host%d - Removing port:%p "
						"attached to lun:%p\n",
						host->instance, temp_port,
						cur_lun));
					kfree(temp_port);

				}
				list_for_each_safe(list, temp_list, &cur_lun->active_list) {
					lu_path = list_entry(list, lu_path_t, next_active);
					DEBUG(printk(KERN_INFO
						"host%d - Deleting active lu_path:%p "
						"attached to lun:%p\n",
						host->instance, lu_path,
						cur_lun));
					list_del_init(&lu_path->next_active);
				}
				list_for_each_safe(list, temp_list,
					&cur_lun->lu_paths) {
					lu_path = list_entry(list, lu_path_t,
							 list);
					list_del_init(&lu_path->list);
					DEBUG(printk(KERN_INFO
						"host%d - Removing lu_path:%p "
						"attached to lun:%p\n",
						host->instance, lu_path,
						cur_lun));
					kfree(lu_path);
				}
				if (cur_lun->asymm_support) {
					list_for_each_safe(list, temp_list,
						 &cur_lun->tport_grps_list) {
						tport_grp = list_entry(list,
								mp_tport_grp_t, list);
						DEBUG(printk(KERN_INFO
							"host%d - Removing tpg:%p "
							"attached to lun:%p\n",
							host->instance, tport_grp,
							cur_lun));
						list_del_init(&tport_grp->list);
						kfree(tport_grp);
					}
				}
				next_lun = cur_lun->next;
				tmp_lun = cur_lun;
				kfree(tmp_lun);
			}
			kfree(dp);
		}

		/* remove this host from host list */
		temp = mp_hosts_base;
		if (temp != NULL) {
			/* Remove from top of queue */
			if (temp == host) {
				mp_hosts_base = host->next;
			} else {
				/*
				 * Remove from middle of queue
				 * or bottom of queue
				 */
				for (temp = mp_hosts_base;
						temp != NULL;
						temp = temp->next) {

					if (temp->next == host) {
						temp->next = host->next;
						break;
					}
				}
			}
		}
		kfree(host);
		mp_num_hosts--;
	}
}

int
qla2x00_is_fcport_in_foconfig(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	mp_device_t	*dp;
	mp_host_t	*host;
	mp_path_t	*path;
	mp_path_list_t	*pathlist;
	uint16_t	dev_no;

	/* no configured devices */
	host = qla2x00_cfg_find_host(ha);
	if (!host)
		return (0);

	for (dev_no = 0; dev_no < MAX_MP_DEVICES; dev_no++) {
		dp = host->mp_devs[dev_no];

		if (dp == NULL)
			continue;

		/* Sanity check */
		if (qla2x00_is_wwn_zero(dp->nodename))
			continue;

		if ((pathlist = dp->path_list) == NULL)
			continue;

		path = qla2x00_find_path_by_name(host, dp->path_list,
		    fcport->port_name);
		if (path != NULL) {
			/* found path for port */
			if (path->config == 1) {
				return (1);
			} else {
			break;
			}
		}
	}

	return (0);
}
