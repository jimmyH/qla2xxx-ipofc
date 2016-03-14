/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include "qla_def.h"
#include "qla_ip.h"

int qla2x00_mailbox_command(scsi_qla_host_t *vha, mbx_cmd_t *mcp);
void qla2x00_isp_cmd(scsi_qla_host_t *vha);
void * qla2x00_req_pkt(scsi_qla_host_t *vha);

extern struct fc_host_statistics *
qla2x00_get_fc_host_stats_foo(scsi_qla_host_t* vha);


#define BROADCAST_4G		0x7ff

extern struct list_head qla_hostlist;
extern rwlock_t qla_hostlist_lock;
int include_me = 1;

static __u8 hwbroadcast_addr[ETH_ALEN] = { [0 ... ETH_ALEN - 1] = 0xFF };

#if 0

/**
 * qla2x00_ip_initialize() - Initialize RISC IP support.
 * @ha: SCSI driver HA context
 *
 * Prior to RISC IP initialization, this routine, if necessary, will reset all
 * buffers in the receive buffer ring.
 *
 * Returns 1 if the RISC IP initialization succeeds.
 */
static int
qla2x00_ip_initialize(scsi_qla_host_t *ha)
{
	int i;
	int status;
	unsigned long flags;
	device_reg_t __iomem *reg;
	static mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct ip_init_cb *ipinit_cb;
	dma_addr_t ipinit_cb_dma;

	DEBUG12(printk("%s: enter\n", __func__));

	status = 0;

	/* Initialize IP data in ha */
	/* Reset/pack buffers owned by RISC in receive buffer ring */
	if (ha->rec_entries_in != ha->rec_entries_out) {
		struct buffer_cb *bcb;
		uint16_t rec_out;
		struct risc_rec_entry *rec_entry;

		bcb = ha->receive_buffers;
		rec_out = ha->rec_entries_out;

		/*
		 * Must locate all RISC owned buffers and pack them in the
		 * buffer ring.
		 */
		/* between IpBufferOut and IpBufferIN */
		for (i = 0; i < ha->max_receive_buffers; i++, bcb++) {
			if (test_bit(BCB_RISC_OWNS_BUFFER, &bcb->state)) {
				/*
				 * Set RISC owned buffer into receive buffer
				 * ring.
				 */
				rec_entry = &ha->risc_rec_q[rec_out];
				rec_entry->handle = bcb->handle;
				rec_entry->data_addr_low =
				    cpu_to_le32(LSD(bcb->skb_data_dma));
				rec_entry->data_addr_high =
				    cpu_to_le32(MSD(bcb->skb_data_dma));
				if (rec_out < IP_BUFFER_QUEUE_DEPTH - 1)
					rec_out++;
				else
					rec_out = 0;
			}
		}

		/* Verify correct number of RISC owned buffers were found */
		if (rec_out != ha->rec_entries_in) {
			/* Incorrect number of RISC owned buffers?? */
			DEBUG12(printk("%s: incorrect number of RISC "
				       "owned buffers, disable IP\n",
				       __func__));
			ha->flags.enable_ip = 0;
			return 0;
		}
	}

	/* Init RISC buffer pointer */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	reg = ha->iobase;
	WRT_MAILBOX_REG(ha, reg, 8, ha->rec_entries_in);
	RD_MAILBOX_REG(ha, reg, 8);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	/* Wait for a ready state from the adapter */
	while (!ha->flags.init_done || ha->dpc_active) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}

	/* Setup IP initialization control block */
	ipinit_cb = pci_alloc_consistent(ha->pdev,
					 sizeof(struct ip_init_cb),
					 &ipinit_cb_dma);
	if (ipinit_cb) {
		memset(ipinit_cb, 0, sizeof(struct ip_init_cb));
		ipinit_cb->version = IPICB_VERSION;
		ipinit_cb->firmware_options =
		    __constant_cpu_to_le16(IPICB_OPTION_OUT_OF_BUFFERS_EVENT |
					   IPICB_OPTION_NO_BROADCAST_FASTPOST |
					   IPICB_OPTION_64BIT_ADDRESSING);
		ipinit_cb->header_size = cpu_to_le16(ha->header_size);
		ipinit_cb->mtu = cpu_to_le16((uint16_t) ha->mtu);
		ipinit_cb->receive_buffer_size =
		    cpu_to_le16((uint16_t) ha->receive_buff_data_size);
		ipinit_cb->receive_queue_size =
		    __constant_cpu_to_le16(IP_BUFFER_QUEUE_DEPTH);
		ipinit_cb->low_water_mark =
		    __constant_cpu_to_le16(IPICB_LOW_WATER_MARK);
		ipinit_cb->receive_queue_addr[0] =
		    cpu_to_le16(LSW(ha->risc_rec_q_dma));
		ipinit_cb->receive_queue_addr[1] =
		    cpu_to_le16(MSW(ha->risc_rec_q_dma));
		ipinit_cb->receive_queue_addr[2] =
		    cpu_to_le16(LSW(MSD(ha->risc_rec_q_dma)));
		ipinit_cb->receive_queue_addr[3] =
		    cpu_to_le16(MSW(MSD(ha->risc_rec_q_dma)));
		ipinit_cb->receive_queue_in = cpu_to_le16(ha->rec_entries_out);
		ipinit_cb->container_count =
		    __constant_cpu_to_le16(IPICB_BUFFER_CONTAINER_COUNT);

		/* Issue mailbox command to initialize IP firmware */
		mcp->mb[0] = MBC_INITIALIZE_IP;
		mcp->mb[2] = MSW(ipinit_cb_dma);
		mcp->mb[3] = LSW(ipinit_cb_dma);
		mcp->mb[6] = MSW(MSD(ipinit_cb_dma));
		mcp->mb[7] = LSW(MSD(ipinit_cb_dma));
		mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->tov = 30;
		mcp->buf_size = sizeof(struct ip_init_cb);
		mcp->flags = MBX_DMA_OUT;

		status = qla2x00_mailbox_command(ha, mcp);
		if (status == QL_STATUS_SUCCESS) {
			/* IP initialization successful */
			DEBUG12(printk("%s: successful\n", __func__));

			ha->flags.enable_ip = 1;

			/* Force database update */
			set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
			set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
			set_bit(REGISTER_FC4_NEEDED, &ha->dpc_flags);

			/* qla2x00_loop_resync(ha); */
			if (ha->dpc_wait && !ha->dpc_active) {
				up(ha->dpc_wait);
			}
			status = 1;
		} else {
			DEBUG12(printk("%s: MBC_INITIALIZE_IP "
				       "failed %x MB0 %x\n",
				       __func__, status, mcp->mb[0]));
			status = 0;
		}
		pci_free_consistent(ha->pdev, sizeof(struct ip_init_cb),
				    ipinit_cb, ipinit_cb_dma);

	} else {
		DEBUG12(printk("%s: memory allocation error\n", __func__));
	}

	return status;

	return 0;
}

#endif

static void
qla24xx_add_buffers(scsi_qla_host_t *ha, uint16_t unused, int ha_locked)
{
	int i;
	unsigned long flags = 0;
	struct buffer_cb *bcbs;
	struct ip_load_pool_24xx *pkt = NULL;
	struct risc_rec_entry *rentry = NULL;

	flags = 0;
	unused = 0;

	if (!ha_locked)
		spin_lock_irqsave(&ha->hw->hardware_lock, flags);

	bcbs = ha->ip.receive_buffers;
	i = 0; /* Need to initalize out of while */
	while (1) {
		for (; i < ha->ip.max_receive_buffers; i++, bcbs++)
			if (!test_and_set_bit(BCB_RISC_OWNS_BUFFER,
			    &bcbs->state))
				break;

		if (i == ha->ip.max_receive_buffers)
			break;

		if (!pkt) {
			pkt = qla2x00_req_pkt(ha);
			if (!pkt) {
				ql_dbg(ql_dbg_disc, ha, 0x0, "%s(%ld): failed to allocate "
				    "IP resource IOCB.\n", __func__,
				    ha->host_no);
				clear_bit(BCB_RISC_OWNS_BUFFER, &bcbs->state);
				break;
			}
			pkt->entry_type = IP_LOAD_POOL_24XX;
			rentry = pkt->buffers;
		}
		ha->ip.rec_entries_in++;

		rentry->handle = bcbs->handle;
		rentry->data_addr_low = cpu_to_le32(LSD(bcbs->skb_data_dma));
		rentry->data_addr_high = cpu_to_le32(MSD(bcbs->skb_data_dma));
		rentry++;

		pkt->buffer_count++;
		if (pkt->buffer_count == IP_POOL_BUFFERS) {
ql_dbg(ql_dbg_disc, ha, 0x0, "qla24xx_add_buffers() %d (%d,%d,%d,%d)\n",pkt->buffer_count,pkt->buffers[0].handle,pkt->buffers[1].handle,pkt->buffers[2].handle,pkt->buffers[3].handle);
			wmb();
			qla2x00_isp_cmd(ha);
			pkt = NULL;
		}
	}

	if (pkt) {
ql_dbg(ql_dbg_disc, ha, 0x0, "qla24xx_add_buffers() %d (%d,%d,%d,%d)\n",pkt->buffer_count,pkt->buffers[0].handle,pkt->buffers[1].handle,pkt->buffers[2].handle,pkt->buffers[3].handle);
		wmb();
		qla2x00_isp_cmd(ha);
	}

	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hw->hardware_lock, flags);
}

static int
qla24xx_ip_initialize(scsi_qla_host_t *ha)
{
	int status;
	static mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct ip_init_cb_24xx *ipinit_cb;
	dma_addr_t ipinit_cb_dma;

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: enter\n", __func__);

	status = 0;

	/* Wait for a ready state from the adapter */
	while (!ha->flags.init_done || ha->hw->dpc_active) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}

	/* Setup IP initialization control block */
	ipinit_cb = pci_alloc_consistent(ha->hw->pdev,
	    sizeof(struct ip_init_cb_24xx), &ipinit_cb_dma);
	if (ipinit_cb) {
		memset(ipinit_cb, 0, sizeof(struct ip_init_cb_24xx));
		ipinit_cb->version = IPICB_VERSION;
		ipinit_cb->firmware_options = __constant_cpu_to_le16(BIT_2);
		ipinit_cb->header_size = cpu_to_le16(ha->ip.header_size);
		ipinit_cb->mtu = cpu_to_le16((uint16_t) ha->ip.mtu);
		ipinit_cb->receive_buffer_size =
		    cpu_to_le16((uint16_t) ha->ip.receive_buff_data_size);
		ipinit_cb->low_water_mark =
		    __constant_cpu_to_le16(IPICB_LOW_WATER_MARK);
		ipinit_cb->container_count =
		    __constant_cpu_to_le16(IPICB_BUFFER_CONTAINER_COUNT);

		/* Issue mailbox command to initialize IP firmware */
		mcp->mb[0] = MBC_INITIALIZE_IP;
		mcp->mb[2] = MSW(ipinit_cb_dma);
		mcp->mb[3] = LSW(ipinit_cb_dma);
		mcp->mb[6] = MSW(MSD(ipinit_cb_dma));
		mcp->mb[7] = LSW(MSD(ipinit_cb_dma));
		mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->tov = 30;
		mcp->buf_size = sizeof(struct ip_init_cb);
		mcp->flags = MBX_DMA_OUT;

		status = qla2x00_mailbox_command(ha, mcp);
		if (status == QL_STATUS_SUCCESS) {
			/* IP initialization successful */
			ql_dbg(ql_dbg_disc, ha, 0x0, "%s: successful\n", __func__);

			ha->ip.flags.enable_ip = 1;

			qla24xx_add_buffers(ha, 0, 0);

			/* Force database update */
			set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
			set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
			set_bit(REGISTER_FC4_NEEDED, &ha->dpc_flags);

			/* qla2x00_loop_resync(ha); */
// TODO... reinstate...
//			if (ha->dpc_wait && !ha->hw->dpc_active) {
//				up(ha->dpc_wait);
//			}
			status = 1;
		} else {
			ql_dbg(ql_dbg_disc, ha, 0x0, "%s: MBC_INITIALIZE_IP failed %x MB0 "
			    "%x\n", __func__, status, mcp->mb[0]);
			status = 0;
		}
		pci_free_consistent(ha->hw->pdev, sizeof(struct ip_init_cb_24xx),
		    ipinit_cb, ipinit_cb_dma);

	} else {
		ql_dbg(ql_dbg_disc, ha, 0x0, "%s: memory allocation error\n", __func__);
	}

	return status;
}

#if 0

/**
 * qla2x00_ip_send_complete() - Handle IP send completion.
 * @ha: SCSI driver HA context
 * @handle: handle to completed send_cb
 * @comp_status: Firmware completion status of send_cb
 *
 * Upon cleanup of the internal active-scb queue, the IP driver is notified of
 * the completion.
 */
void
qla2x00_ip_send_complete(scsi_qla_host_t *ha,
			 uint32_t handle, uint16_t comp_status)
{
	struct send_cb *scb;

	/* Set packet pointer from queue entry handle */
	if (handle < MAX_SEND_PACKETS) {
		scb = ha->active_scb_q[handle];
		if (scb) {
			ha->ipreq_cnt--;
			ha->active_scb_q[handle] = NULL;

			scb->comp_status = comp_status;
			pci_unmap_single(ha->pdev,
					 scb->skb_data_dma,
					 scb->skb->len, PCI_DMA_TODEVICE);

			/* Return send packet to IP driver */
			ha->send_completion_routine(scb);
			return;
		}
	}

	/* Invalid handle from RISC, reset RISC firmware */
	printk(KERN_WARNING
	       "%s: Bad IP send handle %x - aborting ISP\n", __func__, handle);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
}

#endif


void
qla24xx_ip_send_complete(scsi_qla_host_t *ha, uint32_t handle,
    uint16_t comp_status)
{
	struct send_cb *scb;

ql_dbg(ql_dbg_disc, ha, 0x0, "qla24xx_ip_send_complete() handle=%d\n",handle);
	/* Set packet pointer from queue entry handle */
	if (handle < MAX_SEND_PACKETS) {
		scb = ha->ip.active_scb_q[handle];
		if (scb) {
			ha->ip.ipreq_cnt--;
			ha->ip.active_scb_q[handle] = NULL;

			scb->comp_status = comp_status;
			pci_unmap_single(ha->hw->pdev, scb->skb_data_dma,
			    scb->skb->len, PCI_DMA_TODEVICE);

			/* Return send packet to IP driver */
			ha->ip.send_completion_routine(scb);
			return;
		}
	}

	/* Invalid handle from RISC, reset RISC firmware */
	printk(KERN_WARNING
	       "%s: Bad IP send handle %x - aborting ISP\n", __func__, handle);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
}

#if 0

/**
 * qla2x00_ip_receive() - Handle IP receive IOCB.
 * @ha: SCSI driver HA context
 * @pkt: RISC IP receive packet
 *
 * Upon preparation of one or more buffer_cbs, the IP driver is notified of
 * the received packet.
 */
void
qla2x00_ip_receive(scsi_qla_host_t *ha, struct ip_rec_entry *iprec_entry)
{
	uint32_t handle;
	uint32_t packet_size;
	uint16_t linked_bcb_cnt;
	uint32_t rec_data_size;
	uint16_t comp_status;
	struct buffer_cb *bcb;
	struct buffer_cb *nbcb;

	comp_status = le16_to_cpu(iprec_entry->comp_status);

	/* If split buffer, set header size for 1st buffer */
	if (comp_status & IPREC_STATUS_SPLIT_BUFFER)
		rec_data_size = ha->header_size;
	else
		rec_data_size = ha->receive_buff_data_size;

	handle = iprec_entry->buffer_handles[0];
	if (handle >= ha->max_receive_buffers) {
		/* Invalid handle from RISC, reset RISC firmware */
		printk(KERN_WARNING
		       "%s: Bad IP buffer handle %x (> buffer_count)...Post "
		       "ISP Abort\n", __func__, handle);
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	bcb = &ha->receive_buffers[handle];

	if (!test_and_clear_bit(BCB_RISC_OWNS_BUFFER, &bcb->state)) {
		/* Invalid handle from RISC, reset RISC firmware */
		printk(KERN_WARNING
		       "%s: Bad IP buffer handle %x (!RISC_owned)...Post "
		       "ISP Abort\n", __func__, handle);
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	packet_size = le16_to_cpu(iprec_entry->sequence_length);
	bcb->comp_status = comp_status;
	bcb->packet_size = packet_size;
	nbcb = bcb;

	/* Prepare any linked buffers */
	for (linked_bcb_cnt = 1;; linked_bcb_cnt++) {
		if (packet_size > rec_data_size) {
			nbcb->rec_data_size = rec_data_size;
			packet_size -= rec_data_size;

			/*
			 * If split buffer, only use header size on 1st buffer
			 */
			rec_data_size = ha->receive_buff_data_size;

			handle = iprec_entry->buffer_handles[linked_bcb_cnt];
			if (handle >= ha->max_receive_buffers) {
				/*
				 * Invalid handle from RISC reset RISC firmware
				 */
				printk(KERN_WARNING
				       "%s: Bad IP buffer handle %x (> "
				       "buffer_count - PS)...Post ISP Abort\n",
				       __func__, handle);
				set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
				return;
			}
			nbcb->next_bcb = &ha->receive_buffers[handle];
			nbcb = nbcb->next_bcb;

			if (!test_and_clear_bit(BCB_RISC_OWNS_BUFFER,
						&nbcb->state)) {
				/*
				 * Invalid handle from RISC reset RISC firmware
				 */
				printk(KERN_WARNING
				       "%s: Bad IP buffer handle %x "
				       "(!RISC_owned - PS)...Post ISP Abort\n",
				       __func__, handle);
				set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
				return;
			}
		} else {
			/* Single buffer_cb */
			nbcb->rec_data_size = packet_size;
			nbcb->next_bcb = NULL;
			break;
		}
	}

	/* Check for incoming ARP packet with matching IP address */
	if (le16_to_cpu(iprec_entry->service_class) == 0) {
		fc_port_t *fcport;
		struct packet_header *packethdr;

		packethdr = (struct packet_header *)bcb->skb_data;

		/* Scan list of IP devices to see if login needed */
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (!memcmp(&fcport->port_name[2],
				    packethdr->networkh.s.na.addr, ETH_ALEN)) {
				break;
			}
		}
	}

	/* Pass received packet to IP driver */
	bcb->linked_bcb_cnt = linked_bcb_cnt;
	ha->receive_packets_routine(ha->receive_packets_context, bcb);

	/* Keep track of RISC buffer pointer (for IP reinit) */
	ha->rec_entries_out += linked_bcb_cnt;
	if (ha->rec_entries_out >= IP_BUFFER_QUEUE_DEPTH)
		ha->rec_entries_out -= IP_BUFFER_QUEUE_DEPTH;
}

#endif

void
qla24xx_ip_receive(scsi_qla_host_t *ha, struct ip_rec_entry_24xx *iprec_entry)
{
	uint32_t handle;
	uint32_t packet_size;
	uint16_t linked_bcb_cnt;
	uint32_t rec_data_size;
	uint16_t comp_status;
	struct buffer_cb *bcb;
	struct buffer_cb *nbcb;

	comp_status = le16_to_cpu(iprec_entry->comp_status);

	/* If split buffer, set header size for 1st buffer */
	if (comp_status & BIT_0)
		rec_data_size = ha->ip.header_size;
	else
		rec_data_size = ha->ip.receive_buff_data_size;

	handle = iprec_entry->buffer_handles[0];

	if (handle >= ha->ip.max_receive_buffers) {
		/* Invalid handle from RISC, reset RISC firmware */
		printk(KERN_WARNING
		    "%s: Bad IP buffer handle %x (> buffer_count)...Post ISP "
		    "Abort\n", __func__, handle);
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	bcb = &ha->ip.receive_buffers[handle];

	if (!test_and_clear_bit(BCB_RISC_OWNS_BUFFER, &bcb->state)) {
		/* Invalid handle from RISC, reset RISC firmware */
		printk(KERN_WARNING
		    "%s: Bad IP buffer handle %x (!RISC_owned)...Post ISP "
		    "Abort\n", __func__, handle);
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	packet_size = le16_to_cpu(iprec_entry->sequence_length);
	bcb->comp_status = comp_status;
	bcb->packet_size = packet_size;
	nbcb = bcb;

ql_dbg(ql_dbg_disc, ha, 0x0, "%s: comp_status=%d hdr_size=%d recv_buff_data_size=%d handles=%d,%d packet_size=%d\n", __func__,comp_status,ha->ip.header_size,ha->ip.receive_buff_data_size,handle,iprec_entry->buffer_handles[1],packet_size);

	/* Prepare any linked buffers */
	for (linked_bcb_cnt = 0; linked_bcb_cnt < IP_RCV_BUFFERS;
	    linked_bcb_cnt++) {
		if (packet_size > rec_data_size) {
			nbcb->rec_data_size = rec_data_size;
			packet_size -= rec_data_size;

			/*
			 * If split buffer, only use header size on 1st buffer
			 */
			rec_data_size = ha->ip.receive_buff_data_size;

			handle = iprec_entry->buffer_handles[linked_bcb_cnt];
			if (handle >= ha->ip.max_receive_buffers) {
				/*
				 * Invalid handle from RISC reset RISC firmware
				 */
				printk(KERN_WARNING
				    "%s: Bad IP buffer handle %x (> "
				    "buffer_count - PS)...Post ISP Abort\n",
				    __func__, handle);
				set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
				return;
			}
			nbcb->next_bcb = &ha->ip.receive_buffers[handle];
			nbcb = nbcb->next_bcb;

			if (!test_and_clear_bit(BCB_RISC_OWNS_BUFFER,
			    &nbcb->state)) {
				/*
				 * Invalid handle from RISC reset RISC firmware
				 */
				printk(KERN_WARNING
				    "%s: Bad IP buffer handle %x "
				    "(!RISC_owned - PS)...Post ISP Abort\n",
				    __func__, handle);
				set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
				return;
			}
		} else {
			/* Single buffer_cb */
			nbcb->rec_data_size = packet_size;
			nbcb->next_bcb = NULL;
			break;
		}
	}

	/* Check for incoming ARP packet with matching IP address */
	if (le16_to_cpu(iprec_entry->service_class) == 0) {
		fc_port_t *fcport;
		struct packet_header *packethdr;

		packethdr = (struct packet_header *)bcb->skb_data;

		/* Scan list of IP devices to see if login needed */
		list_for_each_entry(fcport, &ha->vp_fcports, list)
			if (!memcmp(&fcport->port_name[2],
			    packethdr->networkh.s.na.addr, ETH_ALEN))
				break;
	}

	/* Pass received packet to IP driver */
	bcb->linked_bcb_cnt = linked_bcb_cnt + 1;
	ha->ip.receive_packets_routine(ha->ip.receive_packets_context, bcb);

	/* Keep track of RISC buffer pointer (for IP reinit) */
	ha->ip.rec_entries_out += linked_bcb_cnt + 1;
	if (ha->ip.rec_entries_out >= IP_BUFFER_QUEUE_DEPTH)
		ha->ip.rec_entries_out -= IP_BUFFER_QUEUE_DEPTH;
}


/**
 * qla2x00_convert_to_arp() - Convert an IP send packet to an ARP packet
 * @ha: SCSI driver HA context
 * @scb: The send_cb structure to convert
 *
 * Returns 1 if conversion successful.
 */
static int
qla2x00_convert_to_arp(scsi_qla_host_t *ha, struct send_cb *scb)
{
	struct sk_buff *skb;
	struct packet_header *packethdr;
	struct arp_header *arphdr;
	struct ip_header *iphdr;

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: convert packet to ARP\n", __func__);

	skb = scb->skb;
	packethdr = scb->header;
	arphdr = (struct arp_header *)skb->data;
	iphdr = (struct ip_header *)skb->data;

	if (packethdr->snaph.ethertype == __constant_htons(ETH_P_IP)) {
		/* Convert IP packet to ARP packet */
		packethdr->networkh.d.na.naa = NAA_IEEE_MAC_TYPE;
		packethdr->networkh.d.na.unused = 0;
		memcpy(packethdr->networkh.d.na.addr,
		       hwbroadcast_addr, ETH_ALEN);
		packethdr->snaph.ethertype = __constant_htons(ETH_P_ARP);

		arphdr->ar_tip = iphdr->iph.daddr;
		arphdr->ar_sip = iphdr->iph.saddr;
		arphdr->arph.ar_hrd = __constant_htons(ARPHRD_IEEE802);
		arphdr->arph.ar_pro = __constant_htons(ETH_P_IP);
		arphdr->arph.ar_hln = ETH_ALEN;
		arphdr->arph.ar_pln = sizeof(iphdr->iph.daddr);	/* 4 */
		arphdr->arph.ar_op = __constant_htons(ARPOP_REQUEST);
		memcpy(arphdr->ar_sha, packethdr->networkh.s.na.addr, ETH_ALEN);
		memset(arphdr->ar_tha, 0, ETH_ALEN);

		skb->len = sizeof(struct arp_header);

		return 1;
	} else {
		return 0;
	}
	return 1;
}

/**
 * qla2x00_get_ip_loopid() - Retrieve loop id of an IP device.
 * @ha: SCSI driver HA context
 * @packethdr: IP device to remove
 * @loop_id: loop id of discovered device
 *
 * This routine will interrogate the packet header to determine if the sender is
 * in the list of active IP devices.  The first two bytes of the destination
 * address will be modified to match the port name stored in the active IP
 * device list.
 *
 * Returns 1 if a valid loop id is returned.
 */
static int
qla2x00_get_ip_loopid(scsi_qla_host_t *ha,
		      struct packet_header *packethdr, uint16_t * loop_id)
{
	fc_port_t *fcport;

	/* Scan list of logged in IP devices for match */
	list_for_each_entry(fcport, &ha->vp_fcports, list) {
		if (memcmp(&fcport->port_name[2],
			   &(packethdr->networkh.d.fcaddr[2]), ETH_ALEN))
			continue;

		/* Found match, return loop ID  */
		*loop_id = fcport->loop_id;

		/* Update first 2 bytes of port name */
		packethdr->networkh.d.fcaddr[0] = fcport->port_name[0];
		packethdr->networkh.d.fcaddr[1] = fcport->port_name[1];

		return 1;
	}

	/* Check for broadcast or multicast packet */
	if (!memcmp(packethdr->networkh.d.na.addr, hwbroadcast_addr,
	    ETH_ALEN) || (packethdr->networkh.d.na.addr[0] & 0x01)) {
		/* Broadcast packet, return broadcast loop ID  */
		if (IS_QLA24XX(ha->hw) || IS_QLA54XX(ha->hw)) {
			*loop_id = BROADCAST_4G;
		} else {
			*loop_id = BROADCAST;
		}

		/* Update destination NAA of header */
		packethdr->networkh.d.na.naa = NAA_IEEE_MAC_TYPE;
		packethdr->networkh.d.na.unused = 0;
		return 1;
	}

	/* TODO */
	/* Try sending FARP IOCB to request login */

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: ID not found for "
		       "XX XX %02x %02x %02x %02x %02x %02x\n",
		       __func__,
		       packethdr->networkh.d.na.addr[0],
		       packethdr->networkh.d.na.addr[1],
		       packethdr->networkh.d.na.addr[2],
		       packethdr->networkh.d.na.addr[3],
		       packethdr->networkh.d.na.addr[4],
		       packethdr->networkh.d.na.addr[5]);

	return 0;
}

/**
 * qla2x00_ip_enable() - Create IP-driver/SCSI-driver IP connection.
 * @ha: SCSI driver HA context
 * @enable_data: bd_enable data describing the IP connection
 *
 * This routine is called by the IP driver to enable an IP connection to the
 * SCSI driver and to pass in IP driver parameters.
 *
 * The HA context is propagated with the specified @enable_data and the
 * Firmware is initialized for IP support.
 *
 * Returns 1 if the IP connection was successfully enabled.
 */
static int
qla2x00_ip_enable(scsi_qla_host_t *ha, struct bd_enable *enable_data)
{
	int status;

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: enable adapter %ld\n", __func__, ha->host_no);

	status = 0;

	/* Verify structure size and version and adapter online */
	if (!(ha->flags.online) ||
	    (enable_data->length != BDE_LENGTH) ||
	    (enable_data->version != BDE_VERSION)) {

		ql_dbg(ql_dbg_disc, ha, 0x0, "%s: incompatable structure or offline\n",
		    __func__);
		return status;
	}

	/* Save parameters from IP driver */
	ha->ip.mtu = enable_data->mtu;
	ha->ip.header_size = enable_data->header_size;
	ha->ip.receive_buffers = enable_data->receive_buffers;
	ha->ip.max_receive_buffers = enable_data->max_receive_buffers;
	ha->ip.receive_buff_data_size = enable_data->receive_buff_data_size;
	if (test_bit(BDE_NOTIFY_ROUTINE, &enable_data->options)) {
		ha->ip.notify_routine = enable_data->notify_routine;
		ha->ip.notify_context = enable_data->notify_context;
	}
	ha->ip.send_completion_routine = enable_data->send_completion_routine;
	ha->ip.receive_packets_routine = enable_data->receive_packets_routine;
	ha->ip.receive_packets_context = enable_data->receive_packets_context;

	/* Enable RISC IP support */
	if (IS_QLA24XX(ha->hw) || IS_QLA54XX(ha->hw))
		status = qla24xx_ip_initialize(ha);
	else
		//status = qla2x00_ip_initialize(ha);
		status = 0; // only qla24xx supported
	if (!status) {
		ql_dbg(ql_dbg_disc, ha, 0x0, "%s: IP initialization failed", __func__);
		ha->ip.notify_routine = NULL;
	}
	return status;
}

/**
 * qla2x00_ip_disable() - Remove IP-driver/SCSI-driver IP connection.
 * @ha: SCSI driver HA context
 *
 * This routine is called by the IP driver to disable a previously created IP
 * connection.
 *
 * A Firmware call to disable IP support is issued.
 */
static void
qla2x00_ip_disable(scsi_qla_host_t *ha)
{
	int rval;
	static mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: disable adapter %ld\n", __func__, ha->host_no);

//
	{
		struct fc_host_statistics* stat = qla2x00_get_fc_host_stats_foo(ha);
		printk("XXXXX got statistics %p\n",stat);
		printk("XXXXX %llu %llu %llu %llu %llu\n",stat->seconds_since_last_reset,stat->tx_frames,stat->tx_words,stat->rx_frames,stat->rx_words);
		printk("XXXXX %llu %llu %llu %llu %llu\n",stat->lip_count,stat->nos_count,stat->error_frames,stat->dumped_frames,stat->link_failure_count);
		printk("XXXXX %llu %llu %llu %llu %llu\n",stat->loss_of_sync_count,stat->loss_of_signal_count,stat->prim_seq_protocol_err_count,stat->invalid_tx_word_count,stat->invalid_crc_count);

	}
//


	/* Wait for a ready state from the adapter */
	while (!ha->flags.init_done || ha->hw->dpc_active) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}

	/* Disable IP support */
	ha->ip.flags.enable_ip = 0;

	mcp->mb[0] = MBC_DISABLE_IP;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(ha, mcp);
	if (rval == QL_STATUS_SUCCESS) {
		/* IP disabled successful */
		ql_dbg(ql_dbg_disc, ha, 0x0, "%s: successful\n", __func__);
	} else {
		ql_dbg(ql_dbg_disc, ha, 0x0, 
			       "%s: MBC_DISABLE_IP failed\n", __func__);
	}

	/* Reset IP parameters */
	ha->ip.rec_entries_in = 0;
	ha->ip.rec_entries_out = 0;
	ha->ip.notify_routine = NULL;
}

#if 0

/**
 * qla2x00_add_buffers() - Adds buffers to the receive buffer queue.
 * @ha: SCSI driver HA context
 * @rec_count: The number of receive buffers to add to the queue
 * @ha_locked: Flag indicating if the function is called with the hardware lock
 *
 * This routine is called by the IP driver to pass new buffers to the receive
 * buffer queue.
 */
static void
qla2x00_add_buffers(scsi_qla_host_t *ha, uint16_t rec_count, int ha_locked)
{
	int i;
	uint16_t rec_in;
	uint16_t handle;
	unsigned long flags = 0;
	device_reg_t __iomem *reg;
	struct risc_rec_entry *risc_rec_q;
	struct buffer_cb *bcbs;

	flags = 0;
	risc_rec_q = ha->risc_rec_q;
	rec_in = ha->rec_entries_in;
	bcbs = ha->receive_buffers;
	/* Set RISC owns buffer flag on new entries */
	for (i = 0; i < rec_count; i++) {
		handle = risc_rec_q[rec_in].handle;
		set_bit(BCB_RISC_OWNS_BUFFER, &(bcbs[handle].state));
		if (rec_in < IP_BUFFER_QUEUE_DEPTH - 1)
			rec_in++;
		else
			rec_in = 0;
	}

	/* Update RISC buffer pointer */
	if (!ha_locked)
		spin_lock_irqsave(&ha->hardware_lock, flags);

	reg = ha->iobase;

	WRT_MAILBOX_REG(ha, reg, 8, rec_in);
	RD_MAILBOX_REG(ha, reg, 8);
	ha->rec_entries_in = rec_in;

	if (!ha_locked)
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

#endif

#if 0

/**
 * qla2x00_send_packet() - Transmit a send_cb.
 * @ha: SCSI driver HA context
 * @scb: The send_cb structure to send
 *
 * This routine is called by the IP driver to pass @scb (IP packet) to the ISP
 * for transmission.
 *
 * Returns QL_STATUS_SUCCESS if @scb was sent, QL_STATUS_RESOURCE_ERROR if the
 * RISC was too busy to send, or QL_STATUS_ERROR.
 */
static int
qla2x00_send_packet(scsi_qla_host_t *ha, struct send_cb *scb)
{
	int i;
	uint16_t cnt;
	uint32_t handle;
	unsigned long flags;
	struct ip_cmd_entry *ipcmd_entry;
	struct sk_buff *skb;
	device_reg_t __iomem *reg;
	uint16_t loop_id;

	skb = scb->skb;
	reg = ha->iobase;

	/* Check adapter state */
	if (!ha->flags.online) {
		return QLA_FUNCTION_FAILED;
	}

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) != QLA_SUCCESS) {
			printk(KERN_WARNING
			       "%s: Unable to issue marker.\n", __func__);
			return QLA_FUNCTION_FAILED;
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	if (ha->req_q_cnt < 4) {
		/* Update number of free request entries */
		cnt = RD_REG_WORD_RELAXED(ISP_REQ_Q_OUT(ha, reg));
		if (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
			    (ha->req_ring_index - cnt);
	}

	if (ha->req_q_cnt >= 4) {
		/* Get tag handle for command */
		handle = ha->current_scb_q_idx;
		for (i = 0; i < MAX_SEND_PACKETS; i++) {
			handle++;
			if (handle == MAX_SEND_PACKETS)
				handle = 0;
			if (ha->active_scb_q[handle] == NULL) {
				ha->current_scb_q_idx = handle;
				goto found_handle;
			}
		}
	}

	/* Low on resources, try again later */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	printk(KERN_WARNING
	       "%s: Low on resources, try again later...\n", __func__);

	return QLA_MEMORY_ALLOC_FAILED;

found_handle:

	/* Build ISP command packet */
	ipcmd_entry = (struct ip_cmd_entry *)ha->request_ring_ptr;

	*((uint32_t *) (&ipcmd_entry->entry_type)) =
	    __constant_cpu_to_le32(ET_IP_COMMAND_64 | (1 << 8));

	ipcmd_entry->handle = handle;
	memset((uint32_t *)ipcmd_entry + 2, 0, REQUEST_ENTRY_SIZE - 8);

	/* Get destination loop ID for packet */
	if (!qla2x00_get_ip_loopid(ha, scb->header, &loop_id)) {
		/* Failed to get loop ID, convert packet to ARP */
		if (qla2x00_convert_to_arp(ha, scb)) {
			/* Broadcast ARP */
			loop_id = BROADCAST;
		} else {
			/* Return packet */
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			printk(KERN_WARNING
			       "%s: Unable to determine loop id for "
			       "destination.\n", __func__);
			return QLA_FUNCTION_FAILED;
		}
	}

	/* Default five second firmware timeout */
	ipcmd_entry->loop_id = cpu_to_le16(loop_id);
	ipcmd_entry->timeout = __constant_cpu_to_le16(5);
	ipcmd_entry->control_flags = __constant_cpu_to_le16(CF_WRITE);
	ipcmd_entry->reserved_2 = 0;
	ipcmd_entry->service_class = __constant_cpu_to_le16(0);
	ipcmd_entry->data_seg_count = __constant_cpu_to_le16(2);
	scb->skb_data_dma = pci_map_single(ha->pdev, skb->data, skb->len,
					   PCI_DMA_TODEVICE);
	ipcmd_entry->dseg_0_address[0] = cpu_to_le32(LSD(scb->header_dma));
	ipcmd_entry->dseg_0_address[1] = cpu_to_le32(MSD(scb->header_dma));
	ipcmd_entry->dseg_0_length =
	    __constant_cpu_to_le32(sizeof(struct packet_header));
	ipcmd_entry->dseg_1_address[0] = cpu_to_le32(LSD(scb->skb_data_dma));
	ipcmd_entry->dseg_1_address[1] = cpu_to_le32(MSD(scb->skb_data_dma));
	ipcmd_entry->dseg_1_length = cpu_to_le32(skb->len);
	ipcmd_entry->byte_count =
	    cpu_to_le32(skb->len + sizeof(struct packet_header));

	wmb();
	
	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	ha->ipreq_cnt++;
	ha->req_q_cnt--;
	ha->active_scb_q[handle] = scb;
	/* Set chip new ring index. */
	WRT_REG_WORD(ISP_REQ_Q_IN(ha, reg), ha->req_ring_index);
	RD_REG_WORD_RELAXED(ISP_REQ_Q_IN(ha, reg));     /* PCI Posting. */

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QL_STATUS_SUCCESS;
}

#endif

static int
qla24xx_send_packet(scsi_qla_host_t *ha, struct send_cb *scb)
{
	int i;
	uint16_t cnt;
	uint16_t loop_id;
	uint32_t handle;
	unsigned long flags;
	struct ip_cmd_entry_24xx *ipcmd_entry;
	cont_a64_entry_t *ipcmd_cont;
	struct sk_buff *skb;
	struct device_reg_24xx __iomem *reg;

ql_dbg(ql_dbg_disc, ha, 0x0, "qla24xx_send_packet() marker_needed=%d\n",ha->marker_needed);
	skb = scb->skb;
	reg = (struct device_reg_24xx __iomem *)ha->hw->iobase;

	/* Check adapter state */
	if (!ha->flags.online) {
		return QLA_FUNCTION_FAILED;
	}

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qla2x00_marker(ha, ha->hw->req_q_map[0], ha->hw->rsp_q_map[0], 
				0, 0, MK_SYNC_ALL) != QLA_SUCCESS) {
			printk(KERN_WARNING
			       "%s: Unable to issue marker.\n", __func__);
			return QLA_FUNCTION_FAILED;
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hw->hardware_lock, flags);

#if 0
// noddy (failed attempt to limit multiple outstanding IP requests)
if (ha->ip.ipreq_cnt>=2)
{
	spin_unlock_irqrestore(&ha->hw->hardware_lock, flags);
	//FOO return QL_STATUS_RESOURCE_ERROR;
	return QLA_MEMORY_ALLOC_FAILED;
}
#endif

	if (ha->req->cnt < 4) {
		/* Update number of free request entries */
		cnt = (uint16_t)RD_REG_DWORD_RELAXED(&reg->req_q_out);
		if (ha->req->ring_index < cnt)
			ha->req->cnt = cnt - ha->req->ring_index;
		else
			ha->req->cnt = ha->req->length -
			    (ha->req->ring_index - cnt);
	}

	if (ha->req->cnt >= 4) {
		/* Get tag handle for command */
		handle = ha->ip.current_scb_q_idx;
		for (i = 0; i < MAX_SEND_PACKETS; i++) {
			handle++;
			if (handle == MAX_SEND_PACKETS)
				handle = 0;
			if (ha->ip.active_scb_q[handle] == NULL) {
				ha->ip.current_scb_q_idx = handle;
				goto found_handle;
			}
		}
	}

	/* Low on resources, try again later */
	spin_unlock_irqrestore(&ha->hw->hardware_lock, flags);
	printk(KERN_WARNING
	       "%s: Low on resources, try again later...\n", __func__);

	return QLA_MEMORY_ALLOC_FAILED;

found_handle:

	/* Build ISP command packet */
	ipcmd_entry = (struct ip_cmd_entry_24xx *)ha->req->ring_ptr;

	/* Set entry type and entry count */
	*((uint32_t *) (&ipcmd_entry->entry_type)) =
	    __constant_cpu_to_le32(IP_COMMAND_24XX | (2 << 8));

	ipcmd_entry->handle = handle;
	memset((uint32_t *)ipcmd_entry + 2, 0, REQUEST_ENTRY_SIZE - 8);

	/* Get destination loop ID for packet */
	if (!qla2x00_get_ip_loopid(ha, scb->header, &loop_id)) {
		/* Failed to get loop ID, convert packet to ARP */
		if (qla2x00_convert_to_arp(ha, scb)) {
			/* Broadcast ARP */
			loop_id = BROADCAST_4G;
		} else {
			/* Return packet */
			spin_unlock_irqrestore(&ha->hw->hardware_lock, flags);
			printk(KERN_WARNING
			       "%s: Unable to determine loop id for "
			       "destination.\n", __func__);
			return QLA_FUNCTION_FAILED;
		}
	}

	/* Default five second firmware timeout */
	ipcmd_entry->nport_handle = cpu_to_le16(loop_id);
	ipcmd_entry->timeout = __constant_cpu_to_le16(5);
	ipcmd_entry->dseg_count = __constant_cpu_to_le16(2);

	ipcmd_entry->control_flags = __constant_cpu_to_le16(BIT_0);
	ipcmd_entry->fhdr_control_flags = __constant_cpu_to_le16(BIT_4|BIT_5);
	ipcmd_entry->byte_count =
	    cpu_to_le32(skb->len + sizeof(struct packet_header));

	scb->skb_data_dma = pci_map_single(ha->hw->pdev, skb->data, skb->len,
	    PCI_DMA_TODEVICE);
	ipcmd_entry->dseg_0_address[0] = cpu_to_le32(LSD(scb->header_dma));
	ipcmd_entry->dseg_0_address[1] = cpu_to_le32(MSD(scb->header_dma));
	ipcmd_entry->dseg_0_length =
	    __constant_cpu_to_le32(sizeof(struct packet_header));

	/* Adjust ring index. */
	ha->req->ring_index++;
	if (ha->req->ring_index == ha->req->length) {
		ha->req->ring_index = 0;
		ha->req->ring_ptr = ha->req->ring;
	} else
		ha->req->ring_ptr++;
	ha->req->cnt--;

	/* Build continuation packet */
	ipcmd_cont = (cont_a64_entry_t *)ha->req->ring_ptr;
	memset(ipcmd_cont, 0, REQUEST_ENTRY_SIZE);
	*((uint32_t *) (&ipcmd_cont->entry_type)) =
	    __constant_cpu_to_le32(CONTINUE_A64_TYPE);

	ipcmd_cont->dseg_0_address[0] = cpu_to_le32(LSD(scb->skb_data_dma));
	ipcmd_cont->dseg_0_address[1] = cpu_to_le32(MSD(scb->skb_data_dma));
	ipcmd_cont->dseg_0_length = cpu_to_le32(skb->len);
	wmb();

	/* Adjust ring index. */
	ha->req->ring_index++;
	if (ha->req->ring_index == ha->req->length) {
		ha->req->ring_index = 0;
		ha->req->ring_ptr = ha->req->ring;
	} else
		ha->req->ring_ptr++;
	ha->req->cnt--;

	ha->ip.ipreq_cnt++;
	ha->ip.active_scb_q[handle] = scb;

ql_dbg(ql_dbg_disc, ha, 0x0, "qla24xx_send_packet() handle=%d byte_count=%d %d %d %d %d xx=%02x%02x %02x%02x\n",(unsigned int)ha->ip.current_scb_q_idx,
	(unsigned int)ipcmd_entry->byte_count,(unsigned int)ha->req->cnt,(unsigned int)ha->ip.ipreq_cnt,(unsigned int)ha->req->ring_index,(unsigned int)RD_REG_DWORD_RELAXED(&reg->req_q_out),
	(skb->len>100) ? skb->data[30] : 0,(skb->len>100) ? skb->data[31] : 0,(skb->len>100) ? skb->data[32] : 0,(skb->len>100) ? skb->data[33] : 0);
//FOO

	/* Set chip new ring index. */
	WRT_REG_DWORD(&reg->req_q_in, ha->req->ring_index);
	RD_REG_DWORD_RELAXED(&reg->req_q_in);           /* PCI Posting. */

	spin_unlock_irqrestore(&ha->hw->hardware_lock, flags);

	return QL_STATUS_SUCCESS;
}

/**
 * qla2x00_tx_timeout() - Handle transmission timeout.
 * @ha: SCSI driver HA context
 *
 * This routine is called by the IP driver to handle packet transmission
 * timeouts.
 *
 * Returns QL_STATUS_SUCCESS if timeout handling completed successfully.
 */
static int
qla2x00_tx_timeout(scsi_qla_host_t *ha)
{
	/* TODO: complete interface */

	/* Reset RISC firmware for basic recovery */
	printk(KERN_WARNING
	       "%s: A transmission timeout occured - aborting ISP\n", __func__);
	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

	return QL_STATUS_SUCCESS;
}

/**
 * qla2x00_ip_inquiry() - Discover IP-capable adapters.
 * @adapter_num: adapter number to check (instance)
 * @inq_data: return bd_inquiry data of the discovered adapter
 *
 * This routine is called by the IP driver to discover adapters that support IP
 * and to get adapter parameters from the SCSI driver.
 *
 * Returns 1 if the specified adapter supports IP.
 */
int
qla2x00_ip_inquiry(uint16_t adapter_num, struct bd_inquiry *inq_data)
{
	int found;
	scsi_qla_host_t *ha;
	int instance = 0;

	/* Verify structure size and version */
	if ((inq_data->length != BDI_LENGTH) ||
	    (inq_data->version != BDI_VERSION)) {
		ql_dbg(ql_dbg_disc, NULL, 0x0, "%s: incompatable structure\n", __func__);
		return 0;
	}

	/* Find the specified host adapter */
	found = 0;

	read_lock(&qla_hostlist_lock);
	list_for_each_entry(ha, &qla_hostlist, list) {
		if (instance++ == adapter_num) {
			found++;
			break;
		}
	}
	read_unlock(&qla_hostlist_lock);
 
	if (!found)
		return 0;
	if (!ha->flags.online)
		return 0;

	ql_dbg(ql_dbg_disc, ha, 0x0, "%s: found adapter %d\n", __func__, adapter_num);
	if (atomic_read(&ha->loop_state)==LOOP_UP)
	{
		ql_dbg(ql_dbg_disc, ha, 0x0, "%s: adapter %d LOOP_UP\n", __func__, adapter_num);
	}

	{
		{
                        /* Get consistent memory allocated for SNS commands */
                        ha->ip.risc_rec_q = dma_alloc_coherent(&ha->hw->pdev->dev,
                            IP_BUFFER_QUEUE_DEPTH *
                            sizeof(struct risc_rec_entry),
                            &ha->ip.risc_rec_q_dma, GFP_KERNEL);
                        if (ha->ip.risc_rec_q == NULL) {
                                /* error */
                        }
                        memset(ha->ip.risc_rec_q, 0, IP_BUFFER_QUEUE_DEPTH *
                            sizeof(struct risc_rec_entry));
                }
	}

	/* Return inquiry data to backdoor IP driver */
	set_bit(BDI_IP_SUPPORT, &inq_data->options);
	if (ha->hw->flags.enable_64bit_addressing)
		set_bit(BDI_64BIT_ADDRESSING, &inq_data->options);
	inq_data->ha = ha;
	inq_data->risc_rec_q = ha->ip.risc_rec_q;
	inq_data->risc_rec_q_size = IP_BUFFER_QUEUE_DEPTH;
	inq_data->link_speed = ha->hw->link_data_rate;
	memcpy(inq_data->port_name, ha->ip.ip_port_name, WWN_SIZE);
	inq_data->pdev = ha->hw->pdev;
	inq_data->ip_enable_routine = qla2x00_ip_enable;
	inq_data->ip_disable_routine = qla2x00_ip_disable;
	if (IS_QLA24XX(ha->hw) || IS_QLA54XX(ha->hw)) {
		set_bit(BDI_64BIT_ADDRESSING, &inq_data->options);
		inq_data->ip_add_buffers_routine = qla24xx_add_buffers;
		inq_data->ip_send_packet_routine = qla24xx_send_packet;
	} else {
		return 0; // We only implemented qla24xx
		//inq_data->ip_add_buffers_routine = qla2x00_add_buffers;
		//inq_data->ip_send_packet_routine = qla2x00_send_packet;
	}
	inq_data->ip_tx_timeout_routine = qla2x00_tx_timeout;

	return 1;
}
EXPORT_SYMBOL_GPL(qla2x00_ip_inquiry);
