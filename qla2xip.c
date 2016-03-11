/*
 * QLogic ISP2x00 IP network driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */

/****************************************************************************
              Please see revision.notes for revision history.
*****************************************************************************/

static const char *qla_name = "qla2xip";
static const char *qla_version = "2.00.00b1-j1";

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include <linux/config.h>
#endif
#include <linux/module.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
//#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>

#include "qla_def.h"
#include "qla_ip.h"		/* Common include file with scsi driver */
#include "qla2xip.h"

#ifdef LOG2CIRC
extern void qla2xxx_log2circ_init(void);
extern void qla2xxx_log2circ_exit(void);
#endif

/* Module command line parameters */
static int mtu = DEFAULT_MTU_SIZE;
static int buffers = DEFAULT_RECEIVE_BUFFERS;

module_param(mtu, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(mtu,
		 "Maximum transmission unit size "
		 "(min=" __MODULE_STRING(MIN_MTU_SIZE)
		 " max=" __MODULE_STRING(MAX_MTU_SIZE) ")");

module_param(buffers, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(buffers,
		 "Maximum number of receive buffers "
		 "(min=" __MODULE_STRING(MIN_RECEIVE_BUFFERS)
		 " max=" __MODULE_STRING(MAX_RECEIVE_BUFFERS) ")");

/* Backdoor entry points into qla2x00 driver */
extern int qla2x00_ip_inquiry(uint16_t, struct bd_inquiry *);

/**
 * qla2xip_driver_entry() - The starting address of the driver.
 */
static void
qla2xip_driver_entry(void)
{
	;
}

/**
 * qla2xip_display_info() - Prints basic driver information.
 *
 * Used mainly for debugging purposes.
 */
static void
qla2xip_display_info(void)
{
	printk(KERN_INFO
	       "%s: QLogic IP via Fibre Channel Network Driver for ISP2xxx\n",
	       qla_name);

	printk(KERN_INFO
	       "%s:    Driver Version %s, Entry point: %p\n",
	       qla_name, qla_version, qla2xip_driver_entry);
}

/**
 * qla2xip_display_dev_info() - Prints basic device information.
 * @dev: the device to interrogate
 */
static void
qla2xip_display_dev_info(struct net_device *dev)
{
#define LS_UNKNOWN      2
	static char *link_speeds[5] = { "1", "2", "?", "4", "10" };
	struct qla2xip_private *qdev = netdev_priv(dev);
	char *link_speed;

	/* Determine link speed from inquiry data */
	link_speed = link_speeds[LS_UNKNOWN];
	if (qdev->link_speed < 5)
		link_speed = link_speeds[qdev->link_speed];

	printk(KERN_INFO
	       "%s: Mapping interface %s to HBA "
	       "%02x%02x%02x%02x%02x%02x%02x%02x %sgb hdma%c.\n",
	       qla_name,
	       dev->name,
	       qdev->port_name[0],
	       qdev->port_name[1],
	       qdev->port_name[2],
	       qdev->port_name[3],
	       qdev->port_name[4],
	       qdev->port_name[5],
	       qdev->port_name[6],
	       qdev->port_name[7],
	       link_speed,
	       (test_bit(BDI_64BIT_ADDRESSING, &qdev->options) ? '+' : '-'));
}

/**
 * qla2xip_allocate_buffers() - Allocates and initializes network structures.
 * @dev: The device to initialize
 *
 * Returns 0 on success.
 */
static int
qla2xip_allocate_buffers(struct net_device *dev)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int i;
	struct sk_buff *skb;
	struct send_cb *scb;
	struct buffer_cb *bcb;
	struct packet_header *packethdr;
	unsigned long iter;

	/*
	 * Allocate/initialize queue of send control blocks for sending packets
	 * to the SCSI driver.
	 */

	if ((PAGE_SIZE / sizeof(struct packet_header)) < MAX_SEND_PACKETS) {
		printk(KERN_ERR
		       "%s: Unable to allocate space for packets %lx/%x\n",
		       qla_name, PAGE_SIZE / sizeof(struct packet_header),
		       MAX_SEND_PACKETS);
		return 1;
	}

	qdev->scb_header = pci_alloc_consistent(qdev->pdev, PAGE_SIZE,
						&qdev->scb_header_dma);
	if (!qdev->scb_header) {
		printk(KERN_ERR
		       "%s: Failed to allocate send_cb headers\n", qla_name);
		return 1;
	}

	for (i = 0, iter = 0; i < MAX_SEND_PACKETS;
	     i++, iter += sizeof(struct packet_header)) {
		scb = &qdev->send_buffers[i];

		scb->qdev = qdev;
		scb->header = (struct packet_header *)
		    (((__u8 *) qdev->scb_header) + iter);
		scb->header_dma = qdev->scb_header_dma + iter;

		/* Build Network and SNAP headers */
		packethdr = (struct packet_header *)scb->header;
		packethdr->networkh.s.na.naa = NAA_IEEE_MAC_TYPE;
		packethdr->networkh.s.na.unused = 0;
		memcpy(&packethdr->networkh.s.fcaddr[2], &qdev->port_name[2],
		       WWN_SIZE - 2);

		packethdr->snaph.dsap = LLC_SAP_IEEE_802DOT2;
		packethdr->snaph.ssap = LLC_SAP_IEEE_802DOT2;
		packethdr->snaph.llc = LLC_CONTROL;
		packethdr->snaph.protid[0] = SNAP_OUI;
		packethdr->snaph.protid[1] = SNAP_OUI;
		packethdr->snaph.protid[2] = SNAP_OUI;

		/* Add send control block to send control block ring */
		qdev->send_q[i] = scb;
		qdev->send_q_in++;
	}

	/*
	 * Allocate/initialize queue of buffers for receiving packets from the
	 * SCSI driver
	 * */
	for (i = 0; i < qdev->max_receive_buffers; i++) {
		/* Initialize receive buffer control block */
		bcb = &qdev->receive_buffers[i];
		bcb->handle = i;

		/* Allocate data buffer */
		skb = dev_alloc_skb(qdev->receive_buff_data_size);
		if (skb == NULL) {
			printk(KERN_ERR
			       "%s: Failed to allocate buffer_cb skb\n",
			       qla_name);
			return 1;
		}

		bcb->skb = skb;
		bcb->skb_data = skb->data;
		bcb->skb_data_dma = pci_map_single(qdev->pdev,
						   skb->data, skb->len,
						   PCI_DMA_FROMDEVICE);
		/* Add receive buffer to receive buffer queue */
		qdev->receive_q_in->handle = bcb->handle;
		qdev->receive_q_in->data_addr_low = LSD(bcb->skb_data_dma);
		qdev->receive_q_in->data_addr_high = MSD(bcb->skb_data_dma);
		qdev->receive_q_in++;
		qdev->receive_q_add_cnt++;
	}

	return 0;
}

/**
 * qla2xip_deallocate_buffers() - Deallocate network structures.
 * @dev: The device to uninitialize
 *
 * The device structure @dev is freed within this routine.
 */
static void
qla2xip_deallocate_buffers(struct net_device *dev)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int i;
	struct send_cb *scb;
	struct buffer_cb *bcb;

	/*
	 * Deallocate queue of control blocks for sending packets to SCSI driver
	 */
	pci_free_consistent(qdev->pdev, sizeof(struct packet_header),
			    qdev->scb_header, qdev->scb_header_dma);
	for (i = 0; i < MAX_SEND_PACKETS; i++) {
		scb = &qdev->send_buffers[i];
		scb->header = NULL;
		scb->header_dma = 0;
	}

	/*
	 * Deallocate queue of buffers for receiving packets from SCSI driver
	 */
	for (i = 0; i < qdev->max_receive_buffers; i++) {
		bcb = &qdev->receive_buffers[i];
		if (bcb->skb) {
			pci_unmap_single(qdev->pdev,
					 bcb->skb_data_dma,
					 bcb->skb->len, PCI_DMA_FROMDEVICE);
			dev_kfree_skb_any(bcb->skb);
			bcb->skb = NULL;
		}
	}

	/* Free dev and private structure */
	kfree(dev);
}

/**
 * qla2xip_get_send_cb() - Retrieves the next available send control block.
 * @qdev: The device's private structure
 *
 * This routine assumes calls to qla2xip_send() are serialized and does NOT use
 * a spinlock to update the @send_q_out pointer.
 *
 * Returns the next available send_cb structure from the send queue, else NULL.
 */
static struct send_cb *
qla2xip_get_send_cb(struct qla2xip_private *qdev)
{
	struct send_cb *scb;

	scb = NULL;
	if (qdev->send_q_in != qdev->send_q_out) {
		scb = qdev->send_q[qdev->send_q_out];
		if (qdev->send_q_out == MAX_SEND_PACKETS)
			qdev->send_q_out = 0;
		else
			qdev->send_q_out++;
	}
	return scb;
}

/**
 * qla2xip_free_send_cb() - Returns the send control block to the free queue.
 * @scb: The send_cb to return to the free queue
 */
static void
qla2xip_free_send_cb(struct send_cb *scb)
{
	struct qla2xip_private *qdev = scb->qdev;

	spin_lock(&qdev->lock);

	/* Return send control block to free queue */
	qdev->send_q[qdev->send_q_in] = scb;
	if (qdev->send_q_in == MAX_SEND_PACKETS)
		qdev->send_q_in = 0;
	else
		qdev->send_q_in++;

	spin_unlock(&qdev->lock);
}

/**
 * qla2xip_notify() - Notification callback routine.
 * @dev: The device context
 * @type: The asyncronous event
 *
 * This callback routine is used to by the SCSI driver to notify the network
 * driver of an asyncronous event.
 */
static void
qla2xip_notify(struct net_device *dev, uint32_t type)
{
	/* Switch on event type */
	switch (type) {
	case NOTIFY_EVENT_RESET_DETECTED:
		printk(KERN_INFO
		       "%s: %s - Reset detected\n", qla_name, dev->name);
		break;

	case NOTIFY_EVENT_LINK_DOWN:
		printk(KERN_INFO
		       "%s: %s - Link down detected\n", qla_name, dev->name);
		break;

	case NOTIFY_EVENT_LINK_UP:
		printk(KERN_INFO
		       "%s: %s - Link up detected\n", qla_name, dev->name);
		break;

	default:
		printk(KERN_INFO
		       "%s: %s - Unsupported notification type %x\n",
		       qla_name, dev->name, type);
		break;
	}
}

/**
 * qla2xip_send_completion() - Send completion callback routine.
 * @scb: The send_cb that was sent
 *
 * This callback routine is used to by the SCSI driver to notify the network
 * driver of a send completion on the specified @scb.
 *
 * Note: this routine is called from an IRQ context.
 */
static void
qla2xip_send_completion(struct send_cb *scb)
{
	struct qla2xip_private *qdev = scb->qdev;
	struct net_device *dev = qdev->dev;

	/* Interrogate completion status from firmware */
	switch (scb->comp_status) {
	case SCB_CS_COMPLETE:
		qdev->stats.tx_packets++;
		qdev->stats.tx_bytes += (scb->skb->len +
					 sizeof(struct packet_header));
		break;

	case SCB_CS_INCOMPLETE:
	case SCB_CS_ABORTED:
		qdev->stats.tx_errors++;
		qdev->stats.tx_aborted_errors++;
		printk(KERN_WARNING
		       "%s: Unsuccessful send-completion status "
		       "(%x)\n", qla_name, scb->comp_status);
		break;

	case SCB_CS_RESET:
	case SCB_CS_TIMEOUT:
	case SCB_CS_PORT_UNAVAILABLE:
	case SCB_CS_PORT_LOGGED_OUT:
	case SCB_CS_PORT_CONFIG_CHG:
		qdev->stats.tx_errors++;
		qdev->stats.tx_carrier_errors++;
		printk(KERN_WARNING
		       "%s: Unsuccessful send-completion status "
		       "(%x)\n", qla_name, scb->comp_status);
		break;

	case SCB_CS_FW_RESOURCE_UNAVAILABLE:
		qdev->stats.tx_errors++;
		qdev->stats.tx_fifo_errors++;
		printk(KERN_WARNING
		       "%s: Unsuccessful send-completion status "
		       "(%x)\n", qla_name, scb->comp_status);
		break;

	default:
		printk(KERN_ERR
		       "%s: Unknown send-completion status returned "
		       "(%x)\n", qla_name, scb->comp_status);
		break;

	}

	/* Free resources */
	dev_kfree_skb_irq(scb->skb);
	qla2xip_free_send_cb(scb);

	/* Start queueing of packets if stopped */
	netif_wake_queue(dev);
}

/**
 * qla2xip_receive_packets() - Receive packet callback routine.
 * @dev: The device context
 * @bcb: The buffer_cb that was received
 *
 * This callback routine is used to by the SCSI driver to notify the network
 * driver of a received packet.
 *
 * The routine will double-buffer any linked buffer_cbs if the packet spans
 * multiple sequence buffers.
 *
 * Note: this routine is called from an IRQ context.
 * Note: the SCSI driver will serialize calls to this routine, hence a spinlock
 * is not used.
 */
static void
qla2xip_receive_packets(struct net_device *dev, struct buffer_cb *bcb)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int pkt_len;
	struct ethhdr *eth;
	struct sk_buff *skb;
	struct packet_header *packethdr;

	/* TODO: Interrogate firmware completion status */

	pkt_len = bcb->packet_size -
	    (sizeof(struct packet_header) - sizeof(struct ethhdr));

	/* Convert Network and SNAP headers into Ethernet header */
	packethdr = (struct packet_header *)bcb->skb_data;
	eth = (struct ethhdr *)(bcb->skb_data +
				(sizeof(struct packet_header) -
				 sizeof(struct ethhdr)));

	eth->h_proto = packethdr->snaph.ethertype;
	memcpy(eth->h_source, packethdr->networkh.s.na.addr, ETH_ALEN);
	memcpy(eth->h_dest, packethdr->networkh.d.na.addr, ETH_ALEN);

	if (bcb->linked_bcb_cnt == 1) {
		/*
		 * Packet is in single receive buffer, no need to double buffer
		 */
		skb = bcb->skb;
		pci_unmap_single(qdev->pdev,
				 bcb->skb_data_dma, skb->len,
				 PCI_DMA_FROMDEVICE);
		skb->dev = dev;

		/* Adjust buffer pointer and length */
		skb_reserve(skb, sizeof(struct packet_header) -
			    sizeof(struct ethhdr));
		skb_put(skb, pkt_len);
		skb->protocol = eth_type_trans(skb, dev);

		/* Indicate receive packet */
		netif_rx(skb);
		dev->last_rx = jiffies;

		qdev->stats.rx_packets++;
		qdev->stats.rx_bytes += bcb->packet_size;

		/* Preallocate replacement receive buffer */
		skb = dev_alloc_skb(qdev->receive_buff_data_size);
		if (skb) {
			bcb->skb = skb;
			bcb->skb_data = skb->data;
			bcb->skb_data_dma = pci_map_single(qdev->pdev,
							   skb->data, skb->len,
							   PCI_DMA_FROMDEVICE);

			/* Add receive buffer to receive buffer queue */
			qdev->receive_q_in->handle = bcb->handle;
			qdev->receive_q_in->data_addr_low =
			    LSD(bcb->skb_data_dma);
			qdev->receive_q_in->data_addr_high =
			    MSD(bcb->skb_data_dma);
			qdev->receive_q_in++;
			if (qdev->receive_q_in == qdev->receive_q_end)
				qdev->receive_q_in = qdev->receive_q;
			qdev->receive_q_add_cnt++;
		} else {
			printk(KERN_ERR
			       "%s: %s - Failed to allocate buffer_cb skb, "
			       "buffer pool has been reduced!\n",
			       qla_name, dev->name);
			bcb->skb = NULL;
		}
	} else {
		int i;
		int buffer_len;
		struct buffer_cb *nbcb;

		/*
		 * Incoming packet was broken into multiple receive buffers.
		 * This is probably due to a MTU mismatch between systems.
		 * Must double buffer packet into single buffer for Linux
		 */
		skb = dev_alloc_skb(pkt_len + 2);
		if (skb) {
			skb->dev = dev;
			skb_reserve(skb, 2);

			/* Move 1st buffer with ethernet header */
			buffer_len = bcb->rec_data_size -
			    (sizeof(struct packet_header) -
			     sizeof(struct ethhdr));
			memcpy(skb_put(skb, buffer_len), eth, buffer_len);

			/* Move rest of receive buffers */
			nbcb = bcb;
			for (i = 1; i < bcb->linked_bcb_cnt; i++) {
				nbcb = nbcb->next_bcb;
				buffer_len = nbcb->rec_data_size;
				memcpy(skb_put(skb, buffer_len),
				       nbcb->skb_data, buffer_len);
			}

			skb->protocol = eth_type_trans(skb, dev);

			/* Indicate receive packet */
			netif_rx(skb);
			dev->last_rx = jiffies;

			qdev->stats.rx_packets++;
			qdev->stats.rx_bytes += bcb->packet_size;
		} else {
			/* Failed to allocate buffer, drop packet */
			printk(KERN_ERR
			       "%s: %s - Failed to allocate buffer_cb skb, "
			       "packet dropped, buffer pool has been "
			       "reduced!\n", qla_name, dev->name);
			qdev->stats.rx_dropped++;
		}

		/* Return buffers to receive buffer queue */
		nbcb = bcb;
		for (i = 0; i < bcb->linked_bcb_cnt;
		    i++, nbcb = nbcb->next_bcb) {
			qdev->receive_q_in->handle = nbcb->handle;
			qdev->receive_q_in->data_addr_low =
			    LSD(nbcb->skb_data_dma);
			qdev->receive_q_in->data_addr_high =
			    MSD(nbcb->skb_data_dma);
			qdev->receive_q_in++;
			if (qdev->receive_q_in == qdev->receive_q_end)
				qdev->receive_q_in = qdev->receive_q;
		}
		qdev->receive_q_add_cnt += bcb->linked_bcb_cnt;
	}

	/* Update (RISC) free buffer count */
	qdev->receive_q_cnt -= bcb->linked_bcb_cnt;

	/* Pass receive buffers to SCSI driver */
	if (qdev->receive_q_add_cnt >= RECEIVE_BUFFERS_ADD_MARK ||
	    qdev->receive_q_cnt <= RECEIVE_BUFFERS_LOW_MARK) {
		qdev->ip_add_buffers_routine(qdev->ha,
					     qdev->receive_q_add_cnt, 1);

		qdev->receive_q_cnt += qdev->receive_q_add_cnt;
		qdev->receive_q_add_cnt = 0;
	}
}

/**
 * qla2xip_open() - Prepares a networking interface for use.
 * @dev: The device to open
 *
 * Returns 0.
 */
static int
qla2xip_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

/**
 * qla2xip_close() - Shutdown a networking interface.
 * @dev: The device to shutdown
 *
 * Returns 0.
 */
static int
qla2xip_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/**
 * qla2xip_send() - Transmit a socket buffer over an interface.
 * @skb: The buffer to transmit
 * @dev: The device to transmit the buffer on
 *
 * Returns 0 if the buffer was sent, else 1.
 */
static int
qla2xip_send(struct sk_buff *skb, struct net_device *dev)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int status;
	struct ethhdr *eth;
	struct send_cb *scb;
	struct packet_header *packethdr;

	/* Get next available send control block */
	scb = qla2xip_get_send_cb(qdev);
	if (scb) {
		/* Finish building Network and SNAP headers */
		eth = (struct ethhdr *)skb->data;
		packethdr = scb->header;

		packethdr->networkh.d.na.naa = NAA_IEEE_MAC_TYPE;
		packethdr->networkh.d.na.unused = 0;
		memcpy(packethdr->networkh.d.na.addr, eth->h_dest, ETH_ALEN);
		packethdr->snaph.ethertype = eth->h_proto;

		/* Skip over ethernet header */
		skb_pull(skb, sizeof(struct ethhdr));

		/* Pass send packet to SCSI driver */
		dev->trans_start = jiffies;
		scb->skb = skb;
		status = qdev->ip_send_packet_routine(qdev->ha, scb);
		if (status == QL_STATUS_SUCCESS) {
			/* Packet successfully sent to ISP */
			/* Move up */
			/*dev->trans_start = jiffies; */
			return 0;
		} else if (status == QL_STATUS_RESOURCE_ERROR) {
			/* ISP too busy now, try later */
			printk(KERN_WARNING
			       "%s: %s - Unable to send packet -- Resource "
			       "error...Try again.\n", qla_name, dev->name);
			/* Free send control block */
			qla2xip_free_send_cb(scb);
			qdev->stats.tx_errors++;
			qdev->stats.tx_fifo_errors++;
			netif_stop_queue(dev);
			return 1;
		} else {
			/* Error, don't send packet */
			printk(KERN_ERR
			       "%s: %s - Unable to send packet -- Bad error "
			       "occured!!!\n", qla_name, dev->name);
			/* Free send control block */
			qla2xip_free_send_cb(scb);
			dev_kfree_skb(skb);
			qdev->stats.tx_errors++;
			qdev->stats.tx_aborted_errors++;
			return 0;
		}
	} else {
		/* Out of send control blocks, pause queueing of packets */
		printk(KERN_WARNING
		       "%s: %s - Unable to send packet -- Out of send "
		       "control blocks!!!\n", qla_name, dev->name);
		qdev->stats.tx_errors++;
		qdev->stats.tx_fifo_errors++;
		netif_stop_queue(dev);
		return 1;
	}
}

/**
 * qla2xip_get_stats() - Retrieves networking statistics.
 * @dev: The device to interrogate
 *
 * Returns a pointer to the net_device_stats structure of the @dev.
 */
static struct net_device_stats *
qla2xip_get_stats(struct net_device *dev)
{
	struct qla2xip_private *qdev = netdev_priv(dev);

	return &qdev->stats;
}

/**
 * qla2xip_change_mtu() - Set the MTU of a device.
 * @dev: The device to update
 * @new_mtu: The new MTU value
 *
 * Returns 0 if the MTU was successfully updated.
 */
static int
qla2xip_change_mtu(struct net_device *dev, int new_mtu)
{
	if ((new_mtu > MAX_MTU_SIZE) || (new_mtu < MIN_MTU_SIZE))
		return -EINVAL;

	return -EOPNOTSUPP;
}

/**
 * qla2xip_set_multicast_list() - Add a device to a multicast group.
 * @dev: The device to add
 */
static void
qla2xip_set_multicast_list(struct net_device *dev)
{
	/* TODO: complete interface */
	return;
}

/**
 * qla2xip_ethtool_ioctl() - Interface for ethtool IOCTLs.
 * @dev: The device to interrogate
 * @useraddr: The user-space IOCTL data
 *
 * Interface example from drivers/net/3c59x.c.
 *
 * Returns 0 if the ethtool IOCTL succeeded.
 */
static int
qla2xip_ethtool_ioctl(struct net_device *dev, void *useraddr)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	u32 ethcmd;
	struct ethtool_drvinfo info = { ETHTOOL_GDRVINFO };

	if (copy_from_user(&ethcmd, useraddr, sizeof(ethcmd)))
		return -EFAULT;

	switch (ethcmd) {
	case ETHTOOL_GDRVINFO:
		strcpy(info.driver, qla_name);
		strcpy(info.version, qla_version);
		strcpy(info.bus_info, pci_name(qdev->pdev));
		if (copy_to_user(useraddr, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	return -EOPNOTSUPP;
}

/**
 * qla2xip_do_ioctl() - Interface for private networking IOCTLs.
 * @dev: The device to interrogate
 * @useraddr: The IOCTL interface request
 *
 * Note: currently only a small subset of ethtool support IOCTLs are
 * implemented.
 *
 * Returns 0 if the IOCTL succeeded.
 */
static int
qla2xip_do_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int retval;

	/* TODO: Complete interface */
	qdev = qdev;
	switch (cmd) {
	case SIOCETHTOOL:
		retval = qla2xip_ethtool_ioctl(dev, (void *)rq->ifr_data);
		break;

	default:
		retval = -EOPNOTSUPP;
		break;
	}
	return retval;
}

/**
 * qla2xip_set_mac_address() - Set the MAC address of a device.
 * @dev: The device to update
 * @p: The new MAC address
 *
 * Returns 0 if the MAC address was successfully updated.
 */
static int
qla2xip_set_mac_address(struct net_device *dev, void *p)
{
	/* TODO: complete interface */
	return 0;
}

/**
 * qla2xip_tx_timeout() - Transmission timeout handler.
 * @dev: The device that timed-out
 */
static void
qla2xip_tx_timeout(struct net_device *dev)
{
	struct qla2xip_private *qdev = netdev_priv(dev);
	int status;

	printk(KERN_ERR
	       "%s: %s - Transmission timed out, cable problem?\n",
	       qla_name, dev->name);
	printk(KERN_DEBUG
	       "%s: %s - Transmission timed out, cable problem?\n",
	       qla_name, dev->name);

	/* Call SCSI driver to perform any internal cleanup */
	status = qdev->ip_tx_timeout_routine(qdev->ha);

	qdev->stats.rx_dropped++;
	dev->trans_start = jiffies;
	netif_wake_queue(dev);
}

/* Chain of configured device structures (just for module unload)*/
static struct net_device *root_dev;


static const struct net_device_ops qla2xip_netdev_ops = { 
	.ndo_open = qla2xip_open,
	.ndo_stop = qla2xip_close,
	.ndo_start_xmit = qla2xip_send,
	.ndo_get_stats = qla2xip_get_stats,
	.ndo_set_mac_address = qla2xip_set_mac_address,
	.ndo_change_mtu = qla2xip_change_mtu,
	.ndo_do_ioctl = qla2xip_do_ioctl,
	.ndo_tx_timeout = qla2xip_tx_timeout,
};

/**
 * qla2xip_init() - Driver initialization routine.
 *
 * This routine scans for and initializes all QLogic adapters that support the
 * IP interface.
 */
static int
qla2xip_init(void)
{
	int rval;
	int adapters_found;
	int version_display;
	int adapter_number;
	struct bd_enable *enable_data;
	struct bd_inquiry *inq_data;
	struct qla2xip_private *qdev;
	struct net_device *dev;

	adapters_found = 0;
	version_display = 0;

#ifdef LOG2CIRC
	qla2xxx_log2circ_init();
	ql2xextended_error_logging=0x7fffffff;
#endif

	/* Allocate buffer for backdoor inquiry to SCSI driver */
	inq_data = kmalloc(sizeof(struct bd_inquiry), GFP_KERNEL);
	if (inq_data == NULL) {
		printk(KERN_ERR
		       "%s: Failed to allocate inquiry data\n", qla_name);

		return -ENOMEM;
	}

	enable_data = kmalloc(sizeof(struct bd_enable), GFP_KERNEL);
	if (enable_data == NULL) {
		printk(KERN_ERR
		       "%s: Failed to allocate enable data\n", qla_name);
		kfree(inq_data);

		return -ENOMEM;
	}

	/* Loop, looking for all adapters with IP support */
	for (adapter_number = 0;
	     adapter_number < MAX_ADAPTER_COUNT; adapter_number++) {

		memset(inq_data, 0, sizeof(struct bd_inquiry));
		inq_data->length = BDI_LENGTH;
		inq_data->version = BDI_VERSION;

		rval = qla2x00_ip_inquiry(adapter_number, inq_data);
		if (!rval)
			continue;

		/* Inquiry succeeded */
		/* Display version info if adapter is found */
		if (!version_display) {
			version_display = 1;
			qla2xip_display_info();
		}

		/*
		 * Allocate device structure and private structure
		 *
		 * The default init_fcdev behaviour is not consistent with the
		 * pre-existing behaviour.
		 *
		 * Allocate the ethernet device and update needed fields.
		 * Post-register when allocations complete.
		 */
		dev = alloc_etherdev(sizeof(struct qla2xip_private));
		if (dev == NULL) {
			printk(KERN_ERR
			       "%s: Failed to allocate net-device structure\n",
			       qla_name);
			break;
		}
		// FOO dev->owner = THIS_MODULE;

		qdev = netdev_priv(dev);

		qdev->dev = dev;
		spin_lock_init(&qdev->lock);

		/* Set driver entry points */
		dev->netdev_ops = &qla2xip_netdev_ops; // FOO
		// FOO dev->set_multicast_list = qla2xip_set_multicast_list;

		/* Update interface name */
		strcpy(dev->name, "fc%d");

		/* Save Inquiry data from SCSI driver */
		qdev->options = inq_data->options;
		qdev->ha = inq_data->ha;
		qdev->receive_q = (struct risc_rec_entry *)inq_data->risc_rec_q;
		qdev->receive_q_size = inq_data->risc_rec_q_size;
		qdev->receive_q_in = qdev->receive_q;
		qdev->receive_q_end = &qdev->receive_q[qdev->receive_q_size];

		qdev->link_speed = inq_data->link_speed;
		memcpy(qdev->port_name, inq_data->port_name, WWN_SIZE);
		qdev->pdev = inq_data->pdev;

		qdev->ip_enable_routine = inq_data->ip_enable_routine;
		qdev->ip_disable_routine = inq_data->ip_disable_routine;
		qdev->ip_add_buffers_routine = inq_data->ip_add_buffers_routine;
		qdev->ip_send_packet_routine = inq_data->ip_send_packet_routine;
		qdev->ip_tx_timeout_routine = inq_data->ip_tx_timeout_routine;

		/* Validate and set parameters */
		qdev->mtu = mtu;
		qdev->max_receive_buffers = buffers;

		if (qdev->mtu > MAX_MTU_SIZE)
			qdev->mtu = MAX_MTU_SIZE;
		if (qdev->mtu < MIN_MTU_SIZE)
			qdev->mtu = MIN_MTU_SIZE;

		if (qdev->max_receive_buffers > MAX_RECEIVE_BUFFERS)
			qdev->max_receive_buffers = MAX_RECEIVE_BUFFERS;
		if (qdev->max_receive_buffers < MIN_RECEIVE_BUFFERS)
			qdev->max_receive_buffers = MIN_RECEIVE_BUFFERS;

		qdev->receive_buff_data_size = qdev->mtu +
		    sizeof(struct packet_header);
		qdev->header_size = DEFAULT_HEADER_SPLIT;

		/* TODO: Update ARP header type */
		/*dev->type = ARPHRD_FCFABRIC; */
		dev->mtu = qdev->mtu;
		dev->tx_queue_len = MAX_SEND_PACKETS;
		if (test_bit(BDI_64BIT_ADDRESSING, &qdev->options))
			dev->features |= NETIF_F_HIGHDMA;

		/*
		 * The Ethernet address is the last 6 bytes of the adapter
		 * portname
		 */
		memcpy(dev->dev_addr, &qdev->port_name[2], ETH_ALEN);
		/* TODO: Why do we need this? */
		/*      dev->dev_addr[6] = qdev->port_name[6 + 2]; */

		dev->irq = qdev->pdev->irq;
		dev->flags &= ~IFF_MULTICAST;
		dev->flags |= IFF_NOTRAILERS;

		/* Allocate and initialize data buffers */
		rval = qla2xip_allocate_buffers(dev);
		if (rval) {
			printk(KERN_ERR
			       "%s: Failed to allocate support buffers\n",
			       qla_name);

			qla2xip_deallocate_buffers(dev);
			break;
		}

		/* Enable connection to SCSI driver */
		memset(enable_data, 0, sizeof(struct bd_enable));
		enable_data->length = BDE_LENGTH;
		enable_data->version = BDE_VERSION;
		set_bit(BDE_NOTIFY_ROUTINE, &enable_data->options);
		enable_data->mtu = qdev->mtu;
		enable_data->header_size = qdev->header_size;
		enable_data->receive_buffers = qdev->receive_buffers;
		enable_data->max_receive_buffers = qdev->max_receive_buffers;
		enable_data->receive_buff_data_size =
		    qdev->receive_buff_data_size;
		enable_data->notify_routine = qla2xip_notify;
		enable_data->notify_context = dev;
		enable_data->send_completion_routine = qla2xip_send_completion;
		enable_data->receive_packets_routine = qla2xip_receive_packets;
		enable_data->receive_packets_context = dev;

		rval = qdev->ip_enable_routine(qdev->ha, enable_data);
		if (!rval) {
			/*
			 * Connection to SCSI driver failed return resources
			 */
			printk(KERN_ERR
			       "%s: Failed to enable backdoor IP\n", qla_name);
			qla2xip_deallocate_buffers(dev);
			break;
		}

		/*
		 * Pass receive buffers to SCSI driver
		 */
		qdev->ip_add_buffers_routine(qdev->ha,
					     qdev->receive_q_add_cnt, 0);
		qdev->receive_q_cnt = qdev->receive_q_add_cnt;
		qdev->receive_q_add_cnt = 0;

		/* Register the device */
		rval = register_netdev(dev);
		if (rval) {
			printk(KERN_ERR
			       "%s: Unable to register net-device\n", qla_name);
			qla2xip_deallocate_buffers(dev);
			break;
		}

		qla2xip_display_dev_info(dev);

		/*
		 * Add to device chain and increment adapter count
		 */
		qdev->next = root_dev;
		root_dev = dev;
		adapters_found++;

		continue;
	}

	kfree(enable_data);
	kfree(inq_data);

	if (adapters_found > 0)
		return 0;
	return -ENODEV;
}

static void
qla2xip_exit(void)
{
	struct qla2xip_private *qdev;
	struct net_device *next;

#ifdef LOG2CIRC
	qla2xxx_log2circ_exit();
#endif

	while (root_dev) {
		qdev = netdev_priv(root_dev);
		next = qdev->next;

		/* Call SCSI driver to disable IP connection */
		qdev->ip_disable_routine(qdev->ha);

		unregister_netdev(root_dev);

		/* Return allocated buffers */
		qla2xip_deallocate_buffers(root_dev);

		root_dev = next;
	}
}

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic IP via Fibre Channel Network Driver for ISP2xxx");
MODULE_LICENSE("GPL");

module_init(qla2xip_init);
module_exit(qla2xip_exit);
