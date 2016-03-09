/*
 * QLogic QLogic ISP2x00 IP network driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */

/****************************************************************************
              Please see revision.notes for revision history.
*****************************************************************************/

#if !defined(_QLA2XIP_H_)
#define _QLA2XIP_H_

#define WWN_SIZE		8
#define MAX_ADAPTER_COUNT	8	/* Maximum adapters supported */

#define MAX_MTU_SIZE		65280	/* Maximum MTU size */
#define MIN_MTU_SIZE		100	/* Minimum MTU size */
#define DEFAULT_MTU_SIZE	4096	/* Default MTU size */
#define DEFAULT_BUFFER_SIZE	(DEFAULT_MTU_SIZE + sizeof(PACKET_HEADER))
#define DEFAULT_RECEIVE_BUFFERS	32	/* Default number of receive buffers */

#define RECEIVE_BUFFERS_LOW_MARK 16	/* Receive buffers low water mark */
#define RECEIVE_BUFFERS_ADD_MARK 10	/* Receive buffers add mark */
#define DEFAULT_HEADER_SPLIT	0	/* Default header split size (== 0) */

#define LSD(x)	((uint32_t)((uint64_t)(x)))
#define MSD(x)	((uint32_t)((((uint64_t)(x)) >> 16) >> 16))

/*
 * Struct private for the QLogic IP adapter
 */
struct qla2xip_private {
	/* Net device members */
	struct net_device *next;
	spinlock_t lock;

	struct net_device_stats stats;	/* Device statistics */
	struct net_device *dev;	/* Parent NET device */

	uint32_t mtu;		/* Maximum transfer unit */
	uint16_t header_size;	/* Split header size */

	/* Send control block queue */
	struct send_cb *send_q[MAX_SEND_PACKETS + 1];
	uint16_t send_q_in;	/*  free in-pointer */
	uint16_t send_q_out;	/*  free out-pointer */
	/* Send control block array */
	struct send_cb send_buffers[MAX_SEND_PACKETS];
	struct packet_header *scb_header;
	dma_addr_t scb_header_dma;

	/* Inquiry data from SCSI driver */
	unsigned long options;	/* QLA2X00 supported options */
	void *ha;		/* Driver ha pointer */
	uint16_t link_speed;	/* Link speed */
	uint8_t port_name[WWN_SIZE];	/* Adapter port name */
	struct pci_dev *pdev;	/* PCI device information */

	/* Pointers to SCSI-backdoor callbacks */
	int (*ip_enable_routine) (void *, struct bd_enable *);
	int (*ip_disable_routine) (void *);
	int (*ip_add_buffers_routine) (void *, uint16_t, int);
	int (*ip_send_packet_routine) (void *, struct send_cb *);
	int (*ip_tx_timeout_routine) (void *);

	/* RISC receive queue */
	uint16_t receive_q_size;	/*  size */
	struct risc_rec_entry *receive_q;	/*  pointer */
	struct risc_rec_entry *receive_q_in;	/*  in-pointer */
	struct risc_rec_entry *receive_q_end;	/*  end-pointer */
	uint16_t receive_q_cnt;	/*  current buffer count */
	uint16_t receive_q_add_cnt;	/*  buffers to be added */

	struct buffer_cb receive_buffers[MAX_RECEIVE_BUFFERS];
	uint16_t max_receive_buffers;	/*  maximum # receive buffers */
	uint32_t receive_buff_data_size;	/*  data size */
};
#endif
