/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <asm/uaccess.h>

#include "exioct.h"
#include "inioct.h"


static int qla2x00_read_option_rom_ext(scsi_qla_host_t *, EXT_IOCTL *, int);
static int qla2x00_update_option_rom_ext(scsi_qla_host_t *, EXT_IOCTL *, int);
static void qla2x00_get_option_rom_table(scsi_qla_host_t *,
    INT_OPT_ROM_REGION **, unsigned long *);
static int qla2x00_get_oem_1_vpd(scsi_qla_host_t *, EXT_IOCTL *, int);

/* Option ROM definitions. */
INT_OPT_ROM_REGION OptionRomTable2312[] =
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHBIOS_FCODE_EFI_CFW, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTable6312[] = // 128k x20000
{
    {INT_OPT_ROM_REGION_ALL,    INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHBIOS_CFW, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTableHp[] = // 128k x20000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHEFI_PHECFW_PHVPD, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION  OptionRomTable2322[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_PHBIOS_PHFCODE_PHEFI_FW, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION  OptionRomTable6322[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_PHBIOS_FW, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTable2422[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2422,
	    0, INT_OPT_ROM_SIZE_2422-1},
    {INT_OPT_ROM_REGION_PHBIOS_PHFCODE_PHEFI, 0x40000,
	    0, 0x40000-1 },
    {INT_OPT_ROM_REGION_FW, 0x80000,
	    0x80000, INT_OPT_ROM_SIZE_2422-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};


/* ========================================================================= */

int
qla2x00_read_nvram(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int	ret = 0;
	char	*ptmp_buf;
	uint32_t transfer_size;
	unsigned long flags;

	DEBUG9(printk("qla2x00_read_nvram: entered.\n"));

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_buf,
	    ha->nvram_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ha->nvram_size));
		return (ret);
	}

	transfer_size = ha->nvram_size;
	if (pext->ResponseLen < ha->nvram_size)
		transfer_size = pext->ResponseLen;

	/* Dump NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_read_nvram_data(ha, (uint8_t *)ptmp_buf, ha->nvram_base,
	    ha->nvram_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_buf, transfer_size);
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

	DEBUG9(printk("qla2x00_read_nvram: exiting.\n"));

	return (ret);
}

/*
 * qla2x00_update_nvram
 *	Write data to NVRAM.
 *
 * Input:
 *	ha = adapter block pointer.
 *	pext = pointer to driver internal IOCTL structure.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_update_nvram(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	uint8_t cnt;
	uint8_t *usr_tmp, *kernel_tmp;
	nvram_t *pnew_nv;
	uint32_t transfer_size;
	int ret = 0;
	unsigned long flags;

	DEBUG9(printk("qla2x00_update_nvram: entered.\n"));

	if (pext->RequestLen < ha->nvram_size)
		transfer_size = pext->RequestLen;
	else
		transfer_size = ha->nvram_size;

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pnew_nv,
	    ha->nvram_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance, ha->nvram_size));
		return (ret);
	}

	/* Read from user buffer */
	kernel_tmp = (uint8_t *)pnew_nv;
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	ret = copy_from_user(kernel_tmp, usr_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qla2x00_update_nvram: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Checksum NVRAM. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)pnew_nv;
		chksum = 0;
		for (cnt = 0; cnt < ((ha->nvram_size >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)pnew_nv;
		chksum = 0;
		for (cnt = 0; cnt < ha->nvram_size - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_write_nvram_data(ha, (uint8_t *)pnew_nv, ha->nvram_base,
	    transfer_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("qla2x00_update_nvram: exiting.\n"));

	/* Schedule DPC to restart the RISC */
	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	up(ha->dpc_wait);

	if (qla2x00_wait_for_hba_online(ha) != QLA_SUCCESS) {
		pext->Status = EXT_STATUS_ERR;
	}

	return ret;
}

static int
qla2x00_loopback_test(scsi_qla_host_t *ha, INT_LOOPBACK_REQ *req,
    uint16_t *ret_mb)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	DEBUG11(printk("qla2x00_send_loopback: req.Options=%x iterations=%x "
	    "MAILBOX_CNT=%d.\n", req->Options, req->IterationCount,
	    MAILBOX_REGISTER_COUNT));

	memset(mcp->mb, 0 , sizeof(mcp->mb));

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = req->Options | MBX_6;
	mcp->mb[10] = LSW(req->TransferCount);
	mcp->mb[11] = MSW(req->TransferCount);
	mcp->mb[14] = LSW(ha->ioctl_mem_phys); /* send data address */
	mcp->mb[15] = MSW(ha->ioctl_mem_phys);
	mcp->mb[20] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[21] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[16] = LSW(ha->ioctl_mem_phys); /* rcv data address */
	mcp->mb[17] = MSW(ha->ioctl_mem_phys);
	mcp->mb[6] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[7] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[18] = LSW(req->IterationCount); /* iteration count lsb */
	mcp->mb[19] = MSW(req->IterationCount); /* iteration count msb */
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->buf_size = req->TransferCount;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = 30;
	rval = qla2x00_mailbox_command(ha, mcp);

	/* Always copy back return mailbox values. */
	memcpy((void *)ret_mb, (void *)mcp->mb, sizeof(mcp->mb));

	if (rval != QLA_SUCCESS) {
		/* Empty. */
		DEBUG2_3_11(printk(
		    "qla2x00_loopback_test(%ld): mailbox command FAILED=%x.\n",
		    ha->host_no, mcp->mb[0]));
	} else {
		/* Empty. */
		DEBUG11(printk(
		    "qla2x00_loopback_test(%ld): done.\n", ha->host_no));
	}

	return rval;
}

static int
qla2x00_echo_test(scsi_qla_host_t *ha, INT_LOOPBACK_REQ *req, uint16_t *ret_mb)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	memset(mcp->mb, 0 , sizeof(mcp->mb));

	mcp->mb[0] = MBC_DIAGNOSTIC_ECHO;
	mcp->mb[1] = BIT_6; /* use 64bit DMA addr */
	mcp->mb[10] = req->TransferCount;
	mcp->mb[14] = LSW(ha->ioctl_mem_phys); /* send data address */
	mcp->mb[15] = MSW(ha->ioctl_mem_phys);
	mcp->mb[20] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[21] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[16] = LSW(ha->ioctl_mem_phys); /* rcv data address */
	mcp->mb[17] = MSW(ha->ioctl_mem_phys);
	mcp->mb[6] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[7] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->out_mb = MBX_21|MBX_20|MBX_17|MBX_16|MBX_15|MBX_14|MBX_10|
	    MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->buf_size = req->TransferCount;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = 30;
	rval = qla2x00_mailbox_command(ha, mcp);

	/* Always copy back return mailbox values. */
	memcpy((void *)ret_mb, (void *)mcp->mb, sizeof(mcp->mb));

	if (rval != QLA_SUCCESS) {
		/* Empty. */
		DEBUG2_3_11(printk(
		    "%s(%ld): mailbox command FAILED=%x/%x.\n", __func__,
		    ha->host_no, mcp->mb[0], mcp->mb[1]));
	} else {
		/* Empty. */
		DEBUG11(printk("%s(%ld): done.\n", __func__, ha->host_no));
	}

	return rval;
}

int
qla2x00_send_loopback(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
#define MAX_LOOPBACK_BUFFER_SIZE	(128 * 1024)
	int		rval = 0;
	int		status;
	uint16_t	ret_mb[MAILBOX_REGISTER_COUNT];
	INT_LOOPBACK_REQ req;
	INT_LOOPBACK_RSP rsp;

	DEBUG9(printk("qla2x00_send_loopback: entered.\n"));


	if (pext->RequestLen != sizeof(INT_LOOPBACK_REQ)) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "qla2x00_send_loopback: invalid RequestLen =%d.\n",
		    pext->RequestLen));
		return rval;
	}

	if (pext->ResponseLen != sizeof(INT_LOOPBACK_RSP)) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "qla2x00_send_loopback: invalid ResponseLen =%d.\n",
		    pext->ResponseLen));
		return rval;
	}

	status = copy_from_user(&req, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla2x00_send_loopback: ERROR copy read of "
		    "request buffer.\n"));
		return (-EFAULT);
	}

	status = copy_from_user(&rsp, Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), pext->ResponseLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla2x00_send_loopback: ERROR copy read of "
		    "response buffer.\n"));
		return (-EFAULT);
	}

	if (req.TransferCount > MAX_LOOPBACK_BUFFER_SIZE ||
	    req.TransferCount > req.BufferLength ||
	    req.TransferCount > rsp.BufferLength) {

		/* Buffer lengths not large enough. */
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk(
		    "qla2x00_send_loopback: invalid TransferCount =%d. "
		    "req BufferLength =%d rspBufferLength =%d.\n",
		    req.TransferCount, req.BufferLength, rsp.BufferLength));

		return rval;
	}

	if (req.TransferCount > ha->ioctl_mem_size) {
		if (qla2x00_get_new_ioctl_dma_mem(ha, req.TransferCount) !=
		    QLA_SUCCESS) {
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "requested DMA buffer size %x.\n",
			    __func__, ha->host_no, ha->instance,
			    req.TransferCount));

			pext->Status = EXT_STATUS_NO_MEMORY;
			return rval;
		}
	}

	status = copy_from_user(ha->ioctl_mem, Q64BIT_TO_PTR(req.BufferAddress,
	    pext->AddrMode), req.TransferCount);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla2x00_send_loopback: ERROR copy read of "
		    "user loopback data buffer.\n"));
		return (-EFAULT);
	}


	DEBUG9(printk("qla2x00_send_loopback: req -- bufadr=%lx, buflen=%x, "
	    "xfrcnt=%x, rsp -- bufadr=%lx, buflen=%x.\n",
	    (unsigned long)req.BufferAddress, req.BufferLength,
	    req.TransferCount, (unsigned long)rsp.BufferAddress,
	    rsp.BufferLength));

	/*
	 * AV - the caller of this IOCTL expects the FW to handle
	 * a loopdown situation and return a good status for the
	 * call function and a LOOPDOWN status for the test operations
	 */
	/*if (atomic_read(&ha->loop_state) != LOOP_READY || */
	if (test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) || ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("qla2x00_send_loopback(%ld): "
		    "loop not ready.\n", ha->host_no));
		return rval;
	}

	if (ha->current_topology == ISP_CFG_F) {
		if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
			pext->Status = EXT_STATUS_INVALID_REQUEST ;
			DEBUG9_10(printk("qla2x00_send_loopback: ERROR "
			    "command only supported for QLA23xx.\n"));
			return rval;
		}
		status = qla2x00_echo_test(ha, &req, ret_mb);
	} else {
		status = qla2x00_loopback_test(ha, &req, ret_mb);
	}

	if (status) {
		if (status == QLA_FUNCTION_TIMEOUT) {
			pext->Status = EXT_STATUS_BUSY;
			DEBUG9_10(printk("qla2x00_send_loopback: ERROR "
			    "command timed out.\n"));
			return rval;
		} else {
			/* EMPTY. Just proceed to copy back mailbox reg
			 * values for users to interpret.
			 */
			pext->Status = EXT_STATUS_ERR;
			DEBUG10(printk("qla2x00_send_loopback: ERROR "
			    "loopback command failed 0x%x.\n", ret_mb[0]));
		}
	}

	DEBUG9(printk("qla2x00_send_loopback: loopback mbx cmd ok. "
	    "copying data.\n"));

	/* put loopback return data in user buffer */
	status = copy_to_user(Q64BIT_TO_PTR(rsp.BufferAddress,
	    pext->AddrMode), ha->ioctl_mem, req.TransferCount);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla2x00_send_loopback: ERROR copy "
		    "write of return data buffer.\n"));
		return (-EFAULT);
	}

	rsp.CompletionStatus = ret_mb[0];
	if (ha->current_topology == ISP_CFG_F) {
		rsp.CommandSent = INT_DEF_LB_ECHO_CMD;
	} else {
		if (rsp.CompletionStatus == INT_DEF_LB_COMPLETE ||
		    rsp.CompletionStatus == INT_DEF_LB_CMD_ERROR) {
			rsp.CrcErrorCount = ret_mb[1];
			rsp.DisparityErrorCount = ret_mb[2];
			rsp.FrameLengthErrorCount = ret_mb[3];
			rsp.IterationCountLastError =
			    (ret_mb[19] << 16) | ret_mb[18];
		}
	}

	status = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), &rsp, pext->ResponseLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla2x00_send_loopback: ERROR copy "
		    "write of response buffer.\n"));
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("qla2x00_send_loopback: exiting.\n"));

	return rval;
}

int
qla2x00_read_option_rom(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		rval = 0;


	if (pext->SubCode)
		return qla2x00_read_option_rom_ext(ha, pext, mode);

	DEBUG9(printk("%s: entered.\n", __func__));

	/* These interfaces are not valid for 24xx and 25xx chips. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	/* The ISP2312 v2 chip cannot access the FLASH registers via MMIO. */
	if (IS_QLA2312(ha) && ha->product_id[3] == 0x2 && !ha->pio_address) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	if (pext->ResponseLen != FLASH_IMAGE_SIZE) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		return rval;
	}

	/* Dump FLASH. This is for non-24xx/25xx */
 	if (qla2x00_update_or_read_flash(ha, Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), 0, FLASH_IMAGE_SIZE, QLA2X00_READ)) {
		pext->Status = EXT_STATUS_ERR;
	} else {
		pext->Status = EXT_STATUS_OK;
		pext->DetailStatus = EXT_STATUS_OK;
	}

	DEBUG9(printk("%s: exiting.\n", __func__));

	return rval;
}

int
qla2x00_read_option_rom_ext(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		iter, found;
	int		rval = 0;
	uint8_t		*image_ptr;
	uint32_t	saddr, length;

	DEBUG9(printk("%s: entered.\n", __func__));

	found = 0;
	saddr = length = 0;

	/* Retrieve region or raw starting address. */
	if (pext->SubCode == 0xFFFF) {
		saddr = pext->Reserved1;
		length = pext->RequestLen;
		found++;
	} else {
		INT_OPT_ROM_REGION *OptionRomTable = NULL;
		unsigned long OptionRomTableSize;

		/* Pick the right OptionRom table based on device id */
		qla2x00_get_option_rom_table(ha, &OptionRomTable,
		    &OptionRomTableSize);

		for (iter = 0; OptionRomTable != NULL && iter <
		    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION));
		    iter++) {
			if (OptionRomTable[iter].Region == pext->SubCode) {
				saddr = OptionRomTable[iter].Beg;
				length = OptionRomTable[iter].Size;
				found++;
				break;
			}
		}
	}

	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return rval;
	}

	if (pext->ResponseLen < length) {
		pext->Status = EXT_STATUS_COPY_ERR;
		return (-EFAULT);
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		image_ptr = vmalloc(length);
		if (image_ptr == NULL) {
			pext->Status = EXT_STATUS_NO_MEMORY;
			printk(KERN_WARNING
			    "%s: ERROR in flash allocation.\n", __func__);
			return rval;
		}
	} else {
		image_ptr = Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode);
	}

	/* Dump FLASH. */
 	if (qla2x00_update_or_read_flash(ha, image_ptr, saddr, length,
	    QLA2X00_READ)) {
		pext->Status = EXT_STATUS_ERR;
	} else {
		pext->Status = EXT_STATUS_OK;
		pext->DetailStatus = EXT_STATUS_OK;
	}

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		rval = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode), image_ptr, length);
		if (rval) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
			    __func__, ha->host_no, ha->instance));
			vfree(image_ptr);
			return (-EFAULT);
		}

		vfree(image_ptr);
	}

	DEBUG9(printk("%s: exiting.\n", __func__));

	return rval;
}

int
qla2x00_update_option_rom(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		rval = 0;
	uint8_t		*usr_tmp;
	uint8_t		*kern_tmp;
	uint16_t	status;

	DEBUG9(printk("%s(%ld): inst=%ld ext ioctl struct dump-\n",
	    __func__, ha->host_no, ha->instance));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)pext,
	    sizeof(EXT_IOCTL)));

	if (pext->SubCode)
		return qla2x00_update_option_rom_ext(ha, pext, mode);

	DEBUG9(printk("%s: entered.\n", __func__));

	/* These interfaces are not valid for 24xx and 25xx chips. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	/* The ISP2312 v2 chip cannot access the FLASH registers via MMIO. */
	if (IS_QLA2312(ha) && ha->product_id[3] == 0x2 && !ha->pio_address) {
		DEBUG10(printk("%s: got 2312 and no flash access via mmio.\n",
		    __func__));
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	if (pext->RequestLen != FLASH_IMAGE_SIZE) {
		DEBUG10(printk("%s: wrong RequestLen=%d, should be %d.\n",
		    __func__, pext->RequestLen, FLASH_IMAGE_SIZE));
		pext->Status = EXT_STATUS_INVALID_PARAM;
		return rval;
	}

	/* Read from user buffer */
	kern_tmp = vmalloc(FLASH_IMAGE_SIZE);
	if (kern_tmp == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG10(printk("%s: vmalloc failed.\n", __func__));
		printk(KERN_WARNING
			"%s: ERROR in flash allocation.\n", __func__);
		return rval;
	}

	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	DEBUG9(printk("%s(%ld): going to copy from user.\n",
	    __func__, ha->host_no));

	rval = copy_from_user(kern_tmp, usr_tmp, FLASH_IMAGE_SIZE);
	if (rval) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n",
		    __func__, Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): done copy from user. data dump:\n",
	    __func__, ha->host_no));
	DEBUG9(qla2x00_dump_buffer((uint8_t *)kern_tmp,
	    FLASH_IMAGE_SIZE));

	/* Go with update */
	status = qla2x00_update_or_read_flash(ha, kern_tmp, 0, FLASH_IMAGE_SIZE,
	    QLA2X00_WRITE);

	vfree(kern_tmp);

	if (status) {
		pext->Status = EXT_STATUS_ERR;
		DEBUG9_10(printk("%s: ERROR updating flash.\n", __func__));
	} else {
		pext->Status = EXT_STATUS_OK;
		pext->DetailStatus = EXT_STATUS_OK;
	}

	DEBUG9(printk("%s: exiting.\n", __func__));

	return rval;
}

int
qla2x00_update_option_rom_ext(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		iter, found;
	int		ret = 0;
	uint16_t	status;
	uint8_t		*usr_tmp;
	uint8_t		*kern_tmp;
	uint8_t		*ptmp_mem = NULL;
	uint32_t	saddr, length;
	scsi_qla_host_t	*hba2 = NULL;

	DEBUG9(printk("%s: entered.\n", __func__));

	found = 0;
	saddr = length = 0;
	/* Retrieve region or raw starting address. */
	if (pext->SubCode == 0xFFFF) {
		saddr = pext->Reserved1;
		length = pext->RequestLen;
		found++;
	} else {
		INT_OPT_ROM_REGION *OptionRomTable = NULL;
		unsigned long  OptionRomTableSize;

		/* Pick the right OptionRom table based on device id */
		qla2x00_get_option_rom_table(ha, &OptionRomTable,
		    &OptionRomTableSize);

		for (iter = 0; OptionRomTable != NULL && iter <
		    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION));
		    iter++) {
			if (OptionRomTable[iter].Region == pext->SubCode) {
				saddr = OptionRomTable[iter].Beg;
				length = OptionRomTable[iter].Size;
				found++;
				break;
			}
		}
	}

	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return ret;
	}

	if (pext->RequestLen < length) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		return ret;
	}

	/* Read from user buffer */
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	kern_tmp = vmalloc(length);
	if (kern_tmp == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		printk(KERN_WARNING
		    "%s: ERROR in flash allocation.\n", __func__);
		return ret;
	}

	ret = copy_from_user(kern_tmp, usr_tmp, length);
	if (ret) {
		vfree(kern_tmp);
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", __func__,
		    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode)));
		return (-EFAULT);
	}

	/* Go with update */
	status = qla2x00_update_or_read_flash(ha, kern_tmp, saddr, length,
	    QLA2X00_WRITE);

	vfree(kern_tmp);
	pext->Status = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	if (status) {
		pext->Status = EXT_STATUS_ERR;
		DEBUG9_10(printk("%s: ERROR updating flash.\n", __func__));
	} else {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			if (qla2x00_get_ioctl_scrap_mem(ha,
			    (void **)&ptmp_mem, PAGE_SIZE)) {
				/* not enough memory */
				pext->Status = EXT_STATUS_NO_MEMORY;
				DEBUG9_10(printk("%s(%ld): inst=%ld scrap not "
				    "big enough. size requested=%ld.\n",
				    __func__, ha->host_no,
				    ha->instance, PAGE_SIZE));
			} else {
				if (qla24xx_refresh_flash_version(ha,
				    ptmp_mem)) {

					pext->Status = EXT_STATUS_ERR;
					DEBUG9_10(printk( "%s: ERROR reading "
					    "updated flash versions.\n",
					    __func__));
				}

				/* Refresh second function if exists. */
				read_lock(&qla_hostlist_lock);
				list_for_each_entry(hba2, &qla_hostlist, list) {
					if ((hba2->pdev->bus->number) ==
					    (ha->pdev->bus->number) &&
					    PCI_SLOT(hba2->pdev->devfn) ==
					    PCI_SLOT(ha->pdev->devfn) &&
					    PCI_FUNC(hba2->pdev->devfn) !=
					    PCI_FUNC(ha->pdev->devfn))  {
						hba2->code_types = ha->code_types;
						hba2->bios_revision[0] = ha->bios_revision[0];
						hba2->bios_revision[1] = ha->bios_revision[1];
						hba2->efi_revision[0] = ha->efi_revision[0];
						hba2->efi_revision[1] = ha->efi_revision[1];
						hba2->fcode_revision[0] = ha->fcode_revision[0];
						hba2->fcode_revision[1] = ha->fcode_revision[1];
						hba2->fw_revision[0] = ha->fw_revision[0];
						hba2->fw_revision[1] = ha->fw_revision[1];
						hba2->fw_revision[2] = ha->fw_revision[2];
						hba2->fw_revision[3] = ha->fw_revision[3];
					}
				}
				read_unlock(&qla_hostlist_lock);
			}

			qla2x00_free_ioctl_scrap_mem(ha);
		}
	}

	DEBUG9(printk("%s: exiting.\n", __func__));

	return ret;
}

int
qla2x00_get_option_rom_layout(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0, iter;
	INT_OPT_ROM_REGION *OptionRomTable = NULL;
	INT_OPT_ROM_LAYOUT *optrom_layout;
	unsigned long	OptionRomTableSize;

	DEBUG9(printk("%s: entered.\n", __func__));

	/* Pick the right OptionRom table based on device id */
	qla2x00_get_option_rom_table(ha, &OptionRomTable, &OptionRomTableSize);

	if (OptionRomTable == NULL) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld) Option Rom Table for device_id=0x%x "
		    "not defined\n", __func__, ha->host_no, ha->pdev->device));
		return ret;
	}

	if (pext->ResponseLen < OptionRomTableSize) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s(%ld) buffer too small: response_len = %d "
		    "optrom_table_len=%ld.\n", __func__, ha->host_no,
		    pext->ResponseLen, OptionRomTableSize));
		return ret;
	}
	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&optrom_layout,
	    OptionRomTableSize)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n", __func__, ha->host_no,
		    ha->instance, OptionRomTableSize));
		return ret;
	}

	// Dont Count the NULL Entry.
	optrom_layout->NoOfRegions = (UINT32)
	    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION) - 1);

	for (iter = 0; iter < optrom_layout->NoOfRegions; iter++) {
		optrom_layout->Region[iter].Region =
		    OptionRomTable[iter].Region;
		optrom_layout->Region[iter].Size =
		    OptionRomTable[iter].Size;

		if (OptionRomTable[iter].Region == INT_OPT_ROM_REGION_ALL)
			optrom_layout->Size = OptionRomTable[iter].Size;
	}

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    optrom_layout, OptionRomTableSize);
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

	DEBUG9(printk("%s: exiting.\n", __func__));

	return ret;
}

static void
qla2x00_get_option_rom_table(scsi_qla_host_t *ha,
    INT_OPT_ROM_REGION **pOptionRomTable, unsigned long  *OptionRomTableSize)
{
	DEBUG9(printk("%s: entered.\n", __func__));

	switch (ha->pdev->device) {
	case PCI_DEVICE_ID_QLOGIC_ISP6312:
		*pOptionRomTable = OptionRomTable6312;
		*OptionRomTableSize = sizeof(OptionRomTable6312);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2312:
		/* HBA Model 6826A - is 2312 V3 Chip */
		if (IS_OEM_1_HBA(ha->pdev->subsystem_vendor,
		    ha->pdev->subsystem_device)) {
			*pOptionRomTable = OptionRomTableHp;
			*OptionRomTableSize = sizeof(OptionRomTableHp);
		} else {
			*pOptionRomTable = OptionRomTable2312;
			*OptionRomTableSize = sizeof(OptionRomTable2312);
		}
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2322:
		*pOptionRomTable = OptionRomTable2322;
		*OptionRomTableSize = sizeof(OptionRomTable2322);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP6322:
		*pOptionRomTable = OptionRomTable6322;
		*OptionRomTableSize = sizeof(OptionRomTable6322);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2422:
	case PCI_DEVICE_ID_QLOGIC_ISP2432:
	case PCI_DEVICE_ID_QLOGIC_ISP5422:
	case PCI_DEVICE_ID_QLOGIC_ISP5432:
		*pOptionRomTable = OptionRomTable2422;
		*OptionRomTableSize = sizeof(OptionRomTable2422);
		break;
	default:
		DEBUG9_10(printk("%s(%ld) Option Rom Table for device_id=0x%x "
		    "not defined\n", __func__, ha->host_no, ha->pdev->device));
		break;
	}

	DEBUG9(printk("%s: exiting.\n", __func__));
}

static int
qla2x00_get_oem_1_vpd(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		indicator = 0;
	uint8_t		*ptmp_buf = NULL;
	uint8_t		*image_ptr = NULL;
	uint32_t	transfer_size;
	PINT_PCI_ROM_HEADER ppci_hdr;
	PINT_PCI_DATA_STRUCT ppci_data;	

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no));

	transfer_size = 0x200; /* 512 */
	if (pext->ResponseLen < transfer_size) {
		pext->ResponseLen = transfer_size;
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Response buffer too small.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	/* Allocate memory for image_ptr, 128K Size of Flash */
	image_ptr = vmalloc(FLASH_IMAGE_SIZE);
	if (!image_ptr) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld Out of Memory. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    FLASH_IMAGE_SIZE));
		return (ret);

	}

	/* Get VPD from FLASH (option ROM) */
        ret = qla2x00_update_or_read_flash(ha, image_ptr, 0, FLASH_IMAGE_SIZE,
            QLA2X00_READ);
	if (ret) {
		ret = -EFAULT;
		pext->Status = EXT_STATUS_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld Unable to read FLASH. "
		    __func__, ha->host_no, ha->instance));
		vfree(image_ptr);
		return (ret);
	}

	ret = -EFAULT;
	/* Get the VPD start pointer */
	ppci_hdr = (PINT_PCI_ROM_HEADER)image_ptr;	
	do {
		/* Get the PCI data struct */
		ppci_data = (PINT_PCI_DATA_STRUCT)((uint8_t *)ppci_hdr + 
		    le16_to_cpu(ppci_hdr->PcirOffset));
		
		/* Validate the PCI data struct */	
		if (le32_to_cpu(ppci_data->Signature) != 
		    INT_PCI_DATA_STRUCT_SIGNATURE) {
	
			DEBUG9_10(printk("%s(%ld): Invalid PCI Sig 0x%x\n", 
			    le32_to_cpu(ppci_data->Signature), __func__, ha->host_no));
			ret = -EFAULT;
			break;
		}

		indicator = ppci_data->Indicator;

		if (le16_to_cpu(ppci_data->DeviceId) == INT_PDS_DID_VPD) {
			/* PCI data is pointing to VPD page */
			ptmp_buf = (uint8_t *)ppci_data +
			    le16_to_cpu(ppci_data->Length);	
			ret = 0;
			break;
		}

		/* Get the next image */
		ppci_hdr = (PINT_PCI_ROM_HEADER) ((uint8_t *)ppci_hdr +
		   (le16_to_cpu(ppci_data->ImageLength) * 512));
		
	} while (indicator != INT_PDS_ID_LAST_IMAGE);	

	if (ret) {
		pext->Status = EXT_STATUS_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld Image looks corrupted. "
		    __func__, ha->host_no, ha->instance));
		vfree(image_ptr);
		return (ret);

	}

	DEBUG2(qla2x00_dump_buffer((uint8_t *)ptmp_buf, transfer_size));
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode), ptmp_buf,
	    transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		vfree(image_ptr);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	vfree(image_ptr);

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no));

	return (ret);
}


int
qla2x00_get_vpd(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*ptmp_buf;
	uint32_t	data_offset;
	uint32_t	transfer_size;
	unsigned long	flags;

	/* Check if this is OEM HBA */
	if (IS_OEM_1_HBA(ha->pdev->subsystem_vendor,
	    ha->pdev->subsystem_device)) {
		ret = qla2x00_get_oem_1_vpd(ha, pext, mode);
		return (ret);
	}


	if (!(IS_QLA24XX(ha) || IS_QLA54XX(ha))) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx or 25xx. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no));

	transfer_size = FA_NVRAM_VPD_SIZE * 4; /* byte count */
	if (pext->ResponseLen < transfer_size) {
		pext->ResponseLen = transfer_size;
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Response buffer too small.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_buf,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ha->nvram_size));
		return (ret);
	}

	if (PCI_FUNC(ha->pdev->devfn))
		data_offset = FA_NVRAM_VPD1_ADDR;
	else
		data_offset = FA_NVRAM_VPD0_ADDR;

	/* Dump VPD region in NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_read_nvram_data(ha, ptmp_buf, data_offset, transfer_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_buf, transfer_size);
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

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no));

	return (ret);
}

int
qla2x00_update_vpd(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_tmp, *kernel_tmp, *pnew_nv;
	uint32_t	data_offset;
	uint32_t	transfer_size;
	unsigned long	flags;


	if (!(IS_QLA24XX(ha) || IS_QLA54XX(ha))) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx or 25xx. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no));

	transfer_size = FA_NVRAM_VPD_SIZE * 4; /* byte count */
	if (pext->RequestLen < transfer_size)
		transfer_size = pext->RequestLen;

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&pnew_nv, transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance, transfer_size));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): transfer_size=%d.\n",
	    __func__, ha->host_no, transfer_size));

	/* Read from user buffer */
	kernel_tmp = (uint8_t *)pnew_nv;
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	ret = copy_from_user(kernel_tmp, usr_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): ERROR in buffer copy READ. RequestAdr=%p\n",
		    __func__, ha->host_no, Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	if (PCI_FUNC(ha->pdev->devfn))
		data_offset = FA_NVRAM_VPD1_ADDR;
	else
		data_offset = FA_NVRAM_VPD0_ADDR;

	/* Write NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_write_nvram_data(ha, pnew_nv, data_offset, transfer_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no));

	/* No need to reset the 24xx. */
	return ret;
}

int
qla2x00_get_sfp_data(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*ptmp_buf, *ptmp_iter;
	uint32_t	transfer_size;
	uint16_t	iter, addr, offset;
	int		rval;

	if (!(IS_QLA24XX(ha) || IS_QLA54XX(ha))) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx or 25xx. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no));

	transfer_size = SFP_DEV_SIZE * 2;
	if (pext->ResponseLen < transfer_size) {
		pext->ResponseLen = transfer_size;
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Response buffer too small.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&ptmp_buf,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ha->nvram_size));
		return (ret);
	}

	ptmp_iter = ptmp_buf;
	addr = 0xa0;
	for (iter = 0, offset = 0; iter < (SFP_DEV_SIZE * 2) / SFP_BLOCK_SIZE;
	    iter++, offset += SFP_BLOCK_SIZE) {
		if (iter == 4) {
			/* Skip to next device address. */
			addr = 0xa2;
			offset = 0;
		}

		rval = qla2x00_read_sfp(ha, ha->sfp_data_dma, addr, offset,
		    SFP_BLOCK_SIZE);
		if (rval != QLA_SUCCESS) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR reading SFP "
			    "data (%x/%x/%x).\n",
			    __func__, ha->host_no, ha->instance, rval, addr,
			    offset));
			qla2x00_free_ioctl_scrap_mem(ha);
			return (-EFAULT);
		}
		memcpy(ptmp_iter, ha->sfp_data, SFP_BLOCK_SIZE);
		ptmp_iter += SFP_BLOCK_SIZE;
	}

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_buf, transfer_size);
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

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no));

	return (ret);
}

int
qla2x00_update_port_param(scsi_qla_host_t *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0, rval, port_found;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	uint16_t	idma_speed;
	uint8_t		*usr_temp, *kernel_tmp;
	fc_port_t	*fcport;
	INT_PORT_PARAM	*port_param;

	if (!IS_QLA24XX(ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	if (qla2x00_get_ioctl_scrap_mem(ha, (void **)&port_param,
	    sizeof(INT_PORT_PARAM))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%Zd.\n",
		    __func__, ha->host_no, ha->instance,
		    sizeof(INT_PORT_PARAM)));
		return (ret);
	}
	/* Copy request buffer */
	usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)port_param;
	ret = copy_from_user(kernel_tmp, usr_temp,
	    sizeof(INT_PORT_PARAM));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	if (port_param->FCScsiAddr.DestType != EXT_DEF_TYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Dest "
		    "type.\n", __func__, ha->host_no, ha->instance));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	port_found = 0;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (memcmp(fcport->port_name,
		    port_param->FCScsiAddr.DestAddr.WWPN, WWN_SIZE))
			continue;

		port_found++;
		break;
	}
	if (!port_found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld FC AddrFormat - DID NOT "
		    "FIND Port matching WWPN.\n",
		    __func__, ha->host_no, ha->instance));
		qla2x00_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Go with operation. */
	if (port_param->Mode) {
		switch (port_param->Speed) {
		case EXT_DEF_PORTSPEED_1GBIT:
			idma_speed = PORT_SPEED_1GB;
			break;
		case EXT_DEF_PORTSPEED_2GBIT:
			idma_speed = PORT_SPEED_2GB;
			break;
		case EXT_DEF_PORTSPEED_4GBIT:
			idma_speed = PORT_SPEED_4GB;
			break;
		default:
			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -invalid "
			    "speed.\n", __func__, ha->host_no, ha->instance));
			qla2x00_free_ioctl_scrap_mem(ha);
			return (ret);
		}

		rval = qla2x00_set_idma_speed(ha, fcport->loop_id, idma_speed,
		    mb);
		if (rval != QLA_SUCCESS) {
			if (mb[0] == MBS_COMMAND_ERROR && mb[1] == 0x09)
				pext->Status = EXT_STATUS_DEVICE_NOT_READY;
			else if (mb[0] == MBS_COMMAND_PARAMETER_ERROR)
				pext->Status = EXT_STATUS_INVALID_PARAM;
			else
				pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk("%s(%ld): inst=%ld set iDMA cmd "
			    "FAILED=%x.\n", __func__, ha->host_no,
			    ha->instance, mb[0]));
			qla2x00_free_ioctl_scrap_mem(ha);
			return (ret);
		}
	} else {
		rval = qla2x00_get_idma_speed(ha, fcport->loop_id,
		    &idma_speed, mb);
		if (rval != QLA_SUCCESS) {
			if (mb[0] == MBS_COMMAND_ERROR && mb[1] == 0x09)
				pext->Status = EXT_STATUS_DEVICE_NOT_READY;
			else if (mb[0] == MBS_COMMAND_PARAMETER_ERROR)
				pext->Status = EXT_STATUS_INVALID_PARAM;
			else
				pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk("%s(%ld): inst=%ld get iDMA cmd "
			    "FAILED=%x.\n", __func__, ha->host_no,
			    ha->instance, mb[0]));
			qla2x00_free_ioctl_scrap_mem(ha);
			return (ret);
		}

		switch (idma_speed) {
		case PORT_SPEED_1GB:
			port_param->Speed = EXT_DEF_PORTSPEED_1GBIT;
			break;
		case PORT_SPEED_2GB:
			port_param->Speed = EXT_DEF_PORTSPEED_2GBIT;
			break;
		case PORT_SPEED_4GB:
			port_param->Speed = EXT_DEF_PORTSPEED_4GBIT;
			break;
		default:
			port_param->Speed = 0xFFFF;
			break;
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)port_param;
		ret = copy_to_user(usr_temp, kernel_tmp,
		    sizeof(INT_PORT_PARAM));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf ret=%d\n",
			    __func__, ha->host_no, ha->instance, ret));
			qla2x00_free_ioctl_scrap_mem(ha);
			return (-EFAULT);
		}
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qla2x00_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no));

	return (ret);
}
