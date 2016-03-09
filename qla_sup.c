/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/delay.h>
#include <asm/uaccess.h>

static uint16_t qla2x00_nvram_request(scsi_qla_host_t *, uint32_t);
static void qla2x00_nv_deselect(scsi_qla_host_t *);
static void qla2x00_nv_write(scsi_qla_host_t *, uint16_t);
static int qla2x00_clear_nvram_protection(scsi_qla_host_t *);
static void qla2x00_set_nvram_protection(scsi_qla_host_t *, int);
static int qla2x00_write_nvram_word_tmo(scsi_qla_host_t *, uint32_t, uint16_t,
    uint32_t);
#ifdef CONFIG_SCSI_QLA2XXX_FAILOVER
uint8_t qla2x00_read_flash_byte(scsi_qla_host_t *, uint32_t);
static void qla2x00_write_flash_byte(scsi_qla_host_t *, uint32_t, uint8_t);
static uint8_t qla2x00_poll_flash(scsi_qla_host_t *, uint32_t, uint8_t,
    uint8_t, uint8_t);
static uint8_t qla2x00_program_flash_address(scsi_qla_host_t *, uint32_t,
    uint8_t, uint8_t, uint8_t);
static uint8_t qla2x00_erase_flash(scsi_qla_host_t *, uint8_t, uint8_t);
static uint8_t qla2x00_erase_flash_sector(scsi_qla_host_t *, uint32_t,
    uint32_t, uint8_t, uint8_t);
void qla2x00_get_flash_manufacturer(scsi_qla_host_t *, uint8_t *,
    uint8_t *);
int qla2x00_get_flash_version(scsi_qla_host_t *);
static int qla2x00_get_fcode_version(scsi_qla_host_t *, uint32_t);
uint16_t qla2x00_get_flash_image(scsi_qla_host_t *, uint8_t *);
uint16_t qla2x00_set_flash_image(scsi_qla_host_t *, uint8_t *, uint32_t,
    uint32_t);
#endif
uint16_t qla24xx_update_or_read_flash(scsi_qla_host_t *, uint8_t *,
    uint32_t, uint32_t, uint8_t);
int qla24xx_get_flash_version(scsi_qla_host_t *, uint8_t *);

/*
 * NVRAM support routines
 */

/**
 * qla2x00_lock_nvram_access() -
 * @ha: HA context
 */
void
qla2x00_lock_nvram_access(scsi_qla_host_t *ha)
{
	uint16_t data;
	device_reg_t __iomem *reg = ha->iobase;

	if (!IS_QLA2100(ha) && !IS_QLA2200(ha) && !IS_QLA2300(ha)) {
		data = RD_REG_WORD(&reg->nvram);
		while (data & NVR_BUSY) {
			udelay(100);
			data = RD_REG_WORD(&reg->nvram);
		}

		/* Lock resource */
		WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0x1);
		RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		udelay(5);
		data = RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		while ((data & BIT_0) == 0) {
			/* Lock failed */
			udelay(100);
			WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0x1);
			RD_REG_WORD(&reg->u.isp2300.host_semaphore);
			udelay(5);
			data = RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		}
	}
}

/**
 * qla2x00_unlock_nvram_access() -
 * @ha: HA context
 */
void
qla2x00_unlock_nvram_access(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;

	if (!IS_QLA2100(ha) && !IS_QLA2200(ha) && !IS_QLA2300(ha)) {
		WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0);
		RD_REG_WORD(&reg->u.isp2300.host_semaphore);
	}
}

/**
 * qla2x00_clear_nvram_protection() -
 * @ha: HA context
 */
static int
qla2x00_clear_nvram_protection(scsi_qla_host_t *ha)
{
	int ret, stat;
	device_reg_t __iomem *reg;
	uint32_t word, wait_cnt;
	uint16_t wprot, wprot_old;

	reg = ha->iobase;

	/* Clear NVRAM write protection. */
	ret = QLA_FUNCTION_FAILED;
	wprot_old = cpu_to_le16(qla2x00_get_nvram_word(ha, ha->nvram_base));
	stat = qla2x00_write_nvram_word_tmo(ha, ha->nvram_base,
	    __constant_cpu_to_le16(0x1234), 100000);
	wprot = cpu_to_le16(qla2x00_get_nvram_word(ha, ha->nvram_base));
	if (stat != QLA_SUCCESS || wprot != 0x1234) {
		/* Write enable. */
		qla2x00_nv_write(ha, NVR_DATA_OUT);
		qla2x00_nv_write(ha, 0);
		qla2x00_nv_write(ha, 0);
		for (word = 0; word < 8; word++)
			qla2x00_nv_write(ha, NVR_DATA_OUT);

		qla2x00_nv_deselect(ha);

		/* Enable protection register. */
		qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qla2x00_nv_write(ha, NVR_PR_ENABLE);
		qla2x00_nv_write(ha, NVR_PR_ENABLE);
		for (word = 0; word < 8; word++)
			qla2x00_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

		qla2x00_nv_deselect(ha);

		/* Clear protection register (ffff is cleared). */
		qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		for (word = 0; word < 8; word++)
			qla2x00_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

		qla2x00_nv_deselect(ha);

		/* Wait for NVRAM to become ready. */
		WRT_REG_WORD(&reg->nvram, NVR_SELECT);
		RD_REG_WORD(&reg->nvram);	/* PCI Posting. */
		wait_cnt = NVR_WAIT_CNT;
		do {
			if (!--wait_cnt) {
				DEBUG9_10(printk("%s(%ld): NVRAM didn't go "
				    "ready...\n", __func__,
				    ha->host_no));
				break;
			}
			NVRAM_DELAY();
			word = RD_REG_WORD(&reg->nvram);
		} while ((word & NVR_DATA_IN) == 0);

		if (wait_cnt)
			ret = QLA_SUCCESS;
	} else
		qla2x00_write_nvram_word(ha, ha->nvram_base, wprot_old);

	return ret;
}

static void
qla2x00_set_nvram_protection(scsi_qla_host_t *ha, int stat)
{
	device_reg_t __iomem *reg;
	uint32_t word, wait_cnt;

	reg = ha->iobase;

	if (stat != QLA_SUCCESS)
		return;

	/* Set NVRAM write protection. */
	/* Write enable. */
	qla2x00_nv_write(ha, NVR_DATA_OUT);
	qla2x00_nv_write(ha, 0);
	qla2x00_nv_write(ha, 0);
	for (word = 0; word < 8; word++)
		qla2x00_nv_write(ha, NVR_DATA_OUT);

	qla2x00_nv_deselect(ha);

	/* Enable protection register. */
	qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	qla2x00_nv_write(ha, NVR_PR_ENABLE);
	qla2x00_nv_write(ha, NVR_PR_ENABLE);
	for (word = 0; word < 8; word++)
		qla2x00_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

	qla2x00_nv_deselect(ha);

	/* Enable protection register. */
	qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	qla2x00_nv_write(ha, NVR_PR_ENABLE);
	qla2x00_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	for (word = 0; word < 8; word++)
		qla2x00_nv_write(ha, NVR_PR_ENABLE);

	qla2x00_nv_deselect(ha);

	/* Wait for NVRAM to become ready. */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	wait_cnt = NVR_WAIT_CNT;
	do {
		if (!--wait_cnt) {
			DEBUG9_10(printk("%s(%ld): NVRAM didn't go ready...\n",
			    __func__, ha->host_no));
			break;
		}
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
	} while ((word & NVR_DATA_IN) == 0);
}

/**
 * qla2x00_get_nvram_word() - Calculates word position in NVRAM and calls the
 *	request routine to get the word from NVRAM.
 * @ha: HA context
 * @addr: Address in NVRAM to read
 *
 * Returns the word read from nvram @addr.
 */
uint16_t
qla2x00_get_nvram_word(scsi_qla_host_t *ha, uint32_t addr)
{
	uint16_t	data;
	uint32_t	nv_cmd;

	nv_cmd = addr << 16;
	nv_cmd |= NV_READ_OP;
	data = qla2x00_nvram_request(ha, nv_cmd);

	return (data);
}

/**
 * qla2x00_write_nvram_word() - Write NVRAM data.
 * @ha: HA context
 * @addr: Address in NVRAM to write
 * @data: word to program
 */
void
qla2x00_write_nvram_word(scsi_qla_host_t *ha, uint32_t addr, uint16_t data)
{
	int count;
	uint16_t word;
	uint32_t nv_cmd, wait_cnt;
	device_reg_t __iomem *reg = ha->iobase;

	qla2x00_nv_write(ha, NVR_DATA_OUT);
	qla2x00_nv_write(ha, 0);
	qla2x00_nv_write(ha, 0);

	for (word = 0; word < 8; word++)
		qla2x00_nv_write(ha, NVR_DATA_OUT);

	qla2x00_nv_deselect(ha);

	/* Write data */
	nv_cmd = (addr << 16) | NV_WRITE_OP;
	nv_cmd |= data;
	nv_cmd <<= 5;
	for (count = 0; count < 27; count++) {
		if (nv_cmd & BIT_31)
			qla2x00_nv_write(ha, NVR_DATA_OUT);
		else
			qla2x00_nv_write(ha, 0);

		nv_cmd <<= 1;
	}

	qla2x00_nv_deselect(ha);

	/* Wait for NVRAM to become ready */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	wait_cnt = NVR_WAIT_CNT;
	do {
		if (!--wait_cnt) {
			DEBUG9_10(printk("%s(%ld): NVRAM didn't go ready...\n",
			    __func__, ha->host_no));
			break;
		}
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
	} while ((word & NVR_DATA_IN) == 0);

	qla2x00_nv_deselect(ha);

	/* Disable writes */
	qla2x00_nv_write(ha, NVR_DATA_OUT);
	for (count = 0; count < 10; count++)
		qla2x00_nv_write(ha, 0);

	qla2x00_nv_deselect(ha);
}

static int
qla2x00_write_nvram_word_tmo(scsi_qla_host_t *ha, uint32_t addr, uint16_t data,
    uint32_t tmo)
{
	int ret, count;
	uint16_t word;
	uint32_t nv_cmd;
	device_reg_t __iomem *reg = ha->iobase;

	ret = QLA_SUCCESS;

	qla2x00_nv_write(ha, NVR_DATA_OUT);
	qla2x00_nv_write(ha, 0);
	qla2x00_nv_write(ha, 0);

	for (word = 0; word < 8; word++)
		qla2x00_nv_write(ha, NVR_DATA_OUT);

	qla2x00_nv_deselect(ha);

	/* Write data */
	nv_cmd = (addr << 16) | NV_WRITE_OP;
	nv_cmd |= data;
	nv_cmd <<= 5;
	for (count = 0; count < 27; count++) {
		if (nv_cmd & BIT_31)
			qla2x00_nv_write(ha, NVR_DATA_OUT);
		else
			qla2x00_nv_write(ha, 0);

		nv_cmd <<= 1;
	}

	qla2x00_nv_deselect(ha);

	/* Wait for NVRAM to become ready */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	do {
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
		if (!--tmo) {
			ret = QLA_FUNCTION_FAILED;
			break;
		}
	} while ((word & NVR_DATA_IN) == 0);

	qla2x00_nv_deselect(ha);

	/* Disable writes */
	qla2x00_nv_write(ha, NVR_DATA_OUT);
	for (count = 0; count < 10; count++)
		qla2x00_nv_write(ha, 0);

	qla2x00_nv_deselect(ha);

	return ret;
}

/**
 * qla2x00_nvram_request() - Sends read command to NVRAM and gets data from
 *	NVRAM.
 * @ha: HA context
 * @nv_cmd: NVRAM command
 *
 * Bit definitions for NVRAM command:
 *
 *	Bit 26     = start bit
 *	Bit 25, 24 = opcode
 *	Bit 23-16  = address
 *	Bit 15-0   = write data
 *
 * Returns the word read from nvram @addr.
 */
static uint16_t
qla2x00_nvram_request(scsi_qla_host_t *ha, uint32_t nv_cmd)
{
	uint8_t		cnt;
	device_reg_t __iomem *reg = ha->iobase;
	uint16_t	data = 0;
	uint16_t	reg_data;

	/* Send command to NVRAM. */
	nv_cmd <<= 5;
	for (cnt = 0; cnt < 11; cnt++) {
		if (nv_cmd & BIT_31)
			qla2x00_nv_write(ha, NVR_DATA_OUT);
		else
			qla2x00_nv_write(ha, 0);
		nv_cmd <<= 1;
	}

	/* Read data from NVRAM. */
	for (cnt = 0; cnt < 16; cnt++) {
		WRT_REG_WORD(&reg->nvram, NVR_SELECT | NVR_CLOCK);
		RD_REG_WORD(&reg->nvram);	/* PCI Posting. */
		NVRAM_DELAY();
		data <<= 1;
		reg_data = RD_REG_WORD(&reg->nvram);
		if (reg_data & NVR_DATA_IN)
			data |= BIT_0;
		WRT_REG_WORD(&reg->nvram, NVR_SELECT);
		RD_REG_WORD(&reg->nvram);	/* PCI Posting. */
		NVRAM_DELAY();
	}

	/* Deselect chip. */
	WRT_REG_WORD(&reg->nvram, NVR_DESELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();

	return (data);
}

/**
 * qla2x00_nv_write() - Clean NVRAM operations.
 * @ha: HA context
 */
static void
qla2x00_nv_deselect(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;

	WRT_REG_WORD(&reg->nvram, NVR_DESELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
}

/**
 * qla2x00_nv_write() - Prepare for NVRAM read/write operation.
 * @ha: HA context
 * @data: Serial interface selector
 */
static void
qla2x00_nv_write(scsi_qla_host_t *ha, uint16_t data)
{
	device_reg_t __iomem *reg = ha->iobase;

	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT | NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT| NVR_CLOCK |
	    NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT | NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
}

#ifdef CONFIG_SCSI_QLA2XXX_FAILOVER
/*
 * Flash support routines
 */

/**
 * qla2x00_flash_enable() - Setup flash for reading and writing.
 * @ha: HA context
 */
void
qla2x00_flash_enable(scsi_qla_host_t *ha)
{
	uint16_t	data;
	device_reg_t __iomem *reg = ha->iobase;

	data = RD_REG_WORD(&reg->ctrl_status);
	data |= CSR_FLASH_ENABLE;
	WRT_REG_WORD(&reg->ctrl_status, data);
	RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
}

/**
 * qla2x00_flash_disable() - Disable flash and allow RISC to run.
 * @ha: HA context
 */
void
qla2x00_flash_disable(scsi_qla_host_t *ha)
{
	uint16_t	data;
	device_reg_t __iomem *reg = ha->iobase;

	data = RD_REG_WORD(&reg->ctrl_status);
	data &= ~(CSR_FLASH_ENABLE);
	WRT_REG_WORD(&reg->ctrl_status, data);
	RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
}

/**
 * qla2x00_read_flash_byte() - Reads a byte from flash
 * @ha: HA context
 * @addr: Address in flash to read
 *
 * A word is read from the chip, but, only the lower byte is valid.
 *
 * Returns the byte read from flash @addr.
 */
uint8_t
qla2x00_read_flash_byte(scsi_qla_host_t *ha, uint32_t addr)
{
	uint16_t	data;
	uint16_t	bank_select;
	device_reg_t __iomem *reg = ha->iobase;

	bank_select = RD_REG_WORD(&reg->ctrl_status);

	if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
		/* Specify 64K address range: */
		/*  clear out Module Select and Flash Address bits [19:16]. */
		bank_select &= ~0xf8;
		bank_select |= addr >> 12 & 0xf0;
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */

		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		data = RD_REG_WORD(&reg->flash_data);

		return ((uint8_t)data);
	}

	/* Setup bit 16 of flash address. */
	if ((addr & BIT_16) && ((bank_select & CSR_FLASH_64K_BANK) == 0)) {
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	} else if (((addr & BIT_16) == 0) &&
	    (bank_select & CSR_FLASH_64K_BANK)) {
		bank_select &= ~(CSR_FLASH_64K_BANK);
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	}

	/* Always perform IO mapped accesses to the FLASH registers. */
	if (ha->pio_address) {
		uint16_t data2;

		reg = (device_reg_t *)ha->pio_address;
		WRT_REG_WORD_PIO(&reg->flash_address, (uint16_t)addr);
		do {
			data = RD_REG_WORD_PIO(&reg->flash_data);
			barrier();
			cpu_relax();
			data2 = RD_REG_WORD_PIO(&reg->flash_data);
		} while (data != data2);
	} else {
		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		data = qla2x00_debounce_register(&reg->flash_data);
	}

	return ((uint8_t)data);
}

/**
 * qla2x00_write_flash_byte() - Write a byte to flash
 * @ha: HA context
 * @addr: Address in flash to write
 * @data: Data to write
 */
static void
qla2x00_write_flash_byte(scsi_qla_host_t *ha, uint32_t addr, uint8_t data)
{
	uint16_t	bank_select;
	device_reg_t __iomem *reg = ha->iobase;

	bank_select = RD_REG_WORD(&reg->ctrl_status);
	if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
		/* Specify 64K address range: */
		/*  clear out Module Select and Flash Address bits [19:16]. */
		bank_select &= ~0xf8;
		bank_select |= addr >> 12 & 0xf0;
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */

		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
		WRT_REG_WORD(&reg->flash_data, (uint16_t)data);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

		return;
	}

	/* Setup bit 16 of flash address. */
	if ((addr & BIT_16) && ((bank_select & CSR_FLASH_64K_BANK) == 0)) {
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	} else if (((addr & BIT_16) == 0) &&
	    (bank_select & CSR_FLASH_64K_BANK)) {
		bank_select &= ~(CSR_FLASH_64K_BANK);
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	}

	/* Always perform IO mapped accesses to the FLASH registers. */
	if (ha->pio_address) {
		reg = (device_reg_t *)ha->pio_address;
		WRT_REG_WORD_PIO(&reg->flash_address, (uint16_t)addr);
		WRT_REG_WORD_PIO(&reg->flash_data, (uint16_t)data);
	} else {
		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
		WRT_REG_WORD(&reg->flash_data, (uint16_t)data);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
	}
}

/**
 * qla2x00_poll_flash() - Polls flash for completion.
 * @ha: HA context
 * @addr: Address in flash to poll
 * @poll_data: Data to be polled
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * This function polls the device until bit 7 of what is read matches data
 * bit 7 or until data bit 5 becomes a 1.  If that hapens, the flash ROM timed
 * out (a fatal error).  The flash book recommeds reading bit 7 again after
 * reading bit 5 as a 1.
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qla2x00_poll_flash(scsi_qla_host_t *ha, uint32_t addr, uint8_t poll_data,
    uint8_t man_id, uint8_t flash_id)
{
	uint8_t		status;
	uint8_t		flash_data;
	uint32_t	cnt;

	status = 1;

	/* Wait for 30 seconds for command to finish. */
	poll_data &= BIT_7;
	for (cnt = 3000000; cnt; cnt--) {
		flash_data = qla2x00_read_flash_byte(ha, addr);
		if ((flash_data & BIT_7) == poll_data) {
			status = 0;
			break;
		}

		if (man_id != 0x40 && man_id != 0xda) {
			if ((flash_data & BIT_5) && cnt > 2)
				cnt = 2;
		}
		udelay(10);
		barrier();
	}
	return (status);
}

/**
 * qla2x00_program_flash_address() - Programs a flash address
 * @ha: HA context
 * @addr: Address in flash to program
 * @data: Data to be written in flash
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qla2x00_program_flash_address(scsi_qla_host_t *ha, uint32_t addr, uint8_t data,
    uint8_t man_id, uint8_t flash_id)
{
	/* Write Program Command Sequence */
	if (IS_OEM_001(ha)) {
		qla2x00_write_flash_byte(ha, 0xaaa, 0xaa);
		qla2x00_write_flash_byte(ha, 0x555, 0x55);
		qla2x00_write_flash_byte(ha, 0xaaa, 0xa0);
		qla2x00_write_flash_byte(ha, addr, data);
	} else {
		if (man_id == 0xda && flash_id == 0xc1) {
			qla2x00_write_flash_byte(ha, addr, data);
			if (addr & 0x7e)
				return 0;
		} else {
			qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
			qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
			qla2x00_write_flash_byte(ha, 0x5555, 0xa0);
			qla2x00_write_flash_byte(ha, addr, data);
		}
	}

	udelay(150);

	/* Wait for write to complete. */
	return (qla2x00_poll_flash(ha, addr, data, man_id, flash_id));
}

/**
 * qla2x00_erase_flash() - Erase the flash.
 * @ha: HA context
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qla2x00_erase_flash(scsi_qla_host_t *ha, uint8_t man_id, uint8_t flash_id)
{
	/* Individual Sector Erase Command Sequence */
	if (IS_OEM_001(ha)) {
		qla2x00_write_flash_byte(ha, 0xaaa, 0xaa);
		qla2x00_write_flash_byte(ha, 0x555, 0x55);
		qla2x00_write_flash_byte(ha, 0xaaa, 0x80);
		qla2x00_write_flash_byte(ha, 0xaaa, 0xaa);
		qla2x00_write_flash_byte(ha, 0x555, 0x55);
		qla2x00_write_flash_byte(ha, 0xaaa, 0x10);
	} else {
		qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
		qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
		qla2x00_write_flash_byte(ha, 0x5555, 0x80);
		qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
		qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
		qla2x00_write_flash_byte(ha, 0x5555, 0x10);
	}

	udelay(150);

	/* Wait for erase to complete. */
	return (qla2x00_poll_flash(ha, 0x00, 0x80, man_id, flash_id));
}

/**
 * qla2x00_erase_flash_sector() - Erase a flash sector.
 * @ha: HA context
 * @addr: Flash sector to erase
 * @sec_mask: Sector address mask
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qla2x00_erase_flash_sector(scsi_qla_host_t *ha, uint32_t addr,
    uint32_t sec_mask, uint8_t man_id, uint8_t flash_id)
{
	/* Individual Sector Erase Command Sequence */
	qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
	qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
	qla2x00_write_flash_byte(ha, 0x5555, 0x80);
	qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
	qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
	if (man_id == 0x1f && flash_id == 0x13)
		qla2x00_write_flash_byte(ha, addr & sec_mask, 0x10);
	else
		qla2x00_write_flash_byte(ha, addr & sec_mask, 0x30);

	udelay(150);

	/* Wait for erase to complete. */
	return (qla2x00_poll_flash(ha, addr, 0x80, man_id, flash_id));
}

/**
 * qla2x00_get_flash_manufacturer() - Read manufacturer ID from flash chip.
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 */
void
qla2x00_get_flash_manufacturer(scsi_qla_host_t *ha, uint8_t *man_id,
    uint8_t *flash_id)
{
	qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
	qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
	qla2x00_write_flash_byte(ha, 0x5555, 0x90);
	*man_id = qla2x00_read_flash_byte(ha, 0x0000);
	*flash_id = qla2x00_read_flash_byte(ha, 0x0001);
	qla2x00_write_flash_byte(ha, 0x5555, 0xaa);
	qla2x00_write_flash_byte(ha, 0x2aaa, 0x55);
	qla2x00_write_flash_byte(ha, 0x5555, 0xf0);
}

static void
qla2x00_read_flash_data(scsi_qla_host_t *ha, uint8_t *tmp_buf, uint32_t saddr,
    uint32_t length)
{
	device_reg_t __iomem *reg = ha->iobase;
	uint32_t	midpoint;
	uint8_t		data;
	uint32_t	ilength;

	midpoint = length / 2;

	WRT_REG_WORD(&reg->nvram, 0);
	RD_REG_WORD(&reg->nvram);
	for (ilength = 0; ilength < length; saddr++, ilength++, tmp_buf++) {
		if (ilength == midpoint) {
			WRT_REG_WORD(&reg->nvram, NVR_SELECT);
			RD_REG_WORD(&reg->nvram);
		}
		data = qla2x00_read_flash_byte(ha, saddr);
		if (saddr % 100)
			udelay(10);
		*tmp_buf = data;
	}
}

/**
 * qla2x00_get_flash_version() - Read version information from flash.
 * @ha: HA context
 *
 * Returns QLA_SUCCESS on successful retrieval of flash version.
 */
int
qla2x00_get_flash_version(scsi_qla_host_t *ha)
{
	int ret = QLA_SUCCESS;
	uint8_t code_type, last_image;
	uint32_t pcihdr, pcids;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha))
		return qla24xx_get_flash_version(ha,
		    (uint8_t *)ha->request_ring);

	if (!ha->pio_address)
		return QLA_FUNCTION_FAILED;

	qla2x00_flash_enable(ha);

	/* Begin with first PCI expansion ROM header. */
	pcihdr = 0;
	last_image = 1;
	do {
		/* Verify PCI expansion ROM header. */
		if (qla2x00_read_flash_byte(ha, pcihdr) != 0x55 ||
		    qla2x00_read_flash_byte(ha, pcihdr + 0x01) != 0xaa) {
			/* No signature */
			DEBUG2(printk("scsi(%ld): No matching ROM signature.\n",
			    ha->host_no));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Locate PCI data structure. */
		pcids = pcihdr +
		    ((qla2x00_read_flash_byte(ha, pcihdr + 0x19) << 8) |
			qla2x00_read_flash_byte(ha, pcihdr + 0x18));

		/* Validate signature of PCI data structure. */
		if (qla2x00_read_flash_byte(ha, pcids) != 'P' ||
		    qla2x00_read_flash_byte(ha, pcids + 0x1) != 'C' ||
		    qla2x00_read_flash_byte(ha, pcids + 0x2) != 'I' ||
		    qla2x00_read_flash_byte(ha, pcids + 0x3) != 'R') {
			/* Incorrect header. */
			DEBUG2(printk("%s(): PCI data struct not found "
			    "pcir_adr=%x.\n",
			    __func__, pcids));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Read version */
		code_type = qla2x00_read_flash_byte(ha, pcids + 0x14);
		switch (code_type) {
		case ROM_CODE_TYPE_BIOS:
			/* Intel x86, PC-AT compatible. */
			set_bit(ROM_CODE_TYPE_BIOS, &ha->code_types);
			ha->bios_revision[0] =
			    qla2x00_read_flash_byte(ha, pcids + 0x12);
			ha->bios_revision[1] =
			    qla2x00_read_flash_byte(ha, pcids + 0x13);
			DEBUG3(printk("%s(): read BIOS %d.%d.\n", __func__,
			    ha->bios_revision[1], ha->bios_revision[0]));
			break;
		case ROM_CODE_TYPE_FCODE:
			/* Open Firmware standard for PCI (FCode). */
			/* Eeeewww... */
			if (qla2x00_get_fcode_version(ha, pcids) == QLA_SUCCESS)
				set_bit(ROM_CODE_TYPE_FCODE, &ha->code_types);
			break;
		case ROM_CODE_TYPE_EFI:
			/* Extensible Firmware Interface (EFI). */
			set_bit(ROM_CODE_TYPE_EFI, &ha->code_types);
			ha->efi_revision[0] =
			    qla2x00_read_flash_byte(ha, pcids + 0x12);
			ha->efi_revision[1] =
			    qla2x00_read_flash_byte(ha, pcids + 0x13);
			DEBUG3(printk("%s(): read EFI %d.%d.\n", __func__,
			    ha->efi_revision[1], ha->efi_revision[0]));
			break;
		default:
			DEBUG2(printk("%s(): Unrecognized code type %x at "
			    "pcids %x.\n", __func__, code_type, pcids));
			break;
		}

		last_image = qla2x00_read_flash_byte(ha, pcids + 0x15) & BIT_7;

		/* Locate next PCI expansion ROM. */
		pcihdr += ((qla2x00_read_flash_byte(ha, pcids + 0x11) << 8) |
		    qla2x00_read_flash_byte(ha, pcids + 0x10)) * 512;
	} while (!last_image);

	if (IS_QLA2322(ha)) {
		uint8_t		dbyte[8];
		uint8_t		length;
		uint16_t	*dcode;

		length = sizeof(dbyte);

		/* Read firmware image information. */
		memset(ha->fw_revision, 0, sizeof(ha->fw_revision));
		memset(dbyte, 0, sizeof(dbyte));
		dcode = (uint16_t *)dbyte;

		qla2x00_read_flash_data(ha, dbyte, FA_RISC_CODE_ADDR*4 + 10,
		    length);
		DEBUG9(printk("%s(%ld): dumping fw ver from flash:\n",
		    __func__, ha->host_no));
		DEBUG9(qla2x00_dump_buffer((uint8_t *)dbyte, length));

		if ((dcode[0] == 0xffff && dcode[1] == 0xffff &&
		    dcode[2] == 0xffff && dcode[3] == 0xffff) ||
		    (dcode[0] == 0 && dcode[1] == 0 && dcode[2] == 0 &&
		    dcode[3] == 0)) {
			DEBUG10(printk(
			    "%s(): Unrecognized fw revision at %x.\n",
			    __func__, FA_RISC_CODE_ADDR*4));
		} else {
			/* values are in big endian */
			ha->fw_revision[0] = dbyte[0] << 16 | dbyte[1];
			ha->fw_revision[1] = dbyte[2] << 16 | dbyte[3];
			ha->fw_revision[2] = dbyte[4] << 16 | dbyte[5];
		}
	}

	qla2x00_flash_disable(ha);

	return ret;
}

/**
 * qla2x00_get_fcode_version() - Determine an FCODE image's version.
 * @ha: HA context
 * @pcids: Pointer to the FCODE PCI data structure
 *
 * The process of retrieving the FCODE version information is at best
 * described as interesting.
 *
 * Within the first 100h bytes of the image an ASCII string is present
 * which contains several pieces of information including the FCODE
 * version.  Unfortunately it seems the only reliable way to retrieve
 * the version is by scanning for another sentinel within the string,
 * the FCODE build date:
 *
 *	... 2.00.02 10/17/02 ...
 *
 * Returns QLA_SUCCESS on successful retrieval of version.
 */
static int
qla2x00_get_fcode_version(scsi_qla_host_t *ha, uint32_t pcids)
{
	int ret = QLA_FUNCTION_FAILED;
	uint32_t istart, iend, iter, vend;
	uint8_t do_next, rbyte, *vbyte;

	memset(ha->fcode_revision, 0, sizeof(ha->fcode_revision));

	/* Skip the PCI data structure. */
	istart = pcids +
	    ((qla2x00_read_flash_byte(ha, pcids + 0x0B) << 8) |
		qla2x00_read_flash_byte(ha, pcids + 0x0A));
	iend = istart + 0x100;
	do {
		/* Scan for the sentinel date string...eeewww. */
		do_next = 0;
		iter = istart;
		while ((iter < iend) && !do_next) {
			iter++;
			if (qla2x00_read_flash_byte(ha, iter) == '/') {
				if (qla2x00_read_flash_byte(ha, iter + 2) ==
				    '/')
					do_next++;
				else if (qla2x00_read_flash_byte(ha,
				    iter + 3) == '/')
					do_next++;
			}
		}
		if (!do_next)
			break;

		/* Backtrack to previous ' ' (space). */
		do_next = 0;
		while ((iter > istart) && !do_next) {
			iter--;
			if (qla2x00_read_flash_byte(ha, iter) == ' ')
				do_next++;
		}
		if (!do_next)
			break;

		/*
		 * Mark end of version tag, and find previous ' ' (space) or
		 * string length (recent FCODE images -- major hack ahead!!!).
		 */
		vend = iter - 1;
		do_next = 0;
		while ((iter > istart) && !do_next) {
			iter--;
			rbyte = qla2x00_read_flash_byte(ha, iter);
			if (rbyte == ' ' || rbyte == 0xd || rbyte == 0x10)
				do_next++;
		}
		if (!do_next)
			break;

		/* Mark beginning of version tag, and copy data. */
		iter++;
		if ((vend - iter) &&
		    ((vend - iter) < sizeof(ha->fcode_revision))) {
			vbyte = ha->fcode_revision;
			while (iter <= vend) {
				*vbyte++ = qla2x00_read_flash_byte(ha, iter);
				iter++;
			}
			ret = QLA_SUCCESS;	
		}
	} while (0);

	return ret;
}

/**
 * qla2x00_get_flash_image() - Read image from flash chip.
 * @ha: HA context
 * @image: Buffer to receive flash image
 *
 * Returns 0 on success, else non-zero.
 */
uint16_t
qla2x00_get_flash_image(scsi_qla_host_t *ha, uint8_t *image)
{
	uint32_t	addr;
	uint32_t	midpoint;
	uint8_t		*data;
	device_reg_t __iomem *reg = ha->iobase;

	midpoint = FLASH_IMAGE_SIZE / 2;

	qla2x00_flash_enable(ha);
	WRT_REG_WORD(&reg->nvram, 0);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	for (addr = 0, data = image; addr < FLASH_IMAGE_SIZE; addr++, data++) {
		if (addr == midpoint)
			WRT_REG_WORD(&reg->nvram, NVR_SELECT);

		*data = qla2x00_read_flash_byte(ha, addr);
	}
	qla2x00_flash_disable(ha);

	return (0);
}

/**
 * qla2x00_set_flash_image() - Write image to flash chip.
 * @ha: HA context
 * @image: Source image to write to flash
 *
 * Returns 0 on success, else non-zero.
 */
uint16_t
qla2x00_set_flash_image(scsi_qla_host_t *ha, uint8_t *image, uint32_t saddr,
    uint32_t length)
{
	uint16_t	status;
	uint32_t	addr;
	uint32_t	liter;
	uint32_t	sec_mask;
	uint32_t	rest_addr;
	uint8_t		man_id, flash_id;
	uint8_t		sec_number;
	uint8_t		data;
	device_reg_t __iomem *reg = ha->iobase;
	uint16_t	wd;

	status = 0;
	sec_number = 0;

	/* Reset ISP chip. */
	WRT_REG_WORD(&reg->ctrl_status, CSR_ISP_SOFT_RESET);
	pci_read_config_word(ha->pdev, PCI_COMMAND, &wd);

	qla2x00_flash_enable(ha);
	do {	/* Loop once to provide quick error exit */
		/* Structure of flash memory based on manufacturer */
		if (IS_OEM_001(ha)) {
			// OEM variant with special flash part.
			man_id = flash_id = 0;
			rest_addr = 0xffff;
			sec_mask   = 0x10000;
			goto update_flash;
		}
		qla2x00_get_flash_manufacturer(ha, &man_id, &flash_id);
		DEBUG9(printk("%s(%ld): Flash man_id=%d flash_id=%d\n",
		    __func__, ha->host_no, man_id, flash_id));
		switch (man_id) {
		case 0x20: // ST flash
			if (flash_id == 0xd2 || flash_id == 0xe3) {
				// ST m29w008at part - 64kb sector size with
				// 32kb,8kb,8kb,16kb sectors at memory address
				// 0xf0000
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			}
			// ST m29w010b part - 16kb sector size
			// Default to 16kb sectors
			rest_addr = 0x3fff;
			sec_mask = 0x1c000;
			break;
		case 0x40: // Mostel flash
			// Mostel v29c51001 part - 512 byte sector size
			rest_addr = 0x1ff;
			sec_mask = 0x1fe00;
			break;
		case 0xbf: // SST flash
			// SST39sf10 part - 4kb sector size
			rest_addr = 0xfff;
			sec_mask = 0x1f000;
			break;
		case 0xda: // Winbond flash
			// Winbond W29EE011 part - 256 byte sector size
			rest_addr = 0x7f;
			sec_mask = 0x1ff80;
			break;
		case 0xc2: // Macronix flash
			// 64k sector size
			if (flash_id == 0x38 || flash_id == 0x4f) {
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			}
			// Fall through...

		case 0x1f: // Atmel flash
			// 512k sector size
			if (flash_id == 0x13) {
				rest_addr = 0x7fffffff;
				sec_mask = 0x80000000;
				break;
			}
			// Fall through...

		case 0x01: // AMD flash
			if (flash_id == 0x38 || flash_id == 0x40 ||
			    flash_id == 0x4f) {
				// Am29LV081 part - 64kb sector size
				// Am29LV002BT part - 64kb sector size
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			} else if (flash_id == 0x3e) {
				// Am29LV008b part - 64kb sector size with
				// 32kb,8kb,8kb,16kb sector at memory address
				// 0xf0000
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			} else if (flash_id == 0x20 || flash_id == 0x6e) {
				// Am29LV010 part or AM29f010 - 16kb sector
				// size
				rest_addr = 0x3fff;
				sec_mask = 0x1c000;
				break;
			} else if (flash_id == 0x6d) {
				// Am29LV001 part - 8kb sector size
				rest_addr = 0x1fff;
				sec_mask = 0x1e000;
				break;
			}
		default:
			// Default to 16 kb sector size
			rest_addr = 0x3fff;
			sec_mask = 0x1c000;
			break;
		}

update_flash:
		if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
			if (qla2x00_erase_flash(ha, man_id, flash_id)) {
				status = 1;
				break;
			}
		}

		for (addr = saddr, liter = 0; liter < length; liter++, addr++) {
			data = image[liter];
			/* Are we at the beginning of a sector? */
			if ((addr & rest_addr) == 0) {
				if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
					if (addr >= 0x10000UL) {
						if (((addr >> 12) & 0xf0) &&
						    ((man_id == 0x01 && flash_id == 0x3e) ||
						    (man_id == 0x20 && flash_id == 0xd2))) {
							sec_number++;
							if (sec_number == 1) {
								rest_addr = 0x7fff;
								sec_mask = 0x18000;
							} else if (sec_number == 2 ||
							    sec_number == 3) {
								rest_addr = 0x1fff;
								sec_mask = 0x1e000;
							} else if (sec_number == 4) {
								rest_addr = 0x3fff;
								sec_mask = 0x1c000;
							}
						}
					}
				} else if (addr == FLASH_IMAGE_SIZE / 2) {
					WRT_REG_WORD(&reg->nvram, NVR_SELECT);
					RD_REG_WORD(&reg->nvram);
				}

				if (flash_id == 0xda && man_id == 0xc1) {
					qla2x00_write_flash_byte(ha, 0x5555,
					    0xaa);
					qla2x00_write_flash_byte(ha, 0x2aaa,
					    0x55);
					qla2x00_write_flash_byte(ha, 0x5555,
					    0xa0);
				} else if (!IS_QLA2322(ha) && !IS_QLA6322(ha)) {
					/* Then erase it */
					if (qla2x00_erase_flash_sector(ha, addr,
					    sec_mask, man_id, flash_id)) {
						DEBUG9(printk("%s(%ld) Unable "
						    "to erase flash sector "
						    "addr=%x mask=%x.\n",
						    __func__, ha->host_no, addr,
						    sec_mask));
						status = 1;
						break;
					}
					if (man_id == 0x01 && flash_id == 0x6d)
						sec_number++;
				}
			}

			if (man_id == 0x01 && flash_id == 0x6d) {
				if (sec_number == 1 &&
				    addr == (rest_addr - 1)) {
					rest_addr = 0x0fff;
					sec_mask   = 0x1f000;
				} else if (sec_number == 3 && (addr & 0x7ffe)) {
					rest_addr = 0x3fff;
					sec_mask   = 0x1c000;
				}
			}

			if (qla2x00_program_flash_address(ha, addr, data,
			    man_id, flash_id)) {
				DEBUG9(printk("%s(%ld) Unable to program flash "
				    "address=%x data=%x.\n", __func__,
				    ha->host_no, addr, data));
				status = 1;
				break;
			}
		}
	} while (0);
	qla2x00_flash_disable(ha);

	return (status);
}

/* qla2x00_cmd_wait
 *	Stall driver until all outstanding commands are returned.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Return;
 *  0 -- Done
 *  1 -- cmds still outstanding
 *
 * Context:
 *  This routine must be called without hardware_lock held.
 */
int
qla2x00_cmd_wait(scsi_qla_host_t *ha)
{
	int status = 0;
	int index = 0;
	int wait_cnt = 30;
	unsigned long cpu_flags;

	DEBUG(printk("%s(%ld): Started\n",__func__,ha->host_no));

	while (wait_cnt) {
		/* Find a command that hasn't completed. */
		for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
			spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
			if (ha->outstanding_cmds[index] != NULL) {
				spin_unlock_irqrestore(&ha->hardware_lock,
				    cpu_flags);
				break;
			}
			spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);
		}

		/* If No Commands are pending wait is complete */
		if (index == MAX_OUTSTANDING_COMMANDS)
			break;

		/*
		 * If we timed out on waiting for commands to come back Reset
		 * the ISP
		 */
		wait_cnt--;
		if (wait_cnt == 0) {
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			status = 1;
			DEBUG(printk("%s(%ld): ISP abort - handle %d\n",
			    __func__, ha->host_no, index));
		} else {
			/* sleep a second */
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(HZ);
		}
	}

	DEBUG(printk("%s(%ld): Done waiting on commands - ind=%d\n",
	    __func__, ha->host_no, index));

	return status;
}

/*
 *  qla2x00_suspend_target
 *	Suspend target
 *
 * Input:
 *	ha = visable adapter block pointer.
 *  target = target queue
 *  time = time in seconds
 *
 * Return:
 *     QL_STATUS_SUCCESS  -- suspended lun
 *     QL_STATUS_ERROR  -- Didn't suspend lun
 *
 * Context:
 *	Interrupt context.
 */
int
qla2x00_suspend_target(scsi_qla_host_t *ha, os_tgt_t *tq, int time)
{
	srb_t *sp, *sptemp;
	unsigned long flags;

	if (test_bit(TQF_SUSPENDED, &tq->flags))
		return QLA_FUNCTION_FAILED;

	/* now suspend the lun */
	set_bit(TQF_SUSPENDED, &tq->flags);

	DEBUG2(printk(KERN_INFO
	    "scsi%ld: Starting - suspend target for %d secs\n", ha->host_no,
	    time));

	/*
	 * Remove all (TARGET) pending commands from request queue and put them
	 * in the scsi_retry queue.
	 */
	spin_lock_irqsave(&ha->list_lock, flags);
	list_for_each_entry_safe(sp, sptemp, &ha->pending_queue, list) {
		if (sp->tgt_queue != tq)
			continue;

		DEBUG3(printk("scsi%ld: %s requeue for suspended target %p\n",
		    ha->host_no, __func__, sp));

		__del_from_pending_queue(ha, sp);
		__add_to_scsi_retry_queue(ha,sp);
	}
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return QLA_SUCCESS;
}

/*
 *  qla2x00_unsuspend_all_target
 *	Unsuspend all target.
 *
 * Input:
 *	ha = visable adapter block pointer.
 *
 * Return:
 *
 * Context:
 *	Process context.
 */
void
qla2x00_unsuspend_all_target(scsi_qla_host_t *ha)
{
	os_tgt_t *tq;
	int 	 t;

	for (t = 0; t < ha->max_targets; t++) {
		if ((tq = ha->otgt[t]) == NULL)
			continue;

		clear_bit(TQF_SUSPENDED, &tq->flags);
	}
}

/*
 *  qla2x00_suspend_all_target
 *	Suspend all target indefinitely. Caller need to make sure
 *	to explicitly unsuspend it later on.
 *
 * Input:
 *	ha = visable adapter block pointer.
 *  target = target queue
 *  time = time in seconds
 *
 * Return:
 *     QL_STATUS_SUCCESS  -- suspended lun
 *     QL_STATUS_ERROR  -- Didn't suspend lun
 *
 * Context:
 *	qla2x00_suspend_target can be called in Interrupt context.
 *	Hold the hardware lock for synchronisation.
 */
int
qla2x00_suspend_all_target(scsi_qla_host_t *ha)
{
	int  status = 0;	
	os_tgt_t *tq;
	int 	 t, time;
	unsigned long cpu_flags = 0;

	/* Suspend the Target until explicitly cleared */
	time = 0;

	for (t = 0; t < ha->max_targets; t++) {
		if ((tq = ha->otgt[t]) == NULL)
			continue;

		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		status = qla2x00_suspend_target(ha, tq, time);
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);
	}

	return status;
}

uint16_t
qla2x00_read_flash_image(scsi_qla_host_t *ha, uint8_t *usr_tmp, uint32_t saddr,
    uint32_t length)
{
	device_reg_t __iomem *reg = ha->iobase;
	uint32_t	midpoint;
	uint8_t		data;
	uint32_t	ilength;
	uint16_t	status = 0;

	midpoint = length / 2;
	qla2x00_flash_enable(ha);
	WRT_REG_WORD(&reg->nvram, 0);
	RD_REG_WORD(&reg->nvram);
	for (ilength = 0; ilength < length; saddr++, ilength++, usr_tmp++) {
		if (ilength == midpoint) {
			WRT_REG_WORD(&reg->nvram, NVR_SELECT);
			RD_REG_WORD(&reg->nvram);
		}
		data = qla2x00_read_flash_byte(ha, saddr);
		if (saddr % 100)
			udelay(10);
		__put_user(data, usr_tmp);
	}
	qla2x00_flash_disable(ha);
	
	return (status);
}

uint16_t
qla2x00_update_or_read_flash(scsi_qla_host_t *ha, uint8_t *image,
    uint32_t saddr, uint32_t length, uint8_t direction)
{
	uint16_t    status;	
	unsigned long flags;
	uint32_t	cnt;
	device_reg_t __iomem *reg = ha->iobase;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha))
		return qla24xx_update_or_read_flash(ha, image, saddr, length,
		    direction);

	/* Not setting the timer so that tgt remains unsuspended */
	qla2x00_suspend_all_target(ha);

	/* wait for big hammer to complete if it fails */
	status = qla2x00_cmd_wait(ha);
	if (status)
		status = qla2x00_wait_for_hba_online(ha);

	if (status)
		return status;

	/* Dont process mailbox cmd until flash operation is done */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qla2x00_disable_intrs(ha);

	/* Pause RISC. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	WRT_REG_WORD(&reg->hccr, HCCR_PAUSE_RISC);
	RD_REG_WORD(&reg->hccr);
	if (IS_QLA2100(ha) || IS_QLA2200(ha) || IS_QLA2300(ha)) {
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD_REG_WORD(&reg->hccr) &
			    HCCR_RISC_PAUSE) != 0)
				break;
			udelay(100);
		}
	} else {
		udelay(10);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	switch (direction) {
	case QLA2X00_READ:
		DEBUG9(printk("%s(%ld): Reading image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr,
		    length));		
		status = qla2x00_read_flash_image(ha, image, saddr, length);
		break;

	case QLA2X00_WRITE:
		DEBUG9(printk("%s(%ld): Writing image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr,
		    length));		
		status = qla2x00_set_flash_image(ha, image, saddr, length);
		break;
	default:
		printk(KERN_INFO "%s unknown operation\n", __func__);
		break;
	}

	/* Schedule DPC to restart the RISC */
	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	up(ha->dpc_wait);
	qla2x00_wait_for_hba_online(ha);

	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);
	
	qla2x00_unsuspend_all_target(ha);

	return status;
}
#endif

//ISP 24xx
//

/*****************************************************************************/
/* Flash Manipulation Routines                                               */
/*****************************************************************************/

static inline uint32_t
flash_conf_to_access_addr(uint32_t faddr)
{
	return FARX_ACCESS_FLASH_CONF | faddr;
}

static inline uint32_t
flash_data_to_access_addr(uint32_t faddr)
{
	return FARX_ACCESS_FLASH_DATA | faddr;
}

static inline uint32_t
nvram_conf_to_access_addr(uint32_t naddr)
{
	return FARX_ACCESS_NVRAM_CONF | naddr;
}

static inline uint32_t
nvram_data_to_access_addr(uint32_t naddr)
{
	return FARX_ACCESS_NVRAM_DATA | naddr;
}

uint32_t
qla24xx_read_flash_dword(scsi_qla_host_t *ha, uint32_t addr)
{
	int rval;
	uint32_t cnt, data;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	WRT_REG_DWORD(&reg->flash_addr, addr & ~FARX_DATA_FLAG);
	/* Wait for READ cycle to complete. */
	rval = QLA_SUCCESS;
	for (cnt = 3000;
	    (RD_REG_DWORD(&reg->flash_addr) & FARX_DATA_FLAG) == 0 &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt)
			udelay(10);
		else
			rval = QLA_FUNCTION_TIMEOUT;
	}

	/* TODO: What happens if we time out? */
	data = 0xDEADDEAD;
	if (rval == QLA_SUCCESS)
		data = RD_REG_DWORD(&reg->flash_data);

	return data;
}

uint32_t *
qla24xx_read_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr, uint32_t faddr,
    uint32_t dwords)
{
	uint32_t i;

	/* Dword reads to flash. */
	for (i = 0; i < dwords; i++, faddr++)
		dwptr[i] = cpu_to_le32(qla24xx_read_flash_dword(ha,
		    flash_data_to_access_addr(faddr)));

	return dwptr;
}

uint8_t *
qla2x00_read_nvram_data(scsi_qla_host_t *ha, uint8_t *buf, uint32_t naddr,
    uint32_t bytes)
{
	uint32_t i;
	uint16_t *wptr;
	uint32_t *dwptr;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		/* Dword reads to flash. */
		dwptr = (uint32_t *)buf;
		for (i = 0; i < bytes >> 2; i++, naddr++)
			dwptr[i] = cpu_to_le32(qla24xx_read_flash_dword(ha,
			    nvram_data_to_access_addr(naddr)));
	} else {
		/* Word reads to NVRAM via registers. */
		wptr = (uint16_t *)buf;
		qla2x00_lock_nvram_access(ha);
		for (i = 0; i < bytes >> 1; i++, naddr++)
			wptr[i] = cpu_to_le16(qla2x00_get_nvram_word(ha,
			    naddr));
		qla2x00_unlock_nvram_access(ha);
	}
	return buf;
}

int
qla24xx_write_flash_dword(scsi_qla_host_t *ha, uint32_t addr, uint32_t data)
{
	int rval;
	uint32_t cnt;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	WRT_REG_DWORD(&reg->flash_data, data);
	RD_REG_DWORD(&reg->flash_data);		/* PCI Posting. */
	WRT_REG_DWORD(&reg->flash_addr, addr | FARX_DATA_FLAG);
	/* Wait for Write cycle to complete. */
	rval = QLA_SUCCESS;
	for (cnt = 500000; (RD_REG_DWORD(&reg->flash_addr) & FARX_DATA_FLAG) &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt)
			udelay(10);
		else
			rval = QLA_FUNCTION_TIMEOUT;
	}
	return rval;
}

void
qla24xx_get_flash_manufacturer(scsi_qla_host_t *ha, uint8_t *man_id,
    uint8_t *flash_id)
{
	uint32_t ids;

	ids = qla24xx_read_flash_dword(ha, flash_data_to_access_addr(0xd03ab));
	*man_id = LSB(ids);
	*flash_id = MSB(ids);

	/* Check if man_id and flash_id are valid. */
	if (ids != 0xDEADDEAD && (*man_id == 0 || *flash_id == 0)) {
		/* Read information using 0x9f opcode
		 * Device ID, Mfg ID would be read in the format:
		 *   <Ext Dev Info><Device ID Part2><Device ID Part 1><Mfg ID>
		 * Example: ATMEL 0x00 01 45 1F
		 * Extract MFG and Dev ID from last two bytes.
		 */
		ids = qla24xx_read_flash_dword(ha,
		    flash_data_to_access_addr(0xd009f));
		*man_id = LSB(ids);
		*flash_id = MSB(ids);
	}
}

int
qla24xx_write_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr, uint32_t faddr,
    uint32_t dwords)
{
	int ret;
	uint32_t liter;
	uint32_t sec_mask, rest_addr, conf_addr, sec_end_mask;
	uint32_t fdata, findex ;
	uint8_t	man_id, flash_id;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	ret = QLA_SUCCESS;

	qla24xx_get_flash_manufacturer(ha, &man_id, &flash_id);
	DEBUG9(printk("%s(%ld): Flash man_id=%d flash_id=%d\n", __func__,
	    ha->host_no, man_id, flash_id));

	conf_addr = flash_conf_to_access_addr(0x03d8);
	switch (man_id) {
	case 0xbf: // STT flash
		rest_addr = 0x1fff;
		sec_mask = 0x3e000;
		if (flash_id == 0x80 || flash_id == 0x8e)
			conf_addr = flash_conf_to_access_addr(0x0352);
		break;
	case 0x13: // ST M25P80
		rest_addr = 0x3fff;
		sec_mask = 0x3c000;
		break;
	case 0x1f: // Atmel 26DF081A
		rest_addr = 0x0fff;
		sec_mask = 0xff000;
		sec_end_mask = 0x003ff;
		conf_addr = flash_conf_to_access_addr(0x0320);
		break;
	default:
		// Default to 64 kb sector size
		rest_addr = 0x3fff;
		sec_mask = 0x3c000;
		break;
	}

	/* Enable flash write. */
	WRT_REG_DWORD(&reg->ctrl_status,
	    RD_REG_DWORD(&reg->ctrl_status) | CSRX_FLASH_ENABLE);
	RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

	/* Disable flash write-protection. */
	qla24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0);
	/* Some flash parts need an additional zero-write to clear bits.*/
	qla24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0);

	do {    /* Loop once to provide quick error exit. */
		for (liter = 0; liter < dwords; liter++, faddr++, dwptr++) {
			if (man_id == 0x1f) {
				findex = faddr << 2;
				fdata = findex & sec_mask;
			} else {
				findex = faddr;
				fdata = (findex & sec_mask) << 2;
			}

			/* Are we at the beginning of a sector? */
			if ((findex & rest_addr) == 0) {
				/*
				 * Do sector unprotect at 4K boundry for Atmel
				 * part.
				 */
				if (man_id == 0x1f)
					qla24xx_write_flash_dword(ha,
					    flash_conf_to_access_addr(0x0339),
					    (fdata & 0xff00) | ((fdata << 16) &
					    0xff0000) | ((fdata >> 16) & 0xff));
				ret = qla24xx_write_flash_dword(ha, conf_addr,
				    (fdata & 0xff00) |((fdata << 16) &
				    0xff0000) | ((fdata >> 16) & 0xff));
				if (ret != QLA_SUCCESS) {
					DEBUG9(printk("%s(%ld) Unable to flash "
					    "sector: address=%x.\n", __func__,
					    ha->host_no, faddr));
					break;
				}
			}
			ret = qla24xx_write_flash_dword(ha,
			    flash_data_to_access_addr(faddr),
			    cpu_to_le32(*dwptr));
			if (ret != QLA_SUCCESS) {
				DEBUG9(printk("%s(%ld) Unable to program flash "
				    "address=%x data=%x.\n", __func__,
				    ha->host_no, faddr, *dwptr));
				break;
			}

			/* Do sector protect at 4K boundry for Atmel part. */
			if (man_id == 0x1f &&
			    ((faddr & sec_end_mask) == 0x3ff))
				qla24xx_write_flash_dword(ha,
				    flash_conf_to_access_addr(0x0336),
				    (fdata & 0xff00) | ((fdata << 16) &
				    0xff0000) | ((fdata >> 16) & 0xff));
		}
	} while (0);

	/* Enable flash write-protection. */
	qla24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0x9c);

	/* Disable flash write. */
	WRT_REG_DWORD(&reg->ctrl_status,
	    RD_REG_DWORD(&reg->ctrl_status) & ~CSRX_FLASH_ENABLE);
	RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

	return ret;
}

int
qla2x00_write_nvram_data(scsi_qla_host_t *ha, uint8_t *buf, uint32_t naddr,
    uint32_t bytes)
{
	int ret;
	uint32_t i;
	uint16_t *wptr;
	uint32_t *dwptr;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	ret = QLA_SUCCESS;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		/* Enable flash write. */
		WRT_REG_DWORD(&reg->ctrl_status,
		    RD_REG_DWORD(&reg->ctrl_status) | CSRX_FLASH_ENABLE);
		RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

		/* Disable NVRAM write-protection. */
		qla24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0);
		qla24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0);

		/* Dword writes to flash. */
		dwptr = (uint32_t *)buf;
		for (i = 0; i < bytes >> 2; i++, naddr++, dwptr++) {
			ret = qla24xx_write_flash_dword(ha,
			    nvram_data_to_access_addr(naddr),
			    cpu_to_le32(*dwptr));
			if (ret != QLA_SUCCESS) {
				DEBUG9(printk("%s(%ld) Unable to program "
				    "nvram address=%x data=%x.\n", __func__,
				    ha->host_no, naddr, *dwptr));
				break;
			}
		}

		/* Enable NVRAM write-protection. */
		qla24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0x8c);

		/* Disable flash write. */
		WRT_REG_DWORD(&reg->ctrl_status,
		    RD_REG_DWORD(&reg->ctrl_status) & ~CSRX_FLASH_ENABLE);
		RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */
	} else {
		int stat;

		qla2x00_lock_nvram_access(ha);

		/* Disable NVRAM write-protection. */
		stat = qla2x00_clear_nvram_protection(ha);

		wptr = (uint16_t *)buf;
		for (i = 0; i < bytes >> 1; i++, naddr++) {
			qla2x00_write_nvram_word(ha, naddr,
			    cpu_to_le16(*wptr));
			wptr++;
		}

		/* Enable NVRAM write-protection. */
		qla2x00_set_nvram_protection(ha, stat);

		qla2x00_unlock_nvram_access(ha);
	}

	return ret;
}

#ifdef CONFIG_SCSI_QLA2XXX_FAILOVER
uint16_t
qla24xx_update_or_read_flash(scsi_qla_host_t *ha, uint8_t *image,
    uint32_t saddr, uint32_t length, uint8_t direction)
{
	uint32_t status;

	/* Not setting the timer so that tgt remains unsuspended */
	qla2x00_suspend_all_target(ha);

	/* wait for big hammer to complete if it fails */
	status = qla2x00_cmd_wait(ha);
	if (status)
		qla2x00_wait_for_hba_online(ha);

	/* Dont process mailbox cmd until flash operation is done */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qla2x00_disable_intrs(ha);

	switch (direction) {
	case QLA2X00_READ:
		DEBUG9(printk("%s(%ld): Reading image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr >> 2,
		    length >> 2));
		qla24xx_read_flash_data(ha, (uint32_t *)image, saddr >> 2,
		    length >> 2);
		break;

	case QLA2X00_WRITE:
		DEBUG9(printk("%s(%ld): Writing image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr >> 2,
		    length >> 2));
		status = qla24xx_write_flash_data(ha, (uint32_t *)image,
		    saddr >> 2, length >> 2);
		break;
	default:
		printk(KERN_INFO "%s unknown operation\n", __func__);
		break;
	}

	if (ql2xfwloadbin == 1 && direction == QLA2X00_WRITE) {
		scsi_qla_host_t	*hba2 = NULL;

		/* Reset the first function */
		DEBUG9(printk("%s(%ld) resetting first function\n", __func__,
		    ha->host_no));
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		up(ha->dpc_wait);
		qla2x00_wait_for_hba_online(ha);

		/* Reset the second function if exist */
		read_lock(&qla_hostlist_lock);
		list_for_each_entry(hba2, &qla_hostlist, list) {
			if (PCI_SLOT(hba2->pdev->devfn) ==
			    PCI_SLOT(ha->pdev->devfn) &&
			    PCI_FUNC(hba2->pdev->devfn) !=
			    PCI_FUNC(ha->pdev->devfn))  {
				DEBUG9(printk("%s(%ld) resetting second "
				    "function\n", __func__, hba2->host_no));
				set_bit(ISP_ABORT_NEEDED, &hba2->dpc_flags);
				up(hba2->dpc_wait);
				qla2x00_wait_for_hba_online(hba2);
				break;
			}
		}
		read_unlock(&qla_hostlist_lock);
	}

	qla2x00_enable_intrs(ha);

	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qla2x00_unsuspend_all_target(ha);

	return status;
}

int
qla24xx_get_flash_version(scsi_qla_host_t *ha, uint8_t *ptmp_mem)
{
	int ret = QLA_SUCCESS;
	uint32_t pcihdr, pcids;
	uint32_t *dcode;
	uint8_t *bcode;
	uint8_t code_type, last_image;
	int i;


	if (ptmp_mem == NULL) {
		/* error */
		return(QLA_FUNCTION_FAILED);
	}

	dcode = (uint32_t *)ptmp_mem;

	/* Begin with first PCI expansion ROM header. */
	pcihdr = 0;
	last_image = 1;
	do {
		/* Verify PCI expansion ROM header. */
		qla24xx_read_flash_data(ha, dcode, pcihdr >> 2, 0x20);
		bcode = (uint8_t *)ptmp_mem + (pcihdr % 4);
		if (bcode[0x0] != 0x55 || bcode[0x1] != 0xaa) {
			/* No signature */
			DEBUG10(printk("scsi(%ld): No matching ROM signature.\n",
			    ha->host_no));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Locate PCI data structure. */
		pcids = pcihdr + ((bcode[0x19] << 8) | bcode[0x18]);

		qla24xx_read_flash_data(ha, dcode, pcids >> 2, 0x20);
		bcode = (uint8_t *)ptmp_mem + (pcihdr % 4);

		/* Validate signature of PCI data structure. */
		if (bcode[0x0] != 'P' || bcode[0x1] != 'C' ||
		    bcode[0x2] != 'I' || bcode[0x3] != 'R') {
			/* Incorrect header. */
			DEBUG10(printk("%s(): PCI data struct not found "
			    "pcir_adr=%x.\n",
			    __func__, pcids));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Read version */
		code_type = bcode[0x14];
		switch (code_type) {
		case ROM_CODE_TYPE_BIOS:
			/* Intel x86, PC-AT compatible. */
			set_bit(ROM_CODE_TYPE_BIOS, &ha->code_types);
			ha->bios_revision[0] = bcode[0x12];
			ha->bios_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read BIOS %d.%d.\n", __func__,
			    ha->bios_revision[1], ha->bios_revision[0]));
			break;
		case ROM_CODE_TYPE_FCODE:
			/* Open Firmware standard for PCI (FCode). */
			set_bit(ROM_CODE_TYPE_FCODE, &ha->code_types);
			ha->fcode_revision[0] = bcode[0x12];
			ha->fcode_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read FCODE %d.%d.\n", __func__,
			    ha->fcode_revision[1], ha->fcode_revision[0]));
			break;
		case ROM_CODE_TYPE_EFI:
			/* Extensible Firmware Interface (EFI). */
			set_bit(ROM_CODE_TYPE_EFI, &ha->code_types);
			ha->efi_revision[0] = bcode[0x12];
			ha->efi_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read EFI %d.%d.\n", __func__,
			    ha->efi_revision[1], ha->efi_revision[0]));
			break;
		default:
			DEBUG10(printk("%s(): Unrecognized code type %x at "
			    "pcids %x.\n", __func__, code_type, pcids));
			break;
		}

		last_image = bcode[0x15] & BIT_7;

		/* Locate next PCI expansion ROM. */
		pcihdr += ((bcode[0x11] << 8) | bcode[0x10]) * 512;
	} while (!last_image);

	/* Read firmware image information. */
	memset(ha->fw_revision, 0, sizeof(ha->fw_revision));
	dcode = (uint32_t *)ptmp_mem;

	qla24xx_read_flash_data(ha, dcode, FA_RISC_CODE_ADDR + 4, 4);
	for (i = 0; i < 4; i++)
		dcode[i] = be32_to_cpu(dcode[i]);

	if ((dcode[0] == 0xffffffff && dcode[1] == 0xffffffff &&
	    dcode[2] == 0xffffffff && dcode[3] == 0xffffffff) ||
	    (dcode[0] == 0 && dcode[1] == 0 && dcode[2] == 0 &&
	    dcode[3] == 0)) {
		DEBUG10(printk("%s(): Unrecognized fw version at %x.\n",
		    __func__, FA_RISC_CODE_ADDR));
	} else {
		ha->fw_revision[0] = dcode[0];
		ha->fw_revision[1] = dcode[1];
		ha->fw_revision[2] = dcode[2];
		ha->fw_revision[3] = dcode[3];
	}

	return ret;
}

int
qla24xx_refresh_flash_version(scsi_qla_host_t *ha, uint8_t *ptmp_mem)
{
	unsigned long	flags;
	int		ret = 0;
	int		status;

	/* suspend targets */
	qla2x00_suspend_all_target(ha);

	/* wait for big hammer to complete if it fails */
	status = qla2x00_cmd_wait(ha);
	if (status)
		qla2x00_wait_for_hba_online(ha);

	/* Dont process mailbox cmd until flash
	 * operation is done.
	 */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qla2x00_disable_intrs(ha);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (qla24xx_get_flash_version(ha, ptmp_mem)) {
		ret = QLA_FUNCTION_FAILED;
		DEBUG9_10(printk( "%s: ERROR reading flash versions.\n",
		    __func__));
	}
	spin_unlock_irqrestore(&ha->hardware_lock,flags);

	qla2x00_enable_intrs(ha);
	clear_bit(MBX_UPDATE_FLASH_ACTIVE,
	    &ha->mbx_cmd_flags);
	qla2x00_unsuspend_all_target(ha);

	return (ret);
}
#endif
