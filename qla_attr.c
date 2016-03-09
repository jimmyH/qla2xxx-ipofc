/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/vmalloc.h>

/* SYSFS attributes --------------------------------------------------------- */

static ssize_t
qla2x00_sysfs_read_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	char *rbuf = (char *)ha->fw_dump;

	if (ha->fw_dump_reading == 0)
		return 0;
	if (off > ha->fw_dump_len)
                return 0;
	if (off + count > ha->fw_dump_len)
		count = ha->fw_dump_len - off;

	memcpy(buf, &rbuf[off], count);

	return (count);
}

static ssize_t
qla2x00_sysfs_write_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int reading;

	if (off != 0)
		return (0);

	reading = simple_strtol(buf, NULL, 10);
	switch (reading) {
	case 0:
		if (!ha->fw_dump_reading)
			break;

		qla_printk(KERN_INFO, ha,
		    "Firmware dump cleared on (%ld).\n", ha->host_no);

		ha->fw_dump_reading = 0;
		ha->fw_dumped = 0;
		break;
	case 1:
		if (ha->fw_dumped && !ha->fw_dump_reading) {
			ha->fw_dump_reading = 1;

			qla_printk(KERN_INFO, ha,
			    "Raw firmware dump ready for read on (%ld).\n",
			    ha->host_no);
		}
		break;
	case 2:
		qla2x00_alloc_fw_dump(ha);
		break;
	}
	return (count);
}

static struct bin_attribute sysfs_fw_dump_attr = {
	.attr = {
		.name = "fw_dump",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_fw_dump,
	.write = qla2x00_sysfs_write_fw_dump,
};

static ssize_t
qla2x00_sysfs_read_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long	flags;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->nvram_size)
		return 0;

	/* Read NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_read_nvram_data(ha, (uint8_t *)buf, ha->nvram_base,
	    ha->nvram_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (count);
}

static ssize_t
qla2x00_sysfs_write_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long	flags;
	uint16_t	cnt;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->nvram_size)
		return 0;

	/* Checksum NVRAM. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < ((count >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < count - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla2x00_write_nvram_data(ha, (uint8_t *)buf, ha->nvram_base, count);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (count);
}

static struct bin_attribute sysfs_nvram_attr = {
	.attr = {
		.name = "nvram",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_nvram,
	.write = qla2x00_sysfs_write_nvram,
};

void
qla2x00_alloc_sysfs_attr(scsi_qla_host_t *ha)
{
	sysfs_create_bin_file(&ha->host->shost_gendev.kobj,
	    &sysfs_fw_dump_attr);
	sysfs_nvram_attr.size = ha->nvram_size;
	sysfs_create_bin_file(&ha->host->shost_gendev.kobj, &sysfs_nvram_attr);
}

void
qla2x00_free_sysfs_attr(scsi_qla_host_t *ha)
{
	sysfs_remove_bin_file(&ha->host->shost_gendev.kobj,
	    &sysfs_fw_dump_attr);
	sysfs_remove_bin_file(&ha->host->shost_gendev.kobj, &sysfs_nvram_attr);
}
