/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include <linux/config.h>
#endif

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)

#include <linux/file.h>

#include "exioct.h"
#include "qlfoln.h"
#include "qla_dbg.h"


/* fs/ioctl.c */
extern asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, void *);
/*
 * Register an 32bit ioctl translation handler for ioctl cmd.
 *
 * handler == NULL: use 64bit ioctl handler.
 * arguments to handler:  fd: file descriptor
 *                        cmd: ioctl command.
 *                        arg: ioctl argument
 *                        struct file *file: file descriptor pointer.
 */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,14)
#define register_ioctl32_conversion(cmd, handler)	(0)
#define unregister_ioctl32_conversion(cmd)		(0)
#else
extern int register_ioctl32_conversion(unsigned int cmd,
    int (*handler)(unsigned int, unsigned int, unsigned long, struct file *));
extern int unregister_ioctl32_conversion(unsigned int cmd);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
int
qla2xxx_ioctl32(unsigned int fd, unsigned int cmd, unsigned long arg,
    struct file *pfile)
{
	return (sys_ioctl(fd, cmd, (void *)arg));
}
#endif

static int
apidev_reg_increasing_idx(uint16_t low_idx, uint16_t high_idx)
{
	int	err = 0;
	int	i;
	unsigned int cmd;

	for (i = low_idx; i <= high_idx; i++) {
		cmd = (unsigned int)QL_IOCTL_CMD(i);
		err = register_ioctl32_conversion(cmd, qla2xxx_ioctl32);
		if (err) {
			DEBUG9(printk(
			    "%s: error registering cmd %x. err=%d.\n",
			    __func__, cmd, err));
			break;
		}
		DEBUG9(printk("%s: registered cmd %x.\n", __func__, cmd));
	}

	return (err);
}

static int
apidev_unreg_increasing_idx(uint16_t low_idx, uint16_t high_idx)
{
	int	err = 0;
	int	i;
	unsigned int cmd;

	for (i = low_idx; i <= high_idx; i++) {
		cmd = (unsigned int)QL_IOCTL_CMD(i);
		err = unregister_ioctl32_conversion(cmd);
		if (err) {
			DEBUG9(printk(
			    "%s: error unregistering cmd %x. err=%d.\n",
			    __func__, cmd, err));
			break;
		}
		DEBUG9(printk("%s: unregistered cmd %x.\n", __func__, cmd));
	}

	return (err);
}

void
apidev_init_32ioctl_reg(void)
{
	int	err;

	DEBUG9(printk("qla2x00: going to register ioctl32 cmds.\n"));

	/* regular external ioctl codes */
	err = apidev_reg_increasing_idx(EXT_DEF_LN_REG_CC_START_IDX,
	    EXT_DEF_LN_REG_CC_END_IDX);
	if (!err) {
		/* regular internal ioctl codes */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_INT_CC_START_IDX,
		    EXT_DEF_LN_INT_CC_END_IDX);
	}
	if (!err) {
		/* additional codes */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_ADD_CC_START_IDX,
		    EXT_DEF_LN_ADD_CC_END_IDX);
	}
	if (!err) {
		/* QL FO specific codes */
		err = apidev_reg_increasing_idx(FO_CC_START_IDX, FO_CC_END_IDX);
	}
	if (!err) {
		/* LN Drvr specific codes are defined in decreasing order */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_SPC_CC_END_IDX,
		    EXT_DEF_LN_SPC_CC_START_IDX);
	}
}

void
apidev_cleanup_32ioctl_unreg(void)
{
	int	err;

	DEBUG9(printk("qla2x00: going to unregister ioctl32 cmds.\n"));

	/* regular external ioctl codes */
	err = apidev_unreg_increasing_idx(EXT_DEF_LN_REG_CC_START_IDX,
	    EXT_DEF_LN_REG_CC_END_IDX);
	if (!err) {
		/* regular internal ioctl codes */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_INT_CC_START_IDX,
		    EXT_DEF_LN_INT_CC_END_IDX);
	}
	if (!err) {
		/* additional codes */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_ADD_CC_START_IDX,
		    EXT_DEF_LN_ADD_CC_END_IDX);
	}
	if (!err) {
		/* QL FO specific codes */
		err = apidev_unreg_increasing_idx(FO_CC_START_IDX,
		    FO_CC_END_IDX);
	}
	if (!err) {
		/* LN Drvr specific codes are defined in decreasing order */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_SPC_CC_END_IDX,
		    EXT_DEF_LN_SPC_CC_START_IDX);
	}
}

#endif
