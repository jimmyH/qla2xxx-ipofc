/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>

/*
 * Extended configuration parameters
 */
#include "qla_opts.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#include "extras/intermodule.h"
#endif

MODULE_DESCRIPTION("QLogic Persistent Binding Data Module");
MODULE_AUTHOR("QLogic Corporation");
MODULE_LICENSE("GPL");


char *qla_persistent_str = NULL ;
CONFIG_BEGIN("qla2xxx_conf")
CONFIG_ITEM("OPTIONS", "")
CONFIG_END

static int conf_init(void)
{
	QLOPTS_CONFIGURE(qla_persistent_str);
	inter_module_register("qla2xxx_conf", THIS_MODULE, qla_persistent_str);
	return 0;
}

static void conf_exit (void)
{
	inter_module_unregister("qla2xxx_conf");
}

module_init(conf_init);
module_exit(conf_exit);


