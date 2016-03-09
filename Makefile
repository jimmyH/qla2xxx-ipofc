EXTRA_CFLAGS += -DUNIQUE_FW_NAME

# Force failover compilation
CONFIG_SCSI_QLA2XXX_FAILOVER=y
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2XXX_FAILOVER

# Handle all ISP2xxx builds.
CONFIG_SCSI_QLA21XX=m
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA21XX -DCONFIG_SCSI_QLA21XX_MODULE
CONFIG_SCSI_QLA22XX=m
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA22XX -DCONFIG_SCSI_QLA22XX_MODULE
CONFIG_SCSI_QLA2300=m
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2300 -DCONFIG_SCSI_QLA2300_MODULE
CONFIG_SCSI_QLA2322=m
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2322 -DCONFIG_SCSI_QLA2322_MODULE
CONFIG_SCSI_QLA24XX=m
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA24XX -DCONFIG_SCSI_QLA24XX_MODULE

qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_rscn.o qla_attr.o

qla2xxx-$(CONFIG_SCSI_QLA2XXX_FAILOVER) += qla_xioct.o qla_inioct.o \
	qla_fo.o qla_foln.o qla_cfg.o qla_cfgln.o qla_32ioctl.o qla_ip.o

qla2100-y := ql2100.o ql2100_fw.o
qla2200-y := ql2200.o ql2200_fw.o
qla2300-y := ql2300.o ql2300_fw.o
qla2322-y := ql2322.o ql2322_fw.o
qla2400-y := ql2400.o ql2400_fw.o

host-progs := extras/qla_nvr extras/qla_opts
always := $(host-progs)

obj-$(CONFIG_SCSI_QLA21XX) += qla2xxx.o qla2100.o
obj-$(CONFIG_SCSI_QLA22XX) += qla2xxx.o qla2200.o
obj-$(CONFIG_SCSI_QLA2300) += qla2xxx.o qla2300.o
obj-$(CONFIG_SCSI_QLA2322) += qla2xxx.o qla2322.o
obj-$(CONFIG_SCSI_QLA24XX) += qla2xxx.o qla2400.o
ifeq ($(CONFIG_SCSI_QLA2XXX_FAILOVER),y)
obj-m += qla2xxx_conf.o
obj-m += qla2xip.o
endif
