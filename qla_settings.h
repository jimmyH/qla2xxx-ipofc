/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
/*
 * Compile time Options:
 *     0 - Disable and 1 - Enable
 */
#define STOP_ON_RESET		0
#define USE_ABORT_TGT		1	/* Use Abort Target mbx cmd */

#define VSA			0	/* Volume Set Addressing */

/* Failover options */
#define MAX_RECOVERYTIME	10	/*
					 * Max suspend time for a lun recovery
					 * time
					 */
#define MAX_FAILBACKTIME	5	/* Max suspend time before fail back */

#define QLA_CMD_TIMER_MINIMUM	30
#define QLA_CMD_TIMER_DELTA	3

/*
 * When a lun is suspended for the "Not Ready" condition then it will suspend
 * the lun for increments of 6 sec delays.  SUSPEND_COUNT is that count.
 */
#define SUSPEND_COUNT		10	/* 6 secs * 10 retries = 60 secs */

/*
 * Defines the time in seconds that the driver extends the command timeout to
 * get around the problem where the mid-layer only allows 5 retries for
 * commands that return BUS_BUSY
 */
#define EXTEND_CMD_TIMEOUT	60

#define MAX_RETRIES_OF_ISP_ABORT	5

/* Max time to wait for the loop to be in LOOP_READY state */
#define MAX_LOOP_TIMEOUT	(60 * 5)
#define EH_ACTIVE		1	/* Error handler active */

#ifdef CONFIG_SCSI_QLA2XXX_FAILOVER
/* Default: IOCTL pass-thru command timeout in seconds.   */
#define QLA_PT_CMD_TOV		(66)
#endif
/*
 * Some vendor subsystems do not recover properly after a device reset.  Define
 * the following to force a logout after a successful device reset.
 */
#undef LOGOUT_AFTER_DEVICE_RESET

#undef ENABLE_MSI
#undef ENABLE_MSIX

#include "qla_version.h"
