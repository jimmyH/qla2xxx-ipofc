/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */

/*
 * QLogic ISP2x00 Failover Header
 *
 */
#ifndef _QLA_FO_H
#define _QLA_FO_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "qlfo.h"
        /*
         * This structure definition is for a scsi I/O request NOT subject to
         * failover re-routing.  It is for the use of configuration operations
         * and diagnostics functions as definted in ExIoct.h
         */
        typedef struct scsi_cdb_request {
                struct adapter_state		*ha;
                uint16_t	target;
                uint16_t	lun;
                uint8_t		*cdb_ptr;	/* Pointer to cdb to be sent */
                uint8_t		cdb_len;	/* cdb length */
                uint8_t		direction;	/* Direction of I/O for buffer */
                uint8_t		scb_len;	/* Scsi completion block length */
                uint8_t		*scb_ptr;	/* Scsi completion block pointer */
                uint8_t		*buf_ptr;	/* Pointer to I/O buffer */
                uint16_t	buf_len;	/* Buffer size */
        }
        SCSI_REQ_t, *SCSI_REQ_p;


        /*
        * Special defines
        */
        typedef	union	_FO_HBA_STAT {
                FO_HBA_STAT_INPUT	input;
                FO_HBA_STAT_INFO	info;
        } FO_HBA_STAT;

        typedef	union	_FO_LUN_DATA {
                FO_LUN_DATA_INPUT	input;
                FO_LUN_DATA_LIST	list;
        } FO_LUN_DATA;

        typedef union	_FO_TARGET_DATA {
                FO_TARGET_DATA_INPUT    input;
                FO_DEVICE_DATABASE    list;
        } FO_TARGET_DATA;

#if defined(__cplusplus)
}
#endif

#endif	/* ifndef _QLA_FO_H */
