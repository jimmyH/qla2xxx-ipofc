#!/bin/sh
#
# QLogic ISP2x00 device driver dump reader
# Copyright (C) 2003-2014 QLogic Corporation
# (www.qlogic.com)
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
version=1.039720
sysfs=/sys
qstats=${sysfs}/class/scsi_host/host${1}/device/stats
qfwd=${sysfs}/class/scsi_host/host${1}/device/fw_dump
dfile=qla2xxx_fw_dump_${1}_`eval date +%Y%m%d_%H%M%S`.txt
mctpfile=mctp_dump_${1}_`eval date +%Y%m%d_%H%M%S`.txt

# Get host number
if [ -z "${1}" ] ; then
	echo "QLogic Firmware Dump Reader: ${version}"
	echo "Usage:"
	echo "   `basename ${0}` <host_no>"
	exit 1
fi

# Verify fw_dump binary-attribute file
if ! test -f ${qfwd} ; then
	echo "No firmware dump file at host ${1}!!!"
	exit 1
fi

# Verify a firmware dump is available for the given host
#if ! test -f ${qstats} ; then
#	echo "No device stats to verify firmware dump available at host ${1}!!!"
#	exit 1
#fi
#do_dump=`eval cat ${qstats} | cut -d ' ' -f5`
#if [ "${do_dump}" = "0" ] ; then
#	echo "No firmware dump available at host ${1}!!!"
#	exit 1
#fi

# Go with dump
echo 1 > ${qfwd}
cat ${qfwd} > ${dfile}
echo 0 > ${qfwd}
if ! test -s "${dfile}" ; then
	echo "No firmware dump available at host ${1}!!!"
	rm ${dfile}
else
	gzip ${dfile}
	echo "Firmware dumped to file ${dfile}.gz."
fi

# Go with mctp dump
echo 7 > ${qfwd}
cat ${qfwd} > ${mctpfile}
echo 6 > ${qfwd}
if ! test -s "${mctpfile}" ; then
	echo "No mctp dump available at host ${1}!!!"
	rm ${mctpfile}
else
	gzip ${mctpfile}
	echo "Mctp dumped to file ${mctpfile}.gz."
fi

exit 0
