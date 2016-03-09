#!/bin/sh -e

#
# ACTION FILE: located in /lib/udev/
#

err() {
	echo "$@" >&2
	if [ -x /bin/logger ]; then
		/bin/logger -t "${0##*/}[$$]" "$@"
	elif [ -x /usr/bin/logger ]; then
		/usr//bin/logger -t "${0##*/}[$$]" "$@"
	fi
}

SYSFS=/sys
HOST=${FW_DUMP}
QFWD=${SYSFS}/class/fc_host/host${HOST}/device/fw_dump
DFILE_PATH=/opt/QLogic_Corporation/FW_Dumps
DFILE=${DFILE_PATH}/qla2xxx_fw_dump_${HOST}_`eval date +%Y%m%d_%H%M%S`.txt

# Verify fw_dump binary-attribute file
if ! test -f ${QFWD} ; then
	err "qla2xxx: no firmware dump file at host $HOST!!!"
	exit 1
fi

# Go with dump
mkdir -p ${DFILE_PATH}
echo 1 > ${QFWD}
cat ${QFWD} > ${DFILE}
echo 0 > ${QFWD}
if ! test -s "${DFILE}" ; then
	err "qla2xxx: no firmware dump file at host ${HOST}!!!"
	rm ${DFILE}
	exit 1
fi

gzip ${DFILE}
err "qla2xxx: firmware dump saved to file ${DFILE}.gz."
exit 0
