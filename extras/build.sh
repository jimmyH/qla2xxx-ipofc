#!/bin/sh

# QLogic ISP2xxx/ISP4xxx device driver build script
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

UNAME=`uname -a`
K_VERSION=`uname -r`
K_LIBS=/lib/modules/${K_VERSION}
K_BUILD_DIR=${K_LIBS}/build
K_SOURCE_DIR=${K_LIBS}/source
K_THREADS=5

SLES=/etc/SuSE-release
RHEL=/etc/redhat-release
UDEV_RULE_DIR=/etc/udev/rules.d/
UDEV_RULE_FILE=99-qla2xxx.rules
UDEV_SCRIPT_DIR=/lib/udev
UDEV_SCRIPT=qla2xxx_udev.sh
UDEV_EARLY_RULE=/etc/udev/rules.d/05-udev-early.rules
UDEV_TMP_RULE=/tmp/tmp.rules

# Determine udev control utility to reload rules
which udevadm 1>/dev/null 2>&1
if [ $? -eq 0 ]
then
	RELOAD_RULES='udevadm control --reload-rules'
else
	RELOAD_RULES='udevcontrol reload_rules'
fi

BOOTDIR="/boot"

Q_NODE=QLA2XXX
MODULE=qla2xxx
K_INSTALL_DIR=${K_LIBS}/extra/qlgc-qla2xxx/
SPARSE_ARGS=""

if test -f "${SLES}" ; then
	K_INSTALL_DIR=${K_LIBS}/updates/
fi

if [ "`uname -m`" = "ia64" ]; then
        if [ -f "$RHEL" ]; then
                BOOTDIR="/boot/efi/efi/redhat"
        fi
fi

###
# drv_build -- Generic 'make' command for driver
#	$1 -- directive
#

set_variables() {
	if [ -f ./qla_os.c ]; then
		Q_NODE=QLA2XXX
		MODULE=qla2xxx
		K_INSTALL_DIR=${K_LIBS}/extra/qlgc-qla2xxx/

		if test -f "${SLES}" ; then
			K_INSTALL_DIR=${K_LIBS}/updates/
		fi

	elif [ -f ./ql4_os.c ]; then
		Q_NODE=QLA4XXX
		MODULE=qla4xxx
		K_INSTALL_DIR=${K_LIBS}/extra/qlgc-qla4xxx/

		if test -f "${SLES}" ; then
			K_INSTALL_DIR=${K_LIBS}/updates/
		fi
	fi
}

drv_build() {
	test -z "$1" && return 1

	# Go with build...
	if test -f "${SLES}" ; then
		# SuSE -------------------------------------------------------
		make -j${K_THREADS} -C ${K_SOURCE_DIR} O=${K_BUILD_DIR} ${SPARSE_ARGS} M=$PWD $1
	else
		# Redhat -----------------------------------------------------
		make -j${K_THREADS} -C ${K_BUILD_DIR} ${SPARSE_ARGS} M=$PWD $1
	fi
}

udev_install()
{
	RET=0
	diff ./extras/${UDEV_RULE_FILE} ${UDEV_RULE_DIR}/${UDEV_RULE_FILE} &> /dev/null
	RET=$?
	diff ./extras/${UDEV_SCRIPT} ${UDEV_SCRIPT_DIR}/${UDEV_SCRIPT} &> /dev/null
	(( RET += $? ))

	if [ $RET -ne 0 ]; then
		echo "${Q_NODE} -- Installing udev rule to capture FW dump..."
		cp ./extras/${UDEV_RULE_FILE} ${UDEV_RULE_DIR}/${UDEV_RULE_FILE}
		cp ./extras/${UDEV_SCRIPT} ${UDEV_SCRIPT_DIR}/${UDEV_SCRIPT}

		# comment out the modules ignore_device rule
		if [ -e ${UDEV_EARLY_RULE} ]; then
			cp ${UDEV_EARLY_RULE} ${UDEV_EARLY_RULE}.bak
			cat ${UDEV_EARLY_RULE} | sed "s/\(^SUBSYSTEM==\"module\".*OPTIONS=\"ignore_device\".*\)/#\1/" > ${UDEV_TMP_RULE}
			if [ -s ${UDEV_TMP_RULE} ]; then
				mv -f ${UDEV_TMP_RULE} ${UDEV_EARLY_RULE}
			fi
		fi
		$RELOAD_RULES
	else
		echo "${Q_NODE} -- udev rules already installed"
	fi
}

udev_remove()
{
		rm -f ${UDEV_RULE_DIR}/${UDEV_RULE_FILE} &> /dev/null
		rm -f ${UDEV_SCRIPT_DIR}/${UDEV_SCRIPT} &> /dev/null
		if [ -e ${UDEV_EARLY_RULE} ]; then
			cat ${UDEV_EARLY_RULE} |sed "s/\#\(SUBSYSTEM==\"module\".*OPTIONS=\"ignore_device\".*\)/\1/" > ${UDEV_TMP_RULE}
			if [ -s ${UDEV_TMP_RULE} ]; then
				echo "${Q_NODE} -- Removing FW capture udev rule..."
				mv -f ${UDEV_TMP_RULE} ${UDEV_EARLY_RULE}
				$RELOAD_RULES
			fi
		fi
}

###
# drv_install -- Generic steps for installation
#
drv_install() {
	if test $EUID -ne 0 ; then
		echo "${Q_NODE} -- Must be root to install..."
		return 1
	fi


	#backup all modules except the one in default path
	for module in `find /lib/modules/$K_VERSION -name $MODULE.ko`
	do
		echo $module | grep "scsi" >& /dev/null
		if [ $? -ne 0 ]; then
			mv $module $module.org
		fi
	done

	echo "${Q_NODE} -- Installing the $MODULE modules to ${K_INSTALL_DIR}..."
	install -d -o root -g root ${K_INSTALL_DIR}
	install -o root -g root -m 0644 *.ko ${K_INSTALL_DIR}

	# depmod
	/sbin/depmod -a

	#install the udev rules to capture FW dump
	if [ -f ./qla2xxx.ko ]; then
		udev_install
	fi
}

build_ramdisk () {
	echo "${Q_NODE} -- Rebuilding INITRD image..."
	if test -f "${SLES}" ; then
		if [ ! -f ${BOOTDIR}/initrd-${K_VERSION}.bak ]; then
			cp ${BOOTDIR}/initrd-${K_VERSION} ${BOOTDIR}/initrd-${K_VERSION}.bak
		fi
		mkinitrd -k /boot/vmlinuz-${K_VERSION} -i /boot/initrd-${K_VERSION} >& /dev/null
	elif test -f "${RHEL}"; then
		# Check if it is RHEL6
		REDHAT_REL=`cat ${RHEL} | cut -d " " -f 7 | cut -d . -f 1`
		if [ "$REDHAT_REL" -le 5 ]; then
			if [ ! -f ${BOOTDIR}/initrd-${K_VERSION}.bak.img ]; then
				cp ${BOOTDIR}/initrd-${K_VERSION}.img ${BOOTDIR}/initrd-${K_VERSION}.bak.img
			fi
			mkinitrd -f /boot/initrd-${K_VERSION}.img ${K_VERSION} >& /dev/null
		else
			if [ ! -f ${BOOTDIR}/initramfs-${K_VERSION}.bak.img ]; then
				cp ${BOOTDIR}/initramfs-${K_VERSION}.img ${BOOTDIR}/initramfs-${K_VERSION}.bak.img
			fi
			dracut --force /boot/initramfs-${K_VERSION}.img $K_VERSION >& /dev/null
		fi
	fi
}

run_sparse () {
	which sparse 1>/dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "Cannot find sparse executable in PATH."
		exit 1
	fi
	echo "${Q_NODE} -- Performing static analysis on $MODULE with sparse."
	drv_build clean
	SPARSE_ARGS="$1"
	drv_build modules
}

###
#
#
shopt -s extglob
case "$1" in
    -h | help)
	echo "QLogic Corporation -- driver build script"
	echo "  build.sh <directive>"
	echo ""
	echo "   # cd <driver source>"
	echo "   # ./extras/build.sh"
	echo ""
	echo "    Build the driver sources based on the standard"
	echo "    SLES10/SLES11/RHEL5/RHEL6 build environment."
	echo ""
	echo "   # ./extras/build.sh clean"
	echo ""
	echo "    Clean driver source directory of all build files (i.e. "
	echo "    *.ko, *.o, etc)."
	echo ""
	echo "   # ./extras/build.sh new"
	echo ""
	echo "    Rebuild the driver sources from scratch."
	echo "    This is essentially a shortcut for:"
	echo ""
	echo "        # ./build.sh clean"
	echo "        # ./build.sh"
	echo ""
	echo "   # ./extras/build.sh install"
	echo ""
	echo "     Build and install the driver module files."
	echo "     This command performs the following:"
	echo ""
	echo "        1. Builds the driver .ko files."
	echo "        2. Copies the .ko files to the appropriate "
	echo "           /lib/modules/... directory."
	echo ""
	echo "   # ./extras/build.sh remove"
	echo ""
	echo "     Remove/uninstall the driver module files."
	echo "     This command performs the following:"
	echo ""
	echo "        1. Uninstalls the driver .ko files from appropriate."
	echo "           /lib/modules/... directory."
	echo "        2. Rebuilds the initrd image with the /sbin/mk_initrd"
	echo "           command."
	echo ""
	echo "   # ./extras/build.sh initrd"
	echo ""
	echo "     Build, install, and update the initrd image."
	echo "     This command performs the following:"
	echo ""
	echo "        1. All steps in the 'install' directive."
	echo "        2. Rebuilds the initrd image with the /sbin/mk_initrd"
	echo "           command."
	echo ""
	echo "   # ./extras/build.sh analyze [--what|--clean|--local]"
	echo ""
	echo "     Perform Coverity source code analysis."
	echo "        --what   show [branch]->stream mapping"
	echo "        --clean  remove previous/incremental data"
	echo "        --local  perform analysis only (do not commit)"
	echo ""
	;;
    -i | install)
	set_variables
	echo "${Q_NODE} -- Building the $MODULE driver..."
	drv_build modules

	drv_install
	;;
    -r | remove)
	set_variables
	echo "${Q_NODE} -- Building the $MODULE driver..."
	if  [ -f ${K_INSTALL_DIR}/$MODULE.ko ]; then
		rm ${K_INSTALL_DIR}/$MODULE.ko
		/sbin/depmod -a
		build_ramdisk
		if [ "$Q_NODE" == "QLA2XXX" ]; then
			udev_remove
		fi
	fi
	;;

    initrd)
	set_variables
	echo "${Q_NODE} -- Building the $MODULE driver..."
	drv_build modules
	drv_install
	build_ramdisk
	;;
    clean)
	echo "${Q_NODE} -- Cleaning driver build directory..."
	drv_build clean
	;;
    new)
	set_variables
	echo "${Q_NODE} -- Building the $MODULE driver..."
	drv_build clean
	drv_build modules
	;;
    analyze)
	cov_analyze.sh $2
	;;
    sparse)
	run_sparse "C=2"
	;;
    sparse_endian)
	run_sparse "C=2 CF=\"-D__CHECK_ENDIAN__\""
	;;
    !())
	echo "Unknown parameter $1"
	exit 1
	;;
    *)
	set_variables
	echo "${Q_NODE} -- Building the $MODULE driver..."
	drv_build modules
	;;
esac
