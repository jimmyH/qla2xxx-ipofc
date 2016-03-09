#!/bin/sh

# QLogic ISP2xxx device driver build script
# Copyright (C) 2003-2004 QLogic Corporation
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

Q_NODE=QLA2XXX
Q_CONF_FILE=/etc/qla2xxx.conf

UNAME=`uname -a`
K_VERSION=`uname -r`
K_MAJ_MIN=`echo $K_VERSION | cut -d . -f -2`
K_LIBS=/lib/modules/${K_VERSION}
K_BUILD_DIR=${K_LIBS}/build
K_SOURCE_DIR=${K_LIBS}/source
K_INSTALL_DIR=${K_LIBS}/kernel/drivers/scsi/qla2xxx/
K_THREADS=5
K_BLACK_LIST="/etc/hotplug/blacklist"

SLES=/etc/SuSE-release
SYS_FILE=kernel
SLES_CONF=/etc/sysconfig/$SYS_FILE
SLES_CONF_KEY=INITRD_MODULES
RHEL=/etc/redhat-release
ASIANUX=/etc/asianux-release
BOOTDIR="/boot"

if [ "`uname -m`" = "ia64" ]; then
	if [ -f "$ASIANUX" ]; then
		BOOTDIR="/boot/efi/efi/asianux"
	elif [ -f "$RHEL" ]; then  
		BOOTDIR="/boot/efi/efi/redhat"
	fi
fi

SLES_MODPROBE="modprobe.conf.local"
SLES_MPC=/etc/$SLES_MODPROBE
RHEL_MODPROBE="modprobe.conf"
RHEL_MPC=/etc/$RHEL_MODPROBE

QLOGIC="qlogic"
# RPM spec file through the installer can update RPMVERSION
# if this is "" that means user is not running RPM package
RPMVERSION="" 
QL_SOURCE=/usr/src/$QLOGIC/$RPMVERSION
QL_BACKUP=$QL_SOURCE/backup
QL_CONF_ENTRIES=$QL_BACKUP/ql_conf_entries
QL_KERNEL_ENTRIES=$QL_BACKUP/ql_kernel_entries # for SuSE /etc/sysconfig/kernel
QL_MOD_REMOVED=$QL_BACKUP/ql_mod_removed

QL_TAKE_BACKUP=0
QL_NO_BACKUP=1
SAVING_STR="Saving copy of"	

QL_RENAMES_BKUP_DIR="/usr/local/tmp/qlogic/"
QL_RENAMES_FILE="/etc/modprobe.d/module-renames"
QL_RENAMES_FILE_BKUP="$QL_RENAMES_BKUP_DIR/module-renames-ql.bak"
QL_RENAMES_FILE_DATE="$QL_RENAMES_BKUP_DIR/module-renames-ql"

#create only if user is root
#only root can come to this point
if [ $EUID -eq 0 ] && [ "${RPMVERSION}" != "" ]; then
	mkdir -p $QL_SOURCE
	mkdir -p $QL_BACKUP
fi


# --------------------------------------------------------- #
# invoke_cmd ()		                                    #
# Invokes the shell command				    #
# Parameter: 	 		                            #
#	$1    the command to be invoked			    #
# 	$2    the text output to the screen                 #
# 	$3    if set to "background", outputs "."s 	    #
#	      while waiting for completion		    #
#							    #
# Returns: Commands exit value.				    #
# --------------------------------------------------------- #
function invoke_cmd() {
    exitval=0
    rm -f .tmp_exitval
    if [ -e .tmp_exitval ]; then
	echo $"invoke_command could not run!" >$std_err
	exit 1
    fi
    if [ "$2" != "" ]; then	
	    echo -en "$2..."
    fi	 
    if [ "$3" == background ]; then
	(eval $1; echo "exitval=$?" >> .tmp_exitval) &
	while ! [ -e .tmp_exitval ]
	do
	  if [ "$4" == "progress" ]; then
	    #echo -en '\E[34;44m '
		echo -en "|"
		echo -en "\b"
		sleep .08
		echo -en "/"
		echo -en "\b"
		sleep .08
		echo -en "-"
		echo -en "\b"
		sleep .08
		echo -en "\\"
		echo -en "\b"
		sleep .08
	  else
	   echo -en "." 
	   sleep 1
	  fi
	done
	echo -en "\b"
	echo " "
	#tput sgr0
	. .tmp_exitval
	rm .tmp_exitval
    else
	eval $1; exitval=$?
    fi
    if [ $exitval -gt 0 ]; then
	echo -en "(bad exit status)" 
	script_location=`dirname $0`
	echo "$1 failed to execute"
	echo $1 >> $script_location/.invoke_command.log
    fi
    echo -en "\n" 
    return $exitval
}

#Check if intermodule .ko need to be built and installed
build_install_im()
{
	IM="intermodule"
	INSTALL_DIR="${K_LIBS}/kernel/kernel/"
	RET=0
	C_DIR=$PWD
	M_DIR=$PWD/extras/im
	#since this issue is specific to SLES 10/RHEL 5 make sure to check kernel > 2.6.12
	KVERSION=`uname -r | sed "s/-.*//" | sed "s/\.//g"`
	if [ "$KVERSION" = "" ]; then
		echo "Unable to determine kernel version."
		echo "skipping installation of inermodule.ko"
		return
	fi
	if [ $KVERSION -ge 2612 ]; then #greater than 2.6.12 kernel 
		modinfo $IM >& /dev/null
		if [ $? -ne 0 ]; then
			#no intermodule installed, lets build it 
			mkdir -p $M_DIR	
			cp ./extras/${IM}.c $M_DIR >& /dev/null
			cd $M_DIR
			echo "obj-m += intermodule.o" > Makefile 
			if [ -s ${MF} ]; then
				make -j${K_THREADS} -C ${K_SOURCE_DIR} O=${K_BUILD_DIR} M=$PWD modules >& im.log 
				RET=$?
				if [ $RET -eq 0 ]; then
					if [ -s ${IM}.ko ]; then
						echo "Installing ${IM}.ko in ${INSTALL_DIR}"
						install -d -o root -g root ${INSTALL_DIR}
						install -o root -g root -m 0644 ${IM}.ko ${INSTALL_DIR}
						depmod -a >& /dev/null
					else
						cat im.log
						RET=1
					fi
				fi
			else
				RET=1
			fi

			if [ $RET -ne 0 ]; then
				echo "Unable to build ${IM}.ko"
			fi
		fi #modinfo
		cd $C_DIR	
	fi #greater than 2.6.12 (2.6.12)
}

###
# drv_build -- Generic 'make' command for driver
#	$1 -- directive
#
drv_build() {
	test -z "$1" && return 1
	mk_ret=0

	#check if need to build and install the intermodule.ko
	if [ "$1" = "modules" ]; then
		build_install_im
	fi

	# Go with build...
	if [ "${RPMVERSION}" == "" ]; then # User running out of installer
        	if test -f "${SLES}" ; then
                	# SuSE -------------------------------------------------------
                	make -j${K_THREADS} -C ${K_SOURCE_DIR} O=${K_BUILD_DIR} M=$PWD $1 >& mk.log
			mk_ret=$?
       		else
                	# Redhat -----------------------------------------------------
                	make -j${K_THREADS} -C ${K_BUILD_DIR} M=$PWD $1 >& mk.log
			mk_ret=$?
        	fi
		if [ $mk_ret -ne 0 ]; then
			if [ -s mk.log ]; then
				cat mk.log
			fi
			echo "${Q_NODE} -- Failed."
		else
			if [ "$1" = "modules" ]; then
				echo "${Q_NODE} -- Build done."
			fi
		fi
	else

		if test -f "${SLES}" ; then
			# SuSE -------------------------------------------------------
			invoke_cmd "make  -j${K_THREADS} -C ${K_SOURCE_DIR} O=${K_BUILD_DIR} \
				M=$PWD $1 >& $QL_SOURCE/build.log" "" "background" "progress"
		else
			# Redhat -----------------------------------------------------
 			invoke_cmd "make  -j${K_THREADS} -C ${K_BUILD_DIR} M=$PWD $1 >& \
					$QL_SOURCE/build.log" "" "background" "progress"
		fi
	fi
}

# --------------------------------------------------------- #
# add_modprobe_commands()                                   #
# Adds the install/remove commands for qla2xxx		    #
#							    #
# Parameter: None					    #
# Returns: None						    #
# --------------------------------------------------------- #
function add_modprobe_commands()
{
	local IS_SLES9=0 # 0 means not SLES 9
	if test -f "${SLES}" ; then
		MPC=${SLES_MPC}
		grep "Server 9"  ${SLES} >& /dev/null
		if [ $? -eq 0 ]; then
			IS_SLES9=1 # 1 means it is SLES 9
		fi
		
	else
		MPC=${RHEL_MPC}
	fi

	#do not use install command for SLES9 PPC64
	if [ ${IS_SLES9} -eq 0 ] || [ "`uname -m`" != "ppc64" ]; then
		#install command for qla2xxx, load qla2xxx_conf before qla2xxx
		if [ `grep -c "^install qla2xxx" ${MPC}` -eq 0 ]; then
			echo "install qla2xxx /sbin/modprobe qla2xxx_conf; /sbin/modprobe --ignore-install qla2xxx" >> ${MPC}
			if [ "${RPMVERSION}" != "" ]; then # in installer, store what was added, so as to remove on un-install
				echo "install qla2xxx /sbin/modprobe qla2xxx_conf; /sbin/modprobe --ignore-install qla2xxx" >> $QL_CONF_ENTRIES
			fi
		fi
	fi
	
	# remove of qla2xxx_conf module
	if [ `grep -c "^remove qla2xxx" ${MPC}` -eq 0 ]; then
		echo "remove qla2xxx /sbin/modprobe -r --first-time --ignore-remove qla2xxx && { /sbin/modprobe -r --ignore-remove qla2xxx_conf; }" >> ${MPC}

		if [ "${RPMVERSION}" != "" ]; then # in installer, store what was added, so as to remove on un-install
			echo "remove qla2xxx /sbin/modprobe -r --first-time --ignore-remove qla2xxx && { /sbin/modprobe -r --ignore-remove qla2xxx_conf; }" >> $QL_CONF_ENTRIES
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
	
	# Need to take backup of old driver
	backup_drivers

	echo "${Q_NODE} -- Installing the qla2xxx modules to "
	echo "${K_INSTALL_DIR}..."
	install -d -o root -g root ${K_INSTALL_DIR}
	install -o root -g root -m 0644 *.ko ${K_INSTALL_DIR}

	#add the remove and install commands for qla2xxx
	add_modprobe_commands	

	#update module-renames for SLES 10
	remove_module_renames >& /dev/null #no need to show any messages to user

	# Update any existing qla2xxx_conf data
	if test -f "${Q_CONF_FILE}" ; then
		echo "${Q_NODE} -- Updating the qla2xxx_conf module..."
		./extras/qla_opts -w qla2xxx_conf
	fi
	# depmod
	/sbin/depmod -a
}

is_module_installed() {
	# Need to check in
	# /lib/modules/2.6.9-5.EL/kernel/drivers/scsi/qla2xxx/
	if [ -f "$K_INSTALL_DIR/${1}.ko" ]; then
		return 0
	fi
	return 1
}


###
# edit_modprobe -- Adds scsi_hostadapter entry in 
# Adds the module in hotplug blacklist to avoid loading 
# the driver using hotplug
# /etc/modprobe.conf
# $1 Name of the module
#
edit_modprobe () {
	test -z "$1" && return 1

	is_module_installed $1
	if [ $? != 0 ]; then
		return 1
	fi
	DONE=0
 	CNT=""
	SCSIHOSTADAPTER="scsi_hostadapter"

   	if test -f "${SLES}" ; then
		MPC=${SLES_MPC}
		return 1
	else
		MPC=${RHEL_MPC}
		# Check if the entry is already in the 
		# /etc/modprobe.conf file
		grep "^[[:space:]]*alias[[:space:]]\+${SCSIHOSTADAPTER}.*${1}$" $MPC >& /dev/null
		if [ $? = 0 ]; then #Entry already in modprobe.conf
			return 1
		fi

		# Get the hostadatper number
		while [ $DONE -eq 0 ]
		do
			TEXT=`cat ${MPC} | grep "^[[:space:]]*alias[[:space:]]\+${SCSIHOSTADAPTER}${CNT}"`
			if [ "$TEXT" = "" ]
				then
					DONE=1
			else
				if [ "$CNT" = "" ]; then
					CNT=0
				fi
				CNT=`expr $CNT + 1`
			fi
		done
		#echo "adding line: alias ${SCSIHOSTADAPTER}${CNT} $1 to $MPC"
		ENTRY_LINE="alias ${SCSIHOSTADAPTER}${CNT} $1"
		echo $ENTRY_LINE >> $MPC
		if [ "${RPMVERSION}" = "" ]; then # not in installer
			return 0
		fi
		# do not add if entry already in, as we might come back here
		# from the include driver in ramdisk option
		if [ -f $QL_CONF_ENTRIES ]; then
			grep "$ENTRY_LINE" $QL_CONF_ENTRIES >& /dev/null
			if [ $? = 0 ]; then
				return 0
			fi
		fi
		echo $ENTRY_LINE >> $QL_CONF_ENTRIES
	fi
	return 0
}


backup_blacklist() {
	# Create backup of the blacklist
	echo "Creating backup of $K_BLACK_LIST as $K_BLACK_LIST.ql.orig.bak...."
	cp --archive $K_BLACK_LIST $K_BLACK_LIST.ql.orig.bak
}

function add_in_blacklist () {
	# Add our moudles in the blacklist
	grep "$1" $K_BLACK_LIST >& /dev/null
	if [ $? != 0 ]; then
		echo $1 >> $K_BLACK_LIST
	fi
}

# --------------------------------------------------------- #
# backup_drivers ()	                                    #
# Backup if any QLogic driver present in the 		    #
# /lib/modules/<kernel ver>/driver/scsi/qla2xxx             #
# Backup is created in the 				    #
# /usr/src/qlogic/<driver-rpm ver>/backup		    #
#							    #
# Parameter: None					    # 
# Returns: 0 on success, 1 on fail			    #
# --------------------------------------------------------- #
function backup_drivers () {
	if [ $EUID -eq 0 ] && [ "${RPMVERSION}" != "" ]; then
		cp -rf $K_INSTALL_DIR $QL_BACKUP
		return $?
	fi
	return 0 # return success, we did nothing
}

function backup_modprobe () {
	MPC=""
	if [ -f $RHEL ]; then
		MPC=$RHEL_MPC
	elif [ -f $SLES ]; then
		MPC=$SLES_MPC
	fi
	BACKUP_FILE=$QL_BACKUP/$RHEL_MODPROBE-$K_VERSION-${1}.bak 
	if [ -f $MPC ]; then
		echo "$SAVING_STR $MPC as"
		echo "$BACKUP_FILE"
		echo ""
		cp -f $MPC $BACKUP_FILE
	fi
}

function backup_initrd () {
	# SLES or RHEL backup /boot/initrd-`uname -r`
	INITRD=$BOOTDIR/initrd-$K_VERSION
	BACKUP_FILE=""
	if [ -f $RHEL ] && [ -f ${INITRD}.img ]; then
		INITRD=${INITRD}.img
		BACKUP_FILE=$QL_BACKUP/initrd-$K_VERSION.img-${1}.bak
	elif [ -f $SLES ] && [ -f ${INITRD} ]; then
		BACKUP_FILE=$QL_BACKUP/initrd-$K_VERSION-${1}.bak
	fi

	if [ "$BACKUP_FILE" != "" ]; then
		cp -f ${INITRD} ${BACKUP_FILE} 
		echo "$SAVING_STR ${INITRD} as"
		echo "$BACKUP_FILE"
		echo ""
	fi
}

function backup_sysconfig () {
	# Backup /etc/sysconfig/kernel
	echo "$SAVING_STR $SLES_CONF as"
	echo "$QL_BACKUP/$SYS_FILE-$K_VERSION-${1}.bak"
	cp -f $SLES_CONF $QL_BACKUP/$SYS_FILE-$K_VERSION-${1}.bak
}

# --------------------------------------------------------- #
# restore_mod_conf()                                        #
# Restore any modules that installer removed from the       #
# modules configuration file during installation.           #
# Parameter:                                                #
#       $1      None                                        #
# Returns: None                                             #
# --------------------------------------------------------- #
restore_mod_conf() {
        #get the entries from  $QL_MOD_REMOVED
        # and put them back. Note this operation must
        # be performed after installer changes are removed
        # from modules conf. files

        if [ -f $QL_MOD_REMOVED ]; then
        	if [ -f $SLES ]; then
                        local MODULES=`cat $SLES_CONF | grep "^INITRD_MODULES" |
                        awk 'BEGIN {FS="="} {print $2}'| sed 's/\"//g'`

                        for MODULE in `cat $QL_MOD_REMOVED`
                        do
                                MODULES="$MODULES $MODULE"
                        done

                        sed "s/^INITRD_MODULES.*/INITRD_MODULES=\"$MODULES\"/"  $SLES_CONF >/tmp/kernel
			if [ -s /tmp/kernel ]; then
                        	mv -f /tmp/kernel $SLES_CONF
			fi
                else #RedHat/AsianUx
			cat $QL_MOD_REMOVED >> $RHEL_MPC
                fi
        fi
}

function restore_original() {
        # Restore driver
	MSG_DISPLAYED=0
        BACKUP_DRIVER=$QL_BACKUP/qla2xxx
	echo -e "Restoring original QLogic drivers...."
	echo -e ""

	# first remove the drivers from /lib/modules path
	if [ -e $K_INSTALL_DIR ]; then
		rm -f $K_INSTALL_DIR/*
	fi

	# check if backup dir is not empty
	ls $BACKUP_DRIVER/* >& /dev/null
	if [ $? = 0 ]; then 
		mv -f $BACKUP_DRIVER/* $K_INSTALL_DIR
	fi

	# Restore modprobe
	if [ -f $QL_CONF_ENTRIES ]; then
		if test -f "${SLES}" ; then
			MPC=${SLES_MPC}
		else
			MPC=${RHEL_MPC}
		fi
		echo -e "Removing installation changes from $MPC...."
		echo -e ""
		grep -v -f $QL_CONF_ENTRIES $MPC > $QL_BACKUP/modprobe
		if [ -f "$QL_BACKUP/modprobe" ]; then
			mv -f $QL_BACKUP/modprobe $MPC
		else
			echo "Unable to update $MPC file"
			return;
		fi
	fi

        # Restore kernel For SuSE
        # Restore initrd
        if [ -f $SLES ]; then
                #From the "INITRD_MODULES" line in the /etc/sysconfig/kernel
                # remove entries present in $QL_BACKUP_KERNEL
		if [ -f "$QL_KERNEL_ENTRIES" ]; then
			INITRD_LINE=`grep "^$SLES_CONF_KEY" $SLES_CONF`

			for MODULES in `cat $QL_KERNEL_ENTRIES`
			do
				INITRD_LINE=`echo $INITRD_LINE | sed "s/$MODULES//"`
			done
			#echo "INITRD_LINE = $INITRD_LINE"
			echo -e "Removing installation changes from $SLES_CONF...."
			echo -e ""
			sed "s/^INITRD_MODULES.*/${INITRD_LINE}/"  $SLES_CONF > /tmp/kernel
			if [ -s /tmp/kernel ]; then
				cp -f /tmp/kernel $SLES_CONF
			fi
		fi
        fi

	#Put back origina here
	restore_mod_conf

	#before creating the ramdisk do depmod
	echo -e "Building module dependency...."
	echo -e "depmod..."
	/sbin/depmod -a
	echo -e ""

	create_ramdisk "" "$QL_NO_BACKUP"
}

# --------------------------------------------------------- #
# edit_sysconfig ()                                         #
# Function to modify list of modules to be included         #
# in the Ram Disk for SuSE Distribution. Edits the          #
# /etc/sysconfig/kernel                                     #
#                                                           #
# Parameter:                                                #
#       $*    Space separated module list                   #
# Returns: None                                             #
# --------------------------------------------------------- #
function edit_sysconfig() {
        MODLIST="$1"
        # check if Module already in the sysconfig/kernel
        grep -w "$MODLIST" $SLES_CONF >& /dev/null
        if [ $? = 0 ]; then
                # MODLIST already there, quit from here
                return 1
        fi
        MODULES=`cat $SLES_CONF | grep "^INITRD_MODULES" |
                        awk 'BEGIN {FS="="} {print $2}'| sed 's/\"//g'`
	# need to be careful on the module sequence, qla2xxx_conf should be first
	# always
        MODULES="$MODULES $MODLIST"
        #echo "New module list: $MODULES"
        sed "s/^INITRD_MODULES.*/INITRD_MODULES=\"$MODULES\"/"  $SLES_CONF>/tmp/kernel
	if [ -s /tmp/kernel ]; then
        	mv -f /tmp/kernel $SLES_CONF
	fi
	if [ -f $QL_KERNEL_ENTRIES ]; then
		grep -w "$MODLIST" $QL_KERNEL_ENTRIES >& /dev/null
		if [ $? = 0 ]; then
			return 0	
		fi
	fi
	echo "$MODLIST" >> $QL_KERNEL_ENTRIES
	return 0
}

#
#	$1	Module list to be added in modprobe
#	$2	Create backup of original ramdisk
#	$3	FORCE_REBUILD:                              #
#		       "YES": Build ramdisk always	    #
#		       "NO": Build ramdisk only if required #
function create_ramdisk() {

	MODULE_LIST=(`echo "$1"`)
	BACKUP_DATE=`date +%m%d%y-%H%M%S`
	SAVING_STR="Saved copy of" 
	BACKUP_FILE=""
	ORIGINAL_FILE=""
	BACKUP_FILE_MOD=""
	ORIGINAL_FILE_MOD=""

	NEED_REBUILD=0
	ret_status=0
	FORCE_REBUILD=$3

	if [ "$FORCE_REBUILD" = "" ]; then
		FORCE_REBUILD="YES"
	fi


	#LSC: Moved the backup logic to top-level qlinstall script
	# Need to backup sysconfig once
	#if [ -f $SLES ] && [ ${#MODULE_LIST[@]} -gt 0 ] && [ $2 != $QL_NO_BACKUP ]; then
	#	#backup_sysconfig $BACKUP_DATE
	#	BACKUP_FILE_K="$QL_BACKUP/$SYS_FILE-$K_VERSION-${BACKUP_DATE}.bak"
	#	ORIGINAL_FILE_K=$SLES_CONF
	#	#echo "$SAVING_STR $SLES_CONF as"
	#	#echo "$QL_BACKUP/$SYS_FILE-$K_VERSION-${1}.bak"
	#	cp -f $SLES_CONF $BACKUP_FILE_K
	#fi	


 	# Backup original modprobe.conf/modprobe.conf.local
	#if [ ${#MODULE_LIST[@]} -gt 0 ] && [ $2 != $QL_NO_BACKUP ]; then
        #	#backup_modprobe $BACKUP_DATE
	#	MPC=""
	#	if [ -f $RHEL ]; then
	#		MPC=$RHEL_MPC
	#	elif [ -f $SLES ]; then
	#		MPC=$SLES_MPC
	#	fi
	#	BACKUP_FILE_MOD=$QL_BACKUP/$RHEL_MODPROBE-$K_VERSION-${BACKUP_DATE}.bak 
	#	ORIGINAL_FILE_MOD=$MPC
	#	if [ -f $MPC ]; then
	#		cp -f $MPC $BACKUP_FILE_MOD
	#	fi
	#fi

        
	if [ ${#MODULE_LIST[@]} -gt 0 ]; then
		add_modprobe_commands

		# Always add qla2xxx_conf  and qla2xxx in modprobe
		edit_modprobe "qla2xxx_conf"
		if [ $? = 0 ] ;then
			NEED_REBUILD=1
		fi

		edit_modprobe "qla2xxx"
		if [ $? = 0 ] ;then
			NEED_REBUILD=1
		fi

		if [ -f $SLES ]; then
			#Append $MODULE modules to the list in sysconfig/kernel.
			edit_sysconfig "qla2xxx_conf"
			if [ $? = 0 ] ;then
				NEED_REBUILD=1
			fi

			edit_sysconfig "qla2xxx"
			if [ $? = 0 ] ;then
				NEED_REBUILD=1
			fi

		fi
	fi

	# mkinitrd
	# Add entry in the /etc/modprobe.conf
	for MODULE in ${MODULE_LIST[@]}
	do
		edit_modprobe "qla$MODULE"
		if [ $? = 0 ] ;then
			NEED_REBUILD=1
		fi

		if [ -f $SLES ]; then
			#Append $MODULE modules to the list in sysconfig/kernel.
			edit_sysconfig "qla$MODULE"
			if [ $? = 0 ] ;then
				NEED_REBUILD=1
			fi
		fi
	done


	# If force rebuild is not yes then build ramdisk
	# only if NEED_REBUILD is set 	
	#if [ "$FORCE_REBUILD" = "NO" ] && [ $NEED_REBUILD = 0 ]; then
	#	#do not rebuild 
	#	#delete any backup created, as it is not required
	#	if [ -f "$BACKUP_FILE_K" ]; then
	#		rm -f $BACKUP_FILE >& /dev/null
	#	fi
	#	if [ -f "$BACKUP_FILE_MOD" ]; then
	#		rm -f $BACKUP_FILE_MOD >& /dev/null
	#	fi
	#	return 1
	#fi

	#if [ -f "$BACKUP_FILE_K" ]; then
	#	# Now give a late message of file saved
        #	echo -e "$SAVING_STR $ORIGINAL_FILE_K as"
        #	echo -e "$BACKUP_FILE_K"
	#	echo -e ""
	#fi
	#if [ -f "$BACKUP_FILE_MOD" ]; then
	#	# Now give a late message of file saved
        #	echo -e "$SAVING_STR $ORIGINAL_FILE_MOD as"
        #	echo -e "$BACKUP_FILE_MOD"
	#	echo -e ""
	#fi

	
	if [ "$2" != "$QL_NO_BACKUP" ]; then
		backup_initrd $BACKUP_DATE
	fi

	echo "${Q_NODE} -- Rebuilding ramdisk image..."
	# Any distribution specific steps
	if test -f "${SLES}" ; then
		/sbin/mk_initrd >& /dev/null
		ret_status=$?
	else
		# Red Hat initrd
		INITRD=initrd-$K_VERSION.img
		if [ -f "$BOOTDIR/$INITRD" ]; then
			/sbin/mkinitrd -f $BOOTDIR/$INITRD $K_VERSION
			ret_status=$?
		else
			/sbin/mkinitrd  $BOOTDIR/$INITRD $K_VERSION
			ret_status=$?
		fi
	fi	
       	return $ret_status
}

# --------------------------------------------------------- #
# remove_module_renames()                                   #
# Removes any aliases to the module renames done in the     #
# mdoule-renames files. This is applicable to SLES 10 only  #
# Since on SLES 10,qla2300, qla2400 etc are renamed to 	    #
# qla2xxx						    #
# Parameter: None 		                            #
# Returns: 0: In success, 1 on failure			    #
# --------------------------------------------------------- #
function remove_module_renames ()
{
        local BACKUP_DATE=`date +%m%d%y-%H%M%S`
        local TMP_RENAMES=/etc/modprobe.d/renames.ql
        local TMP_RESTORE=$QL_RENAMES_BKUP_DIR/renames.restore.ql
        #if this is SuSe and 2.6
        if [ "${K_MAJ_MIN}" = "2.6" ] && [ -f "${SLES}" ]; then
		#create the bakup dir
		mkdir -p $QL_RENAMES_BKUP_DIR >& /dev/null
		if [ $? -ne 0 ]; then
			echo "Warning: Unable to create backup dir for module renames."
			echo "Please update $QL_RENAMES_FILE manually to remove the qla2xxx alias."
			echo "This is required so that correct FW module gets loaded."
			return 1
		fi
                #Take backup of the file once
                if [ -f "${QL_RENAMES_FILE}" ]; then
			echo "${Q_NODE} -- Making changes in $QL_RENAMES_FILE"
                        if [ ! -f $QL_RENAMES_FILE_BKUP ]; then
                                cp -f $QL_RENAMES_FILE $QL_RENAMES_FILE_BKUP
                        fi
                        #also take date-wise backup
                        rm -f ${QL_RENAMES_FILE_DATE}-* >& /dev/null
                        cp -f $QL_RENAMES_FILE ${QL_RENAMES_FILE_DATE}-${BACKUP_DATE}
                        #now remove the alias
                        grep "^alias.*qla2xxx$" $QL_RENAMES_FILE | sed "s/^/#/" > $TMP_RESTORE
                        cat $QL_RENAMES_FILE | sed "s/\(^alias.*qla2xxx$\)/#\1/" > $TMP_RENAMES
                        if [ -s "$TMP_RENAMES" ]; then
                                mv -f $TMP_RENAMES $QL_RENAMES_FILE
                        fi
                fi
        else
		return 1
	fi
	return 0
}

# --------------------------------------------------------- #
# restore_module_renames()                                  #
# Restores the module renames				    #
# Parameter: None 		                            #
# Returns: 0: In success, 1 on failure			    #
# --------------------------------------------------------- #
function restore_module_renames ()
{
        local TMP_RENAMES=/etc/modprobe.d/renames.ql
        local TMP_RESTORE=$QL_RENAMES_BKUP_DIR/renames.restore.ql
        #if this is SuSe and 2.6
        if [ "${K_MAJ_MIN}" = "2.6" ] && [ -f "${SLES}" ]; then
                if [ -f "${TMP_RESTORE}" ]; then
                        #first remove the lines that we commented
                        grep -v -f $TMP_RESTORE $QL_RENAMES_FILE > $TMP_RENAMES
                        if [ -s $TMP_RENAMES ]; then
                                #now add the one tha we commented by un-commenting
                                grep "^#alias.*qla2xxx" $TMP_RESTORE | sed "s/^#//" >> $TMP_RENAMES

                                if [ -s $TMP_RENAMES ]; then
                                        #the actual restore
                                        mv -f $TMP_RENAMES $QL_RENAMES_FILE
                                        #remove backup
                                        rm -f ${QL_RENAMES_FILE_DATE}-* >& /dev/null
                                        rm -f $TMP_RESTORE >& /dev/null
                                fi
                        fi

                fi
        else
		return 1
	fi
	return 1
}


###
#
#
case "$1" in
    help)
	echo "QLogic Corporation -- qla2xxx build script"
	echo "  build.sh <directive>"
	echo ""
	echo "   # cd <driver source>"
	echo "   # ./extras/build.sh"
	echo ""
	echo "    Build the driver sources based on the standard SLES9/RHEL4"
	echo "    build environment."
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
	echo "        3. Adds the appropriate directive in the "
	echo "           modprobe.conf[.local] to remove the qla2xxx_conf "
	echo "           module when the qla2xxx module is unloaded."
	echo "        4. Updates the newly built qla2xxx_conf.ko module with "
	echo "           any previously saved data in /etc/qla2xxx.conf."
	echo ""
	echo "   # ./extras/build.sh remove-renames"
	echo ""
	echo "     Removes the qla2xxx alias from the /etc/modprobe.d/module-renames"
	echo "     on SLES 10. This is required to load the appropriate FW module."
	echo "     For example, if alias qla2xxx is not removed, loading the qla2300"
	echo "     module would load the qla2xxx module. That is on doing"
	echo "     modprobe [qla2300|qla2400|qla2322] would load qla2xxx only."
	echo ""
	echo "   # ./extras/build.sh restore-renames"
	echo ""
	echo "    Restores the qla2xxx alias in /etc/modprobe.d/module-renames on SLES 10"
	echo "    This is required in case the in-built qla2xxx module need to be loaded"
	;;
    install)
	# QLA2XXX Specific
	echo ""
	echo "${Q_NODE} -- Building the qla2xxx driver, please wait..."
	drv_build modules
	echo ""
	drv_install
	;;
    -d | --ramdisk)
	if [ "${RPMVERSION}" = "" ]; then
		echo "This option is available through qlinstall only."
		exit 1
	fi
	create_ramdisk "$2" $3 "$4"
	exit $?
	;;
    restore)
	if [ "${RPMVERSION}" = "" ]; then
		echo "This option is available through qlinstall only."
		exit 1
	fi

	# Restore all the backed up files
	# driver/modprobe/initrd/sysconfig
	restore_original
	;;
    clean)
	echo "${Q_NODE} -- Cleaning driver build directory..."
	drv_build clean
	;;
    new)
	echo "${Q_NODE} -- Clean rebuild of the qla2xxx driver, please wait..."
	drv_build clean
	drv_build modules
	;;
     remove-renames)
		remove_module_renames	
		if [ $? -ne 0 ]; then
			echo "This option is supported on SLES 10 only."
		else
			echo "Remove renames done."
		fi
	;;
     restore-renames)
		restore_module_renames	
		if [ $? -ne 0 ]; then
			echo "This option is supported on SLES 10 only."
		else
			echo "Restore renames done."
		fi
	;;
    *)
	echo "${Q_NODE} -- Building the qla2xxx driver, please wait..."
	drv_build modules
	;;
esac
