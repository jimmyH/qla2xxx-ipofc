#!/bin/bash

VERSION=3.3
MODULE=qla2xxx
MSSPARAM=ql2xsmartsan
MFEPARAM=ql2xfdmienable

SYSFS_MODULE=/sys/module/${MODULE}
SYSFS_DRVRVERS=${SYSFS_MODULE}/version
SYSFS_SSENABLE=${SYSFS_MODULE}/parameters/${MSSPARAM}

STATE=1
NOMAKE=

MODPROBE_DIR=/etc/modprobe.d
CONF=${MODPROBE_DIR}/${MODULE}.conf
TEMP=${MODPROBE_DIR}/temp.conf

EXIT=

verify_driver_loaded() {
	if [ ! -d ${SYSFS_MODULE} ]; then
		echo "${MODULE} not loaded"
		if [ $1 ]; then
			exit 1
		fi
		return 1
	fi
	return 0
}

verify_parameter_exists() {
	if [ ! -f ${SYSFS_SSENABLE} ]; then
		echo "${MSSPARAM} not supported by this ${MODULE}"
		if [ $1 ]; then
			exit 1
		fi
		return 1
	fi
	return 0
}

show_help() {
	cat <<-END
	$0: ${MODULE} ${MSSPARAM} enabler

	USAGE: $0 [PARAMETERS...] | [OPTIONS...]

	PARAMETERS:
		1|on		enable ${MSSPARAM} in ${CONF} (default)
		0|off		disable ${MSSPARAM} in ${CONF}
		nomake		do not build initrd image

	OPTIONS (if present will override PARAMETERS):
		help		show help text for this script
		this		show version of this script
		conf		show ${CONF}
		state		show ${MSSPARAM} of loaded ${MODULE}
		driver		show version of loaded ${MODULE}
		modinfo		show modinfo for ${MODULE}

	NOTES:
		Any previous contents of ${CONF} are preserved.
		If ${CONF} was non-existent, it is now created.
		If it was previously empty, it is now filled in.
		If it contained no options line, an options line is now added.
		If ${MSSPARAM} had no instances, a single instance of it is now added.
		If ${MSSPARAM} had multiple instances, they are now reduced to a single instance.
		The instance of ${MSSPARAM} will now assigned the value specified.
	END
	exit 0
}

show_conf() {
	verify_driver_loaded && verify_parameter_exists
	echo ${CONF}:
	cat ${CONF} 2>/dev/null
	EXIT=0
}

show_state() {
	verify_driver_loaded exit
	verify_parameter_exists exit
	path=${SYSFS_SSENABLE}
	echo -n $path:" "
	cat $path 2>/dev/null
	EXIT=0
}

show_driver() {
	verify_driver_loaded exit
	verify_parameter_exists
	path=${SYSFS_DRVRVERS}
	echo -n $path:" "
	cat $path 2>/dev/null
	EXIT=0
}

show_modinfo() {
	verify_driver_loaded exit
	modinfo ${MODULE} 2>/dev/null
	exit 0
}

show_version() {
	echo $0: version ${VERSION}
	EXIT=0
}

say_what() {
	echo What? $@
	EXIT=0
}

for x in $@ ; do
	case $x in
		help    ) show_help ;;
		this    ) show_version ;;
		conf    ) show_conf ;;
		state   ) show_state ;;
		driver  ) show_driver ;;
		modinfo ) show_modinfo ;;
		nomake  ) NOMAKE=$x ;;
		1|on    ) STATE=1 ;;
		0|off   ) STATE=0 ;;
		*       ) say_what $x ;;
	esac
done

if [ $EXIT ]; then exit $EXIT; fi

parse() {
	awk -f <(cat - <<-AWK
		NF < 3 { next }

		/options/ {
			del = 0
			for (i = 3; i <= NF; i++) {
				if (\$i ~ "^${MSSPARAM}") {
					\$i = ""
					del++
				} else if (\$i ~ "^${MFEPARAM}") {
					fdmi = \$i
					\$i = ""
					del++
				}
			}
			if (NF - del < 3)
				next
		}

		{ print }

		END {
			if (fdmi) {
				if (state)
					fdmi = "${MFEPARAM}=1"
				print "options qla2xxx " fdmi
			}
			print "options qla2xxx ${MSSPARAM}=" state
		}
	AWK
	) $@
}

build_ramdisk() {
	UNAME=$(uname -a)
	K_VERSION=$(uname -r)
	K_LIBS=/lib/modules/${K_VERSION}

	BOOTDIR="/boot"

	SLES=/etc/SuSE-release
	RHEL=/etc/redhat-release

	K_INSTALL_DIR=${K_LIBS}/extra/qlgc-qla2xxx/
	if test -f "${SLES}" ; then
		K_INSTALL_DIR=${K_LIBS}/updates/
	fi

	echo "${MODULE} rebuilding INITRD image..."
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

if [ ! -f ${CONF} ] ; then
	touch ${CONF}
fi
if [ ${STATE} -gt 1 ] ; then
	STATE=1
fi

parse -v state=${STATE} ${CONF} > ${TEMP}
mv -f ${TEMP} ${CONF}
echo "${CONF}:"
cat ${CONF}

if [ -z ${NOMAKE} ] ; then
	build_ramdisk
	exit 2
else
	echo "${MODULE} NOT rebuilding INITRD image."
	exit 3
fi
