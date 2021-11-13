#!/bin/bash


set -euo pipefail
set -x


## Usage: <script_filename> [initial|postreboot|remoteaccess]


## Variables:
## See '.variables.template' for configuration options before running script


## Script to be run in multiple parts
## SETUP : Required: Copy '.variables.template' and save as '.variables' in the same folder as the script
## SETUP : Required: Modify '.variables' to suit your needs
## Part 1: Required: Run with "initial" option from Ubuntu 20.04+ live iso (desktop version). Reboot when completed.
## Part 2: Required: Run with "postreboot" option after first boot into new install (login as root. p/w as set in variables file).
## Part 3: Optional: Run with "remoteaccess" to enable SSH access to unlock server remotely.


## Remote access can be installed by either:
## Setting the remoteaccess variable to "yes" in the variables section below,
## or running the script with the "remoteaccess" option after part 1 and part 2 are run.
## It's better to leave the remoteaccess variable below as "no" and run the script with the "remoteaccess" option
## as that will use the user's authorized_keys file. Setting the remoteaccess variable to "yes" will use root's authorized_keys.
## The user's authorized_keys file will not be available until the user account is created in part 2 of the script.
## So remote login using root's authorized_keys file is the only option during the 1st reboot.

## Connect as "root" on port 222 to the server's ip.
## Login as "root" during remote access, even if using a user's authorized_keys file. No other users are available in the initramfs environment.


## If running in a Virtualbox virtualmachine, setup tips below:
## 1.  Enable EFI
## 2.  Set networking to bridged mode so VM gets its own IP. Fewer problems with ubuntu keyserver.
## 3.  Minimum drive size of 5GB

## If running in VMware virtualmachine, setup tips below:
## 1.  Enable EFI
## 2.  Edit '*.vmx' to include: disk.EnableUUID = "TRUE"
## 2a. Can be modified in vSphere configuration


## Rescuing using a Live CD
## Export all pools
#  zpool export -a
## "rpool" should be the root pool name
#  zpool import -N -R /mnt rpool
## -r Recursively loads the keys
## -L is for a keylocation or to "prompt" user for an input
## -a Loads the keys for all encryption roots in all imported pools
#  zfs load-key -r -L prompt -a
## Mount all datasets
#  zfs mount -a


## Check for root priviliges
if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root."
	exit 1
fi

## Check for EFI boot environment
if [ -d /sys/firmware/efi ]; then
	echo "Boot environment check passed. Found EFI boot environment."
else
	echo "Boot environment check failed. EFI boot environment not found. Script requires EFI."
	exit 1
fi


## Functions
loadVariables(){

	## Copy .variables.template and save as .variables with your own info for setup
	SCRIPT=$(readlink -f "$0")
	SCRIPTPATH=`dirname ${SCRIPT}`
	if [ -f "${SCRIPTPATH}/.variables" ]; then
		trap 'printf "%s\n%s" "Unable to load '.variables' file." "Check formatting and run the script again."' ERR
		source "${SCRIPTPATH}/.variables"
		trap - ERR
	else
		echo "See script header for instructions. '.variables' file not found. Exiting."
		exit 1
	fi

	if [ -z "${install_log}" ]; then
		echo "Failed to load variables. Exiting."
		exit1
	fi

}


logFunc(){

	## Log everything we do
	exec > >(tee -a "${log_loc}"/"${install_log}") 2>&1

}


disclaimer(){

	echo "*****		WARNING     *****************************************************************************************"
	echo "*****		This script could wipe out all your data, or worse! I am not responsible for your decisions."
	echo "*****		Carefully enter the ID of the disk YOU WANT TO DESTROY to ensure no data is accidentally lost."
	echo "*****		Press Enter to Continue or CTRL+C to abort."
	read -r _

}


identify_ubuntu_dataset_uuid(){

	rootzfs_full_name=0
	rootzfs_full_name="$(zfs list -o name | awk '/ROOT\/ubuntu/{print $1;exit}'|sed -e 's,^.*/,,')"

}


ipv6_apt_live_iso_fix(){

	## Try diabling ipv6 in the live iso if setting the preference to ipv4 doesn't work \
	## to resolve slow apt-get and slow debootstrap in the live Ubuntu iso.
	## https://askubuntu.com/questions/620317/apt-get-update-stuck-connecting-to-security-ubuntu-com

	prefer_ipv4(){
		sed -i 's,#precedence ::ffff:0:0/96  100,precedence ::ffff:0:0/96  100,' /etc/gai.conf
	}

	dis_ipv6(){
		cat >> /etc/sysctl.conf <<-EOF
			net.ipv6.conf.all.disable_ipv6 = 1
			#net.ipv6.conf.default.disable_ipv6 = 1
			#net.ipv6.conf.lo.disable_ipv6 = 1
		EOF
		tail -n 3 /etc/sysctl.conf
		sudo sysctl -p /etc/sysctl.conf
		sudo netplan apply
	}

	prefer_ipv4
	#dis_ipv6

}


debootstrap_part1_Func(){

	## use closest mirrors
	## disable cdrom - remote/headless deploy may be over ipmi
	cp /etc/apt/sources.list /etc/apt/sources.list.bak
	sed -i \
		-e 's,deb cdrom,#deb cdrom,' \
		-e 's/http:\/\/archive/mirror:\/\/mirrors/' \
		-e 's/http:\/\/security/mirror:\/\/mirrors/' \
		-e 's/\/ubuntu\//\/mirrors.txt/' \
		-e '/mirrors/ s,main restricted,main restricted universe multiverse,' \
		/etc/apt/sources.list
	cat /etc/apt/sources.list

<< 'DISABLED_OVERRIDESOURCE'
	overrideSource(){
		cat <<-EOF > /etc/apt/sources.list
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version} main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version} main universe restricted multiverse
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version}-updates main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version}-updates main universe restricted multiverse
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version}-backports main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version}-backports main universe restricted multiverse
			deb http://security.ubuntu.com/ubuntu ${ubuntu_version}-security main universe restricted multiverse
			#deb-src http://security.ubuntu.com/ubuntu ${ubuntu_version}-security main universe restricted multiverse
		EOF
	}
	overrideSource
DISABLED_OVERRIDESOURCE

	trap 'printf "%s\n%s" "The script has experienced an error during the first apt update." "Try running the script again."' ERR
	apt-get --yes --quiet update
	trap - ERR

<< 'DISABLED_SSHSETUP'
	ssh_Func(){
		## Setup SSH to allow remote access in live environment
		apt-get install --yes openssh-server
		service sshd start
		ip addr show scope global | grep inet
	}
	ssh_Func
DISABLED_SSHSETUP

	if [ "${use_zfs_ppa}" = "yes" ]; then
		apt-get --yes --quiet install software-properties-common
		add-apt-repository --yes --update ppa:jonathonf/zfs

		## Install PPA version before we get started
		DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet install gdisk debootstrap zfs-initramfs zfsutils-linux zfs-zed
	else
		DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet install gdisk debootstrap zfs-initramfs software-properties-common
	fi

	if service --status-all | grep -Fq 'zfs-zed'; then
		systemctl stop zfs-zed
	fi

}


getdiskID1(){

	## Get root Disk UUID
	ls -la /dev/disk/by-id
	echo "Enter Disk ID (must match exactly):"
	read -r DISKID1

	## error check
	errchk="$(find /dev/disk/by-id -maxdepth 1 -mindepth 1 -name "${DISKID1}")"
	if [ -z "${errchk}" ]; then
		echo "Disk ID not found. Exiting."
		exit 1
	fi

	echo "Disk ID set to ""${DISKID1}"""

}


getdiskID2(){

	## Get root Disk UUID
	ls -la /dev/disk/by-id
	echo "Enter Disk ID (must match exactly):"
	read -r DISKID2

	## error check
	errchk="$(find /dev/disk/by-id -maxdepth 1 -mindepth 1 -name "${DISKID2}")"
	if [ -z "${errchk}" ]; then
		echo "Disk ID not found. Exiting."
		exit 1
	fi
	if [ "${DISKID1}" = "${DISKID2}" ]; then
		echo "Cannot use the same disk twice. Exiting."
		exit 1
	fi

	echo "Disk ID set to ""${DISKID2}"""

}


debootstrap_createzfspools_Func(){

	partitionsFunc(){

		## Clear partition tables
		sgdisk     --zap-all /dev/disk/by-id/"${DISKID1}"
		[ "${rpool_vdev_layout}" = "mirror" ] && \
			sgdisk --zap-all /dev/disk/by-id/"${DISKID2}"
		sleep 2

		## gdisk hex codes:
		## EF02 BIOS boot partitions
		## EF00 EFI system
		## BE00 Solaris boot
		## BF00 Solaris root
		## BF01 Solaris /usr & Mac Z
		## 8200 Linux swap
		## 8300 Linux file system

		## Create bootloader partition
		sgdisk     -n1:1M:+"${EFI_boot_size}"M -t1:EF00 /dev/disk/by-id/"${DISKID1}"
		[ "${rpool_vdev_layout}" = "mirror" ] && \
			sgdisk -n1:1M:+"${EFI_boot_size}"M -t1:EF00 /dev/disk/by-id/"${DISKID2}"

		## Create swap partition
		## bug with swap on zfs zvol so use swap on partition:
		## https://github.com/zfsonlinux/zfs/issues/7734
		sgdisk     -n2:0:+"${swap_size}"M -t2:8200 /dev/disk/by-id/"${DISKID1}"
		[ "${rpool_vdev_layout}" = "mirror" ] && \
			sgdisk -n2:0:+"${swap_size}"M -t2:8200 /dev/disk/by-id/"${DISKID2}"

		## Create root pool partition
		sgdisk     -n3:0:0      -t3:BF00 /dev/disk/by-id/"${DISKID1}"
		[ "${rpool_vdev_layout}" = "mirror" ] && \
			sgdisk -n3:0:0      -t3:BF00 /dev/disk/by-id/"${DISKID2}"
		sleep 2
	}

	zpool_encrypted_mirror_Func(){

		zpool create -f \
			-o ashift="${zfs_rpool_ashift}" \
			-o autotrim=on \
			-O acltype=posixacl \
			-O canmount=off \
			-O compression="${zfs_compression}" \
			-O dnodesize=auto \
			-O normalization=formD \
			-O relatime=on \
			-O xattr=sa \
			-O encryption=aes-256-gcm \
			-O keylocation=prompt \
			-O keyformat=passphrase \
			-O mountpoint=/ \
			-R "${mountpoint}" \
			"${RPOOL}" mirror \
			/dev/disk/by-id/"${DISKID1}"-part3 \
			/dev/disk/by-id/"${DISKID2}"-part3

	}

	zpool_encrypted_single_Func(){

		zpool create -f \
			-o ashift="${zfs_rpool_ashift}" \
			-o autotrim=on \
			-O acltype=posixacl \
			-O canmount=off \
			-O compression="${zfs_compression}" \
			-O dnodesize=auto \
			-O normalization=formD \
			-O relatime=on \
			-O xattr=sa \
			-O encryption=aes-256-gcm \
			-O keylocation=prompt \
			-O keyformat=passphrase \
			-O mountpoint=/ \
			-R "${mountpoint}" \
			"${RPOOL}" /dev/disk/by-id/"${DISKID1}"-part3

	}

	mountpointsFunc(){

		## zfsbootmenu setup for no separate boot pool
		## https://github.com/zbm-dev/zfsbootmenu/wiki/Debian-Buster-installation-with-ESP-on-the-zpool-disk

		sleep 2
		## Create filesystem datasets to act as containers
		zfs create -o canmount=off -o mountpoint=none "${RPOOL}"/ROOT

		## Create root filesystem dataset
		rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
		zfs create -o canmount=noauto -o mountpoint=/ "${RPOOL}"/ROOT/"${rootzfs_full_name}"

		## zfsbootmenu debian guide
		## assigns canmount=noauto on any file systems with mountpoint=/ (that is, on any additional boot environments you create).
		## With ZFS, it is not normally necessary to use a mount command (either mount or zfs mount).
		## This situation is an exception because of canmount=noauto.
		zfs mount "${RPOOL}"/ROOT/"${rootzfs_full_name}"
		zpool set bootfs="${RPOOL}"/ROOT/"${rootzfs_full_name}" "${RPOOL}"

		## Create datasets
		## Aim is to separate OS from user data.
		## Allows root filesystem to be rolled back without rolling back user data such as logs.
		## https://didrocks.fr/2020/06/16/zfs-focus-on-ubuntu-20.04-lts-zsys-dataset-layout/
		## https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/Debian%20Buster%20Root%20on%20ZFS.html#step-3-system-installation
		## "-o canmount=off" is for a system directory that should rollback with the rest of the system.

		zfs create									"${RPOOL}"/opt
		zfs create									"${RPOOL}"/srv						## server webserver content
		zfs create -o canmount=off					"${RPOOL}"/usr
		zfs create									"${RPOOL}"/usr/local				## locally compiled software
		zfs create -o canmount=off					"${RPOOL}"/var
		zfs create -o canmount=off					"${RPOOL}"/var/lib
		#zfs create									"${RPOOL}"/var/lib/AccountsService	## If this system will use GNOME desktop
		#zfs create									"${RPOOL}"/var/games				## game files
		zfs create									"${RPOOL}"/var/log					## log files
		zfs create									"${RPOOL}"/var/mail					## local mails
		#zfs create									"${RPOOL}"/var/snap					## snaps handle revisions themselves
		zfs create									"${RPOOL}"/var/spool				## printing tasks
		zfs create									"${RPOOL}"/var/www					## server webserver content

		## USERDATA datasets
		zfs create -o canmount=off -o mountpoint=/	"${RPOOL}"/USERDATA
		zfs create -o mountpoint=/root 				"${RPOOL}"/USERDATA/root
		chmod 700 "${mountpoint}"/root

		## optional - exclude from snapshots
		zfs create -o com.sun:auto-snapshot=false	"${RPOOL}"/var/cache
		zfs create -o com.sun:auto-snapshot=false	"${RPOOL}"/var/tmp
		chmod 1777 "${mountpoint}"/var/tmp
		zfs create -o com.sun:auto-snapshot=false	"${RPOOL}"/var/lib/docker				##Docker manages its own datasets & snapshots

		## Mount a tempfs at /run
		mkdir "${mountpoint}"/run
		mount -t tmpfs tmpfs "${mountpoint}"/run

	}

	## Run disk operations
	## Partition disk(s)
	partitionsFunc

	## Create root pool
	if [ "${rpool_vdev_layout}" = "mirror" ]; then
		echo -e "${zfspassword}" | zpool_encrypted_mirror_Func
	elif [ "${rpool_vdev_layout}" = "single" ]; then
		echo -e "${zfspassword}" | zpool_encrypted_single_Func
	else
		echo "Unsupported layout provided. Exiting."
		exit 1
	fi

	## Create system mount points on root pool
	mountpointsFunc

}


debootstrap_installminsys_Func(){

	## Install minimum system
	## drive size check
	FREE="$(df -k --output=avail "${mountpoint}" | tail -n1)"
	## 15G = 15728640 = 15*1024*1024k
	if [ "${FREE}" -lt 5242880 ]; then
		 echo "Less than 5 GBs free!"
		 exit 1
	fi

	debootstrap "${ubuntu_version}" "${mountpoint}"

}


remote_zbm_access_Func(){

<< 'DISABLED_GETNETMASK'
	if [ "${network_static}" = "yes" ]; then
		# Calculate netmask from CIDR
		subnet_bits=${ipv4_cidr##*/}
		value=$(( 0xffffffff ^ ((1 << (32 - ${subnet_bits})) - 1) ))
		ipv4_netmask=$(echo "$(( (value >> 24) & 0xff )).$(( (value >> 16) & 0xff )).$(( (value >> 8) & 0xff )).$(( value & 0xff ))")
		echo "Provided IP CIDR:		$ipv4_cidr"
		echo "Detected subnet mask:	$ipv4_netmask"
	fi
DISABLED_GETNETMASK

	## Get ethernet interface/mac address
	if [ "${network_static}" = "yes" ]; then
		ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"
		ethernetmac=$(cat /sys/class/net/"${ethernetinterface}"/address)
	fi

	modulesetup="/usr/lib/dracut/modules.d/60crypt-ssh/module-setup.sh"
	cat <<-EOH >/tmp/remote_zbm_access.sh
		#!/bin/sh

		## https://github.com/zbm-dev/zfsbootmenu/wiki/Remote-Access-to-ZBM
		apt-get --yes --quiet install dracut-network dropbear

		git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
		mkdir /usr/lib/dracut/modules.d/60crypt-ssh
		cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
		rm /usr/lib/dracut/modules.d/60crypt-ssh/Makefile

		## Comment out references to /helper/ folder from module-setup.sh
		sed -i 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' "${modulesetup}"
		sed -i 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' "${modulesetup}"
		sed -i 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' "${modulesetup}"
		sed -i 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' "${modulesetup}"

		## fix dropbearconvert path on ubuntu 20.04 (focal)
		[ "${ubuntu_version}" = "focal" ] && \
			ln -s /usr/lib/dropbear/dropbearconvert /usr/sbin/dropbearconvert

		## Create host keys
		mkdir -p /etc/dropbear
		ssh-keygen -t rsa -m PEM -f /etc/dropbear/ssh_host_rsa_key -N ""
		ssh-keygen -t ecdsa -m PEM -f /etc/dropbear/ssh_host_ecdsa_key -N ""
		[ "${ubuntu_version}" = "focal" ] || \
			ssh-keygen -t ed25519 -m PEM -f /etc/dropbear/ssh_host_ed25519_key -N ""

		mkdir -p /etc/cmdline.d
		## Added timeouts to wait for network link to fix "no carrier" errors on some systems
		## Create bootnet interface to configure the correct nic in multi-nic environments
		if [ "${network_static}" = "yes" ]; then
			echo "ifname=bootnet:${ethernetmac} ip=${ipv4_cidr%%/*}::${ipv4_gateway}:${ipv4_cidr##*/}:${new_hostname}:bootnet:none nameserver=${ipv4_dns1} nameserver=${ipv4_dns2} rd.neednet=1 rd.net.timeout.ifup=60 rd.net.timeout.carrier=60" \
				> /etc/cmdline.d/dracut-network.conf
		else
			echo "ifname=bootnet:${ethernetmac} ip=bootnet:dhcp rd.neednet=1 rd.net.timeout.ifup=60 rd.net.timeout.carrier=60" \
				> /etc/cmdline.d/dracut-network.conf
		fi

		## Create zfsbootmenu starter script
		cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/zbm
			#!/bin/sh
			rm /zfsbootmenu/active
			zfsbootmenu
		EOF
		chmod 755 /etc/zfsbootmenu/dracut.conf.d/zbm

		## Add remote session welcome message
		cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/banner.txt
			Welcome to the ZFSBootMenu initramfs shell. Enter "zbm" to start ZFSBootMenu.
		EOF
		chmod 755 /etc/zfsbootmenu/dracut.conf.d/banner.txt
		sed -i 's,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid -b /etc/banner.txt,' /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh

		## Copy files into initramfs
		sed -i '$ s,^},,' "${modulesetup}"
		echo "  ## Copy ZFSBootMenu start helper script" | tee -a "${modulesetup}"
		echo "  inst /etc/zfsbootmenu/dracut.conf.d/zbm /usr/bin/zbm" | tee -a "${modulesetup}"
		echo "" | tee -a "${modulesetup}"
		echo "  ## Copy dropbear welcome message" | tee -a "${modulesetup}"
		echo "  inst /etc/zfsbootmenu/dracut.conf.d/banner.txt /etc/banner.txt" | tee -a "${modulesetup}"
		echo "}" | tee -a "${modulesetup}"

		## ubuntu 20.04 dropbear does not support ed25519
		## fixed, new variable - https://github.com/dracut-crypt-ssh/dracut-crypt-ssh/commit/6ae8c358d24989ac7c6e625609bd1af4cf8ce1de
		if [ "${ubuntu_version}" = "focal" ]; then
			cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/dropbear.conf
				## Enable dropbear ssh server and pull in network configuration args
				## The default configuration will start dropbear on TCP port 222.
				## This can be overridden with the dropbear_port configuration option.
				## You do not want the server listening on the default port 22.
				## Clients that expect to find your normal host keys when connecting to an SSH server on port 22 will
				## refuse to connect when they find different keys provided by dropbear.
				add_dracutmodules+=" crypt-ssh "
				install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
				## Copy system keys for consistent access
				dropbear_keytypes="rsa ecdsa"
				dropbear_rsa_key=/etc/dropbear/ssh_host_rsa_key
				dropbear_ecdsa_key=/etc/dropbear/ssh_host_ecdsa_key
				## Access by authorized keys only. No password.
				## By default, the list of authorized keys is taken from /root/.ssh/authorized_keys on the host.
				## Remember to "generate-zbm" after adding the remote user key to the authorized_keys file.
				## The last line is optional and assumes the specified user provides an authorized_keys file
				## that will determine remote access to the ZFSBootMenu image.
				## Note that login to dropbear is "root" regardless of which authorized_keys is used.
				#dropbear_acl=/home/${username}/.ssh/authorized_keys
			EOF
		else
			cat <<-EOF >/etc/zfsbootmenu/dracut.conf.d/dropbear.conf
				## Enable dropbear ssh server and pull in network configuration args
				## The default configuration will start dropbear on TCP port 222.
				## This can be overridden with the dropbear_port configuration option.
				## You do not want the server listening on the default port 22.
				## Clients that expect to find your normal host keys when connecting to an SSH server on port 22 will
				## refuse to connect when they find different keys provided by dropbear.
				add_dracutmodules+=" crypt-ssh "
				install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
				## Copy system keys for consistent access
				dropbear_rsa_key=/etc/dropbear/ssh_host_rsa_key
				dropbear_ecdsa_key=/etc/dropbear/ssh_host_ecdsa_key
				dropbear_ed25519_key=/etc/dropbear/ssh_host_ed25519_key
				## Access by authorized keys only. No password.
				## By default, the list of authorized keys is taken from /root/.ssh/authorized_keys on the host.
				## Remember to "generate-zbm" after adding the remote user key to the authorized_keys file.
				## The last line is optional and assumes the specified user provides an authorized_keys file
				## that will determine remote access to the ZFSBootMenu image.
				## Note that login to dropbear is "root" regardless of which authorized_keys is used.
				#dropbear_acl=/home/${username}/.ssh/authorized_keys
			EOF
		fi

		## Reduce timer on initial rEFInd screen
		sed -i 's,timeout 20,timeout $timeout_rEFInd,' /boot/efi/EFI/refind/refind.conf

		## Increase ZFSBootMenu timer to allow for remote connection
		sed -i 's,zbm.timeout=${timeout_zbm_no_remote_access},zbm.timeout=${timeout_zbm_remote_access},' /boot/efi/EFI/ubuntu/refind_linux.conf

		## Disable dropbear on system
		systemctl disable dropbear
		systemctl stop dropbear

		[ "${run_mode}" = "initial" ] && \
			generate-zbm --debug

		echo "Dropbear installed."
	EOH

	case "$1" in
	chroot)
		cp /tmp/remote_zbm_access.sh "${mountpoint}"/tmp
		chroot "${mountpoint}" /bin/bash -x /tmp/remote_zbm_access.sh
	;;
	base)
		/bin/bash /tmp/remote_zbm_access.sh
	;;
	*)
		exit 1
	;;
	esac

}


systemsetupFunc_part1(){

	## System configuration
	## Configure hostname
	echo "${new_hostname}" > "${mountpoint}"/etc/hostname
	echo 127.0.1.1       "${new_hostname}" >> "${mountpoint}"/etc/hosts

	## Configure network interface
	ethernetinterface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ethprefix}*")")"

	configureStatic(){

		cat > "${mountpoint}"/etc/netplan/01-"${ethernetinterface}".yaml <<-EOF
			network:
			  version: 2
			  ethernets:
			    ${ethernetinterface}:
			      dhcp4: false
			      dhcp-identifier: mac
			      addresses:
			        - $ipv4_cidr
			      gateway4: $ipv4_gateway
			      nameservers:
			        search:
			          - local
			        addresses:
			          - $ipv4_dns1
			          - $ipv4_dns2
		EOF

	}

	configureDHCP(){

		cat > "${mountpoint}"/etc/netplan/01-"${ethernetinterface}".yaml <<-EOF
			network:
			  version: 2
			  ethernets:
			    ${ethernetinterface}:
			      dhcp4: true
			      dhcp-identifier: mac
		EOF

	}

	if [ "${network_static}" = "yes" ]; then
		configureStatic
	else	## Otherwise assume DHCP
		configureDHCP
	fi

	## Bind virtual filesystems from LiveCD to new system
	mount --rbind /dev  "${mountpoint}"/dev
	mount --rbind /proc "${mountpoint}"/proc
	mount --rbind /sys  "${mountpoint}"/sys

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Configure package sources
		cp /etc/apt/sources.list /etc/apt/sources.bak
		cat > /etc/apt/sources.list <<-EOLIST
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version} main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version} main universe restricted multiverse
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version}-updates main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version}-updates main universe restricted multiverse
			deb http://archive.ubuntu.com/ubuntu ${ubuntu_version}-backports main universe restricted multiverse
			#deb-src http://archive.ubuntu.com/ubuntu ${ubuntu_version}-backports main universe restricted multiverse
			deb http://security.ubuntu.com/ubuntu ${ubuntu_version}-security main universe restricted multiverse
			#deb-src http://security.ubuntu.com/ubuntu ${ubuntu_version}-security main universe restricted multiverse
		EOLIST

		## Set locale
		locale-gen en_US.UTF-8 $locale
		echo 'LANG="$locale"' > /etc/default/locale

		## Set timezone
		ln -fs /usr/share/zoneinfo/"$timezone" /etc/localtime
		dpkg-reconfigure -f noninteractive tzdata
	EOCHROOT

}


systemsetupFunc_part2(){

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Install zfs
		apt-get --yes --quiet update

		## Install Kernel
		## Need to use '--no-install-recommends' otherwise grub gets installed
		if [ "${ubuntu_version}" = "focal" ]; then
			## Install HWE Kernel for LTS
			apt-get --yes --quiet install --no-install-recommends linux-headers-generic-hwe-20.04 linux-generic-hwe-20.04 thermald
		else
			apt-get --yes --quiet install --no-install-recommends linux-headers-generic linux-image-generic
		fi

		apt-get --yes --quiet install --no-install-recommends dkms wget nano vim
		apt-get --yes --quiet install software-properties-common

		## Setup ZFS PPA
		if [ "${use_zfs_ppa}" = "yes" ]; then
			add-apt-repository --yes --update ppa:jonathonf/zfs
		fi

		DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet install zfs-dkms
		apt-get --yes --quiet install zfsutils-linux zfs-zed zfs-initramfs
	EOCHROOT

}


systemsetupFunc_part3(){

	identify_ubuntu_dataset_uuid

	mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/"${DISKID1}"-part1
	[ "${rpool_vdev_layout}" = "mirror" ] && \
		mkdosfs -F 32 -s 1 -n EFI /dev/disk/by-id/"${DISKID2}"-part1

	sleep 2

	blkid_part1=""
	blkid_part1="$(blkid -s UUID -o value /dev/disk/by-id/"${DISKID1}"-part1)"
	echo "${blkid_part1}"

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Create the EFI filesystem

		## Create FAT32 filesystem in EFI partition
		apt-get --yes --quiet install dosfstools
		mkdir -p /boot/efi

		## fstab entries
		echo /dev/disk/by-uuid/"${blkid_part1}" /boot/efi vfat defaults 0 0 >> /etc/fstab

		## Mount from fstab entry
		mount /boot/efi
		## If mount fails error code is 0. Script won't fail. Need the following check.
		## Could use "mountpoint" command but not all distros have it.
		if ! grep /boot/efi /proc/mounts > /dev/null 2>&1; then
			echo "/boot/efi not mounted."
			exit 1
		fi
	EOCHROOT

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet install refind kexec-tools
		apt-get --yes --quiet install dpkg-dev git systemd-sysv

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec

		## dracut-core components for ZBM initramfs
		apt-get --yes --quiet install dracut-core
	EOCHROOT

}


systemsetupFunc_part4(){

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		zfsbootmenuinstall(){

			## Convert rpool to use keyfile
			## This file will live inside your initramfs stored ON the ZFS boot environment.
			echo ${zfspassword} > /etc/zfs/${RPOOL}.key
			chmod 600 /etc/zfs/${RPOOL}.key
			zfs change-key -o keylocation=file:///etc/zfs/${RPOOL}.key -o keyformat=passphrase ${RPOOL}

			if [ "${quiet_boot}" = "yes" ]; then
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro quiet" "${RPOOL}"/ROOT
			else
				zfs set org.zfsbootmenu:commandline="spl_hostid=\$( hostid ) ro" "${RPOOL}"/ROOT
			fi

			## Install ZFSBootMenu
			compile_zbm_git(){
				apt-get --yes --quiet install git make
				cd /tmp
				git clone 'https://github.com/zbm-dev/zfsbootmenu.git'
				cd zfsbootmenu
				make install
			}
			compile_zbm_git

			## Configure ZFSBootMenu
			config_zbm(){
				cat <<-EOF > /etc/zfsbootmenu/config.yaml
					Global:
					  ManageImages: true
					  BootMountPoint: /boot/efi
					  DracutConfDir: /etc/zfsbootmenu/dracut.conf.d
					Components:
					  ImageDir: /boot/efi/EFI/ubuntu
					  Versions: 3
					  Enabled: true
					  syslinux:
					    Config: /boot/syslinux/syslinux.cfg
					    Enabled: false
					EFI:
					  ImageDir: /boot/efi/EFI/ubuntu
					  Versions: false
					  Enabled: false
					Kernel:
					  CommandLine: ro quiet loglevel=0
				EOF

				[ "${quiet_boot}" = "no" ] && \
					sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml

				## Omit systemd dracut modules to prevent ZBM boot breaking
				cat <<-EOF >> /etc/zfsbootmenu/dracut.conf.d/zfsbootmenu.conf
					omit_dracutmodules+=" systemd systemd-initrd dracut-systemd "
				EOF

				## Install ZFSBootMenu dependencies
				apt-get --yes --quiet install libconfig-inifiles-perl libsort-versions-perl libboolean-perl fzf mbuffer
				cpan 'YAML::PP'

				update-initramfs -k all -c

				## Generate ZFSBootMenu
				generate-zbm --debug

				## Create refind_linux.conf
				## zfsbootmenu command-line parameters:
				## https://github.com/zbm-dev/zfsbootmenu/blob/master/pod/zfsbootmenu.7.pod
				cat <<-EOF > /boot/efi/EFI/ubuntu/refind_linux.conf
					"Boot default"  "zfsbootmenu:POOL=${RPOOL} zbm.import_policy=hostid zbm.set_hostid zbm.timeout=${timeout_zbm_no_remote_access} ro quiet loglevel=0"
					"Boot to menu"  "zfsbootmenu:POOL=${RPOOL} zbm.import_policy=hostid zbm.set_hostid zbm.show ro quiet loglevel=0"
				EOF

				[ "${quiet_boot}" = "no" ] && \
					sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf

			}
			config_zbm
		}
		zfsbootmenuinstall
	EOCHROOT

	if [ "${remoteaccess}" = "yes" ]; then
		remote_zbm_access_Func "chroot"
	else
		true
	fi

}


systemsetupFunc_part5(){

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Set root password
		echo -e "root:${root_password}" | chpasswd

		## Configure swap
		if [ "${rpool_vdev_layout}" = "mirror" ]; then
			apt-get --yes --quiet install cryptsetup mdadm

			mdadm --create /dev/md0 \
				--metadata=1.2 \
				--level=mirror --raid-devices=2 \
				/dev/disk/by-id/"${DISKID1}"-part2 \
				/dev/disk/by-id/"${DISKID2}"-part2 <<-EOF
					yes
				EOF

			## "plain" required in crypttab to avoid message at boot: "From cryptsetup: couldn't determine device type, assuming default (plain)."
			## Add swap mapping based on hostname:volume format - live cd hostname is 'ubuntu'
			echo "swap /dev/md/ubuntu:0 /dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512" >> /etc/crypttab
			echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
		else
			apt-get --yes --quiet install cryptsetup

			##"plain" required in crypttab to avoid message at boot: "From cryptsetup: couldn't determine device type, assuming default (plain)."
			echo swap /dev/disk/by-id/"${DISKID1}"-part2 /dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512 >> /etc/crypttab
			echo /dev/mapper/swap none swap defaults 0 0 >> /etc/fstab
		fi

		## Mount a tmpfs to /tmp
		cp /usr/share/systemd/tmp.mount /etc/systemd/system/
		systemctl enable tmp.mount

		## Setup system groups
		addgroup --system lpadmin
		addgroup --system lxd
		addgroup --system sambashare
	EOCHROOT

	chroot "${mountpoint}" /bin/bash -x <<-"EOCHROOT"
		## Refresh initrd files
		ls /usr/lib/modules

		update-initramfs -k all -c
	EOCHROOT

}


systemsetupFunc_part6(){

	identify_ubuntu_dataset_uuid

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Fix filesystem mount ordering

		fixfsmountorderFunc(){
			mkdir -p /etc/zfs/zfs-list.cache

			touch /etc/zfs/zfs-list.cache/${RPOOL}
			ln -s /usr/lib/zfs-linux/zed.d/history_event-zfs-list-cacher.sh /etc/zfs/zed.d
			zed -F &
			sleep 2

			## Verify that zed updated the cache by making sure this is not empty:
			## If it is empty, force a cache update and check again:
			## Note can take a while. c.30 seconds for loop to succeed.
			cat /etc/zfs/zfs-list.cache/${RPOOL}
			while [ ! -s /etc/zfs/zfs-list.cache/${RPOOL} ]
			do
				zfs set canmount=noauto ${RPOOL}/ROOT/${rootzfs_full_name}
				sleep 1
			done
			cat /etc/zfs/zfs-list.cache/${RPOOL}

			## Stop zed:
			pkill -9 "zed*"

			## Fix the paths to eliminate ${mountpoint}:
			sed -Ei "s|${mountpoint}/?|/|" /etc/zfs/zfs-list.cache/${RPOOL}
			cat /etc/zfs/zfs-list.cache/${RPOOL}

		}
		fixfsmountorderFunc
	EOCHROOT

}


systemsetupFunc_part7(){

	identify_ubuntu_dataset_uuid

	chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		## Install samba tools
		apt-get --yes --quiet install cifs-utils

		## Install openssh-server
		[ "${openssh}" = "yes" ] && \
			apt-get --yes --quiet install openssh-server

		## Exit chroot
		echo 'Exiting chroot.'
	EOCHROOT

	## Copy script into new installation
	cp "$(readlink -f "$0")" "${mountpoint}"/root/
	cp "${SCRIPTPATH}/.variables" "${mountpoint}"/root/
	if [ -f "${mountpoint}"/root/"$(basename "$0")" ] && [ -f "${mountpoint}"/root/.variables ]; then
		echo "Install script copied to /root/ in new installation."
	else
		echo "Error copying install script to new installation."
	fi

}


usersetup(){

	## Create user account and setup groups
	zfs create -o mountpoint=/home/"${username}" "${RPOOL}"/USERDATA/${username}

	## gecos parameter disabled asking for finger info
	adduser --disabled-password --gecos "" "${username}"
	cp -a /etc/skel/. /home/"${username}"
	chown -R "${username}":"${username}" /home/"${username}"
	usermod --append --groups adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "${username}"
	echo -e "${username}:${user_password}" | chpasswd

}


distroinstall(){

	## Upgrade the minimal system
	apt-get --yes --quiet update
	DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet dist-upgrade

	## Install command-line or desktop environment
	if [ "${install_gui}" = "yes" ]; then
		## Install full GUI environment
		apt-get --yes --quiet install ubuntu-desktop man-db tldr locate
	else
		## Assume "server" if not "desktop"
		apt-get --yes --quiet install ubuntu-server man-db tldr locate htop
	fi

	## Remove snapd
	apt-get --yes --quiet remove --purge snapd

	## Update locate search index
	updatedb

}


logcompress(){

	## Disable log compression
	for file in /etc/logrotate.d/* ; do
		if grep -Eq "(^|[^#y])compress" "${file}" ; then
			sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "${file}"
		fi
	done

}


pyznapinstall(){

	## Install pyznap snapshot management
	## https://github.com/yboetz/pyznap
	snapshotmanagement(){

		## Install pip3
		apt-get --yes --quiet install python3-pip
		#pip3 --version

		## https://docs.python-guide.org/dev/virtualenvs/
		## Install python virtualenv packages
		pip3 install virtualenv
		#virtualenv --version
		pip3 install virtualenvwrapper

		## Create virtualenv
		mkdir /root/pyznap
		cd /root/pyznap
		virtualenv venv
		source venv/bin/activate
		## Install pyznap
		pip install pyznap

		## exit virtual env
		deactivate

		## Install pyznap binary
		ln -s /root/pyznap/venv/bin/pyznap /usr/local/bin/pyznap

		## Intialize pyznap
		/root/pyznap/venv/bin/pyznap setup

		## Config file created /etc/pyznap/pyznap.conf
		chown root:root -R /etc/pyznap/

		## Update config
		cat >> /etc/pyznap/pyznap.conf <<-EOF
			[${RPOOL}/ROOT]
			frequent = 4
			hourly = 24
			daily = 7
			weekly = 4
			monthly = 6
			yearly = 1
			snap = yes
			clean = yes
		EOF

		## Schedule snapshots every 15 minutes
		cat > /etc/cron.d/pyznap <<-EOF
			SHELL=/bin/sh
			PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
			*/15 * * * *   root    /root/pyznap/venv/bin/pyznap snap >> /var/log/pyznap.log 2>&1
		EOF

		## Integrate with apt
		cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
			DPkg::Pre-Invoke {"if [ -x /usr/local/bin/pyznap ]; then /usr/local/bin/pyznap snap; fi"};
		EOF

		## Take ZFS snapshots
		pyznap snap

	}
	snapshotmanagement

	## Clean up apt and unneeded packages
	apt-get --yes --quiet clean
	apt-get --yes --quiet autoremove --purge

}


setupremoteaccess(){

	if [ -f /etc/zfsbootmenu/dracut.conf.d/dropbear.conf ]; then
		echo "Remote access already appears to be installed owing to the presence of '/etc/zfsbootmenu/dracut.conf.d/dropbear.conf'. Install cancelled."
	else
		disclaimer
		remote_zbm_access_Func "base"

		echo "Configuring ZFSBootMenu to load user SSH keys."
		sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
		mkdir -p /home/"${username}"/.ssh
		touch /home/"${username}"/.ssh/authorized_keys
		chmod 644 /home/"${username}"/.ssh/authorized_keys
		chown "${username}":"${username}" /home/"${username}"/.ssh/authorized_keys
		hostname -I
		echo "Remote access installed. Connect as root on port 222."
		echo "Your SSH public key must be placed in '/home/${username}/.ssh/authorized_keys' prior to reboot or remote access will not work."
		echo "Run 'generate-zbm' after copying across the remote user's public ssh key into the authorized_keys file."
	fi

}


resettime(){

	## Manual reset time to correct out of date virtualbox clock
	timedatectl
	timedatectl set-ntp off
	sleep 1
	timedatectl set-time "2021-01-01 00:00:00"
	timedatectl

}


initialinstall(){

	disclaimer
	ipv6_apt_live_iso_fix
	debootstrap_part1_Func
	getdiskID1
	[ "${rpool_vdev_layout}" = "mirror" ] && \
		getdiskID2
	debootstrap_createzfspools_Func
	debootstrap_installminsys_Func
	systemsetupFunc_part1			## Basic system configuration
	systemsetupFunc_part2			## Install zfs
	systemsetupFunc_part3			## Format EFI partition
	systemsetupFunc_part4			## Install zfsbootmenu
	systemsetupFunc_part5			## Config swap, tmpfs, rootpass
	systemsetupFunc_part6			## ZFS file system mount ordering
	systemsetupFunc_part7			## Final installs and prep for reboot

	logcopy(){

		## Copy install log into new installation.
		if [ -d "${mountpoint}" ]; then
			cp "${log_loc}"/"${install_log}" "${mountpoint}""${log_loc}"
		else
			echo "No mountpoint dir present. Install log not copied."
		fi

	}
	logcopy

	echo "Reboot before continuing."
	echo "Post reboot login as root and run script with 'postreboot' option."
	echo "Script should be in the root login dir following reboot (/root/)"
	echo "First login is root:${root_password-}"

}


postreboot(){

	disclaimer
	usersetup						## Create user account and setup groups
	distroinstall					## Upgrade the minimal system
	logcompress						## Disable log compression
	dpkg-reconfigure \
		keyboard-configuration && \
		setupcon					## Configure keyboard and console
	pyznapinstall					## Snapshot management

	echo "Install complete."

}

<< 'TODO_CREATEDATAPOOL'
## Create different vdev configurations
## single disk, mirror, raidz1, raidz2
createdatapool(){
	disclaimer

	## Get datapool disk UUID
	echo "Enter diskID for non-root drive to create data pool on."
	getdiskID1

	## Check on whether data pool already exists
	if [ "$(zpool status "${datapool}")" ]; then
		echo "Warning: ${datapool} already exists. Are you use you want to wipe the drive and destroy ${datapool}? Press Enter to Continue or CTRL+C to abort."
		read -r _
	else
		true
	fi

	## Wipe disk
	sgdisk --zap-all /dev/disk/by-id/"${DISKID1}"
	sleep 2

	## Create pool mount point
	if [ -d "${datapool}mount" ]; then
		echo "Data pool mount point exists."
	else
		mkdir -p "${datapool}mount"
		chown "${username}":"${username}" "${datapool}mount"
		echo "Data pool mount point created."
	fi

	## Automount with zfs-mount-generator
	touch /etc/zfs/zfs-list.cache/"${datapool}"

	## Set data pool key to use rpool key for single unlock at boot. So data pool uses the same password as the root pool.
	datapool_keyloc="/etc/zfs/${RPOOL}.key"

	## Create data pool
	echo "${datapool}mount"
	zpool create \
		-o ashift="$zfs_dpool_ashift" \
		-O acltype=posixacl \
		-O compression="${zfs_compression}" \
		-O normalization=formD \
		-O relatime=on \
		-O dnodesize=auto \
		-O xattr=sa \
		-O encryption=aes-256-gcm \
		-O keylocation=file://"${datapool}_keyloc" \
		-O keyformat=passphrase \
		-O mountpoint="${datapool}mount" \
		"${datapool}" /dev/disk/by-id/"${DISKID1}"

	## Verify that zed updated the cache by making sure the cache file is not empty.
	cat /etc/zfs/zfs-list.cache/"${datapool}"

	## If it is empty, force a cache update and check again.
	## Note can take a while. c.30 seconds for loop to succeed.
	while [ ! -s /etc/zfs/zfs-list.cache/"${datapool}" ]
	do
		## Reset any pool property to update cache files
		zfs set canmount=on "${datapool}"
		sleep 1
	done
	cat /etc/zfs/zfs-list.cache/"${datapool}"

	## Create link to datapool mount point in user home directory.
	ln -s "${datapool}mount" "/home/${username}/"
	chown -R "${username}":"${username}" {"${datapool}mount","/home/${username}/${datapool}"}

	zpool status
	zfs list

}
TODO_CREATEDATAPOOL


## Start script

run_mode="$1"
loadVariables
logFunc
date
#resettime

case "${1-default}" in
	initial)
		echo "Running 'initial' setup. Press Enter to Continue or CTRL+C to abort."
		read -r _
		initialinstall
	;;
	postreboot)
		echo "Running 'postreboot' setup. Press Enter to Continue or CTRL+C to abort."
		read -r _
		postreboot
	;;
	remoteaccess)
		echo "Enabling 'remoteaccess' to ZFSBootMenu. Press Enter to Continue or CTRL+C to abort."
		read -r _
		setupremoteaccess
	;;
	*)
		echo -e "Usage: $0 [initial|postreboot|remoteaccess]"
	;;
esac

date
exit 0
