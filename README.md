# Ubuntu server zfsbootmenu install script
This script creates an ubuntu server installation using the ZFS filesystem. The installation has integrated snapshot management using pyznap. Snapshots can be rolled back remotely at boot over ssh using zfsbootmenu. This is useful where there is no physical access to the machine.

Snapshots allow you to rollback your system to a previous state if there is a problem. The system automatically creates snapshots on a timer and also when the system is updated with apt. Snapshots are pruned over time to keep fewer older snapshots.

* Supports Ubuntu 20.04 and higher
* Support for Jonathan F ZFS PPA to install ZFS 2.x on Ubuntu 20.04 (support for zstd compression)
* Support for single disk or mirror RPOOL layout
* Support for static IP/DHCP configuration (will also configure dracut-network if 'remoteaccess' is setup)
* TODO: DATAPOOL setup


# Usage
Boot the system with an Ubuntu live desktop iso (ZFS 2.0 support needed for native encryption, so use Ubuntu 21.04 or later). Start the terminal (Ctrl+Alt+T) and enter the following.

	git clone https://github.com/edifus/ubuntu-server-zfsbootmenu.git ~/ubuntu-server-zfsbootmenu
    cd ~/ubuntu-server-zfsbootmenu
    chmod +x ubuntu-server-zfsbootmenu.sh

Make a copy of the variables template file.

	cp .variables.template .variables

Edit '.variables' file to your preferences.

	nano .variables

Run the first part of the script.

	./ubuntu-server-zfsbootmenu.sh initial

Reboot after the initial installation completes and login to the new install. Username is root, password is as set in the script variables. Then run the second part of the script.

	./ubuntu-server-zfsbootmenu.sh postreboot

Additional guidance and notes can be found in the script.

## Headless/Remote access
After completing 'postreboot' step, run the optional 'remoteaccess' part of the script.

	./ubuntu-server-zfsbootmenu.sh remoteaccess

Install SSH public key

	nano /home/$user/.ssh/authorized_keys

Regenerate ZFSBootMenu

	generate-zbm --debug


# Reddit discussion threads
* https://www.reddit.com/r/zfs/comments/mj4nfa/ubuntu_server_2104_native_encrypted_root_on_zfs/
* https://www.reddit.com/r/zfs/comments/qrt1vx/remotely_unlocking_headless_server/


# Credits
* Sithuk (https://gitlab.com/Sithuk/ubuntu-server-zfsbootmenu)
* rlaager (https://openzfs.github.io/openzfs-docs/Getting%20Started/Ubuntu/Ubuntu%2020.04%20Root%20on%20ZFS.html)
* ahesford E39M5S62/zdykstra (https://github.com/zbm-dev/zfsbootmenu)
* cythoning (https://github.com/yboetz/pyznap)
