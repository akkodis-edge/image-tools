#!/bin/sh


die() {
	echo $1
	exit 1	
}

if [ "$#" -lt "4" ]; then
	die "Usage: $0 <disk drive> <filesystem> <label> <rootfs tar file>"
fi

if [ $(id -u) -ne 0 ]; then
	die "Must be run as root"
fi

drive="${1}"
part="${drive}1"
fs="${2}"
fslabel="${3}"
rootfs="${4}"

if [ ${fs} != "ext4" ] && [ ${fs} != "vfat" ]; then
	die "Unsupported fs"
fi

echo "Disk ${drive} using ${part}"
parted --script ${drive} mklabel msdos || die "Unable to create partition table on ${drive}"

echo "Creating ${fs} on ${part}"
if [ ${fs} = "ext4" ]; then
	parted --script ${drive} mkpart primary 4 1000 || die "Unable to create partition on ${drive}"
	sleep 1	
	mkfs.ext4 -b 4096 ${part} -L ${fslabel} || die "Unable to create FS on ${part}"
elif [ ${fs} = "vfat" ]; then
	parted --script ${drive} mkpart primary fat32 4 1000 || die "Unable to create partition on ${drive}"
	sleep 1	
	mkfs.vfat ${part} || die "Unable to create FS on ${part}"
	fatlabel ${part} ${fslabel} || die "Unable to set label on ${part}"
fi
	

d=$(mktemp -d)
mount ${part} ${d} || die "Unable to mount ${part} on tmp ${d}"
echo "extract ${rootfs} on ${part}"
tar -C ${d} -xf ${rootfs} || die "Tar failure"
umount ${d}

echo "Done"
