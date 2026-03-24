#!/bin/bash

TMP="NONE"
VERITY="NONE"
path=""

cleanup() {
	if [ "$TMP" != "NONE" ]; then
		if [ -d "$TMP"/mnt ]; then
			umount "$TMP"/mnt
		fi
		if [ "$VERITY" != "NONE" ]; then
			tmpverity="$VERITY"
			VERITY="NONE"
			PATH="$path:$PATH" container-util --close "$tmpverity" || die "Failed closing container"
		fi
		rm -r "$TMP"
		TMP="NONE"
	fi
}
trap cleanup EXIT

die() {
	echo "$1"
	cleanup
	exit 1
}

print_usage() {
    echo "Usage: install-container [OPTIONS] CONTAINER"
    echo "Install container to blockdevice"
    echo "Mandatory:"
    echo "  -d,--device           Path to target blockdevice"
    echo "Optional:"
    echo "  --any-pubkey          Flag to only use public key in container for validation -- do not match public key to known key"
    echo "  -p,--path             Additional \$PATH for container-util application"
    echo "  --key-dir             Path to directory of public keys for validating container signature"
    echo "  --verify-device       Verify disk image to device by:"
    echo "                         - zero full device before image installation"
    echo "                         - do NOT execute preinstall and postinstall"
    echo "                         - write disk image to device"
    echo "                         - sha256 whole device and compare to disk sha256 in container"
    echo "                         - return 0 if sha256 sums are equal"
    echo "                        Warning: should only be used with full disk images and no partitions"
    echo "  --alias               Map container partitions to actual partition names with form \"name:target\""
    echo "                        For example a container partition named rootfs can be mapped to rootfs2 by:"
    echo "                        \"rootfs:rootfs2\". This option can be supplied multiple times."
    echo "  --reset-nvram-update  Reset nvram A/B update to defaults"
    echo "  --unmount             Unmount target --device before installation"
}

declare -A part_aliases
validate_pubkey="yes"
while [ "$#" -gt 0 ]; do
	case $1 in
	-d|--device)
		[ "$#" -gt 1 ] || die "Invalid argument -d/--device"
		device="$2"
		shift # past argument
		shift # past value
		;;
	-p|--path)
		[ "$#" -gt 1 ] || die "Invalid argument -p/--path"
		path="$2"
		shift # past argument
		shift # past value
		;;
	--key-dir)
		[ "$#" -gt 1 ] || die "Invalid argument --key-dir"
		keydir="$2"
		shift # past argument
		shift # past value
		;;
	--any-pubkey)
		validate_pubkey="no"
		shift # past argument
		;;
	--verify-device)
		verify_device="yes"
		shift # past argument
		;;
	--reset-nvram-update)
		reset_nvram_update="yes"
		shift # past argument
		;;
	--unmount)
		unmount="yes"
		shift # past argument
		;;
	--alias)
		[ "$#" -gt 1 ] || die "Invalid argument --alias"
		declare -a tmpalias
		readarray -d ":" -t tmpalias < <(printf "%s" "$2")
		[ ${#tmpalias[@]} -eq 2 ] || die "Invalid argument --alias"
		part_aliases["${tmpalias[0]}"]="${tmpalias[1]}"
		shift # past argument
		shift # past value
		;;
	-*|--*)
		print_usage
		exit 1
		;;
	*)
		container="$1"
		shift # past argument
		;;
  esac
done

[ "$validate_pubkey" = "yes" -a "x$keydir" = "x" ] && die "Missing argument --keydir or --any-pubkey"
[ "x$device" != "x" ] || die "Missing argument -d/--device"
[ "x$container" != "x" ] || die "Missing argument CONTAINER"

TMP="$(mktemp -d)" || die "Failed creating tmp directory"

# Validate and mount container
container_util_args="--open imageinstaller "$container""
if [ "$validate_pubkey" != "yes" ]; then
	container_util_args="$container_util_args --pubkey-any"
elif [ "x$keydir" != "x" ]; then
	container_util_args="$container_util_args --pubkey-dir "$keydir""
else
	die "No known key validation provided"
fi
PATH="$path:$PATH" container-util $container_util_args || die "Failed opening container"
VERITY="imageinstaller"
mkdir "${TMP}/mnt" || die "Failed creating mnt dir"
mount -t squashfs -o ro /dev/mapper/imageinstaller "${TMP}/mnt" || die "Failed mounting squashfs" 

# Detect whether individual partitions are provided
declare -A partition_targets
declare -A partition_devices
partition_images="$(find "${TMP}/mnt"  -name 'partition\.*' ! -name '*.bmap' -type f,l)" || die "Failed reading container content"
if [ "x$partition_images" != "x" ]; then
	for image in "$partition_images"; do
		# Strip path and file prefix "partition." to get target partition name
		partname="${image#*partition.}"
		# Use alias if available
		if [ "x${part_aliases["$partname"]}" != "x" ]; then
			tmp="$partname"
			partname="${part_aliases["$partname"]}"
			unset part_aliases["$tmp"]
		fi
		partition_targets["$partname"]="$image"
		# resolve partition name to blockdevice
		blkdev="$(blkid -l -o device -t PARTLABEL="$partname" "$device")" || die "Failed finding blockdev for partition \"$partname\""
		partition_devices["$partname"]="$blkdev"
	done
	echo "Targets:"
	for part in "${!partition_targets[@]}"; do
		echo "  ${partition_devices["$part"]}[$part]=${partition_targets["$part"]}"
	done
fi

if [ "${#part_aliases[@]}" -ne 0 ]; then
	echo "Provided aliases did not match partitions in container"
	for part in "${!part_aliases[@]}"; do
		echo "  $part=${part_aliases[$part]}"
	done
	die "ERROR: unused aliases"
fi

# Detect whether full disk image is provided
if [ -f "${TMP}/mnt/disk.img" ]; then
	disk_image="${TMP}/mnt/disk.img"
fi

# Something must be installable
[ "x$partition_images" = "x" -a "x$disk_image" = "x" ] && die "ERROR: container contains no disk or partition images"
# We do not now how to manage both full disk and partition images
[ "x$partition_images" != "x" -a "x$disk_image" != "x" ] && die "ERROR: container contains both disk and partition images"
# --verify-device only supported on full disk images
[ "$verify_device" = "yes" -a "x$partition_images" != "x" ] && die "ERROR: --verify-device only supported on disk images"

# Check if mounted
all_mounted=""
if [ "x$disk_image" != "x" ]; then
	# Find mounted partitions on device
	all_mounted="$(cut -d ' ' -f 1 /proc/self/mounts | grep "^${device}*" | tr '\n' ' ')" || die "Failed checking /proc/self/mounts"
fi
if [ "x$partition_images" != "x" ]; then
	# Check if target partitions are mounted
	for part in "${partition_devices[@]}"; do
		if findmnt "$part" >/dev/null; then
			all_mounted="$all_mounted $part"
		fi
	done
fi
# trim whitespace from all_mounted
read -r all_mounted <<< "$all_mounted"

[ "x$all_mounted" != "x" -a "$unmount" != "yes" ] && die "ERROR: target device partitions mounted: \"$all_mounted\""

# unmount if requested
if [ "$unmount" = "yes" ]; then
	for mounted in $all_mounted; do
		echo "Unmount $mounted"
		umount "$mounted" || die "Failed unmounting partition"
	done
fi

# Zero device when verifying device or run preinstall in normal flow
if [ "$verify_device" = "yes" ]; then
	echo "Zeroing $device"
	cat /dev/zero > "$device" || die "Failed zeroing device"
elif [ -x "${TMP}/mnt/preinstall" ]; then
	echo "preinstall: $(readlink ${TMP}/mnt/preinstall)"
	"${TMP}/mnt/preinstall" "$device" || die "Failed executing preinstall"
fi

# Perform installation
if [ "x$disk_image" != "x" ]; then
	bmaptool copy "$disk_image" "$device" || die "Failed installing disk image"
fi
if [ "x$partition_images" != "x" ]; then
	for part in "${!partition_targets[@]}"; do
		bmaptool copy "${partition_targets["$part"]}" "${partition_devices["$part"]}" || die "Failed installing partition image"
	done
fi

# Validate device sha256sum when verifying device or run postinstall in normal flow
if [ "$verify_device" = "yes" ]; then
	echo "Calculating device checksum"
	imagesize="$(stat -L -c %s ${TMP}/mnt/disk.img)" || die "Failed getting image size"
	echo "Size: ${imagesize}"
	device_sha256="$(head --bytes ${imagesize} ${device} | sha256sum)" || die "Failed calculating device sha256"
	image_sha256="$(cat ${TMP}/mnt/disk.img.sha256)" || die "Failed reading image sha256"
	echo "device sha256: ${device_sha256}"
	echo "image sha256:  ${image_sha256}"
	[ "$device_sha256" = "$image_sha256" ] || die "sha256 mismatch"
	echo "Valid!"
elif [ -x "${TMP}/mnt/postinstall" ]; then
	echo "postinstall: $(readlink ${TMP}/mnt/postinstall)"
	"${TMP}/mnt/postinstall" "$device" || die "Failed executing postinstall"
fi

if [ "$reset_nvram_update" = "yes" ]; then
	echo "Resetting nvram update variables"
	NVRAM_SYSTEM_UNLOCK=16440 nvram --sys \
		--set SYS_BOOT_PART rootfs1 \
		--set SYS_BOOT_SWAP rootfs1 \
		--del SYS_BOOT_ATTEMPTS || die "Failed resetting nvram"
fi

cleanup
exit 0
