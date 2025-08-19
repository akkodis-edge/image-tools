#!/bin/bash
# Require bash due to builtin read

TMP="NONE"
VERITY="NONE"

cleanup() {
	if [ "$TMP" != "NONE" ]; then
		if [ -d "$TMP"/mnt ]; then
			umount "$TMP"/mnt
		fi
		if [ "$VERITY" != "NONE" ]; then
			veritysetup close "$VERITY"
			VERITY="NONE"
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
    echo "  -c,--conf             Path to yaml config describing disk, allows overriding full disk install. To be used with --images"
    echo "                        Value of - means config in stdin"
    echo "  -i,--images           Space separated list of imagename=imagepath. Relative path to image within container. To be used with --conf"
    echo "  --any-pubkey          Flag to only use public key in container for validation -- do not match public key to known key"
    echo "  -p,--path             Additional \$PATH for image-install and container-util application"
    echo "  --key-dir             Path to directory of public keys for validating container signature"
    echo "  --verify-device       Verify disk image to device by:"
    echo "                         - zero full device before image installation"
    echo "                         - do NOT execute preinstall and postinstall"
    echo "                         - write disk image to device"
    echo "                         - sha256 whole device and compare to disk sha256 in container"
    echo "                         - return 0 if sha256 sums are equal"
    echo "                        Warning: should only be used with full disk images and no partitions"
    echo "  --reset-nvram-update  Reset nvram A/B update to defaults"
}

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
	-c|--conf)
		[ "$#" -gt 1 ] || die "Invalid argument -c/--conf"
		conf="$2"
		shift # past argument
		shift # past value
		;;
	-i|--images)
		[ "$#" -gt 1 ] || die "Invalid argument -i/--images"
		images="$2"
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

# Zero device when verifying device or run preinstall in normal flow
if [ "$verify_device" = "yes" ]; then
	zerofill="--zero-fill"
elif [ -x "${TMP}/mnt/preinstall" ]; then
	echo "preinstall: $(readlink ${TMP}/mnt/preinstall)"
	"${TMP}/mnt/preinstall" "$device" || die "Failed executing preinstall"
fi

echo "Installing image"
if [ "x$conf" != "x" ]; then
	# Install individual partitions with config
	if [ "$conf" = "-" ]; then
		config="$(cat)"
	else
		config="$(cat ${conf})"
	fi
	# cd to container for relative --image paths
	cd "${TMP}/mnt"
	printf '%s\n' "$config" | PATH="$path:$PATH" image-install --force-unmount --device "$device" --config - $images || die "Failed installing image"
	# Return to previous dir
	cd -
	
else
	# Perform full disk installation without config
	read -r -d '' config <<- EOM
images:
   - name: image
     type: raw-bmap
     target: device
     reload_partitions: true
EOM
	printf '%s\n' "$config" | PATH="$path:$PATH" image-install $zerofill --force-unmount --wipefs --device "$device" --config - "image=${TMP}/mnt/disk.img" || die "Failed installing image"
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
