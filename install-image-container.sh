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
    echo "  -p,--path             Path to image-install application. By default resolve by \$PATH"
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

image_install="image-install"
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
		image_install="$2"
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

container_size="$(stat -L -c %s ${container})" || die "Failed getting container size"
tail --bytes 64 "$container" > "${TMP}/offsets" || die "Failed extracting offset blob"
magic="$(od -N 4 -A none --endian=little --format=u4 ${TMP}/offsets)" || die "Failed extracting tree offset"
magic="$(printf '0x%08x' ${magic})" || die "Failed converting magic"
[ "$magic" = 0x494d4721 ] || die "Invalid container magic [$magic] not the expected 0x494d4721"
tree_offset="$(od -N 8 -j 32 -A none --endian=little --format=u8 ${TMP}/offsets)" || die "Failed extracting tree offset"
tree_offset="$(echo "$tree_offset" | tr -d ' ')" || die "Failed truncating"
root_offset="$(od -N 8 -j 40 -A none --endian=little --format=u8 ${TMP}/offsets)" || die "Failed extracting root offset"
root_offset="$(echo "$root_offset" | tr -d ' ')" || die "Failed truncating"
digest_offset="$(od -N 8 -j 48 -A none --endian=little --format=u8 ${TMP}/offsets)" || die "Failed extracting digest offset"
digest_offset="$(echo "$digest_offset" | tr -d ' ')" || die "Failed truncating"
key_offset="$(od -N 8 -j 56 -A none --endian=little --format=u8 ${TMP}/offsets)" || die "Failed extracting key offset"
key_offset="$(echo "$key_offset" | tr -d ' ')" || die "Failed truncating"

[ $tree_offset -lt $root_offset ] || die "Invalid container, tree offset not less than root offset"
[ $root_offset -lt $digest_offset ] || die "Invalid container, root offset not less than digest offset"
[ $digest_offset -lt $key_offset ] || die "Invalid container, digest offset not less than key offset"
[ $key_offset -lt $container_size ] || die "Invalid container, key offset less than container size"

tree_size=$(( $root_offset - $tree_offset ))
root_size=$(( $digest_offset - $root_offset ))
digest_size=$(( $key_offset - $digest_offset ))
key_size=$(( $container_size - $key_offset - 64 ))

echo "Container:"
printf " 0x%08x squashfs - %d b\n" 0 $tree_offset
printf " 0x%08x tree     - %d b\n" $tree_offset $tree_size
printf " 0x%08x root     - %d b\n" $root_offset $root_size
printf " 0x%08x digest   - %d b\n" $digest_offset $digest_size
printf " 0x%08x key      - %d b\n" $key_offset $key_size

# Extract data for validating container
dd "if=${container}" "of=${TMP}/container.roothash" "bs=${root_size}" count=1 iflag=skip_bytes "skip=${root_offset}" status=none || die "Failed extracting roothash"
dd "if=${container}" "of=${TMP}/container.digest" "bs=${digest_size}" count=1 iflag=skip_bytes "skip=${digest_offset}" status=none || die "Failed extracting digest"
dd "if=${container}" "of=${TMP}/container.key" "bs=${key_size}" count=1 iflag=skip_bytes "skip=${key_offset}" status=none || die "Failed extracting key"
# Validate key
openssl pkey -in "${TMP}/container.key" -pubin -pubcheck -noout || die "Failed validating public key"
key_sha256="$(cat ${TMP}/container.key | sha256sum)" || die "Failed calculating public key sha256"
echo " key sha256: ${key_sha256}"

# Find matching public key if requested
if [ "$validate_pubkey" != "no" ]; then
	for pub in "$keydir"/*; do
		if openssl pkey -in "$pub" -pubcheck -pubin -noout; then
			tmpsha256="$(openssl pkey -in ${pub} -pubin -outform DER | sha256sum)"
			echo "Matching with keydir/$(basename ${pub}) sha256: ${tmpsha256}"
			if [ "$key_sha256" = "$tmpsha256" ]; then
				echo "Match!"
				foundkey="$pub"
				break
			fi
		fi
	done
	[ "x$foundkey" != "x" ] || die "No matching public key available"
else
	foundkey="${TMP}/container.key"
fi	

# Validate and mount container
openssl dgst -sha256 -verify "$foundkey" -signature "${TMP}/container.digest" \
	"${TMP}/container.roothash" || die "Failed validating roothash"
veritysetup open "$container" imageinstaller "$container" "--hash-offset=${tree_offset}" \
	"--root-hash-file=${TMP}/container.roothash" || die "Failed enabling dm-verity"
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
	printf '%s\n' "$config" | "$image_install" --force-unmount --device "$device" --config - $images || die "Failed installing image"
	# Return to previous dir
	cd -
	
else
	# Perform full disk installation without config
	read -r -d '' config <<- EOM
images:
   - name: image
     type: raw-sparse
     target: device
     reload_partitions: true
EOM
	printf '%s\n' "$config" | "$image_install" $zerofill --force-unmount --wipefs --device "$device" --config - "image=${TMP}/mnt/disk.img" || die "Failed installing image"
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
