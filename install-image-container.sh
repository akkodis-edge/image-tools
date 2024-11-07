#!/bin/bash
# Require bash due to builtin read

TMP="NONE"

cleanup() {
	if [ "$TMP" != "NONE" ]; then
		if [ -d "$TMP"/mnt ]; then
			umount "$TMP"/mnt
		fi
		rm -r "$TMP"
		TMP="NONE"
	fi
}

die() {
	echo "$1"
	cleanup
	exit 1
}

print_usage() {
    echo "Usage: install-container [OPTIONS] CONTAINER"
    echo "Install container to blockdevice"
    echo "Mandatory:"
    echo "  -d,--device       Path to target blockdevice"
    echo "Optional:"
    echo "  --any-pubkey      Flag to only use public key in container for validation -- do not match public key to known key"
    echo "  -p,--path         Path to image-install application. By default resolve by \$PATH"
    echo "  --key-dir         Path to directory of public keys for validating container signature"
    echo "  --verify-device   Verify disk image to device by:"
    echo "                      - zero full device before image installation"
    echo "                      - do NOT execute preinstall and postinstall"
    echo "                      - write disk image to device"
    echo "                      - sha256 whole device and compare to disk sha256 in container"
    echo "                      - return 0 if sha256 sums are equal"
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

tail --bytes 8192 "$container" > "${TMP}/signature" || die "Failed extracting signature blob"
tail --bytes 4096 "${TMP}/signature" > "${TMP}/pub.orig" || die "Failed extracting public key"
head --bytes 4096 "${TMP}/signature" > "${TMP}/digest" || die "Failed extracting digest"
openssl pkey -in "${TMP}/pub.orig" -pubin -out "${TMP}/pub.der" -outform DER || die "Failed validating public key"
pub_sha256="$(cat ${TMP}/pub.der | sha256sum)" || die "Failed calculating public key sha256"
echo "Container public key sha256: ${pub_sha256}"

# Find matching public key if requested
if [ "$validate_pubkey" != "no" ]; then
	for pub in "$keydir"; do
		if openssl pkey -in "$pub" -pubcheck -pubin -noout; then
			tmpsha256="$(cat  ${pub} | sha256sum)"
			echo "Matching with keydir/$(basename ${pub}) sha256: ${tmpsha256}"
			if [ "$pub_sha256" = "$tmpsha256" ]; then
				echo "Match!"
				foundkey="$pub"
				break
			fi
		fi
	done
	[ "x$foundkey" != "x" ] || die "No matching public key available"
else
	foundkey="${TMP}/pub.der"
fi

# Validate and mount container
head --bytes=-8192 "$container" | openssl dgst -sha256 -verify "$foundkey" -signature "${TMP}/digest" || die "Failed validating container"
mkdir "${TMP}/mnt" || die "Failed creating mnt dir"
mount -t squashfs -o ro "$container" "${TMP}/mnt" || die "Failed mounting container" 

# Zero device when verifying device or run preinstall in normal flow
if [ "$verify_device" = "yes" ]; then
	echo "Writing zeroes to device"
	#devicesize="$(lsblk -bno SIZE ${device})" || die "Failed getting device size"
	#head --bytes "$devicesize" > "$device" || die "Failed zeroing drive"
	dd if=/dev/zero of="$device" bs=4K conv=notrunc 2>/dev/null
else
	if [ -x "${TMP}/mnt/preinstall" ]; then
		echo "preinstall: $(readlink ${TMP}/mnt/preinstall)"
		"${TMP}/mnt/preinstall" "$device" || die "Failed executing preinstall"
	fi
fi

# Perform installation
read -r -d '' config <<- EOM
images:
   - name: image
     type: raw-sparse
     target: device
EOM
echo "Installing image"
printf '%s\n' "$config" | "$image_install" --wipefs --device "$device" --config - image="${TMP}/mnt/disk.img" || die "Failed installing image"

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
else
	if [ -x "${TMP}/mnt/postinstall" ]; then
		echo "postinstall: $(readlink ${TMP}/mnt/postinstall)"
		"${TMP}/mnt/postinstall" "$device" || die "Failed executing postinstall"
	fi
fi

cleanup
exit 0
