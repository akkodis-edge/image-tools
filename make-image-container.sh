#!/bin/sh

LODEV="NONE"

cleanup() {
	if [ "$LODEV" != "NONE" ]; then
		if ! losetup -d "$LODEV"; then
			echo "Failed destroying loopback device"
			exit 1
		fi
		LODEV="NONE"
	fi
}

die () {
	echo "$1"
	cleanup
	exit 1
}

print_usage() {
    echo "Usage: image-container [OPTIONS] CONTAINER"
    echo "Make image container of disk"
    echo "Mandatory:"
    echo "  -b,--build        Path to build directory, will be created if needed"
    echo "  -c,--conf         Path to yaml config describing disk"
    echo "Optional:"
    echo "  -i,--images       Space separated list of imagename=imagepath"
    echo "                    where imagename is defined by --descriptor file."
    echo "  -p,--path         Path to image-install application. By default resolve by \$PATH"
    echo "  --key             Path to private key for signing image"
    echo "  --disk-name       Name to use for disk image inside container"
    echo "                    Reserved names: disk.img disk.img.sha256 preinstall postinstall"
}

image_install="image-install"
while [ "$#" -gt 0 ]; do
	case $1 in
	-b|--build)
		[ "$#" -gt 1 ] || die "Invalid argument -b/--build"
		build="$(realpath -s --relative-to=./ ${2})" || die "Failed getting build path"
		shift # past argument
		shift # past value
		;;
	-c|--conf)
		[ "$#" -gt 1 ] || die "Invalid argument -c/--conf"
		conf="$2"
		shift # past argument
		shift # past value
		;;
	-p|--path)
		[ "$#" -gt 1 ] || die "Invalid argument -p/--path"
		image_install="$2"
		shift # past argument
		shift # past value
		;;
	-i|--images)
		[ "$#" -gt 1 ] || die "Invalid argument -i/--images"
		images="$2"
		shift # past argument
		shift # past value
		;;
	--key)
		[ "$#" -gt 1 ] || die "Invalid argument --key"
		keyfile="$2"
		shift # past argument
		shift # past value
		;;
	--disk-name)
		[ "$#" -gt 1 ] || die "Invalid argument --disk-name"
		disk_name="$2"
		shift # past argument
		shift # past value
		;;
	-*|--*)
		print_usage
		exit 1
		;;
	*)
		container_name="$1"
		shift # past argument
		;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Must be run as root"
[ "x$build" != "x" ] || die "Missing argument -b/--build"
[ "x$conf" != "x" ] || die "Missing argument -c/--conf"
[ "x$container_name" != "x" ] || die "Missing argument CONTAINER"

# Get size in bytes from config file:
# disk:
#   size: BYTES
cmd="from yaml import safe_load; print(safe_load(open(\"${conf}\"))['disk']['size'])"
disk_size="$(python3 -c "$cmd")" || die "Failed reading disk size from config"

disk_image="${build}/disk.img"
if [ "x$disk_name" != "x" ]; then
	disk_image="${build}/${disk_name}"
fi

# Prepare and mount disk as loopback device
mkdir -p "$build" || die "Failed creating build dir"
# Disk image will be sparse, remove any existing image to start from fresh sparse image
rm -f "$disk_image" || die "Failed removing disk image"LS

truncate -s "$disk_size" "$disk_image" || die "Failed creating disk image"
LODEV="$(losetup --show -P -f ${disk_image})" || die "Failed creating loopback device"

# Finalize disk image
cat "$conf"
echo ""
"$image_install" --config "$conf" --device "$LODEV" $images || die "Failed finalizing image"
# Remove loopback device
cleanup

# Calculate checksum
echo "Calculating disk sha256"
disk_sha256="$(cat ${disk_image} | sha256sum)" || die "Failed calculating checksum"
echo "$disk_sha256" > "${disk_image}.sha256" || die "Failed writing sha256"

artifacts="${disk_image} ${disk_image}.sha256"
# Create symlink for disk image if name provided
if [ "x$disk_name" != "x" ]; then
	ln -sf "$(basename ${disk_image})" "${build}/disk.img" || die "Failed creating link"
	ln -sf "$(basename ${disk_image}).sha256" "${build}/disk.img.sha256" || die "Failed creating link"
	artifacts="${artifacts} ${build}/disk.img ${build}/disk.img.sha256"
fi

# Create squashfs image
mksquashfs $artifacts "${build}/container.nosign" -noappend -all-root || die "Failed creating squashfs"

# Sign if key provided
sign="no"
if [ "x$keyfile" != "x" ]; then
	# Get public key in DER format and truncate to 4K blob
	openssl pkey -in "$keyfile" -out "${build}/key.pub.der" -pubout -outform DER || die "Failed getting pubkey from key"
	truncate --no-create -s %4096 "${build}/key.pub.der" || die "Failed truncating pubkey"
	# Calculate and sign digest
	openssl dgst -sha256 -out "${build}/container.digest" -sign "$keyfile" "${build}/container.nosign" || die "Failed signing digest"
	truncate --no-create -s %4096 "${build}/container.digest" || die "Failed truncating digest"
	sign="yes"
fi

if [ "$sign" = "yes" ]; then
	cat "${build}/container.nosign" "${build}/container.digest" "${build}/key.pub.der" > "${build}/${container_name}" || die "Failed assembling container"
else
	cat "${build}/container.nosign" > "${build}/${container_name}" || die "Failed assembling container"
fi

exit 0
