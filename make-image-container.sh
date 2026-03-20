#!/bin/sh

die () {
	echo "$1"
	exit 1
}

print_usage() {
    echo "Usage: image-container [OPTIONS] CONTAINER"
    echo "Make image container of disk"
    echo "  Reserved names: disk.img disk.img.sha256 disk.img.bmap preinstall postinstall"
    echo ""
    echo "Mandatory:"
    echo "  -b,--build        Path to build directory, will be created if needed"
    echo "Optional:"
    echo "  --partitions      Space separated list to paths of partitions"
    echo "  --disk            Path to disk image"
    echo "  -p,--path         Additional \$PATH for container-util application"
    echo "  --key             Path to private key for signing image"
    echo "  --key-pkcs11      PKCS#11 URL for private key"
    echo "  --disk-name       Name to use for disk image inside container"
    echo "  --preinstall      Path to preinstall script which will be called before image installation"
    echo "  --postinstall     Path to postinstall script which will be called after image installation"
}

while [ "$#" -gt 0 ]; do
	case $1 in
	-b|--build)
		[ "$#" -gt 1 ] || die "Invalid argument -b/--build"
		build="$(realpath -s --relative-to=./ ${2})" || die "Failed getting build path"
		shift # past argument
		shift # past value
		;;
	-p|--path)
		[ "$#" -gt 1 ] || die "Invalid argument -p/--path"
		path="$2"
		shift # past argument
		shift # past value
		;;
	--partitions)
		[ "$#" -gt 1 ] || die "Invalid argument --partitions"
		partitions="$2"
		shift # past argument
		shift # past value
		;;
	--disk)
		[ "$#" -gt 1 ] || die "Invalid argument --disk"
		disk="$2"
		shift # past argument
		shift # past value
		;;
	--key)
		[ "$#" -gt 1 ] || die "Invalid argument --key"
		keyfile="$2"
		shift # past argument
		shift # past value
		;;
	--key-pkcs11)
		[ "$#" -gt 1 ] || die "Invalid argument --key-pkcs11"
		key_pkcs11="$2"
		shift # past argument
		shift # past value
		;;
	--disk-name)
		[ "$#" -gt 1 ] || die "Invalid argument --disk-name"
		disk_name="$2"
		shift # past argument
		shift # past value
		;;
	--preinstall)
		[ "$#" -gt 1 ] || die "Invalid argument --preinstall"
		preinstall="$2"
		shift # past argument
		shift # past value
		;;
	--postinstall)
		[ "$#" -gt 1 ] || die "Invalid argument --postinstall"
		postinstall="$2"
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

[ "x$build" != "x" ] || die "Missing argument -b/--build"
[ "x$partitions" = "x" -a "x$disk" = "x" ] && die "Missing argument --partitions or --disk"
count=0
[ "x$partitions" != "x" ] && count=$(( $count + 1 ))
[ "x$disk" != "x" ] && count=$(( $count + 1 ))
[ $count -eq 1 ] || ie "Invalid argument --partitions and --disk are mutually exclusive"
[ "x$container_name" != "x" ] || die "Missing argument CONTAINER"
[ "x$keyfile" = "x" -a "x$key_pkcs11" = "x" ] && die "No signing method provided"

# Verify no reserved names are used
for x in "$container_name" "$preinstall" "$postinstall" $partitions; do
	if [ "x${x}" != "x" ]; then
		basename="$(basename ${x})" || die "Failed basename"
		for reserved in "disk.img" "disk.img.sha256" "disk.img.bmap" "preinstall" "postinstall"; do
			[ "$x" = "$reserved" ] && die "Invalid use of reserved name ${reserved}"
		done
	fi
done

mkdir -p "$build" || die "Failed creating build dir"

if [ "x$partitions" != "x" ]; then
	artifacts=""
	# Create bmap file for each partition
	for part in $partitions; do
		part_basename="$(basename "$part")" || die "Failed getting partition basename"
		bmaptool create -o "${build}/${part_basename}.bmap" "$part" || die "Failed creating bmap"
		artifacts="${artifacts} ${part} ${build}/${part_basename}.bmap"
	done
fi

if [ "x$disk" != "x" ]; then
	disk_basename="$(basename "$disk")" || die "Failed getting disk basename"
	# Create bmap
	bmaptool create -o "${build}/${disk_basename}.bmap" "$disk" || die "Failed creating bmap"
	# Calculate sha256
	disk_sha256="$(cat ${disk} | sha256sum)" || die "Failed calculating sha256"
	echo "$disk_sha256" > "${build}/${disk_basename}.sha256"|| die "Failed writing sha256"
	artifacts="${disk} ${build}/${disk_basename}.bmap ${build}/${disk_basename}.sha256"
	# Create links unless already named disk.img
	if [ "$disk_basename" != "disk.img" ]; then
		ln -sf "$disk_basename" "${build}/disk.img" || die "Failed creating link"
		ln -sf "$disk_basename.sha256" "${build}/disk.img.sha256" || die "Failed creating link"
		ln -sf "$disk_basename.bmap" "${build}/disk.img.bmap" || die "Failed creating link"
		artifacts="${artifacts} ${build}/disk.img.bmap ${build}/disk.img.sha256 ${build}/disk.img"
	fi
fi

# Add pre/postinstall if requested
if [ "x$preinstall" != "x" ]; then
	echo "Adding preinstall"
	preinstall_basename="$(basename ${preinstall})" || die "Failed retrieving preinstall basename"
	mkdir -p "${build}/input" || die "Failed creating build/input dir"
	install -m 0755 "$preinstall" "${build}/input/${preinstall_basename}" || die "Failed retrieving preinstall"
	ln -sf "$preinstall_basename" "${build}/preinstall" || die "Failed creating link"
	artifacts="${artifacts} ${build}/preinstall ${build}/input/${preinstall_basename}"
fi

if [ "x$postinstall" != "x" ]; then
	echo "Adding postinstall"
	postinstall_basename="$(basename ${postinstall})" || die "Failed retrieving postinstall basename"
	mkdir -p "${build}/input" || die "Failed creating build/input dir"
	install -m 0755 "$postinstall" "${build}/input/${postinstall_basename}" || die "Failed retrieving postinstall"
	ln -sf "$postinstall_basename" "${build}/postinstall" || die "Failed creating link"
	artifacts="${artifacts} ${build}/postinstall ${build}/input/${postinstall_basename}"
fi

# Create squashfs
mksquashfs $artifacts "${build}/image.container" -noappend -all-root || die "Failed creating squashfs"
# Package as container
if [ "x$key_pkcs11" != "x" ]; then
	sign_method="--key-pkcs11"
	sign_arg="$key_pkcs11"
elif [ "x$keyfile" != "x" ]; then
	sign_method="--keyfile"
	sign_arg="$keyfile"
else
	die "No signing method provided"
fi
PATH="$path:$PATH" container-util --create $sign_method "$sign_arg" "${build}/image.container" || die "Failed creating container"
mv "${build}/image.container" "$container_name" || die "Failed moving output container"

exit 0
