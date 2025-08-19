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
    echo "  Reserved names: disk.img disk.img.sha256 disk.img.bmap preinstall postinstall"
    echo ""
    echo "Mandatory:"
    echo "  -b,--build        Path to build directory, will be created if needed"
    echo "Optional:"
    echo "  --partitions      Space separated list to paths of partitions"
    echo "  -c,--conf         Path to yaml config describing disk"
    echo "  -i,--images       Space separated list of imagename=imagepath"
    echo "                    where imagename is defined by --conf file."
    echo "  -p,--path         Additional \$PATH for image-install and container-util application"
    echo "  --key             Path to private key for signing image"
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
	-c|--conf)
		[ "$#" -gt 1 ] || die "Invalid argument -c/--conf"
		conf="$2"
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

[ "$(id -u)" -eq 0 ] || die "Must be run as root"
[ "x$build" != "x" ] || die "Missing argument -b/--build"
[ "x$conf" != "x" -a "x$partitions" != "x" ] && die "Invalid argument -c/--conf and --partitions are mutually exclusive"
[ "x$conf" = "x" -a "x$partitions" = "x" ] && die "Missing argument -c/--conf or --partitions" 
[ "x$container_name" != "x" ] || die "Missing argument CONTAINER"
[ "x$keyfile" != "x" ] || die "No signing method provided"

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

if [ "x$conf" != "x" ]; then
	# Get size in bytes from config file:
	# disk:
	#   size: BYTES
	cmd="from yaml import safe_load; print(safe_load(open(\"${conf}\"))['disk']['size'])"
	disk_size="$(python3 -c "$cmd")" || die "Failed reading disk size from config"
	
	disk_image="${build}/disk.img"
	if [ "x$disk_name" != "x" ]; then
		disk_image="${build}/${disk_name}"
	fi

	# Disk image will be sparse, remove any existing image to start from fresh sparse image
	rm -f "$disk_image" || die "Failed removing disk image"LS
	
	truncate -s "$disk_size" "$disk_image" || die "Failed creating disk image"
	LODEV="$(losetup --show -P -f ${disk_image})" || die "Failed creating loopback device"
	
	# Finalize disk image
	cat "$conf"
	echo ""
	PATH="$path:$PATH" image-install --config "$conf" --device "$LODEV" $images || die "Failed finalizing image"
	# Remove loopback device
	cleanup
	
	# Calculate checksum
	echo "Calculating disk sha256"
	disk_sha256="$(cat ${disk_image} | sha256sum)" || die "Failed calculating checksum"
	echo "$disk_sha256" > "${disk_image}.sha256" || die "Failed writing sha256"

	# Create bmap
	echo "Creating bmap"
	bmaptool create -o "${disk_image}.bmap" "$disk_image" || die "Failed creating bmap"

	artifacts="${disk_image} ${disk_image}.sha256 ${disk_image}.bmap"
	# Create symlink for disk image if name provided
	if [ "x$disk_name" != "x" ]; then
		ln -sf "$(basename ${disk_image})" "${build}/disk.img" || die "Failed creating link"
		ln -sf "$(basename ${disk_image}).sha256" "${build}/disk.img.sha256" || die "Failed creating link"
		ln -sf "$(basename ${disk_image}).bmap" "${build}/disk.img.bmap" || die "Failed creating link"
		artifacts="${artifacts} ${build}/disk.img ${build}/disk.img.sha256"
	fi
fi

if [ "x$partitions" != "x" ]; then
	artifacts=""
	# Create bmap file for each partition
	for part in $partitions; do
		part_basename="$(basename "$part")" || die "Failed getting partition basename"
		bmaptool create -o "${build}/${part_basename}.bmap" "$part" || die "Failed creating bmap"
		artifacts="${artifacts} ${part} ${build}/${part_basename}.bmap"
	done
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
mksquashfs $artifacts "${build}/${container_name}" -noappend -all-root || die "Failed creating squashfs"
# Package as container
PATH="$path:$PATH" container-util --create --keyfile "$keyfile" "${build}/${container_name}" || die "Failed creating container"

exit 0
