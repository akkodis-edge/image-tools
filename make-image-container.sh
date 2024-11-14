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
    echo "  Reserved names: disk.img disk.img.sha256 preinstall postinstall"
    echo ""
    echo "Mandatory:"
    echo "  -b,--build        Path to build directory, will be created if needed"
    echo "Optional:"
    echo "  --partitions      Space separated list to paths of partitions"
    echo "  -c,--conf         Path to yaml config describing disk"
    echo "  -i,--images       Space separated list of imagename=imagepath"
    echo "                    where imagename is defined by --conf file."
    echo "  -p,--path         Path to image-install application. By default resolve by \$PATH"
    echo "  --key             Path to private key for signing image"
    echo "  --disk-name       Name to use for disk image inside container"
    echo "  --preinstall      Path to preinstall script which will be called before image installation"
    echo "  --postinstall     Path to postinstall script which will be called after image installation"
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
		for reserved in "disk.img" "disk.img.sha256" "preinstall" "postinstall"; do
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
fi

if [ "x$partitions" != "x" ]; then
	artifacts="$partitions"
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

# Create squashfs image
mksquashfs $artifacts "${build}/container.squashfs" -noappend -all-root || die "Failed creating squashfs"

# Create verity data
veritysetup --data-block-size=4096 --hash-block-size=4096 format \
	--root-hash-file "${build}/container.roothash" "${build}/container.squashfs" \
	"${build}/container.hashtree" || die "Failed dm-verity formatting"

# Sign root hash with provided method and extract public key
if [ "x$keyfile" != "x" ]; then
	openssl pkey -in "$keyfile" -out "${build}/container.key" -pubout -outform DER || die "Failed getting pubkey from key"
	openssl dgst -sha256 -out "${build}/container.digest" -sign "$keyfile" "${build}/container.roothash" || die "Failed signing roothash"
fi

# Calculate offsets in file
squashfs_size="$(stat -c %s ${build}/container.squashfs)" || die "Failed getting squashfs size"
tree_size="$(stat -c %s ${build}/container.hashtree)" || die "Failed getting hashtree size"
root_size="$(stat -c %s ${build}/container.roothash)" || die "Failed getting roothash size"
digest_size="$(stat -c %s ${build}/container.digest)" || die "Failed getting digest size"
key_size="$(stat -c %s ${build}/container.key)" || die "Failed getting public key size"
tree_offset=$(( $squashfs_size ))
root_offset=$(( $tree_offset + $tree_size ))
digest_offset=$(( $root_offset + $root_size ))
key_offset=$(( $digest_offset + $digest_size ))

echo "Container blob offsets:"
printf " 0x%08x squashfs - %d b\n" 0 $squashfs_size
printf " 0x%08x tree     - %d b\n" $tree_offset $tree_size
printf " 0x%08x root     - %d b\n" $root_offset $root_size
printf " 0x%08x digest   - %d b\n" $digest_offset $digest_size
printf " 0x%08x key      - %d b\n" $key_offset $key_size

printf "%08x" 0x21474d49 | xxd -r -p > "${build}/container.offsets" || die "Failed writing offset"
dd if=/dev/zero of="${build}/container.offsets" bs=28 count=1 oflag=append conv=notrunc
printf "%016x" "$tree_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' | xxd -r -p >> "${build}/container.offsets" || die "Failed writing offset"
printf "%016x" "$root_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' | xxd -r -p >> "${build}/container.offsets" || die "Failed writing offset"
printf "%016x" "$digest_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' | xxd -r -p >> "${build}/container.offsets" || die "Failed writing offset"
printf "%016x" "$key_offset" | sed 's@\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)@0x\8\7\6\5\4\3\2\1@' | xxd -r -p >> "${build}/container.offsets" || die "Failed writing offset"

cat "${build}/container.squashfs" "${build}/container.hashtree" "${build}/container.roothash" \
	"${build}/container.digest" "${build}/container.key" "${build}/container.offsets" \
	> "${build}/${container_name}" || die "Failed assembling container"

exit 0
