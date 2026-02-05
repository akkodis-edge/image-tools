#!/bin/sh


die () {
	echo "$1"
	exit 1
}

fstype_to_gpt_type() {
	case $1 in
	ext*)
		echo ext2
		;;
	fat32)
		echo fat32
		;;
	*)
		die "Unknown filesystem type $1"
		;;
	esac
}

build_filesystem() {
	local fsdir="$1"
	local fsimg="$2"
	local fstype="$3"
	local size_mib="$4"
	local archive="$5"

	local fs_size_bytes="$((${size_mib}*1024*1024))"
	local fs_size_kbytes="$((${size_mib}*1024))"
	local cmd="true"

	# Create rootfs dir, remove if already exists to ensure clean build
	mkdir "$fsdir" || die "Failed creating fsdir"
	if [ "x$archive" != "x" ]; then
		cmd="$cmd && tar --numeric-owner -xf "$archive" -C "$fsdir""
	fi
	if [ "$fstype" = "ext4" ]; then
		cmd="$cmd && truncate -s "$fs_size_bytes" "$fsimg" && /usr/sbin/mkfs.ext4 -F -b 4096 "$fsimg" -d "$fsdir""
	elif [ "$fstype" = "fat32" ]; then
		cmd="$cmd && /usr/sbin/mkfs.vfat -F 32 -C "$fsimg" "$fs_size_kbytes" && mcopy -i "$fsimg" -smpQ "$fsdir"/* \:\:/ "
	else
		die "Unsupported filesystem: $fstype"
	fi
	echo "Executing as fakeroot:"
	echo "\"$cmd\""
	fakeroot -- /bin/sh -c "$cmd" || die "Failed creating filesystem"
}

print_usage() {
	echo "Usage: simple-container"
	echo ""
	echo "Mandatory:"
	echo "  -b,--build                Path to build directory"
	echo "  -n,--name                 Name of output"
	echo "  --disk-size-gb            Disk size in GB (Not GiB)"
	echo "  --disk-size-ratio         How many % of disk to use (0.0 ~ 1.0)"
	echo "Optional:"
	echo "  --k,--key                 Path to private key for signing image. New key will be generated if not provided."
	echo "  --esp-label               esp partition label"
	echo "  --esp-secondary           Add a secondary esp partition with this label"
	echo "  --esp-size-mib            esp partition size"
	echo "  --esp-fstype              esp filesystem type"
	echo "  --rootfs-label            rootfs gpt label"
	echo "  --rootfs-secondary        Add a secondary rootfs with this label"
	echo "  --rootfs-size-mib         rootfs size in MIB"
	echo "  --rootfs-fstype           rootfs fstype"
	echo "  --rootfs-image            rootfs tar archive"
	echo "  --data-label              data partition label"
	echo "  --data-size-mib           data partition size"
	echo "  --data-fstype             data partition type"
}

while [ "$#" -gt 0 ]; do
	case $1 in
	-b|--build)
		[ "$#" -gt 1 ] || die "Invalid argument -b/--build"
		build="$2"
		shift # past argument
		shift # past value
		;;
	-k|--key)
		[ "$#" -gt 1 ] || die "Invalid argument -k/--key"
		keyfile="$2"
		shift # past argument
		shift # past value
		;;
	-n|--name)
		[ "$#" -gt 1 ] || die "Invalid argument -n/--name"
		name="$2"
		shift # past argument
		shift # past value
		;;
	--disk-size-gb)
		[ "$#" -gt 1 ] || die "Invalid argument --disk-size-gb"
		disk_size_gb="$2"
		shift # past argument
		shift # past value
		;;
	--disk-size-ratio)
		[ "$#" -gt 1 ] || die "Invalid argument --disk-size-ratio"
		disk_size_ratio="$2"
		shift # past argument
		shift # past value
		;;
	--esp-label)
		[ "$#" -gt 1 ] || die "Invalid argument --esp-label"
		esp_label="$2"
		shift # past argument
		shift # past value
		;;
	--esp-secondary)
		[ "$#" -gt 1 ] || die "Invalid argument --esp-secondary"
		esp_secondary_label="$2"
		shift # past argument
		shift # past value
		;;
	--esp-fstype)
		[ "$#" -gt 1 ] || die "Invalid argument --esp-fstype"
		esp_fstype="$2"
		shift # past argument
		shift # past value
		;;
	--esp-size-mib)
		[ "$#" -gt 1 ] || die "Invalid argument --esp-size-mib"
		esp_size_mib="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-label)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-label"
		rootfs_label="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-fstype)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-fstype"
		rootfs_fstype="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-image)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-image"
		rootfs_image="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-size-mib)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-size-mib"
		rootfs_size_mib="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-secondary)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-secondary"
		rootfs_secondary_label="$2"
		shift # past argument
		shift # past value
		;;
	--data-label)
		[ "$#" -gt 1 ] || die "Invalid argument --data-label"
		data_label="$2"
		shift # past argument
		shift # past value
		;;
	--data-fstype)
		[ "$#" -gt 1 ] || die "Invalid argument --data-fstype"
		data_fstype="$2"
		shift # past argument
		shift # past value
		;;
	--data-size-mib)
		[ "$#" -gt 1 ] || die "Invalid argument --data-size-mib"
		data_size_mib="$2"
		shift # past argument
		shift # past value
		;;
	-h/--help)
		print_usage
		exit 1
		;;
	-*|--*)
		die "Invalid argument: $1"
		;;
	*)
		disk="$1"
		shift # past value
		;;
  esac
done

[ "x$build" != "x" ] || die "Missing argument -b/--build"
[ "x$name" != "x" ] || die "Missing argument -n/--name"
[ "x$disk_size_gb" != "x" ] || die "Missing argument --disk-size-gb"
[ "x$disk_size_ratio" != "x" ] || die "Missing argument --disk-size-ratio"
if [ "x$esp_label" != "x" ]; then
	[ "x$esp_fstype" != "x" ] || die "Missing argument --esp-fstype"
	[ "x$esp_size_mib" != "x" ] || die "Missing argument --esp-size-mib"
fi
if [ "x$rootfs_label" != "x" ]; then
	[ "x$rootfs_fstype" != "x" ] || die "Missing argument --rootfs-fstype"
	[ "x$rootfs_size_mib" != "x" ] || die "Missing argument --rootfs-size-mib"
fi
if [ "x$data_label" != "x" ]; then
	[ "x$data_fstype" != "x" ] || die "Missing argument --data-fstype"
	[ "x$data_size_mib" != "x" ] || die "Missing argument --data-size-mib"
fi

mkdir -p "$build" || die "Failed creating build dir"

# No key provided -- generate key here. The container must always be signed 
# for integrity validation.
if [ "x$keyfile" = "x" ]; then
	echo "Signing key not provided -- generating..."
	keyfile="${build}/signing-key.pem"
	openssl genrsa -out "$keyfile" 1024 || die "Failed generating key"
fi

# Calculate disk size in bytes
disk_size_bytes_weighted=$(echo "scale=0; ${disk_size_gb}*1000000000*${disk_size_ratio}/1" | bc) || die "Failed calculating disk size"
echo "Creating disk of size $disk_size_bytes_weighted bytes ($disk_size_gb GB * $disk_size_ratio)"

# Remove any existing disk
rm -rf "${build}/disk.img" || die "Failed removing existing disk"
# Remove any existing rootfs
rm -rf "${build}/partition.rootfs" || die "Failed removing existing rootfs"
rm -rf "${build}/rootfs" || die "Failed removing existing rootfs"
# Remove any existing data
rm -rf "${build}/partition.data" || die "Failed removing existing data"
rm -rf "${build}/data" || die "Failed removing existing data"

# Create sparse disk
truncate -s "$disk_size_bytes_weighted" "${build}/disk.img" || die "Failed creating disk"

# Create partition table
/usr/sbin/parted -s "${build}/disk.img" mklabel gpt || die "Failed creating partition table"
end=4

# Add esp partition
if [ "x$esp_label" != "x" ]; then
	echo "Adding esp partition: $esp_label"
	start=$end
	end=$(( $start + $esp_size_mib))
	esp_gpt_type="$(fstype_to_gpt_type "$esp_fstype")"
	/usr/sbin/parted -s "${build}/disk.img" mkpart "$esp_label" "$esp_gpt_type" "${start}MiB" "${end}MiB" || die "Failed creating partition"
	/usr/sbin/parted -s "${build}/disk.img" set 1 esp on || die "Failed setting esp flag"
	if [ "x$esp_secondary_label" != "x" ]; then
		echo "Adding esp secondary partition: $esp_secondary_label"
		start=$end
		end=$(( $start + $esp_size_mib))
		/usr/sbin/parted -s "${build}/disk.img" mkpart "$esp_secondary_label" "$esp_gpt_type" "${start}MiB" "${end}MiB" || die "Failed creating partition"
		/usr/sbin/parted -s "${build}/disk.img" set 2 esp on || die "Failed setting esp flag"
	fi
fi

# Add rootfs partition
if [ "x$rootfs_label" != "x" ]; then
	echo "Adding rootfs partition: $rootfs_label"
	start=$end
	end=$(( $start + $rootfs_size_mib))
	rootfs_gpt_type="$(fstype_to_gpt_type "$rootfs_fstype")"
	/usr/sbin/parted -s "${build}/disk.img" mkpart "$rootfs_label" "$rootfs_gpt_type" "${start}MiB" "${end}MiB" || die "Failed creating partition"
	if [ "x$rootfs_secondary_label" != "x" ]; then
		echo "Adding rootfs secondary partition: $rootfs_secondary_label"
		start=$end
		end=$(( $start + $rootfs_size_mib))
		/usr/sbin/parted -s "${build}/disk.img" mkpart "$rootfs_secondary_label" "$rootfs_gpt_type" "${start}MiB" "${end}MiB" || die "Failed creating partition"
	fi

	if [ "x$rootfs_image" != "x" ]; then
		# Build and inject rootfs
		echo "Building and inserting rootfs"
		build_filesystem "${build}/rootfs" "${build}/partition.rootfs" "$rootfs_fstype" "$rootfs_size_mib" "$rootfs_image"
		gpt-insert --label "$rootfs_label" --input "${build}/partition.rootfs" "${build}/disk.img" || die "Failed inserting filesystem in disk"
		# Build rootfs update container
		make-image-container --build "${build}/update" --partitions "${build}/partition.rootfs" --key "$keyfile" "${build}/${name}-update.container" || die "Failed creating update container"
	fi
fi

# Add data partition
if [ "x$data_label" != "x" ]; then
	echo "Adding data partition: $data_label"
	start=$end
	end=$(( $start + $data_size_mib))
	data_gpt_type="$(fstype_to_gpt_type "$data_fstype")"
	/usr/sbin/parted -s "${build}/disk.img" mkpart "$data_label" "$data_gpt_type" "${start}MiB" "${end}MiB" || die "Failed creating partition"
	# Format partition
	echo "Building and inserting data partition"
	build_filesystem "${build}/data" "${build}/partition.data" "$data_fstype" "$data_size_mib" ""
	gpt-insert --label "$data_label" --input "${build}/partition.data" "${build}/disk.img" || die "Failed inserting filesystem in disk"
fi

# Dump partition table
/usr/sbin/parted -s "${build}/disk.img" print

# Due to the disk being created is smaller than
# actual device (if following recommendations)
# the gpt secondary header will not be
# placed at and of the disk. This is fixed by
# a small post installation script prepared here.
cat << 'EOF' > "${build}/fix-gpt.sh"
#!/bin/sh
# Move gpt secondary header to end of blockdevice
parted -s --fix "$1" align-check optimal 1
EOF

# Build full disk container
make-image-container --build "${build}/disk" --disk "${build}/disk.img" --key "$keyfile" --postinstall "${build}/fix-gpt.sh" "${build}/${name}-disk.container" || die "Failed creating disk container"

echo "Success!"

exit 0
