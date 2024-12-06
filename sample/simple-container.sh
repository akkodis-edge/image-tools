#!/bin/sh

die () {
	echo "$1"
	exit 1
}

disk_size_gb="16"
rootfs_size_mib="3000"
data_size_mib="8000"

print_usage() {
	echo "Usage: simple-container [OPTIONS]"
	echo "Convert tar-archive of rootfs to ext4 image and package as full disk and update container"
	echo ""
	echo "Mandatory:"
	echo "  -b,--build        Path to build directory"
	echo "  -p,--path         Path to image-tools directory"
	echo "  -i,--image        Path to image file archive"
	echo "  -n,--name         Name of container"
	echo "Optional:"
	echo "  --k,--key         Path to private key for signing image. New key will be generated if not provided."
	echo "  --no-disk         Do not create full disk container"
	echo "  --no-update       Do not create update container"
	echo "  --disk-size       Size of disk in GB (Note: NOT GiB). Default: ${disk_size_gb}"
	echo "  --rootfs-size     Size of rootfs in MiB. Default: ${rootfs_size_mib}"
	echo "  --data-size       Size of data in MiB. Default: ${data_size_mib}"

}

while [ "$#" -gt 0 ]; do
	case $1 in
	-b|--build)
		[ "$#" -gt 1 ] || die "Invalid argument -b/--build"
		build="$2"
		shift # past argument
		shift # past value
		;;
	-p|--path)
		[ "$#" -gt 1 ] || die "Invalid argument -p/--path"
		path="$2"
		shift # past argument
		shift # past value
		;;
	-k|--key)
		[ "$#" -gt 1 ] || die "Invalid argument -k/--key"
		keyfile="$2"
		shift # past argument
		shift # past value
		;;
	-i|--image)
		[ "$#" -gt 1 ] || die "Invalid argument -i/--image"
		image="$2"
		shift # past argument
		shift # past value
		;;
	-n|--name)
		[ "$#" -gt 1 ] || die "Invalid argument -n/--name"
		name="$2"
		shift # past argument
		shift # past value
		;;
	--no-update)
		no_update="yes"
		shift # past argument
		;;
	--no-disk)
		no_disk="yes"
		shift # past argument
		;;
	--disk-size)
		[ "$#" -gt 1 ] || die "Invalid argument --disk-size"
		disk_size_gb="$2"
		shift # past argument
		shift # past value
		;;
	--rootfs-size)
		[ "$#" -gt 1 ] || die "Invalid argument --rootfs-size"
		rootfs_size_mib="$2"
		shift # past argument
		shift # past value
		;;
	--data-size)
		[ "$#" -gt 1 ] || die "Invalid argument --data-size)"
		data_size_mib="$2"
		shift # past argument
		shift # past value
		;;
	*)
		print_usage
		exit 1
		;;
  esac
done

[ "x$build" != "x" ] || die "Missing argument -b/--build"
[ "x$path" != "x" ] || die "Missing argument -p/--path"
[ "x$image" != "x" ] || die "Missing argument -i/--image"
[ "x$name" != "x" ] || die "Missing argument -n/--name"

mkdir -p "$build" || die "Failed creating build dir"

# No key provided -- generate key here. The container must always be signed 
# for integrity validation.
if [ "x$keyfile" = "x" ]; then
	echo "Signing key not provided -- generating..."
	keyfile="${build}/signing-key.pem"
	openssl genrsa -out "$keyfile" 4096 || die "Failed generating key"
fi

# Prepare disk configuration which describes disk layout and
# what payloads to install.
disk_size_bytes_weighted=$(echo "scale=0; ${disk_size_gb}*1000000000*0.96/1" | bc) || die "Failed calculating disk size"
cat << EOF > "${build}/disk-conf.yaml"
# Device with ${disk_size_gb}GB storage..
# A/B root partitions and persistent data partition.

disk:
   # Size in bytes, 96% of disk.
   # 4% capacity reserved for worst 
   # known housekeeping overhead on eMMC.
   size: ${disk_size_bytes_weighted}

partitions:
   - type: table_gpt
   - label: rootfs1
     type: raw
     size: ${rootfs_size_mib} # MiB
   - label: rootfs2
     type: raw
     size: ${rootfs_size_mib} # MiB
   - label: data
     type: raw
     size: ${data_size_mib} # MiB

images:
   - name: rootfs
     type: raw-sparse
     target: label-raw:rootfs1
   - name: data
     type: raw-sparse
     target: label-raw:data
EOF

# Due to the disk being created is 4% smaller than
# actual device the gpt secondary header will not be
# placed at and of the disk. This is fixed by
# a smalll post installation script prepared here.
cat << 'EOF' > "${build}/fix-gpt.sh"
#!/bin/sh
# Move gpt secondary header to end of blockdevice
parted -s --fix "$1" align-check optimal 1
EOF


# Prepare ext4 formatted rootfs -- ensure permissions are kept
echo "Preparing rootfs.."
sudo rm -rf "${build}/rootfs" || die "Failed removing rootfs"
mkdir "${build}/rootfs" || die "Failed creating rootfs dir"
# base image
sudo tar --numeric-owner -xf "$image" -C "${build}/rootfs" || die "Failed extracting base image"
##
# <--- Additional modifications to rootfs here
##
# Create sparse image of virtual partition
rootfs_size_bytes="$((${rootfs_size_mib}*1024*1024))"
truncate -s "$rootfs_size_bytes" "${build}/partition.rootfs" || die "Failed creating sparse image"
sudo mkfs.ext4 -F -b 4096 "${build}/partition.rootfs" -d "${build}/rootfs" || die "Failed creating filesystem"

# Prepare ext4 formatted data -- ensure permissions are kept
echo "Preparing data.."
sudo rm -rf "${build}/data" || die "Failed removing data"
mkdir "${build}/data" || die "Failed creating data dir"
##
# <--- Additional modifications to data here
##
# Create sparse image of virtual partition
data_size_bytes="$((${data_size_mib}*1024*1024))"
truncate -s "$data_size_bytes" "${build}/partition.data" || die "Failed creating sparse image"
sudo mkfs.ext4 -F -b 4096 "${build}/partition.data" -d "${build}/data" || die "Failed creating filesystem"


# Make full disk installation container
if [ "$no_disk" != "yes" ]; then
	sudo "${path}/make-image-container.sh" -b "${build}/build-disk" \
		-c "${build}/disk-conf.yaml" -i "rootfs=${build}/partition.rootfs data=${build}/partition.data" --postinstall "${build}/fix-gpt.sh" \
		-p "${path}/image-install.py" --key "$keyfile" "${name}-disk.container" || die "Failed creating full disk container"
fi

# Make update container
if [ "$no_update" != "yes" ]; then
	sudo "${path}/make-image-container.sh" -b "${build}/build-update" \
		--partitions "${build}/partition.rootfs" \
		-p "${path}/image-install.py" --key "$keyfile" "${name}-update.container" || die "Failed creating update container"
fi

echo "Output files available at:"
[ "$no_disk" = "yes" ] || echo "${build}/build-disk/${name}-disk.container"
[ "$no_update" = "yes" ] || echo "${build}/build-update/${name}-update.container"

exit 0
