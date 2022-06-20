#!/bin/bash

FILESYSTEM="ext4"
EXTRA="500"
LABEL=""
DEVICE=""
ARCHIVE=""

print_usage() {
    echo "Usage: install-usb-image [OPTIONS] -d DEVICE -l LABEL ARCHIVE"
    echo "Options:"
    echo "  -d,--device       Target block device, not partition"
    echo "  -f,--filesystem   Filesystem to use. Default ${FILESYSTEM}"
    echo "  -e,--extra        Extra free space in MiB. Default ${EXTRA}"
    echo "  -l,--label        Gptlabel"
}

while [ $# -gt 0 ]; do
	case $1 in
		-f|--filesystem)
		FILESYSTEM="$2"
		shift # past argument
		shift # past value
		;;
	-d|--device)
		DEVICE="$2"
		shift # past argument
		shift # past value
		;;
	-e|--extra)
		EXTRA="$2"
		shift # past argument
		shift # past value
		;;
	-l|--label)
		LABEL="$2"
		shift # past argument
		shift # past value
		;;
	-*|--*)
		print_usage
		exit 1
		;;
	*)
		ARCHIVE="$1"
		shift # past argument
		;;
  esac
done

if [ "x$ARCHIVE" = "x" ]; then
	echo "Missing mandatory argument ARCHIVE"
	exit 1
fi

if [ "x$LABEL" = "x" ]; then
	echo "Missing mandatory argument LABEL"
	exit 1
fi

archive_size=$(( "$(tar -xf ${ARCHIVE} --to-stdout | wc -c)" / 1024 / 1024 ))
partition_size=$(( (("${archive_size}" + "${EXTRA}") / 5) \
						+ "${archive_size}" + "${EXTRA}" ))
echo -n "Calculating partition size.. "
echo "(ARCHIVE ${archive_size} + EXTRA ${EXTRA}) * 1,2 = ${partition_size}MiB"
read -r -d '' config <<- EOM
partitions:
   - label: "${LABEL}"
     fs: "${FILESYSTEM}"
     size: ${partition_size}
     blocksize: 4096

images:
   - name: image
     type: tar.bz2
     target: "label:${LABEL}"
EOM
printf '%s\n' "$config"
if printf '%s\n' "$config" | image-install --wipefs --device "$DEVICE" --config - image="${ARCHIVE}"; then
	echo "Success!"
	exit 0
fi

echo "Image installation failed"
exit 1
