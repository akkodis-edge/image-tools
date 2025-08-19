#!/bin/bash
set -x

# Require bash due to builtin read

# Tests that need execution as super user

TMP="NONE"
LODEV="NONE"

cleanup() {
	if [ "$TMP" != "NONE" ]; then
		if [ -d "${TMP}/mnt" ]; then
			sudo umount "${TMP}/mnt" || echo "Failed unmount"
		fi
		sudo rm -r "$TMP" || echo "Failed removing TMP"
		TMP="NONE"
	fi
	if [ "$LODEV" != "NONE" ]; then
		if ! sudo losetup -d "$LODEV"; then
			echo "Failed destroying loopback device"
			exit 1
		fi
		LODEV="NONE"
	fi
}
die() {
	echo "$1"
	cleanup
	exit 1
}

# Prepare work area
TMP="$(mktemp -d)" || die "Failed creating temp dir"

# prepare keys
mkdir -p "${TMP}/keys" || die "Failed creating key dir"
openssl genrsa -out "${TMP}/keys/private.pem" 2048 || die "Failed generating key"
openssl rsa -in "${TMP}/keys/private.pem" -pubout -out "${TMP}/keys/public.pem" || die "Failed extracting public key"

# Make sample archive
echo content1 > "${TMP}/file1" || die "Failed making file"
echo content2 > "${TMP}/file2" || die "Failed making file"
tar -jcf "${TMP}/sample.tar.bz2" -C "$TMP" file1 file2 || die "Failed making archive"

# Make sample disk config
cat << EOF > "${TMP}/disk-conf.yaml"
disk:
   size: 20971520
partitions:
   - type: table_gpt
   - label: first
     type: ext4
     size: 10
images:
   - name: image
     type: tar.bz2
     target: label:first
EOF

# build container
mkdir "${TMP}/build" || die "Failed creating build dir"
sudo build/make-image-container -c "${TMP}/disk-conf.yaml" \
    --images "image=${TMP}/sample.tar.bz2" --key "${TMP}/keys/private.pem" \
    --path build --build "${TMP}/build" \
    sample.container || die "Failed creating container"

# prepare target device
truncate -s 21000192 "${TMP}/blockdevice" || die "Failed creating blockdevice"
LODEV="$(sudo losetup --show -P -f "${TMP}/blockdevice")" || die "Failed creating loopback device"

# Install container
sudo build/install-image-container --device "$LODEV" --key-dir "${TMP}/keys" \
    --path build "${TMP}/build/sample.container" || die "Failed installing container"

mkdir "${TMP}/mnt" || die "Failed creating mount dir"
sudo mount "${LODEV}p1" "${TMP}/mnt" || die "Failed mounting loop device"
file1="$(cat "${TMP}/mnt/file1")" || die "Failed reading file1"
file2="$(cat "${TMP}/mnt/file2")" || die "Failed reading file2"
[ "$file1" = "content1" ] || die "Failed file1 content"
[ "$file2" = "content2" ] || die "Failed file1 content"

cleanup
exit 0