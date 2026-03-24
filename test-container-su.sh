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
		if [ -d "${TMP}/mnt2" ]; then
			sudo umount "${TMP}/mnt2" || echo "Failed unmount"
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

# Make disk container
sample/simple-container.sh --build "${TMP}/build" --name sample --key "${TMP}/keys/private.pem" \
    --disk-size-gb 1 --disk-size-ratio 0.96 \
    --rootfs-label rootfs1 --rootfs-fstype ext4 --rootfs-size-mib 40 \
    --rootfs-secondary rootfs2 \
    --rootfs-image "${TMP}/sample.tar.bz2" --path build/ || die "Failed creating container"

# prepare target device
truncate -s 1000000000 "${TMP}/blockdevice" || die "Failed creating blockdevice"
LODEV="$(sudo losetup --show -P -f "${TMP}/blockdevice")" || die "Failed creating loopback device"

# Install container
sudo build/install-image-container --device "$LODEV" --key-dir "${TMP}/keys" \
    --path build "${TMP}/build/sample-disk.container" || die "Failed installing container"

mkdir "${TMP}/mnt" || die "Failed creating mount dir"
sudo mount "${LODEV}p1" "${TMP}/mnt" || die "Failed mounting loop device"
file1="$(cat "${TMP}/mnt/file1")" || die "Failed reading file1"
file2="$(cat "${TMP}/mnt/file2")" || die "Failed reading file2"
[ "$file1" = "content1" ] || die "Failed file1 content"
[ "$file2" = "content2" ] || die "Failed file1 content"

# full disk install container fails without --unmount
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-disk.container" && die "Should fail on unmount on disk"
# works with --unmount
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-disk.container" --unmount || die "Failed with unmount on disk"

# update install container fails without --unmount
sudo mount "${LODEV}p1" "${TMP}/mnt" || die "Failed mounting loop device"
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-update.container" --alias "rootfs:rootfs1" && die "Should fail on unmount on update"
# works with --unmmount
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-update.container" --alias "rootfs:rootfs1" --unmount || die "Failed with unmount on update"

# --unmount detects two mounted partitions
sudo mount "${LODEV}p1" "${TMP}/mnt" || die "Failed mounting loop device"
mkdir "${TMP}/mnt2" || die "Failed creating mountpoint"
sudo mkfs.ext4 "${LODEV}p2" || die "Failed formatting partition"
sudo mount "${LODEV}p2" "${TMP}/mnt2" || die "Failed mounting loop device"
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-disk.container" && die "Should fail on unmount on disk"
sudo build/install-image-container --device "$LODEV" --any-pubkey --path build "${TMP}/build/sample-disk.container" --unmount || die "Failed with unmount on disk"

cleanup
echo "Success!"
exit 0