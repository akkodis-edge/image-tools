FROM debian:13.4
RUN apt update && apt install -y \
		build-essential libcryptsetup-dev libssl-dev python3-parted squashfs-tools \
		pkcs11-provider bash util-linux bmaptool parted fakeroot e2fsprogs dosfstools \
		udev tar openssl python3-cryptography cryptsetup sudo bc git
COPY ./ /usr/src/image-tools
WORKDIR /usr/src/image-tools

