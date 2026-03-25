FROM ghcr.io/archlinux/archlinux:base-devel

# Update, install git, keys, and all system packages as root
RUN pacman -Syu --noconfirm \
    git \
    cryptsetup openssl python-pyparted squashfs-tools \
    pkcs11-provider bash util-linux curl parted fakeroot e2fsprogs \
    dosfstools udev tar python python-six python-cryptography sudo bc && \
    pacman-key --init && \
    pacman-key --populate archlinux

# Create user aen with sudo access (no password)
RUN groupadd -g 1000 aen && \
    useradd -m -u 1000 -g 1000 -s /bin/bash aen && \
    chown -R aen:aen /home/aen && \
    echo "aen ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/aen && \
    chmod 0440 /etc/sudoers.d/aen

USER aen
RUN git clone https://aur.archlinux.org/bmaptool.git /tmp/bmaptool && \
    cd /tmp/bmaptool && \
    makepkg -si --noconfirm && \
    cd / && rm -rf /tmp/bmaptool

USER root
RUN pacman -Scc --noconfirm && rm -rf /var/cache/pacman/pkg/ /tmp/*
COPY ./ /home/aen/image-tools
RUN chown -R aen:aen /home/aen/

USER aen
WORKDIR /home/aen/image-tools
