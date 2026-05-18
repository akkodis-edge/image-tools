# image-tools
Collection of tools for working with images of various types.

# Build

```
# Build dependencies
apt install build-essential libcryptsetup-dev libssl-dev

# Additional runtime dependencies
apt install python3-parted squashfs-tools pkcs11-provider bash util-linux bmaptool parted fakeroot \
		e2fsprogs dosfstools udev tar openssl bc

# Additional testing dependencies
apt install python3-cryptography cryptsetup sudo

# Build
make

# Run tests
make test

# Run tests requiring super user privilegies
make test-su

# Running distro tests
# debian 13 / trixie
docker build -t image-tools:debian13 -f debian13.dockerfile .
docker run -i -v /dev:/dev --privileged image-tools:debian13 /bin/sh -c 'make clean && make test && make test-su'
# ubuntu 24.04
docker build -t image-tools:ubuntu2404 -f ubuntu2404.dockerfile .
docker run -i -v /dev:/dev --privileged image-tools:ubuntu2404 /bin/sh -c 'make clean && make test && make test-su'
# archlinux
docker build -t image-tools:archlinux -f archlinux.dockerfile .
docker run -i -v /dev:/dev --privileged image-tools:archlinux /bin/sh -c 'make clean && make test && make test-su'


```

## Image container
Image format for packaging complete disk or partition images with checksum and optional installation scripts. The whole container is signed.

The container is a concatenated blob of:

```
+---------------+-------+-----------------------------------+
| PART          | BYTES | TYPE                              |
+---------------+-------+-----------------------------------+
| container     | n     | squashfs file                     |
+---------------+-------+-----------------------------------+
| tree          | n     | dm-verity verification data       |
+---------------+-------+-----------------------------------+
| root          | n     | dm-verity root hash          (hex)|
+---------------+-------+-----------------------------------+
| digest        | n     | root hash openssl digest     (bin)|
+---------------+-------+-----------------------------------+
| key           | n     | public key of digest signer  (DER)|
+---------------+-------+-----------------------------------+
| magic         | 4     | magic 0x494d4721         (u32, LE)|
+---------------+-------+-----------------------------------+
| reserved      | 28    | All bytes shall be set to 0       |
+---------------+-------+-----------------------------------+
| tree_offset   | 8     | Offset of hash_tree      (u64, LE)|
+---------------+-------+-----------------------------------+
| root_offset   | 8     | Offset of root_hash      (u64, LE)|
+---------------+-------+-----------------------------------+
| digest_offset | 8     | Offset of digest         (u64, LE)|
+---------------+-------+-----------------------------------+
| key_offset    | 8     | Offset of public key     (u64, LE)|
+---------------+-------+-----------------------------------+

The container squashfs file may include either a full disk image or partition images. Possible files:

Available for all:
- preinstall: executable script run before image installation
- postinstall: executable script run after image installation

Full disk installation:
- disk.img: sparse image of full disk
- disk.img.sha256: sha256 of full disk. Used for verifying successful installation.
- disk.img.bmap: blockmap file for installation with bmaptool

Partition installation:
- partition.NAME:      Named partition. Always prefixed with "partition.". Naming depending on usage.
                       For swap-root updates the name should be "partition.rootfs".
- partition.NAME.bmap: blockmap file for installation with bmaptool


Creating containers with "make-image-container".
For full disk installation the disk layout and required filesystem images are provided by argument
--conf and --images.
For a simple case with a single root filesystem the description file could look like, example.yaml:
# Device with 16GB eMMC running linux.
# A/B root partitions and persistent data partition.

disk:
   # Size in bytes, 96% of 16GB disk.
   # 4% capacity reserved for worst 
   # known housekeeping overhead on eMMC.
   size: 15360000000

partitions:
   - type: table_gpt
   - label: rootfs1
     type: raw
     size: 3000
   - label: rootfs2
     type: raw
     size: 3000
   - label: data
     type: ext4
     size: 8000

images:
   - name: image
     type: raw-bmap
     target: label-raw:rootfs1


Creating the container based on this description file (Multiple images can be passed in, space separated):
$ make-image-container.sh -b BUILDDIR -c example.yaml -i image=ROOTFSIMAGE --key SIGNINGKEY example-disk.container

Creating an update container from same ROOTFSIMAGE:
$ make-image-container.sh -b BUILDDIR --partitions ROOTFSIMAGE --key SIGNINGKEY example-update.container

Signatures for container are normally expected to be verified by a list of known and trusted public keys.
Location of the public keys is passed in by --key-dir argument. It is possible to use public key embedded in container by
flag --any-pubkey and thus trust any container, in that case the signature is only for validating integrity.
The images are installed to full disk target by:
$ install-image-container.sh -d BLOCKDEVICE --key-dir PUBKEYDIR

Root update is performed by:
$ swap-root update --container example-update.container

For validation purposes before releasing full disk images to factory the installation is verified by
comparing resulting sha256 of disk with provided disk.img.sha256 inside the container.
Note: In this step no preinstall or postinstall scripts are executed.
$ install-image-container.sh -d BLOCKDEVICE --key-dir PUBKEYDIR --verify-device

It is the responsibility of preinstall and postinstall scripts to return non-zero exit code on errors.
An exit code of zero means the execution was successful.

Hash function will be selected based on key bits. Only RSA and ECDSA type keys are supported.
PKCS#1 v1.5 padding is used with RSA keys.

+-------+----------+--------+
| KEY   | BITS     | HASH   |
+-------+----------+--------+
| RSA   | <  7680  | SHA256 |
+-------+----------+--------+
| RSA   | >= 7680  | SHA384 |
+-------+----------+--------+
| RSA   | >= 15360 | SHA512 |
+-------+----------+--------+
| ECDSA | <  384   | SHA256 |
+-------+----------+--------+
| ECDSA | >= 384   | SHA384 |
+-------+----------+--------+
| ECDSA | >= 512   | SHA512 |
+-------+----------+--------+
```

Container roothash can optionally be signed as a CMS (Cryptographic Message Syntax, RFC 5652) "SignedData Type".

Create an image container signed by a self-signed certificate.

```
# Create self-signed certificate
openssl req -x509 -noenc -newkey EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -keyout tmp.pem -out tmp.crt -days 14 -addext extendedKeyUsage=emailProtection -subj "/CN=image release v0.11.0"

# Create 10MB dummy file
dd if=/dev/random of=image.container bs=1M count=10

# Create signed image container
container-util --create --keyfile tmp.pem --keyfile-ca tmp.crt image.container

# Extract CMS as cms.pem
container-util --signer cms.pem image.container
```

Setup 2-tier CA and signing key

```
# CA key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ca.pem
# CA crt
openssl req -x509 -key ca.pem -out ca.crt -sha256 -days 14600 -addext basicConstraints=critical,CA:TRUE,pathlen:1 -addext keyUsage=critical,keyCertSign -addext extendedKeyUsage=emailProtection -subj "/CN=Akkodis Image CA"

# Inter key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out inter.pem
# Inter cert
openssl req -x509 -CA ca.crt -CAkey ca.pem -key inter.pem -out inter.crt -sha256 -days 14600 -addext basicConstraints=critical,CA:TRUE,pathlen:0 -addext keyUsage=critical,keyCertSign -addext extendedKeyUsage=emailProtection -subj "/CN=Akkodis Image Intermediate"

# Signing key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out user.pem
# Signign cert
openssl req -x509 -CA inter.crt -CAkey inter.pem -key user.pem -out user.crt -sha256 -days 14600 -addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature -addext extendedKeyUsage=emailProtection -subj "/CN=ms@akkodis.se"

# Collect certificate chain as pem stack
cat inter.crt ca.crt > chain.crt
```

Create new CMS with signing key, including certificate chain

```
# inspect cms data
openssl cms -cmsout -in cms.pem -inform pem -print

# Extract roothash
openssl cms -verify -in cms.pem -inform pem -out roothash -binary -noverify

# Sign with new key and include certificate chain
openssl cms -sign -in roothash -md sha256 -signer user.crt -inkey user.pem -certfile chain.crt -out cms2.pem -outform pem -binary -nosmimecap -nodetach
```

Replace CMS in image container

```
# Replace CMS
container-util --replace cms2.pem image.container

# Confirm verification towards root CA
container-util --verify --pubkey-ca ca.crt image.container

# Container verification towards hashed root ca directory
mkdir ca
cp ca.crt ca/
openssl rehash ca
container-util --verify --pubkey-ca-dir ca image.container
```

### simple-container.sh
Skeleton utility providing a base for creating more advanced processing of image files to be deployed. In the provided form it simply repackages a tar archived rootfs into a preformatted filesystem image which is then provided as a full disk and update container.

Example usage:

```
# Build image-tools first
make

# Disk with empty partition table
# 4GB (3,72529 Gib) disk. 96% of disk used.
PATH="build/:$PATH" sample/simple-container.sh --build image/ --name test \
    --disk-size-gb 4 --disk-size-ratio 0.96

# ROOT A/B scheme with data partition.
# 4GB (3,72529 Gib) disk. 96% of disk used.
# 500 MiB ext4 root partitions "rootfs1" and "rootfs2".
#   - "rootfs1" formatted as ext4.
#   - image.tar.bz2 extracted to "rootfs1".
# 500 MiB ext4 "data" partition.
#   - "data" formatted as ext4.
PATH="build/:$PATH" sample/simple-container.sh --build image/ --name test \
    --disk-size-gb 4 --disk-size-ratio 0.96 \
    --data-label data --data-fstype ext4 --data-size-mib 500 \
    --rootfs-label rootfs1 --rootfs-secondary rootfs2 --rootfs-fstype ext4 --rootfs-size-mib 500 \
    --rootfs-image image.tar.bz2

# ESP partition and single root
# 4GB (3,72529 Gib) disk. 96% of disk used.
# 500 MiB fat32 esp partition
# 500 MiB ext4 root partition
PATH="build/:$PATH" sample/simple-container.sh --build image/ --name test \
    --disk-size-gb 4 --disk-size-ratio 0.96 \
    --esp-label boot1 --esp-fstype fat32 --esp-size-mib 500 \
    --rootfs-label rootfs1 --rootfs-fstype ext4 --rootfs-size-mib 500
```
