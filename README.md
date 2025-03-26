# image-tools
Collection of tools for working with images of various types.

## image-install
Partition disk and install images based on configuration.

Config file format:

```
# Entries in config are treated in order, top to bottom.
#
# Optional partitions section.
# Partitions create mode
#   If first entry is a table type (i.e. table_gpt) then
#   partition table will be created and following
#   partition definitions are created as well.
#   For types defining filesystems the filesytem 
#   will be created as well.
#   Created partitions must at a minimum define attributes:
#     label, size
#
# Partitions update mode
#   If first entry is NOT a table type (i.e. table_gpt)
#   then partitions are assumed to already exists
#   and only filesystem operations will be perforemd.
#   Updated partitions must at a minimum define attributes:
#     label
#   Size attribute has no effect.
# 
# List of partition descriptions.
partitions:
     # Type of partition.
     # Supported types:
     #   raw
     #      no filesystem.
     #      Respects attributes:
     #        size, label
     #   ext4
     #      ext4 filesystem
     #      Respects attributes:
     #        size, label, blocksize, fslabel
     #   table_gpt
     #      gpt partition table.
     #      This type must be first list entry.
     #      No attributes.
   - type: ext4
     # gpt label of partition.
     label: rootfs
     # Size of partition in MiB
     size: 1000
     # Optionally define blocksize in bytes.
     # By default blocksize is not defined to mkfs.
     blocksize: 4096
     # Optionally set a filessytem label in addition
     # to gpt label. Defaults to false.
     fslabel: false

# Optional images section.
# List of image descriptions.
images:
     # Name of image. For each image defined in section the
     # a name=path pair must be provided on image-install commandline.
   - name: image
     # Type of image. Supported types:
     #  tar.bz2
     #  raw
     #  raw.bz2
     #  android-sparse
     #  android-sparse.bz2
     #     Note: android-sparse.bz2 not recommended as 
     #           may return errors if decompression too slow.
     #           The tool used for writing image do disk (simg2img)
     #           will attempt to seek within input file
     #           which is piped to stdin through bzip2.
     type: tar.bz2
     # Where to install image. Possible targets:
     #  label:[LABEL_OF_PARTITION]
     #    target partition will be mounted and image installed to mounted root.
     #    note: label does not have to be defined in partitions section.
     #  label:[LABEL_OF_PARTITION]/[PATH]
     #    target partition will be mounted and image installed to mounted root/[PATH].
     #    note: label does not have to be defined in partitions section.
     #  label-raw:[LABEL_OF_PARTITION]
     #    image will be installed directly to partition without mounting.
     #  device
     #    root of device, i.e. /dev/sdb
     target: label:rootfs
     # Optional. Instruct kernel to reload partitions after
     # image installation if set to true. Default value false.
     reload_partitions: false

# Example on installing image to above config:
$ image-install --wipefs --config above.config --device /dev/sdb image=files/rootfs.tar.bz2
```

## install-usb-image
Wrapper to image-install for installing a tar.bz2 archive to usb pen.

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

```

### simple-container.sh
Skeleton utility providing a base for creating more advanced processing of image files to be deployed. In the provided form it simply repackages a tar archived rootfs into a preformatted filesystem image which is then provided as a full disk and update container.

Example usage:

```
sample/simple-container.sh --build build --path ./ --image service-image-rv8007.rootfs.tar.bz2 --name service-v0.0.1

```

### Run tests

```
# prepare build
mkdir -p build/keys
# make test key
openssl genrsa -out build/private.pem 4096
mkdir build/keys
openssl rsa -in build/private.pem -pubout -out build/keys/public.pem
# Make sample archive
echo content1 > build/file1
echo content2 > build/file2
tar -jcf build/sample.tar.bz2 -C build file1 file2
# build container
sudo ./make-image-container.sh -b build/ -c test/small.yaml \
	--images "image=build/sample.tar.bz2" \
	--key build/private.pem --path ./image-install.py \
	sample.container
# prepare target device
truncate -s 21000192 build/blockdevice
# Create loopdevice
sudo losetup --show -P -f build/blockdevice 
# /dev/loop0
# Install and validate image
sudo ./install-image-container.sh --device /dev/loop0 --key-dir build/keys \
	--path ./image-install.py --verify-device build/sample.container
# Install image
sudo ./install-image-container.sh --device /dev/loop0 --key-dir build/keys \
	--path ./image-install.py build/sample.container
```
