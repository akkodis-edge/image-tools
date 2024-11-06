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
+---------------+-------+-----------------------+
| PART          | BYTES | TYPE                  |
+---------------+-------+-----------------------+
| Container     | n     | squashfs              |
+---------------+-------+-----------------------+
| Signature     | 4K    | openssl binary digest |
+---------------+-------+-----------------------+
| Public key    | 4K    | DER formatted key     |
+---------------+-------+-----------------------+
```

make-image-container utility will output a container based on a config file describing target device.

The config file needs an additional "disk" section with a "size" key describing size of disk in bytes.

```
disk:
  size: 1000000
  
partitions:
  ...
  
images:
  ...
```

See example "example-linux-container.yaml".

Reference usage for the example file which will output "build/service-image-sdb8000.container".

```
sudo ./make-image-container.sh -b build/ -c example-linux-container.yaml \
	--images "image=../sdb8000/service-image-sdb8000.rootfs.tar.bz2" \
	--key private.pem --path ./image-install.py \
	service-image-sdb8000.container


```
