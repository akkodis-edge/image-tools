# image-tools
Collection of tools for working with images of various types.

## image-install
Partition disk and install images based on configuration.

Config file format:

```
# Optional partitions section.
# List of partition descriptions.
partitions:
     # gpt label of partition.
   - label: rootfs
     # filesystem of partition.
     # Supported filesystems:
     #   raw
     #   ext4
     fs: ext4
     # Size of partition in MiB
     size: 1000
     # Optionally define blocksize in bytes.
     # By default blocksize is not defined to mkfs.
     blocksize: 4096

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
     #     Note: android-sparse.bz2 not recommended as may return errors if decompression too slow.
     #           The tool used for writing image do disk (simg2img) will attempt to seek within input file
     #           which is piped to stdin through bzip2.
     type: tar.bz2
     # Where to install image. Possible targets:
     #  label:[LABEL_OF_PARTITION] (label does not have to be defined in partitions section)
     #  device                     (root of device, i.e. /dev/sdb)
     target: label:rootfs
     # Optional. Instruct kernel to reload partitions after image installation
     # if set to true. Default value false.
     reload_partitions: false

# Example on installing image to above config:
$ image-install --wipefs --config above.config --device /dev/sdb image=files/rootfs.tar.bz2
```

## install-usb-image
Wrapper to image-install for installing a tar.bz2 archive to usb pen.
