#!/usr/bin/env python3

import sys
import os
import parted
import errno
from argparse import ArgumentParser, RawDescriptionHelpFormatter

def get_partitions(image):
    dev = parted.device.Device(image)
    if (dev.type != parted._ped.DEVICE_FILE):
        raise ValueError('IMAGE [{}] not of type FILE [{}]'.format(dev.type, parted._ped.DEVICE_FILE))
    disk = parted.newDisk(dev)
    if disk.type != 'gpt':
        raise ValueError('IMAGE header [{}] not of type gpt'.format(disk.type))
    part_data = {}
    for part in disk.partitions:
        part_data[part.name] = {'offset': part.geometry.start * dev.sectorSize,
                                'size': part.geometry.length * dev.sectorSize}
    return part_data

def write(input, size, output):
    bytes_remaining = size
    block_size = 4096
    while bytes_remaining:
        bytes = input.read(min(block_size, bytes_remaining))
        if len(bytes) == 0 or len(bytes) > bytes_remaining:
            raise RuntimeError('Unexpected number of bytes read from input')
        if output.write(bytes) != len(bytes):
            raise RuntimeError('Unexpected number of bytes written to output')
        bytes_remaining -= len(bytes)

def main():
    parser = ArgumentParser(description='''Write data to image file gpt partitions''',
                                     epilog='''Return value:
0 for success, 1 for failure
''',
                                     formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('IMAGE', help='Path to image file')
    parser.add_argument('--label', help='Label of target partition')
    parser.add_argument('--input', help='Data being written to target partition')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if not args.label:
        raise ValueError('Mandatory argument --label missing')
    if not args.input:
        raise ValueError('Mandatory argument --input missing')

    part_data = get_partitions(args.IMAGE)

    if not args.label in part_data:
        if args.debug:
            print(part_data)
        raise RuntimeError('Partition label "{}" not found in IMAGE'.format(args.label))

    with open(args.input, 'rb') as input_file:
        input_size = os.fstat(input_file.fileno()).st_size
        if part_data[args.label]['size'] < input_size:
            raise RuntimeError('Partition "{}" [{} b] smaller than input [{} b]'
                                .format(args.label, part_data[args.label]['size'], input_size))
        if args.debug:
            print('Input size:  {} b'.format(input_size))
            print('Part offset: {} b'.format(part_data[args.label]['offset']))
            print('Part size:   {} b'.format(part_data[args.label]['size']))

        with open(args.IMAGE, 'r+b') as output_file:
            offset = 0
            size = 0
            while True:
                try:
                    offset = input_file.seek(offset, os.SEEK_DATA)
                except OSError as e:
                    if e.errno == errno.ENXIO:
                        # No further data available
                        break
                next_hole = input_file.seek(offset, os.SEEK_HOLE)
                size = next_hole - offset

                if args.debug:
                    print('input: {} -> {} [{} b]'.format(offset, offset + size, size))

                input_file.seek(offset, os.SEEK_SET)
                output_file.seek(part_data[args.label]['offset'] + offset, os.SEEK_SET)
                write(input_file, size, output_file)
                offset += size

    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Error: {}'.format(e))
    sys.exit(1)
