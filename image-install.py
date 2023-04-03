#!/usr/bin/env python3

# deps:
#   wipefs
#   mount
#   umount
#   parted
#   partprobe
#   blkid
#   mkfs.ext4
#   tar
#   sync
#   dd
#   bzcat
#   simg2img

import os
import sys
import subprocess
import argparse
import shutil
import pathlib
import tempfile
from contextlib import contextmanager

import yaml

class ConfigError(Exception):
    pass

class InvalidArgument(Exception):
    pass

def make_ext4(partition, config):
    args = ['-F', '-q']
    if 'blocksize' in config:
        args.extend(['-b', str(config['blocksize'])])
    if config['fslabel']:
        args.extend(['-L', config['label']])
    args.append(partition)
    run_command('mkfs.ext4', args)
    
def make_raw(partition, config):
    pass

def make_fat32(partition, config):
    run_command('mkfs.fat', ['-F', '32',  partition])

partition_types = {
    'ext4': make_ext4,
    'raw': make_raw,
    'fat32': make_fat32,
}
partition_parted_fs_type = {
    'ext4': 'ext2',
    'raw': None,
    'fat32': 'fat32',   
}

def partlabel_to_part(label, device=None):
    args = ['-l', '-o', 'device', '-t', f'PARTLABEL={label}']
    if device:
        args.append(device)
    return run_command('blkid', args, capture=True).strip('\n')

def split_target(target, delim=':'):
    l = target.split(delim, 1)
    if len(l) > 1:
        return (l[0], l[1])
    return (l[0], None)



@contextmanager
def mount(partition):
    mounted = False
    tmpdir = tempfile.TemporaryDirectory()
    try:
        run_command('mount', [partition, tmpdir.name])
        mounted = True
        yield tmpdir.name
    finally:
        if mounted:
            run_command('umount', [partition])
        tmpdir.cleanup()

def install_tar_bz2(device, target, file):
    (type, name) = split_target(target)
    part = None
    if type == 'label':
        (partname, dirpath) = split_target(name, delim='/')
        part = partlabel_to_part(partname, device=device)
    if part is None:
        raise ConfigError(f'Unresolved target: {target}')
    with mount(part) as path:
        args = ['--numeric-owner', '-xf', file, '-C']
        if dirpath:
            args.append(path + '/'  + dirpath)
        else:
            args.append(path)
        run_command('tar', args)

@contextmanager
def popen(cmd, args, stdin=None, stdout=None):
    l = [shutil.which(cmd)]
    if l[0] is None:
        raise OSError(f'Could not find {cmd}')
    l.extend(args)
    p = subprocess.Popen(l, stdin=stdin, stdout=stdout)
    try:
        yield p
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()

def dd(input, output, bz2=False):
        if bz2:
            with popen('bzcat', [input], stdout=subprocess.PIPE) as bzcat:
                with popen('dd', [f'of={output}', 'bs=1M'], stdin=bzcat.stdout) as dd:
                    dd.wait()
                    bzcat.wait()
                    if dd.returncode:
                        raise OSError(f'dd exited with {dd.returncode}')
                    if bzcat.returncode:
                        raise OSError(f'bzcat exited with {bzcat.returncode}')
        else:
            run_command('dd', [f'if={input}', f'of={output}', 'bs=1M'])

def install_raw(device, target, file, bz2=False):
    (type, name) = split_target(target)
    out = None
    if type == 'device' and name is None and device:
        out = device
    if type == 'label' and name is not None:
        (partname, dirpath) = split_target(name, delim='/')
        out = partlabel_to_part(partname, device=device)
    if out is None:
        raise ConfigError(f'Unresolved target: {target}')
    if dirpath:
        with mount(out) as path:
            dd(file, f'{path}/{dirpath}', bz2)
    else:
        dd(file, out, bz2)

def install_raw_bz2(device, target, file):
    install_raw(device, target, file, bz2=True)
    
def install_android_sparse(device, target, file, bz2=False):
    (type, name) = split_target(target)
    out = None
    if type == 'device' and name is None and device:
        out = device
    if type == 'label' and name is not None:
        out = partlabel_to_part(name, device=device)
    if out is None:
        raise ConfigError(f'Unresolved target: {target}')
    if bz2:
        with popen('bzcat', [file], stdout=subprocess.PIPE) as bzcat:
            with popen('simg2img', ['-', out], stdin=bzcat.stdout) as simg:
                simg.wait()
                bzcat.wait()
                if simg.returncode:
                    raise OSError(f'simg2img exited with {simg.returncode}')
                if bzcat.returncode:
                    raise OSError(f'bzcat exited with {dd.returncode}')
    else:
        run_command('simg2img', [file, out])
    
def install_android_sparse_bz2(device, target, file):
    install_android_sparse(device, target, file, bz2=True)
    
image_types = {       
    'tar.bz2': install_tar_bz2,
    'raw': install_raw,
    'raw.bz2': install_raw_bz2,
    'android-sparse': install_android_sparse,
    'android-sparse.bz2': install_android_sparse_bz2,
}

def read_config(path):
    if path == '-':
        return sys.stdin.read()
    with open(path, 'r') as f:
        return f.read()

def split_images(images):
    d = {}
    for i in images:
        l = i.split('=', 1)
        if len(l) != 2:
            raise InvalidArgument('images argument invalid format')
        if l[0] in d:
            raise InvalidArgument('images argument duplicate names detected')
        d[l[0]] = l[1]
    return d

def validate_images(images):
    for name, path in images.items():
        if not os.path.isfile(path):
            raise InvalidArgument(f'image "{name}" not found at path: {path}')

def check_attribute(name, dict, attribute, type):
    if not attribute in dict:
        raise ConfigError(f'{name} missing {attribute} attribute')
    if not isinstance(dict[attribute], type):
        raise ConfigError(f'{name} {attribute} not of type {type}')

def prepare_config(config, images):
    if 'partitions' in config:
        if not isinstance(config['partitions'], list):
            raise ConfigError('partitions not of type list')
        create_partitions = False
        for index, p in enumerate(config['partitions']):
            # Test for special case where first partitions entry may be
            # a partition table instruction.
            if index == 0 and p['type'] == 'table_gpt':
                create_partitions = True
                continue
            check_attribute('partition', p, 'label', str)
            check_attribute('partition', p, 'type', str)
            if 'blocksize' in p:
                check_attribute('partition', p, 'blocksize', int)
            p['fslabel'] = p.get('fslabel', False)
            check_attribute('partition', p, 'fslabel', bool)
            if not p['type'] in partition_types:
                raise ConfigError(f'partition unknown type: {p["type"]}')
            if create_partitions:
                # These attributes are mandatory when creating new partitions.
                check_attribute('partition', p, 'size', int)

    if 'images' in config:
        if not isinstance(config['images'], list):
            raise ConfigError('images not of type list')
        for i in config['images']:
            check_attribute('image', i, 'name', str)
            check_attribute('image', i, 'type', str)
            check_attribute('image', i, 'target', str)
            i['reload_partitions'] = i.get('reload_partitions', False)
            check_attribute('image', i, 'reload_partitions', bool)
            if not i['name'] in images:
                raise InvalidArgument(f'image "{i["name"]}" missing path argument')

def mounted_partitions(starts_with=None):
    list = []
    with open('/proc/mounts', 'r') as f:
        data = f.read().split('\n')
    cond = lambda x: x.startswith(starts_with) if starts_with else True
    return [x.split(' ', 1)[0] for x in data if cond(x)]

def run_command(cmd, args, capture=False):
    l = [shutil.which(cmd)]
    if l[0] is None:
        raise OSError(f'Could not find {cmd}')
    l.extend(args)
    return subprocess.run(l, check=True, capture_output=capture, text=True).stdout

def partprobe(device):
    run_command('partprobe', [device])

def create_partitions(config, device):
    partitions = config['partitions']
    # Create partitions if first partition entry is a partition table type.
    if len(partitions) > 0 and partitions[0]['type'] == 'table_gpt':
        print(f'creating gpt partition table on device {device}')
        run_command('parted', ['-s', device, 'mklabel', 'gpt'])
        start = 4
        partitions = partitions[1:]
        for p in partitions:
            end = start + p['size']
            args = ['-s', device, 'mkpart', p['label']]
            if partition_parted_fs_type[p['type']] is not None:
                args.append(partition_parted_fs_type[p['type']])
            args.extend([f'{start}MiB', f'{end}MiB'])
            run_command('parted', args)
            start += p['size']
        partprobe(device)
    
    # Always format defined partitions.
    for p in partitions:
        part = partlabel_to_part(p['label'], device=device)
        print(f'creating {p["type"]} filesystem on {part} with label {p["label"]}')
        partition_types[p['type']](part, p)
 
def install_images(config, device, images):
    for i in config['images']:
        type = i['type']
        target = i['target']
        file = images[i['name']]
        print(f'install of {type} to {target} from {file}')
        image_types[type](device, target, file)
        if 'reload_partitions' in i and i['reload_partitions']:
            print('partition reload requested..')
            partprobe(device)

def is_create_partitions(config):
    return 'partitions' in config and len(config['partitions']) > 0 \
        and config['partitions'][0]['type'] == 'table_gpt'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''Image installer''',
                                     epilog='''Return value:
0 for success, 1 for failure                                
''',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', required=True, help='Session configuration. When config is "-", read standard input')
    parser.add_argument('--device', help='Name of block device')
    parser.add_argument('--force-unmount', action='store_true', help='Unmount any mounted partitions on --device')
    parser.add_argument('--wipefs', action='store_true', help='Wipe any existing filesystems from --device if partitions node present in config')
    parser.add_argument('--log', help='Path to optional output logfile')
    parser.add_argument('images', nargs='*', help='Paths to images defined in config. I.e. image=rootfs.tar.bz')
    args = parser.parse_args()
    
    if args.device and not pathlib.Path(args.device).is_block_device() and not os.path.isfile(args.device):
        print('device not found', file=sys.stderr)
        sys.exit(1)
    
    if args.wipefs and not args.device:
        print('missing --wipefs requirement --device')
        sys.exit(1)
    
    if args.log:
        try:
            with open(args.log, 'w') as f:
                pass
        except IOError:
            print('outout log path write access denied', file=sys.stderr)
            sys.exit(1)
    
    config = yaml.load(read_config(args.config), Loader=yaml.loader.SafeLoader)
    images = split_images(args.images)
    validate_images(images)
    prepare_config(config, images)

    if is_create_partitions(config) and not args.device:
        print('missing partition create requirement --device')
        sys.exit(1)
    
    to_unmount = []
    if is_create_partitions(config):
        to_unmount = mounted_partitions(starts_with=args.device)
    elif 'partitions' in config and len(config['partitions']) > 0:
        mounted = mounted_partitions()
        to_unmount = []
        for cpart in config['partitions']:
            block = partlabel_to_part(cpart['label'])
            if block in mounted:
                to_unmount.append(block)   
    if len(to_unmount) > 0:
        print('mounted partitions: ', to_unmount, sep='\n')
        if not args.force_unmount:
            print('partitions mounted but --force-unmount not set', file=sys.stderr)
            sys.exit(1)
        for part in to_unmount:
            print(f'unmounting {part}')
            run_command('umount', [part])

    if args.wipefs:
        print('wiping partition table..')
        run_command('wipefs', ['--all', args.device])
        partprobe(args.device)
            
    if 'partitions' in config:
        create_partitions(config, args.device)
        
    if 'images' in config:
        install_images(config, args.device, images)
        print('Syncing filesystem')
        run_command('sync', [])    
    
    if args.log:
        config['log'] = {
            'device': args.device,
            'force-unmount': args.force_unmount,
            'wipefs': args.wipefs,
            'images': {k: os.path.basename(v) for (k, v) in images.items()},
        }
        print(f'Writing log to {args.log}')
        with open(args.log, 'w') as f:
            f.write(yaml.safe_dump(config, sort_keys=False))
            
    sys.exit(0)
