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
    args.append(partition)
    run_command('mkfs.ext4', args)
    
def make_raw(partition, config):
    pass

fs_types = {
    'ext4': make_ext4,
    'raw': make_raw,
}

def partlabel_to_part(device, label):
    return run_command('blkid', ['-l', '-o', 'device', '-t', f'PARTLABEL={label}', device], capture=True).strip('\n')

def split_target(target):
    l = target.split(':', 1)
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
        part = partlabel_to_part(device, name)
    if part is None:
        raise ConfigError(f'Unresolved target: {target}')
    with mount(part) as path:
        run_command('tar', ['-xf', file, '-C', path])

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

def install_raw(device, target, file, bz2=False):
    (type, name) = split_target(target)
    out = None
    if type == 'device' and name is None:
        out = device
    if type == 'label' and name is not None:
        out = partlabel_to_part(device, name)
    if out is None:
        raise ConfigError(f'Unresolved target: {target}')
    if bz2:
        with popen('bzcat', [file], stdout=subprocess.PIPE) as bzcat:
            with popen('dd', [f'of={out}', 'bs=1M'], stdin=bzcat.stdout) as dd:
                dd.wait()
                bzcat.wait()
                if dd.returncode:
                    raise OSError(f'dd exited with {dd.returncode}')
                if bzcat.returncode:
                    raise OSError(f'bzcat exited with {bzcat.returncode}')
    else:
        run_command('dd', [f'if={file}', f'of={out}', 'bs=1M'])

def install_raw_bz2(device, target, file):
    install_raw(device, target, file, bz2=True)
    
def install_android_sparse(device, target, file, bz2=False):
    (type, name) = split_target(target)
    out = None
    if type == 'device' and name is None:
        out = device
    if type == 'label' and name is not None:
        out = partlabel_to_part(device, name)
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
        for p in config['partitions']:
            check_attribute('partition', p, 'label', str)
            check_attribute('partition', p, 'fs', str)
            if not p['fs'] in fs_types:
                raise ConfigError(f'partition fs unknown type: {p["fs"]}')
            check_attribute('partition', p, 'size', int)
            if 'blocksize' in p:
                check_attribute('partition', p, 'blocksize', int)

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

def mounted_partitions(device):
    list = []
    with open('/proc/mounts', 'r') as f:
        data = f.read()
        for line in data.split('\n'):
            if line.startswith(device):
                list.append(line.split(' ', 1)[0])
    return list

def list_partitions(device):
    l = []
    with open('/proc/partitions', 'r') as f:
        data = f.read()
        for line in data.split('\n'):
            cols = line.split(' ')
            if cols[-1].startswith(device.lstrip('/dev/')):
                l.append(f'/dev/{cols[-1]}')
    return l

def run_command(cmd, args, capture=False):
    l = [shutil.which(cmd)]
    if l[0] is None:
        raise OSError(f'Could not find {cmd}')
    l.extend(args)
    return subprocess.run(l, check=True, capture_output=capture, text=True).stdout

def partprobe(device):
    run_command('partprobe', [device])

def create_partitions(config, device):
    run_command('parted', ['-s', device, 'mklabel', 'gpt'])
    start = 4
    for p in config['partitions']:
        end = start + p['size']
        run_command('parted', ['-s', device, 'mkpart', p['label'], p['fs'], f'{start}MiB', f'{end}MiB'])
        start += p['size']
    
    partprobe(device)
    for p in config['partitions']:
        part = partlabel_to_part(device, p['label'])
        print(f'creating {p["fs"]} filesystem on {part} with label {p["label"]}')
        fs_types[p['fs']](part, config)
 
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
            
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''Image installer''',
                                     epilog='''Return value:
0 for success, 1 for failure                                
''',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', required=True, help='Session configuration. When config is "-", read standard input')
    parser.add_argument('--device', required=True, help='Name of block device')
    parser.add_argument('--force-unmount', action='store_true', help='Unmount any mounted partitions on --device')
    parser.add_argument('--wipefs', action='store_true', help='Wipe any existing filesystems from --device if partitions node present in config')
    parser.add_argument('--log', help='Path to optional output logfile')
    parser.add_argument('images', nargs='*', help='Paths to images defined in config. I.e. image=rootfs.tar.bz')
    args = parser.parse_args()
    
    if not pathlib.Path(args.device).is_block_device() and not os.path.isfile(args.device):
        print('device not found', file=sys.stderr)
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

    mounted = mounted_partitions(args.device)
    if len(mounted) > 0:
        if not args.force_unmount:
            print('device partitions are mounted', file=sys.stderr)
            sys.exit(1)
        for part in mounted:
            print(f'unmounting {part}')
            run_command('umount', [part])
            
    if args.wipefs:
        print('wiping partition table..')
        run_command('wipefs', ['--all', args.device])
            
    if 'partitions' in config:
        parts = list_partitions(args.device)
        if len(parts) > 0:
            print('requested creating partition table but it already exists', file=sys.stderr)
        print('creating partition table..')
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
