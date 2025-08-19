#!/usr/bin/python3

import unittest
import tempfile
import os
import subprocess
import struct
from subprocess import CalledProcessError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class ENOENT(Exception):
    pass
class EBADF(Exception):
    pass
class EFAULT(Exception):
    pass
class EINVAL(Exception):
    pass
class EUNKNOWN(Exception):
    pass

def container_util(args):
    largs = ['./container-util.sh']
    largs.extend(args)
    r = subprocess.run(largs, capture_output=True, text=True)
    if r.returncode == 2:
        raise ENOENT
    if r.returncode == 9:
        raise EBADF
    if r.returncode == 14:
        raise EFAULT
    if r.returncode == 22:
        raise EINVAL
    if r.returncode != 0:
        raise EUNKNOWN
    return r.stdout

def container_util_verify(container, public_key):
    return container_util(['--verify', '--pubkey', public_key, container])

def container_util_create(file, private_key):
    return container_util(['--create', '--keyfile', private_key, file])

def generate_rsa_keypair(key_size):
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public = private.public_key()
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def generate_file(path, size):
    with open(path, mode='wb') as f:
        f.write(b'\x7a' * size)

def write_file(path, data):
    with open(path, mode='wb') as f:
        f.write(data)

def dmverity_format(roothash, tree, data):
    args = ['/usr/sbin/veritysetup', '--data-block-size=4096', '--hash-block-size=4096',
            'format', '--root-hash-file={}'.format(roothash), data, tree]
    r = subprocess.run(args, capture_output=True, text=True, check=True)
    return r.stdout

def sign_data(key, data, digest):
    args = ['openssl', 'dgst', '-sha256', '-out', digest, '-sign', key, data]
    r = subprocess.run(args, capture_output=True, text=True, check=True)
    return r.stdout

def make_header(path, data, tree, roothash, digest, public_key):
    with open(path, mode='wb') as f:
        f.write(struct.pack('<L', 0x494d4721))
        f.write(bytes(28))
        tree_offset = os.path.getsize(data)
        f.write(struct.pack('<Q', tree_offset))
        roothash_offset = tree_offset + os.path.getsize(tree)
        f.write(struct.pack('<Q', roothash_offset))
        digest_offset = roothash_offset + os.path.getsize(roothash)
        f.write(struct.pack('<Q', digest_offset))
        public_key_offset = digest_offset + os.path.getsize(digest)
        f.write(struct.pack('<Q', public_key_offset))

def assemble_file(path, data, tree, roothash, digest, public_key, header):
    with open(path, mode='wb') as f:
        subprocess.run(['cat', data, tree, roothash, digest, public_key, header],
                       stdout=f, check=True)

class test_verify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_pem, cls.public_pem = generate_rsa_keypair(1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.roothash = os.path.join(self.dir, 'roothash')
        self.tree = os.path.join(self.dir, 'tree')
        self.data = os.path.join(self.dir, 'data')
        generate_file(self.data, 16384)
        self.private_key = os.path.join(self.dir, 'private_key')
        self.public_key = os.path.join(self.dir, 'public_key')
        write_file(self.private_key, self.private_pem)
        write_file(self.public_key, self.public_pem)
        self.digest = os.path.join(self.dir, 'digest')
        self.header = os.path.join(self.dir, 'header')
        self.container = os.path.join(self.dir, 'container')
        dmverity_format(self.roothash, self.tree, self.data)
        sign_data(self.private_key, self.roothash, self.digest)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        make_header(self.header, self.data, self.tree, self.roothash, self.digest, self.public_key)
        assemble_file(self.container, self.data, self.tree, self.roothash, self.digest, self.public_key, self.header)
        self.assertIn('File verified OK', container_util_verify(self.container, self.public_key))
    def test_error_wrong_public_key(self):
        wrong_private_pem, wrong_public_pem = generate_rsa_keypair(1024)
        write_file(self.public_key, wrong_public_pem)
        make_header(self.header, self.data, self.tree, self.roothash, self.digest, self.public_key)
        assemble_file(self.container, self.data, self.tree, self.roothash, self.digest, self.public_key, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, self.public_key)
    def test_error_modified_data(self):
        with open(self.data, 'r+b') as f:
            f.write(b'\x00')
        make_header(self.header, self.data, self.tree, self.roothash, self.digest, self.public_key)
        assemble_file(self.container, self.data, self.tree, self.roothash, self.digest, self.public_key, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, self.public_key)
    def test_error_no_header(self):
        with self.assertRaises(EBADF):
            container_util_verify(self.data, self.public_key)
    def test_error_no_header(self):
        with self.assertRaises(EBADF):
            container_util_verify(self.data, self.public_key)
    def test_error_file_smaller_than_header(self):
        generate_file(self.data, 63)
        with self.assertRaises(EBADF):
            container_util_verify(self.data, self.public_key)
    def test_error_invalid_header_magic(self):
        make_header(self.header, self.data, self.tree, self.roothash, self.digest, self.public_key)
        with open(self.header, 'r+b') as f:
            f.write(b'\x00')
        assemble_file(self.container, self.data, self.tree, self.roothash, self.digest, self.public_key, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, self.public_key)

class test_create(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_pem, cls.public_pem = generate_rsa_keypair(1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.data = os.path.join(self.dir, 'data')
        generate_file(self.data, 16384)
        self.private_key = os.path.join(self.dir, 'private_key')
        self.public_key = os.path.join(self.dir, 'public_key')
        write_file(self.private_key, self.private_pem)
        write_file(self.public_key, self.public_pem)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        container_util_create(self.data, self.private_key)
        self.assertIn('File verified OK', container_util_verify(self.data, self.public_key))

if __name__ == '__main__':
    unittest.main()
