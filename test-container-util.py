#!/usr/bin/python3

import unittest
import tempfile
import os
import subprocess
import struct
import shutil
import datetime
from subprocess import CalledProcessError
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes

class ENOENT(RuntimeError):
    pass
class EBADF(RuntimeError):
    pass
class EFAULT(RuntimeError):
    pass
class EINVAL(RuntimeError):
    pass
class EUNKNOWN(RuntimeError):
    pass

def container_util(args):
    largs = ['build/container-util', '-d']
    largs.extend(args)
    r = subprocess.run(largs, capture_output=True, text=True)
    if r.returncode == 2:
        raise ENOENT(r.stdout + r.stderr)
    if r.returncode == 9:
        raise EBADF(r.stdout + r.stderr)
    if r.returncode == 14:
        raise EFAULT(r.stdout + r.stderr)
    if r.returncode == 22:
        raise EINVAL(r.stdout + r.stderr)
    if r.returncode != 0:
        raise EUNKNOWN(r.stdout + r.stderr)
    return r.stdout

def container_util_verify(container, public_key=None, public_dir=None, public_key_ca=None):
    args = ['--verify',  container]
    extra = []
    if public_key != None:
        extra.extend(['--pubkey', public_key])
    if public_dir != None:
        extra.extend(['--pubkey-dir', public_dir])
    if public_key_ca != None:
        extra.extend(['--pubkey-ca', public_key_ca])
    if not extra:
        extra.append('--pubkey-any')
    args.extend(extra)
    return container_util(args)

def container_util_create(file, private_key):
    return container_util(['--create', '--keyfile', private_key, file])

def container_util_roothash(file, public_key):
    return container_util(['--roothash', '-q', '--pubkey', public_key, file])

def generate_cert_selfigned():
    pkey = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'root CA')
                ])
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(pkey.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    builder = builder.not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
            ),
        critical=True)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        critical=False)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pkey.public_key()),
        critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(pkey.public_key()),
        critical=False)
    cert = builder.sign(pkey, hashes.SHA256())
    return pkey, cert

def generate_file(path, size):
    with open(path, mode='wb') as f:
        f.write(b'\x7a' * size)

def write_file(path, data, encoding=serialization.Encoding.PEM,
                           priv_format=serialization.PrivateFormat.PKCS8):
    # Serialize if needed
    if isinstance(data, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
        out = data.private_bytes(
            encoding=encoding,
            format=priv_format,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(data, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        out = data.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif isinstance(data, x509.Certificate):
        out = data.public_bytes(encoding=encoding)
    elif isinstance(data, (str, bytes, bytearray)):
        out = data
    else:
        raise RuntimeError('Unsupported type for writing: {}'.format(type(data)))

    with open(path, mode='wb') as f:
        f.write(out)

def dmverity_format(tree, data):
    tmp = tempfile.NamedTemporaryFile()
    args = ['/usr/sbin/veritysetup', '--data-block-size=4096', '--hash-block-size=4096',
            'format', '--root-hash-file={}'.format(tmp.name), data, tree]
    r = subprocess.run(args, capture_output=True, text=True, check=True)
    with open(tmp.name, 'r+b') as f:
        out = f.read()
    return out

def sign_data(pkey, data, hash=hashes.SHA256(), rsa_padding=padding.PKCS1v15()):
    if isinstance(pkey, ec.EllipticCurvePrivateKey):
        return pkey.sign(data, ec.ECDSA(hash))
    if isinstance(pkey, rsa.RSAPrivateKey):
        return pkey.sign(data, rsa_padding, hash)
    raise RuntimeError('unsupported pkey type for signing')

def sign_cms(key, cert, certfile, data, out, hash='sha256'):
    args = ['openssl', 'cms', '-sign', '-in', data, '-md' ,hash, '-signer', cert,
            '-inkey', key, '-out', out, '-outform', 'der', '-binary', '-nosmimecap',
            '-nodetach']
    if certfile:
        args.extend(['-certfile', certfile])
    r = subprocess.run(args, capture_output=True, text=True, check=True)
    return r.stdout

def make_header(path, data, tree, roothash, digest, public_key):
    with open(path, mode='wb') as f:
        f.write(struct.pack('<L', 0x494d4721))
        f.write(bytes(28))
        tree_offset = os.path.getsize(data)
        f.write(struct.pack('<Q', tree_offset))
        roothash_offset = tree_offset + os.path.getsize(tree) if roothash else 0
        f.write(struct.pack('<Q', roothash_offset))
        digest_offset = roothash_offset + os.path.getsize(roothash) if digest else 0
        f.write(struct.pack('<Q', digest_offset))
        public_key_offset = digest_offset + os.path.getsize(digest) if digest else tree_offset + os.path.getsize(tree)
        f.write(struct.pack('<Q', public_key_offset))

def assemble_file(path, data, tree, roothash, digest, public_key, header):
    args = ['cat', data, tree]
    if roothash:
        args.append(roothash)
    if digest:
        args.append(digest)
    args.extend([public_key, header])
    with open(path, mode='wb') as f:
        subprocess.run(args, stdout=f, check=True)

class test_verify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.roothash_path = os.path.join(self.dir, 'roothash')
        self.tree = os.path.join(self.dir, 'tree')
        self.data = os.path.join(self.dir, 'data')
        generate_file(self.data, 16384)
        self.private_key_path = os.path.join(self.dir, 'private_key')
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.private_key_path, self.pkey)
        write_file(self.public_key_path, self.pkey.public_key(), encoding=serialization.Encoding.DER)
        self.digest_path = os.path.join(self.dir, 'digest')
        self.header = os.path.join(self.dir, 'header')
        self.container = os.path.join(self.dir, 'container')
        self.roothash = dmverity_format(self.tree, self.data)
        self.digest = sign_data(self.pkey, self.roothash)
        write_file(self.roothash_path, self.roothash)
        write_file(self.digest_path, self.digest)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        self.assertIn('File verified OK', container_util_verify(self.container, public_key=self.public_key_path))
    def test_ok_pubkey_any(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        self.assertIn('File verified OK', container_util_verify(self.container))
    def test_ok_pubkey_dir(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        shutil.copy(self.public_key_path, public_dir)
        self.assertIn('File verified OK', container_util_verify(self.container, public_dir=public_dir))
    def test_cms_ok(self):
        self.ca_key, self.ca_cert = generate_cert_selfigned()
        self.ca_key_path = os.path.join(self.dir, 'ca_key')
        self.ca_cert_path = os.path.join(self.dir, 'ca_cert')
        self.cms_path = os.path.join(self.dir, 'cms')
        write_file(self.ca_key_path, self.ca_key)
        write_file(self.ca_cert_path, self.ca_cert)
        sign_cms(self.ca_key_path, self.ca_cert_path, None, self.roothash_path, self.cms_path)
        make_header(self.header, self.data, self.tree, None, None, self.cms_path)
        assemble_file(self.container, self.data, self.tree, None, None, self.cms_path, self.header)
        self.assertIn('File verified OK', container_util_verify(self.container, public_key_ca=self.ca_cert_path))
    def test_ok_pubkey_dir_multiple_keys(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        shutil.copy(self.public_key_path, public_dir)
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        write_file(os.path.join(public_dir, 'public_key.wrong'), wrong_pkey.public_key())
        self.assertIn('File verified OK', container_util_verify(self.container, public_dir=public_dir))
    def test_error_empty_pubkey_dir(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, public_dir=public_dir)
    def test_error_empty_pubkey_dir(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        write_file(os.path.join(public_dir, 'public_key.wrong'), wrong_pkey.public_key())
        with self.assertRaises(EBADF):
            container_util_verify(self.container, public_dir=public_dir)
    def test_error_wrong_public_key(self):
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        write_file(self.public_key_path, wrong_pkey.public_key(), encoding=serialization.Encoding.DER)
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, public_key=self.public_key_path)
    def test_error_modified_data(self):
        with open(self.data, 'r+b') as f:
            f.write(b'\x00')
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, public_key=self.public_key_path)
    def test_error_no_header(self):
        with self.assertRaises(EBADF):
            container_util_verify(self.data, public_key=self.public_key_path)
    def test_error_no_header(self):
        with self.assertRaises(EBADF):
            container_util_verify(self.data, public_key=self.public_key_path)
    def test_error_file_smaller_than_header(self):
        generate_file(self.data, 63)
        with self.assertRaises(EBADF):
            container_util_verify(self.data, public_key=self.public_key_path)
    def test_error_invalid_header_magic(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        with open(self.header, 'r+b') as f:
            f.write(b'\x00')
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container, public_key=self.public_key_path)
    def test_error_no_file(self):
        with self.assertRaises(ENOENT):
            container_util_verify(os.path.join(self.dir, 'no-container'), public_key=self.public_key_path)

class test_create(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.data = os.path.join(self.dir, 'data')
        generate_file(self.data, 16384)
        self.private_key_path = os.path.join(self.dir, 'private_key')
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.private_key_path, self.pkey)
        write_file(self.public_key_path, self.pkey.public_key())
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        container_util_create(self.data, self.private_key_path)
        self.assertIn('File verified OK', container_util_verify(self.data, public_key=self.public_key_path))

class test_roothash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.roothash_path = os.path.join(self.dir, 'roothash')
        self.tree = os.path.join(self.dir, 'tree')
        self.data = os.path.join(self.dir, 'data')
        generate_file(self.data, 16384)
        self.private_key_path = os.path.join(self.dir, 'private_key')
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.private_key_path, self.pkey)
        write_file(self.public_key_path, self.pkey.public_key(), encoding=serialization.Encoding.DER)
        self.digest_path = os.path.join(self.dir, 'digest')
        self.header = os.path.join(self.dir, 'header')
        self.container = os.path.join(self.dir, 'container')
        self.roothash = dmverity_format(self.tree, self.data)
        self.digest = sign_data(self.pkey, self.roothash)
        write_file(self.roothash_path, self.roothash)
        write_file(self.digest_path, self.digest)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        make_header(self.header, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path)
        assemble_file(self.container, self.data, self.tree, self.roothash_path, self.digest_path, self.public_key_path, self.header)
        with open(self.roothash_path, 'r') as f:
            roothash = f.read()
        self.assertEqual(container_util_roothash(self.container, self.public_key_path), '{}\n'.format(roothash))

class test_key_types(unittest.TestCase):
    def setUp(self):
        traditional=serialization.PrivateFormat.TraditionalOpenSSL
        pkcs8=serialization.PrivateFormat.PKCS8
        pkcs1=padding.PKCS1v15()
        pss=padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH)
        self.rsa_key_types = [
            # bits, hash, pkey_format, padding, success
            (1024, hashes.SHA256(), pkcs8, pkcs1, True),
            (2048, hashes.SHA256(), pkcs8, pkcs1, True),
            (3072, hashes.SHA256(), pkcs8, pkcs1, True),
            (4096, hashes.SHA256(), pkcs8, pkcs1, True),
            # traditional format OK
            (4096, hashes.SHA256(), traditional, pkcs1, True),
            # error on wrong hash
            (4096, hashes.SHA1(), pkcs8, pkcs1, False),
            # error on wrong padding
            (4096, hashes.SHA256(), pkcs8, pss, False)
        ]
        self.ec_key_types = [
            # oid, hash, pkey_format, success
            (ec.SECP192R1, hashes.SHA256(), pkcs8, True),
            (ec.SECP224R1, hashes.SHA256(), pkcs8, True),
            (ec.SECP256K1, hashes.SHA256(), pkcs8, True),
            (ec.SECP256R1, hashes.SHA256(), pkcs8, True),
            (ec.SECP384R1, hashes.SHA384(), pkcs8, True),
            (ec.SECP521R1, hashes.SHA512(), pkcs8, True),
            # traditional format OK
            (ec.SECP192R1, hashes.SHA256(), traditional, True),
            # error on wrong hash
            (ec.SECP521R1, hashes.SHA256(), pkcs8, False),
        ]
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_rsa_verify(self):
        for bits, hash, pkey_format, padding, success in self.rsa_key_types:
            # generate data
            data_path = os.path.join(self.dir, 'rsa-{}.data'.format(bits))
            generate_file(data_path, 16384)
            # generate and write keys
            pkey = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            pkey_path = os.path.join(self.dir, 'rsa-{}.priv'.format(bits))
            pub_path  = os.path.join(self.dir, 'rsa-{}.pub'.format(bits))
            write_file(pkey_path, pkey, priv_format=pkey_format)
            write_file(pub_path, pkey.public_key(), encoding=serialization.Encoding.DER)
            # Generate tree and roothash
            tree_path = os.path.join(self.dir, 'rsa-{}.tree'.format(bits))
            root_path = os.path.join(self.dir, 'rsa-{}.root'.format(bits))
            roothash = dmverity_format(tree_path, data_path)
            # generate and write digest
            digest_path = os.path.join(self.dir, 'rsa-{}.digest'.format(bits))
            digest = sign_data(pkey, roothash, hash=hash, rsa_padding=padding)
            # create header
            write_file(root_path, roothash)
            write_file(digest_path, digest)
            header_path = os.path.join(self.dir, 'rsa-{}.header'.format(bits))
            make_header(header_path, data_path, tree_path, root_path, digest_path, pub_path)
            # assemble container
            container_path = os.path.join(self.dir, 'rsa-{}.container'.format(bits))
            assemble_file(container_path, data_path, tree_path, root_path, digest_path, pub_path, header_path)
            # verify
            if success:
                self.assertIn('File verified OK', container_util_verify(container_path, public_key=pub_path))
            else:
                with self.assertRaises(EBADF):
                    container_util_verify(container_path, public_key=pub_path)
    def test_rsa_create(self):
        for bits, hash, pkey_format, extra, success in self.rsa_key_types:
            if not success:
                # We can't force --create to use invalid signing parameters, skip
                continue
            # generate data
            data_path = os.path.join(self.dir, 'rsa-{}.data'.format(bits))
            generate_file(data_path, 16384)
            # generate and write keys
            pkey = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            pkey_path = os.path.join(self.dir, 'rsa-{}.priv'.format(bits))
            pub_path  = os.path.join(self.dir, 'rsa-{}.pub'.format(bits))
            write_file(pkey_path, pkey, priv_format=pkey_format)
            write_file(pub_path, pkey.public_key())
            container_util_create(data_path, pkey_path)
            self.assertIn('File verified OK', container_util_verify(data_path, public_key=pub_path))
    def test_ec_verify(self):
        for curve, hash, pkey_format, success in self.ec_key_types:
            # generate data
            data_path = os.path.join(self.dir, 'ec-{}.data'.format(curve.name))
            generate_file(data_path, 16384)
            # generate and write keys
            pkey = ec.generate_private_key(curve())
            pkey_path = os.path.join(self.dir, 'ec-{}.priv'.format(curve.name))
            pub_path  = os.path.join(self.dir, 'ec-{}.pub'.format(curve.name))
            write_file(pkey_path, pkey, priv_format=pkey_format)
            write_file(pub_path, pkey.public_key(), encoding=serialization.Encoding.DER)
            # Generate tree and roothash
            tree_path = os.path.join(self.dir, 'ec-{}.tree'.format(curve.name))
            root_path = os.path.join(self.dir, 'ec-{}.root'.format(curve.name))
            roothash = dmverity_format(tree_path, data_path)
            # generate and write digest
            digest_path = os.path.join(self.dir, 'ec-{}.digest'.format(curve.name))
            digest = sign_data(pkey, roothash, hash=hash)
            # create header
            write_file(root_path, roothash)
            write_file(digest_path, digest)
            header_path = os.path.join(self.dir, 'ec-{}.header'.format(curve.name))
            make_header(header_path, data_path, tree_path, root_path, digest_path, pub_path)
            # assemble container
            container_path = os.path.join(self.dir, 'ec-{}.container'.format(curve.name))
            assemble_file(container_path, data_path, tree_path, root_path, digest_path, pub_path, header_path)
            # verify
            if success:
                self.assertIn('File verified OK', container_util_verify(container_path, public_key=pub_path))
            else:
                with self.assertRaises(EBADF):
                    container_util_verify(container_path, public_key=pub_path)
    def test_ec_create(self):
        for curve, hash, pkey_format, success in self.ec_key_types:
            if not success:
                # We can't force --create to use invalid signing parameters, skip
                continue
            # generate data
            data_path = os.path.join(self.dir, 'rsa-{}.data'.format(curve.name))
            generate_file(data_path, 16384)
            # generate and write keys
            pkey = ec.generate_private_key(curve())
            pkey_path = os.path.join(self.dir, 'rsa-{}.priv'.format(curve.name))
            pub_path  = os.path.join(self.dir, 'rsa-{}.pub'.format(curve.name))
            write_file(pkey_path, pkey, priv_format=pkey_format)
            write_file(pub_path, pkey.public_key())
            container_util_create(data_path, pkey_path)
            self.assertIn('File verified OK', container_util_verify(data_path, public_key=pub_path))

if __name__ == '__main__':
    unittest.main()
