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
from cryptography.hazmat.primitives.serialization import pkcs7

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

def container_util_verify(container, public_key=None, public_dir=None, public_key_ca=None, public_key_ca_dir=None):
    args = ['--verify',  container]
    extra = []
    if public_key != None:
        extra.extend(['--pubkey', public_key])
    if public_dir != None:
        extra.extend(['--pubkey-dir', public_dir])
    if public_key_ca != None:
        extra.extend(['--pubkey-ca', public_key_ca])
    if public_key_ca_dir != None:
        extra.extend(['--pubkey-ca-dir', public_key_ca_dir])
    if not extra:
        extra.append('--pubkey-any')
    args.extend(extra)
    return container_util(args)

def container_util_create(file, private_key):
    return container_util(['--create', '--keyfile', private_key, file])

def container_util_roothash(file, public_key=None, public_key_ca=None):
    args = ['--roothash', '-q', file]
    if public_key != None:
        args.extend(['--pubkey', public_key])
    if public_key_ca != None:
        args.extend(['--pubkey-ca', public_key_ca])
    return container_util(args)

# Will be self-signed if issuers is None.
def generate_cert(cn, issuer_pkey=None, issuer=None, ca=False, path_length=None):
    pkey = ec.generate_private_key(ec.SECP256R1())
    subject_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)
            ])
    if issuer == None:
        issuer_name = subject_name
        authority = x509.AuthorityKeyIdentifier.from_issuer_public_key(pkey.public_key())
        usage = x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True if ca else False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                )
        basic = x509.BasicConstraints(ca=ca, path_length=path_length)
        signer = pkey
    else:
        issuer_name = issuer.subject
        authority = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value)
        usage = x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True if ca else False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                )
        basic = x509.BasicConstraints(ca=ca, path_length=path_length)
        signer = issuer_pkey

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(pkey.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    builder = builder.not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
    builder = builder.add_extension(
        basic,
        critical=True)
    builder = builder.add_extension(
        usage,
        critical=True)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        critical=False)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pkey.public_key()),
        critical=False)
    builder = builder.add_extension(
        authority,
        critical=False)
    cert = builder.sign(signer, hashes.SHA256())
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

# Create openssl-style CA directory for trusted certificate lookup
def openssl_rehash(dir):
    subprocess.run(['openssl', 'rehash', dir],
                   capture_output=True, text=True, check=True)

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

def sign_cms(pkey, cert, data, certfile=[], hash=hashes.SHA256()):
    builder = pkcs7.PKCS7SignatureBuilder()
    builder = builder.set_data(data)

    padding = None
    if isinstance(pkey, rsa.RSAPrivateKey):
        padding = padding.PKCS1v15()
    builder = builder.add_signer(cert, pkey, hash, rsa_padding=padding)

    for certificate in certfile:
        builder = builder.add_certificate(certificate)

    options = (pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoCapabilities)
    return builder.sign(serialization.Encoding.DER, options)

def make_header(data, tree, roothash, digest, public_key):
    out = bytearray()
    out += struct.pack('<L', 0x494d4721)
    out.extend(b'0' * 28)
    tree_offset = os.path.getsize(data)
    out += struct.pack('<Q', tree_offset)
    roothash_offset = tree_offset + os.path.getsize(tree) if roothash else 0
    out += struct.pack('<Q', roothash_offset)
    digest_offset = roothash_offset + len(roothash) if digest else 0
    out += struct.pack('<Q', digest_offset)
    public_key_offset = digest_offset + len(digest) if digest else tree_offset + os.path.getsize(tree)
    out += struct.pack('<Q', public_key_offset)
    return bytes(out)

def pub_to_der(pub):
    return pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def assemble_file(path, data, tree, roothash, digest, public_key, header=None):
    args = ['cat', data, tree]
    with open(path, mode='wb') as f:
        subprocess.run(args, stdout=f, check=True)
        if roothash != None:
            f.write(roothash)
        if digest != None:
            f.write(digest)
        f.write(public_key)
        if not header:
            f.write(make_header(data, tree, roothash, digest, public_key))
        else:
            f.write(header)

class test_verify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.tree_path = os.path.join(self.dir, 'tree')
        self.data_path = os.path.join(self.dir, 'data')
        generate_file(self.data_path, 16384)
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.public_key_path, self.pkey.public_key(), encoding=serialization.Encoding.DER)
        self.container_path = os.path.join(self.dir, 'container')
        self.roothash = dmverity_format(self.tree_path, self.data_path)
        self.roothash_path = os.path.join(self.dir, 'roothash')
        write_file(self.roothash_path, self.roothash)
        self.digest = sign_data(self.pkey, self.roothash)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_key=self.public_key_path))
    def test_ok_pubkey_any(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        self.assertIn('File verified OK', container_util_verify(self.container_path))
    def test_ok_pubkey_dir(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        shutil.copy(self.public_key_path, public_dir)
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_dir=public_dir))
    def test_cms_ss_ok(self):
        self.ca_key, self.ca_cert = generate_cert('self-signed', ca=True, path_length=0)
        self.ca_cert_path = os.path.join(self.dir, 'ca_cert')
        write_file(self.ca_cert_path, self.ca_cert)
        cms = sign_cms(self.ca_key, self.ca_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_key_ca=self.ca_cert_path))
    def test_cms_ss_ok_pubkey_any(self):
        self.ca_key, self.ca_cert = generate_cert('self-signed', ca=True, path_length=0)
        cms = sign_cms(self.ca_key, self.ca_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        self.assertIn('File verified OK', container_util_verify(self.container_path))
    def test_cms_ss_ok_pubkey_ca_dir(self):
        self.ca_key, self.ca_cert = generate_cert('self-signed', ca=True, path_length=0)
        cms = sign_cms(self.ca_key, self.ca_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        ca_dir = os.path.join(self.dir, 'ca')
        os.mkdir(ca_dir)
        write_file(os.path.join(ca_dir, 'cert1.crt'), self.ca_cert)
        openssl_rehash(ca_dir)
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_key_ca_dir=ca_dir))
    def test_cms_t1_ok(self):
        self.ca_key, self.ca_cert = generate_cert('root-ca', ca=True, path_length=0)
        self.signer_key, self.signer_cert = generate_cert('signer', issuer_pkey=self.ca_key, issuer=self.ca_cert, ca=False, path_length=None)
        self.ca_cert_path = os.path.join(self.dir, 'ca_cert')
        write_file(self.ca_cert_path, self.ca_cert)
        cms = sign_cms(self.signer_key, self.signer_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_key_ca=self.ca_cert_path))
    def test_cms_t1_ok_pubkey_any(self):
        self.ca_key, self.ca_cert = generate_cert('root-ca', ca=True, path_length=0)
        self.signer_key, self.signer_cert = generate_cert('signer', issuer_pkey=self.ca_key, issuer=self.ca_cert, ca=False, path_length=None)
        cms = sign_cms(self.signer_key, self.signer_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        self.assertIn('File verified OK', container_util_verify(self.container_path))
    def test_cms_t1_ok_pubkey_ca_dir(self):
        self.ca_key, self.ca_cert = generate_cert('root-ca', ca=True, path_length=0)
        self.signer_key, self.signer_cert = generate_cert('signer', issuer_pkey=self.ca_key, issuer=self.ca_cert, ca=False, path_length=None)
        cms = sign_cms(self.signer_key, self.signer_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        ca_dir = os.path.join(self.dir, 'ca')
        os.mkdir(ca_dir)
        write_file(os.path.join(ca_dir, 'cert1.crt'), self.ca_cert)
        openssl_rehash(ca_dir)
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_key_ca_dir=ca_dir))
    def test_ok_pubkey_dir_multiple_keys(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        shutil.copy(self.public_key_path, public_dir)
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        write_file(os.path.join(public_dir, 'public_key.wrong'), wrong_pkey.public_key())
        self.assertIn('File verified OK', container_util_verify(self.container_path, public_dir=public_dir))
    def test_error_empty_pubkey_dir(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        with self.assertRaises(EBADF):
            container_util_verify(self.container_path, public_dir=public_dir)
    def test_error_empty_pubkey_dir(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        public_dir = os.path.join(self.dir, 'public_dir')
        os.mkdir(public_dir)
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        write_file(os.path.join(public_dir, 'public_key.wrong'), wrong_pkey.public_key())
        with self.assertRaises(EBADF):
            container_util_verify(self.container_path, public_dir=public_dir)
    def test_error_wrong_public_key(self):
        wrong_pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(wrong_pkey.public_key()))
        with self.assertRaises(EBADF):
            container_util_verify(self.container_path, public_key=self.public_key_path)
    def test_error_modified_data(self):
        with open(self.data_path, 'r+b') as f:
            f.write(b'\x00')
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        with self.assertRaises(EBADF):
            container_util_verify(self.container_path, public_key=self.public_key_path)
    def test_error_no_header(self):
        with self.assertRaises(EBADF):
            container_util_verify(self.data_path, public_key=self.public_key_path)
    def test_error_file_smaller_than_header(self):
        generate_file(self.data_path, 63)
        with self.assertRaises(EBADF):
            container_util_verify(self.data_path, public_key=self.public_key_path)
    def test_error_invalid_header_magic(self):
        invalid_header = bytearray(make_header(self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key())))
        invalid_header[0:1] = b'\x00'
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()), invalid_header)
        with self.assertRaises(EBADF):
            container_util_verify(self.container_path, public_key=self.public_key_path)
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
        self.data_path = os.path.join(self.dir, 'data')
        generate_file(self.data_path, 16384)
        self.private_key_path = os.path.join(self.dir, 'private_key')
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.private_key_path, self.pkey)
        write_file(self.public_key_path, self.pkey.public_key())
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        container_util_create(self.data_path, self.private_key_path)
        self.assertIn('File verified OK', container_util_verify(self.data_path, public_key=self.public_key_path))

class test_roothash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(delete=True)
        self.dir = self.tmpdir.name
        self.tree_path = os.path.join(self.dir, 'tree')
        self.data_path = os.path.join(self.dir, 'data')
        generate_file(self.data_path, 16384)
        self.public_key_path = os.path.join(self.dir, 'public_key')
        write_file(self.public_key_path, self.pkey.public_key(), encoding=serialization.Encoding.DER)
        self.container_path = os.path.join(self.dir, 'container')
        self.roothash = dmverity_format(self.tree_path, self.data_path)
        self.digest = sign_data(self.pkey, self.roothash)
    def tearDown(self):
        self.tmpdir.cleanup()
    def test_ok(self):
        assemble_file(self.container_path, self.data_path, self.tree_path, self.roothash, self.digest, pub_to_der(self.pkey.public_key()))
        self.assertEqual(container_util_roothash(self.container_path, public_key=self.public_key_path), '{}\n'.format(self.roothash.decode('UTF-8')))
    def test_cms_ok(self):
        self.ca_key, self.ca_cert = generate_cert('root-ca')
        self.ca_cert_path = os.path.join(self.dir, 'ca_cert')
        self.cms_path = os.path.join(self.dir, 'cms')
        write_file(self.ca_cert_path, self.ca_cert)
        cms = sign_cms(self.ca_key, self.ca_cert, self.roothash)
        assemble_file(self.container_path, self.data_path, self.tree_path, None, None, cms)
        self.assertEqual(container_util_roothash(self.container_path, public_key_ca=self.ca_cert_path), '{}\n'.format(self.roothash.decode('UTF-8')))

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
            pub_path  = os.path.join(self.dir, 'rsa-{}.pub'.format(bits))
            write_file(pub_path, pkey.public_key(), encoding=serialization.Encoding.DER)
            # Generate tree and roothash
            tree_path = os.path.join(self.dir, 'rsa-{}.tree'.format(bits))
            roothash = dmverity_format(tree_path, data_path)
            # generate digest
            digest = sign_data(pkey, roothash, hash=hash, rsa_padding=padding)
            # assemble container
            container_path = os.path.join(self.dir, 'rsa-{}.container'.format(bits))
            assemble_file(container_path, data_path, tree_path, roothash, digest, pub_to_der(pkey.public_key()))
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
            pub_path  = os.path.join(self.dir, 'ec-{}.pub'.format(curve.name))
            pkey = ec.generate_private_key(curve())
            write_file(pub_path, pkey.public_key())
            # Generate tree and roothash
            tree_path = os.path.join(self.dir, 'ec-{}.tree'.format(curve.name))
            roothash = dmverity_format(tree_path, data_path)
            # generate digest
            digest = sign_data(pkey, roothash, hash=hash)
            # assemble container
            container_path = os.path.join(self.dir, 'ec-{}.container'.format(curve.name))
            assemble_file(container_path, data_path, tree_path, roothash, digest, pub_to_der(pkey.public_key()))
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
