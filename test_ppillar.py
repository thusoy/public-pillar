from ppillar import PublicPillar

from contextlib import contextmanager
import os
import subprocess
import tempfile
import unittest
import yaml

@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class SecurePillarTest(unittest.TestCase):

    def setUp(self):
        self.keyfile = tempfile.NamedTemporaryFile(delete=False)
        genrsa_cmd = ['openssl', 'genrsa', '-out', self.keyfile.name, '2048']
        with open(os.devnull, 'w') as devnull:
            # Shelling out to openssl because it's orders of magnitude faster
            # than Crypto.PublicKey.RSA.generate()
            subprocess.check_call(genrsa_cmd, stdout=devnull, stderr=devnull)
        self.keyfile.close()
        self.ppillar = PublicPillar(self.keyfile.name)


    def tearDown(self):
        with ignored(OSError):
            os.remove(self.keyfile.name)
            os.remove('all.sls')


    def test_encrypt(self):
        val = 'secretstuff'
        encrypted = self.ppillar.encrypt(val)
        self.assertEqual(self.ppillar.decrypt(encrypted), 'secretstuff')


    def test_short_dict_val(self):
        source = {
            'test': 'supersecret',
        }
        encrypted = self.ppillar.encrypt_dict(source)
        self.assertEqual(self.ppillar.decrypt_dict(encrypted), source)


    def test_long_dict_val(self):
        source = {
            'test': 'secret' * 100,
            'other': 'hey, ho and a bottle of rum' * 20,
        }
        self.assertTrue(self.ppillar.key.size() < len(source['test'])*8)
        encrypted = self.ppillar.encrypt_dict(source)
        self.assertEqual(self.ppillar.decrypt_dict(encrypted), source)


    def test_multiline(self):
        source = 'this\nspans\nseveral\nlines'
        encrypted = self.ppillar.encrypt(source)
        self.assertEqual(self.ppillar.decrypt(encrypted), source)


class ShortKeyTest(unittest.TestCase):

    def setUp(self):
        self.keyfile = tempfile.NamedTemporaryFile(delete=False)
        self.keyfile.close()
        genrsa_cmd = ['openssl', 'genrsa', '-out', self.keyfile.name, '1024']
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(genrsa_cmd, stdout=devnull, stderr=devnull)
        self.ppillar = PublicPillar(self.keyfile.name)


    def tearDown(self):
        with ignored(OSError):
            os.remove(self.keyfile.name)
            os.remove('all.sls')


    def test_encrypt_long_string(self):
        data = 'secret'*100
        self.assertRaises(ValueError, self.ppillar.encrypt, data)


class NestedDataTest(unittest.TestCase):

    def setUp(self):
        self.keyfile = tempfile.NamedTemporaryFile(delete=False)
        genrsa_cmd = ['openssl', 'genrsa', '-out', self.keyfile.name, '2048']
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(genrsa_cmd, stdout=devnull, stderr=devnull)
        self.keyfile.close()
        self.ppillar = PublicPillar(self.keyfile.name)


    def test_nested_data(self):
        data = {
            'servers': {
                'apache': {
                    'password': 'secret',
                },
                'nginx': {
                    'password': 'very secret',
                }
            }
        }
        enc_dict = self.ppillar.encrypt_dict(data)
        plaintext_data = self.ppillar.decrypt_dict(enc_dict)
        self.assertEqual(data, plaintext_data)


class EncryptedPrivateKeyTest(unittest.TestCase):

    def setUp(self):
        self.ppillar = PublicPillar(os.path.join('test-data', 'key2048enc.pem'), passphrase='test')


    def test_encrypted_private_key(self):
        with open(os.path.join('test-data', 'plaintext.json')) as fh:
            plaintext = yaml.load(fh)
        with open(os.path.join('test-data', 'ciphertext.yml')) as fh:
            enc_data = yaml.load(fh)
        decrypted_plaintext = self.ppillar.decrypt_dict(enc_data)
        self.assertEqual(plaintext, decrypted_plaintext)


class WrongKeyTest(unittest.TestCase):

    def test_wrong_pass_encrypted_key(self):
        self.assertRaises(ValueError, PublicPillar, os.path.join('test-data', 'key2048enc.pem'),
            passphrase='foo')
