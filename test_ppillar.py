from ppillar import PublicPillar

from contextlib import contextmanager
import os
import subprocess
import tempfile
import unittest

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
