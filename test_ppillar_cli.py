import ppillar

from contextlib import contextmanager
from mock import MagicMock, patch
import os
import sys
import random
import shutil
import string
import tempfile
import unittest
import yaml

try:
    from StringIO import StringIO
except ImportError:
    # python 3
    from io import StringIO


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class RegressionTest(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.remove('all.sls')


    def test_decryption(self):
        # test that we can decrypt a file encrypted with the public key in test-data
        key = os.path.join('test-data', 'key2048.pem')
        input_file = os.path.join('test-data', 'ciphertext.yml')
        cli_args = ['-k', key, 'decrypt', input_file]
        ret = ppillar.main(cli_args)
        self.assertEqual(ret, 0)
        output = sys.stdout.getvalue().strip()
        results = yaml.load(output)
        self.assertEqual(len(results), 2)


class EncryptedKeyTest(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.remove('all.sls')


    def test_encrypted_key_cli(self):
        key = os.path.join('test-data', 'key2048enc.pem')
        ciphertext = os.path.join('test-data', 'ciphertext.yml')
        getpass_mock = MagicMock(**{'getpass.return_value': 'test'})
        with patch('ppillar.getpass', getpass_mock):
            ret = ppillar.main(['-k', key, 'decrypt', ciphertext])
        self.assertEqual(ret, 0)


class WrongPassEncryptedKeyTest(unittest.TestCase):

    def test_encrypted_key_cli(self):
        key = os.path.join('test-data', 'key2048enc.pem')
        ciphertext = os.path.join('test-data', 'ciphertext.yml')
        getpass_mock = MagicMock(**{'getpass.return_value': 'foo'})
        with patch('ppillar.getpass', getpass_mock):
            ret = ppillar.main(['-k', key, 'decrypt', ciphertext])
        self.assertEqual(ret, 1)


class NonexistentOutputDirectoryTest(unittest.TestCase):

    def setUp(self):
        tempdir = tempfile.gettempdir()
        self.target_dir = os.path.join(tempdir,
            ''.join([random.choice(string.ascii_letters) for i in range(10)]))


    def tearDown(self):
        shutil.rmtree(self.target_dir, ignore_errors=True)


    def test_nonexisting_target_dir(self):
        source_data = os.path.join('test-data', 'encrypted_dir')
        key = os.path.join('test-data', 'key2048.pem')
        ppillar.main(['-k', key, 'decrypt', source_data, '-o', self.target_dir])
        self.assertTrue('database.yml' in os.listdir(self.target_dir))


class EncryptionTest(unittest.TestCase):

    def setUp(self):
        self.dec_ppillar = ppillar.PublicPillar(os.path.join('test-data', 'key2048.pem'))
        self.key = os.path.join('test-data', 'key2048.pub')


    def test_simple_encryption(self):
        secret = 'supersecret'
        self._do_check(secret)


    def test_longer_encryption(self):
        secret = str([os.urandom(10) for i in range(10)])
        self._do_check(secret)


    def _do_check(self, secret):
        ret = ppillar.main(['-k', self.key, 'encrypt', secret])
        self.assertEqual(ret, 0)
        output = sys.stdout.getvalue().strip()
        if output[0] == '{':
            # was encrypted with symmetric key, parse the yaml output
            output = yaml.load(output)
        self.assertEqual(self.dec_ppillar.decrypt(output), secret)


    def test_file_encryption(self):
        secret = '@' + os.path.join('test-data', 'key2048.pem')
        ret = ppillar.main(['-k', self.key, 'encrypt', secret])
        self.assertEqual(ret, 0)
        output = yaml.load(sys.stdout.getvalue().strip())
        rsa_preamble = '-----BEGIN RSA PRIVATE KEY-----'
        self.assertTrue(self.dec_ppillar.decrypt(output).startswith(rsa_preamble))


    def test_encrypt_stdin(self):
        secret = 'supersecret'
        with patch('ppillar.sys.stdin', StringIO(secret)):
            ret = ppillar.main(['-k', self.key, 'encrypt'])
        self.assertEqual(ret, 0)
        output = sys.stdout.getvalue().strip()
        self.assertEqual(self.dec_ppillar.decrypt(output), 'supersecret')
