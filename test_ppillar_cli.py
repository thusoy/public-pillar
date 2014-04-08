import ppillar

from contextlib import contextmanager
from mock import MagicMock, patch
import os
import random
import shutil
import string
import tempfile
import unittest
import yaml


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class CLITest(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.remove('test-data.yml')


    def test_json_parse(self):
        input_file = os.path.join('test-data', 'plaintext.json')
        key = os.path.join('test-data', 'key2048.pem')
        cli_args = ['-e', input_file, '-k', key, '-o', 'test-data.yml']
        ret = ppillar.main(cli_args)
        self.assertEqual(ret, 0)
        with open('test-data.yml') as fh:
            results = yaml.load(fh)
        self.assertEqual(len(results['all']), 2)
        self.assertTrue('DB_PW' in results['all'])
        self.assertTrue('SECRET_KEY' in results['all'])


class RegressionTest(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.remove('all.sls')


    def test_decryption(self):
        # test that we can decrypt a file encrypted with the public key in test-data
        key = os.path.join('test-data', 'key2048.pem')
        input_file = os.path.join('test-data', 'ciphertext.yml')
        cli_args = ['-k', key, '-d', input_file]
        ret = ppillar.main(cli_args)
        self.assertEqual(ret, 0)
        with open(os.path.join('all.sls')) as fh:
            results = yaml.load(fh)
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
            ret = ppillar.main(['-k', key, '-d', ciphertext])
        self.assertEqual(ret, 0)


class WrongPassEncryptedKeyTest(unittest.TestCase):

    def test_encrypted_key_cli(self):
        key = os.path.join('test-data', 'key2048enc.pem')
        ciphertext = os.path.join('test-data', 'ciphertext.yml')
        getpass_mock = MagicMock(**{'getpass.return_value': 'foo'})
        with patch('ppillar.getpass', getpass_mock):
            ret = ppillar.main(['-k', key, '-d', ciphertext])
        self.assertEqual(ret, 1)


class NonexistentOutputDirectoryTest(unittest.TestCase):

    def setUp(self):
        tempdir = tempfile.gettempdir()
        self.target_dir = os.path.join(tempdir, str([random.choice(string.ascii_letters) for i in range(10)]))


    def tearDown(self):
        shutil.rmtree(self.target_dir, ignore_errors=True)


    def test_nonexisting_target_dir(self):
        source_data = os.path.join('test-data', 'ciphertext.yml')
        ppillar.main(['-k', os.path.join('test-data', 'key2048.pem'), '-d', source_data, '-o',
            self.target_dir])
        self.assertTrue('all.sls' in os.listdir(self.target_dir))
