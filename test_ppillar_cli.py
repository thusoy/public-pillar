import ppillar

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


class CLITest(unittest.TestCase):

    def setUp(self):
        self.keyfile = tempfile.NamedTemporaryFile(delete=False)
        self.keyfile.close()
        genrsa_cmd = ['openssl', 'genrsa', '-out', self.keyfile.name, '2048']
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(genrsa_cmd, stdout=devnull, stderr=devnull)


    def tearDown(self):
        with ignored(OSError):
            os.remove(self.keyfile.name)
            os.remove('test-data.yml')


    def test_json_parse(self):
        input_file = os.path.join('test-data', 'plaintext.json')
        cli_args = ['-e', input_file, '-k', self.keyfile.name, '-o', 'test-data.yml']
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
