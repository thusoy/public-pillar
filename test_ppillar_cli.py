import ppillar

import os
import subprocess
import tempfile
import unittest
import yaml

class CLITest(unittest.TestCase):

    def setUp(self):
        self.keyfile = tempfile.NamedTemporaryFile(delete=False)
        self.keyfile.close()
        genrsa_cmd = ['openssl', 'genrsa', '-out', self.keyfile.name, '1024']
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(genrsa_cmd, stdout=devnull, stderr=devnull)


    def tearDown(self):
        os.remove(self.keyfile.name)


    def test_json_parse(self):
        input_file = os.path.join('test-data', 'plaintext.json')
        cli_args = ['-e', input_file, '-k', self.keyfile.name]
        ret = ppillar.main(cli_args)
        self.assertEqual(ret, 0)
        with open('encrypted.yml') as fh:
            results = yaml.load(fh)
        self.assertEqual(len(results['all']), 2)
        self.assertTrue('DB_PW' in results['all'])
        self.assertTrue('SECRET_KEY' in results['all'])


class RegressionTest(unittest.TestCase):

    def test_decryption(self):
        # test that we can decrypt a file encrypted with the public key in test-data
        key = os.path.join('test-data', 'key1024.pem')
        input_file = os.path.join('test-data', 'ciphertext.yml')
        cli_args = ['-k', key, '-i', input_file]
        ret = ppillar.main(cli_args)
        self.assertEqual(ret, 0)
        with open(os.path.join('all.sls')) as fh:
            results = yaml.load(fh)
        self.assertEqual(len(results), 2)
