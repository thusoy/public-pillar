from ppillar import PublicPillar

from contextlib import contextmanager
import os
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
        self.enc_ppillar = PublicPillar(os.path.join('test-data', 'key2048.pub'))
        self.dec_ppillar = PublicPillar(os.path.join('test-data', 'key2048.pem'))


    def test_ppillar(self):
        input_dicts = [
            # Plain key-value dict
            {
                'db': 'secretstuff',
            },
            # Deeply nested dict
            {
                'servers': {
                    'web': {
                        'apache': {
                            'debian': 'secretdebianpw',
                            'rhel': 'secretrhelpw',
                        }
                    }
                }
            },
            # Several values
            {
                'key1': 'val1',
                'key2': 'val2',
                'key3': 'val3',
            },
            # Long values over several lines
            {
                'long_key'*100: ('secret'*100 + '\n')*20,
            },
            # Random data
            {
                'random': str([os.urandom(10) for i in range(10)]),
            },
            # Almost looks like a encrypted long test
            {
                'ciphertext': 'not very long after all',
            },
            # Almost breakage again
            {
                'key': 'breakage'
            }
        ]
        for input_dict in input_dicts:
            encrypted = self.enc_ppillar.encrypt_dict(input_dict)
            self.assertEqual(self.dec_ppillar.decrypt_dict(encrypted), input_dict)


class ShortKeyTest(unittest.TestCase):

    def setUp(self):
        self.ppillar = PublicPillar(os.path.join('test-data', 'key1024.pem'))


    def test_encrypt_long_string(self):
        data = 'secret'*100
        self.assertRaises(ValueError, self.ppillar.encrypt, data)


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
