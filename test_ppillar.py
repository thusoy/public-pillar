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
        input_values = [
            # Plain key-value dict
            'secretstuff',
            # Long value over several lines
            ('secret'*100 + '\n')*20,
            # Random  binary data
            str([os.urandom(10) for i in range(10)]),
        ]
        for input_value in input_values:
            encrypted = self.enc_ppillar.encrypt(input_value)
            plaintext = {
                'secret_data': input_value,
            }
            ciphertext = {
                'secret_data': encrypted,
            }
            self.assertEqual(self.dec_ppillar.decrypt_dict(ciphertext), plaintext)


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
        expected_plaintext = {
            'database': {
                'password': 'supersecretdbpassword',
            },
            'webserver': {
                'secret_key': 'signstuffwiththiskey',
            }
        }
        with open(os.path.join('test-data', 'ciphertext.yml')) as fh:
            enc_data = yaml.load(fh)
        decrypted_plaintext = self.ppillar.decrypt_dict(enc_data)
        self.assertEqual(decrypted_plaintext, expected_plaintext)


class WrongKeyTest(unittest.TestCase):

    def test_wrong_pass_encrypted_key(self):
        self.assertRaises(ValueError, PublicPillar, os.path.join('test-data', 'key2048enc.pem'),
            passphrase='foo')
