from ppillar import PublicPillar

from contextlib import contextmanager
import os
import shutil
import stat
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


@unittest.skipIf(os.name == 'nt', 'File permission tests are not run on windows due to '
    'an unsupported security model')
class FilePermissionsTest(unittest.TestCase):

    def setUp(self):
        self.ppillar = PublicPillar(os.path.join('test-data', 'key2048enc.pem'), passphrase='test')
        self.target_dir = tempfile.mkdtemp()


    def tearDown(self):
        shutil.rmtree(self.target_dir, ignore_errors=True)


    def _assert_all_files_in_dir_are_0600(self, directory):
        at_least_one_result = False
        for dirpath, dirnames, filenames in os.walk(self.target_dir):
            for filename in filenames:
                st_mode = os.stat(os.path.join(self.target_dir, dirpath, filename)).st_mode
                mode = stat.S_IMODE(st_mode)
                self.assertEqual(oct(mode), '0600')
                at_least_one_result = True
        self.assertTrue(at_least_one_result)


    def test_correct_decrypted_permissions(self):
        source_dir = os.path.join('test-data', 'encrypted_dir')
        self.ppillar.decrypt_directory(source_dir, self.target_dir)
        self._assert_all_files_in_dir_are_0600(self.target_dir)


    def test_correct_permissions_on_existing_file(self):
        source_dir = os.path.join('test-data', 'encrypted_dir')
        word_readable_file = os.path.join(self.target_dir, 'database.yml')
        with open(word_readable_file, 'w') as fh:
            pass
        os.chmod(word_readable_file, 0o644)

        self.ppillar.decrypt_directory(source_dir, self.target_dir)
        self._assert_all_files_in_dir_are_0600(self.target_dir)


    def test_does_not_allow_existing_file_descriptors_to_read_contents(self):
        source_dir = os.path.join('test-data', 'encrypted_dir')
        word_readable_file = os.path.join(self.target_dir, 'database.yml')
        with open(word_readable_file, 'wb') as fh:
            fh.write('prepillarcontents')
        os.chmod(word_readable_file, 0o644)
        word_readable_file_fd = open(word_readable_file, 'rb', 0)

        self.ppillar.decrypt_directory(source_dir, self.target_dir)
        self._assert_all_files_in_dir_are_0600(self.target_dir)

        # When the file already existed, it should have created a new file descriptor
        # in the target location, which means that the contents we can read from the old
        # one is not the sensitive data in the new file
        self.assertEqual(word_readable_file_fd.read(), 'prepillarcontents')
