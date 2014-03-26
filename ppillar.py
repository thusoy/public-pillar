#!/usr/bin/env python

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util import number
from Crypto.Hash import SHA512 as _hash
from Crypto import Random
from os import path
import argparse
import base64
import sys
import yaml


class PublicPillar(object):

    def __init__(self, keyfile):
        with open(keyfile) as key_fh:
            self.key = RSA.importKey(key_fh.read())


    def encrypt(self, plaintext):
        """ Encrypts `plaintext` with the key, and returns the result base64-encoded.

        If possible, encrypt directly with the public key, if long enough. Else, use symmetric
        encryption, and encrypt the symmetric key.
        """
        if self._needs_symmetric(plaintext):
            return self._encrypt_long_string(plaintext.encode('utf-8'))
        else:
            return self._encrypt_short_string(plaintext.encode('utf-8'))


    def _needs_symmetric(self, plaintext):
        """ Determines whether the key is big enough for the plaintext, or whether we need to go
        symmetric. Stolen from pycrypto source.
        """

        modBits = number.size(self.key.n)
        k = number.ceil_div(modBits, 8) # Convert from bits to bytes
        hLen = _hash.digest_size
        mLen = len(plaintext)

        ps_len = k-mLen-2*hLen-2
        return ps_len < 0


    def _encrypt_short_string(self, plaintext):
        """ Encrypt with a OAEP, using the key directly. """
        cipher = PKCS1_OAEP.new(self.key, hashAlgo=_hash)
        encrypted = cipher.encrypt(plaintext)
        return base64.b64encode(encrypted)


    def _encrypt_long_string(self, plaintext):
        """ Generate random key and use that for AES. """
        # Not long enough key for message. Use symmetric encryption instead, and use RSA on
        # the symmetric key
        symmetric_key = Random.new().read(32)
        # Check if we can encrypt the symmetric key with OAEP
        if self._needs_symmetric(symmetric_key):
            raise ValueError("Key is too small to encrypt a AES256 key! Can't encrypt messages " +
                "this long securely.")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(symmetric_key, AES.MODE_CFB, iv)
        encrypted = iv + cipher.encrypt(plaintext)
        return {
            'key': self._encrypt_short_string(symmetric_key),
            'ciphertext': base64.b64encode(encrypted),
        }


    def encrypt_dict(self, d):
        """ Encrypt values in a dict. Return a new dict with the values encrypted. """
        enc_dict = {}
        for key, val in d.items():
            enc_dict[key] = self.encrypt(val)
        return enc_dict


    def decrypt(self, b64_ciphertext):
        """ Decrypts base64-encoded data with the key. """
        if isinstance(b64_ciphertext, dict):
            return self._decrypt_long_text(b64_ciphertext).decode('utf-8')
        else:
            return self._decrypt_short_text(b64_ciphertext).decode('utf-8')


    def _decrypt_short_text(self, b64_ciphertext):
        cipher = PKCS1_OAEP.new(self.key, hashAlgo=_hash)
        ciphertext = base64.b64decode(b64_ciphertext)
        return cipher.decrypt(ciphertext)


    def _decrypt_long_text(self, d):
        # Message was too long for plain RSA. Use the symmetric key instead
        symmetric_key = self._decrypt_short_text(d['key'])
        encrypted_data = base64.b64decode(d['ciphertext'])
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(symmetric_key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext


    def decrypt_dict(self, enc_dict):
        """ Decrypt a dict of base64 encoded encrypted values. """
        d = {}
        for key, val in enc_dict.items():
            d[key] = self.decrypt(val)
        return d


def cli(): # pragma: no cover
    """ Entry point for the CLI. """
    return main(sys.argv[1:])


def main(cli_args):
    args = get_args(cli_args)
    if not args.encrypt:
        decrypt_pillar(args)
    else:
        encrypt_pillar(args)
    return 0


def decrypt_pillar(args):
    public_pillar = PublicPillar(args.key)
    with open(args.decrypt) as sources_fh:
        sources = yaml.load(sources_fh)
    for role, plaintext in sources.items():
        plaintexts = public_pillar.decrypt_dict(plaintext)
        print('Decrypting keys for %s...' % role)
        output_dir = args.output or '.'
        with open(path.join(output_dir, '%s.sls' % role), 'w') as target_fh:
            yaml.safe_dump(plaintexts, target_fh, default_flow_style=False)


def encrypt_pillar(args):
    public_pillar = PublicPillar(args.key)
    if args.encrypt:
        with open(args.encrypt) as src_fh:
            src_dict = yaml.load(src_fh)
    else:
        src_dict = yaml.load(sys.stdin)
    src = {
        'all': public_pillar.encrypt_dict(src_dict),
    }
    if args.output:
        with open(args.output, 'w') as out_fh:
            yaml.dump(src, out_fh, default_flow_style=False)
    else:
        print(yaml.dump(src, default_flow_style=False))


def get_args(cli_args):
    parser = argparse.ArgumentParser(prog='decrypt-pillar')
    parser.add_argument('-e', '--encrypt',
        metavar='<string-to-encrypt>',
        help='Encrypt a new value to pillar',
    )
    parser.add_argument('-k', '--key',
        metavar='<key-location>',
        help='Location of key to use for the operation.',
    )
    parser.add_argument('-d', '--decrypt',
        metavar='<input-file>',
        help='File to read data to decrypt from. Default: stdin. Must be ' +
            'either JSON or YAML.'
    )
    parser.add_argument('-o', '--output',
        metavar='<output>',
        help="Where to place the generated files. If decrypting the default is the current " +
            "directory, if encrypting the default is to print to stdout.",
    )
    args = parser.parse_args(cli_args)
    if not args.key:
        print('A key is necessary to do anything! Point the --key parameter ' +
            'to a key to want to use.\n')
        parser.print_help()
        sys.exit(1)
    return args


if __name__ == '__main__': # pragma: no cover
    sys.exit(main(sys.argv[1:]))
