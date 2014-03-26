public-pillar [![Build Status](https://travis-ci.org/thusoy/public-pillar.svg)](https://travis-ci.org/thusoy/public-pillar)
=============

An PKI encrypted datastructure to keep secrets in the public. Primarily intended for usage with the command and control system [saltstack] and the [pillar] data structures, but should be generally usable for encrypting stuff for public storage.

[Test coverage.](http://thusoy.github.io/public-pillar/)


What does it do
---------------

First of all, it helps you encrypt your secrets, so that they're safe from eavesdropping! Put your
secrets in a file:

```yaml
all:
    DB_PW: supersecretdbpw

webserver:
    SECRET_KEY: youcansignstuffwiththissecretkey
```

The general format is

```yaml
<server-role>:
    <key-name>: <key>
```

Where the `role-name` determines the name of the file that will contain those keys later on. In
your configuration management tool you can use these files to set which of your servers have access
to which keys. If you only have one, or don't want to partition your keys any way, just put them
all under a role named `all` or something.

Note that only the secret portion of the key will be encrypted! The role names and key names will
be left entirely unprotected, if you need those to be protected you should probably look elsewhere.

Encrypt your secrets:

    $ ppillar -k mykem.pub -e data-to-be-encrypted.yml

This will generate a file like this:

```yaml
all:
  DB_PW: H7gWqpRToOu74wOrRhDMXh0KQ3sbbOnhG3N2YpX <..>

webserver:
  SECRET_KEY: FGFH6ZXd0SuTTsfBZfH9+S52ZXfByYDocGhlseqNl <..>
```

Go ahead, put it under source control or whatever you want. Then, to use the keys, typically from
a configuration management master like the saltmaster, puppetmaster or similar:

    $ ppillar -k mykem.pem -i encrypted_data.yml

```yaml
# all.sls
DB_PW: supersecretdbpw
```

```yaml
# webserver.sls
SECRET_KEY: youcansignstuffwiththissecretkey
```

This makes it easier to keep your servers secrets in a repo, without compromising the integrity
of the keys. They will be encrypted using your public key, and only your corresponding private
key will be able to decrypt the data.


Usage
-----

Install it (the package is called ppillar):

    $ pip install ppillar (will be on pip soon)

If you already have some data encrypted in a datastructure somewhere, you can already start using
ppillar, if not, encrypt some stuff first.

    $ ppillar -k key.pub -e unencrypted_data.yml

Where `key.pub` is the public key to use for encryption.

To decrypt data:
    
    $ ppillar -k key.pem -i enc_data.yml

**Note**: This doesn't work like this yet, but this is the goal. Approximately.


Security
--------

We're using a hybrid encryption scheme to keep your data safe. If the keys are short enough*, they
will be encrypted directly with the public key given, using [PKCS #1.2 OAEP] with SHA-512. If the
values to encrypt are longer than your key permits, we'll generate a 256 bit AES key, encrypt your
data with this key, encrypt this symmetric key with your public key, and store it next to the
ciphertext.

You choose the strength of your RSA keys yourself, but since this is unlikely to be used in
performance critical applications, but might frequently be attempted broken, you should probably
use 4096 bit keys. Totally up to you though, ppillar doesn't imply any restrictions on your keys.

_*_: Maximum length of data that can be encrypted with an RSA key is the size of the RSA modulus
(in bytes) minus 2, minus twice the size of the hash output (SHA512: 64 bytes). So if your key is
2048 bits, the maximum length of data that can be encrypted before switching to the AES method
is (2048/8 - 2 - 2*64) = 126 bytes. With a stronger 4096 bit key, this will be (4096/8 - 2 - 2*64)
= 382 bytes.


Development
-----------

Create new virtualenv:

    $ virtualenv venv

Install dependencies:

    $ pip install -e .[test]

Run the tests:

    $ nosetests

Keep test coverage up, and have fun hacking!

[saltstack]: http://docs.saltstack.com/en/latest/
[pillar]: http://docs.saltstack.com/topics/tutorials/pillar.html
