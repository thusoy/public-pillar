public-pillar [![Build Status](https://travis-ci.org/thusoy/public-pillar.svg)](https://travis-ci.org/thusoy/public-pillar)
=============

An encrypted datastructure to store secrets publicly. Primarily intended for usage with the command and control system [saltstack] and the [pillar] data structures, but should be generally usable for encrypting stuff for storing in public.

[Test coverage.](http://thusoy.github.io/public-pillar/)

Goals
-----

* It should enable easy and secure handling of secret values in public repositories
* Users should be able to add new secrets without needing the private key of the server deploying the keys
* It should be easy to encrypt both single values and larger files
* It should be easy to integrate with a SaltStack setup with a saltmaster


What does it do
---------------

ppillar (or public-pillar, if you prefer) helps you encrypt secret values you need to distribute to your servers,
enabling you to keep them in public version control systems.

    $ ppillar -k mykey.pub encrypt "supersecretdbpw"
    5bBspX19aI62mGNIjZgO2DOGu9k0Yzk6plxeSIr5KTX4/BzvsW026wL7K+QcAEZITwXVmxOSLgDkw4H+z2tY6RZdeGZOripOlMaEtNSYoAwnxCNErLaWIpTxq/8EwcSeRhymu/6lrqqyYOYXC36S3hHeGUzq60mefT3/z5GlVP6F2P/hJADF4ywleav+KTkfDQAPjNGHJ5X3wtHPQqpfr8SySs5Rwy2WtC53eY7fov+74I1VjNbEQ+YcjfKI9m33nypFLvlYCcmXhvmxm0jyashISRChLGJBuASgEqhsnnQ6hdtwC56VFp6GkQxv7+jRjbBQzOxT8GtCTID3U40+iA==

Store this value in a YAML/JSON file in your repository, like so:

```yaml
# secrets.yml
database:
    password: 5bBspX19aI62mGNIjZgO2DOGu9k0Yzk6plxeSIr5KTX4/BzvsW026w <..>
```

Commit it. On the server where you're deploying from, decrypt the values:

    $ ppillar --key myprivatekey.pem decrypt secrets.yml
    database:
        password: supersecretdbpw

You can redirect this output to wherever you need the files, like in a pillar state or similar.

ppillar can also work on directories, if you have a lot of secrets, or partition them into files
based on who should have access to what (good!), like a hierarchy like this:

```
secrets/
secrets/webserver.yml
secrets/database.yml
```

You can decrypt all of them and output them into a new directory like this:

    $ ppillar -k myprivatekey.pem decrypt secrets -o pillar/secrets

This will generate a pillar/secrets directory like this:

```
pillar/secrets/webserver.yml
pillar/secrets/database.yml
```


Installation
-----

Install it with pip:

    $ pip install ppillar

Note that you need have a C compiler to compile the pycrypto package we're using. Precompiled
binaries for Windows can be found at [Michael Foord's website, voidspace.org.uk], if you install
pycrypto from here you don't need the compiler.


Security
--------

ppillar uses a hybrid encryption scheme to keep your data safe. If the keys are short
enough<sup>1</sup>, they will be encrypted directly with the public key given, using
[PKCS #1.2 OAEP] with SHA-512. If the values to encrypt are longer than your key permits, we'll
generate a 256 bit AES key, encrypt your data with this key, encrypt this symmetric key with your
public key, and store it next to the ciphertext.

You choose the strength of your RSA keys yourself, but since this is unlikely to be used in
performance critical applications, but might frequently be attempted broken, you should probably
use 4096 bit keys. Totally up to you though, ppillar doesn't imply any restrictions on your keys.

<sup>1</sup>: Maximum length of data that can be encrypted with an RSA key is the size of the RSA modulus
(in bytes) minus 2, minus twice the size of the hash output (SHA512: 64 bytes). So if your key is
2048 bits, the maximum length of data that can be encrypted before switching to the AES method
is (2048/8 - 2 - 2*64) = 126 bytes. With a stronger 4096 bit key, this will be (4096/8 - 2 - 2*64)
= 382 bytes.

**Note:** Decrypting encrypted private keys can only be done with pycrypto>=2.6.1.


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
[Michael Foord's website, voidspace.org.uk]: http://www.voidspace.org.uk/python/modules.shtml#pycrypto
