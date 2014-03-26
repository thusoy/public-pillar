public-pillar [![Build Status](https://travis-ci.org/thusoy/public-pillar.svg)](https://travis-ci.org/thusoy/public-pillar)
=============

An PKI encrypted datastructure to keep secrets in the public. Primarily intended for usage with the command and control system [saltstack] and the [pillar] data structures, but should be generally usable for encrypting stuff for public storage.

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
