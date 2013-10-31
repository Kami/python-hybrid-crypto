Python Hybrid Crypto
====================

Python module which exposes a simple hybrid cryptography abstraction on
top of KeyCzar and pycrypto.

.. note::

    This module has NOT been extensively tested or audited so general usage is
    strongly discouraged at this point.

How it works
------------

Key encapsulation scheme
~~~~~~~~~~~~~~~~~~~~~~~~

Key encapsulation scheme uses RSA-OAEP public-key cryptography with 2048 bit
key.

This functionality heavily relies on public-key cryptography functionality
exposed by KeyCzar.

Data encapsulation scheme
~~~~~~~~~~~~~~~~~~~~~~~~~

Data encapsulation scheme uses AES in CBC mode with 256 bit key.

This release on primitives and functionality provided by pycrypto.

Example Usage
-------------

TBW.

Questions and Answers
---------------------

Why do I need this, can't I just use keyczar directly?
------------------------------------------------------

KeyCzar exposes a higher level, safe and easy to use interface for handling
both, asymmetric and symmetric encryption, but it doesn't provide a higher
level interface for handling `hybrid cryptography`_ (well, that's not 100%
accurate, because there is some support, but it's experimental and only
available in Java).

.. _`hybrid cryptography`: http://en.wikipedia.org/wiki/Hybrid_cryptosystem
