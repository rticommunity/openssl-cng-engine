.. _algorithms_hmac_rst:

Customized HMAC key (``PKEY``)
==============================

The HMAC keyed hash algorithm is different in the sense that OpenSSL does not define any specific type for it like it does for many of the other algorithms. Instead, it requires a custom `EVP_PKEY_METHOD <https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html>`_ implementation. This is what the BCrypt EVP engine does; it supports HMAC with the digests enumerated in :ref:`algorithms_md_rst`.

To use this algorithm, use `the EVP_PKEY_new_raw_private_key <https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_new_raw_private_key.html>`_ function with the ``EVP_PKEY_HMAC`` type. For examples, see the ``test_bcrypt_hmac_sha.cpp`` which contains its associated functional tests.


Control commands
----------------

There are no control commands for the custom HMAC key.


Known issues or limitations
---------------------------

This algorithm has no know issues or limitations.
