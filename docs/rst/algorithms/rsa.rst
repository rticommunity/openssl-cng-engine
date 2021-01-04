.. _algorithms_rsa_rst:

RSA operations (``RSA``)
========================

For alternative implementation of the RSA algorithms, OpenSSL exposes the `opaque RSA_METHOD type <https://www.openssl.org/docs/man1.1.1/man3/RSA_meth_new.html>`_. The BCrypt EVP engine implements the following RSA mechanisms:

* Creating a signature of a message, using a private key
* Verifying a signature, using the associated public key
* Encrypting plain text, using a public key
* Decrypting cipher text, using the associated private key

RSA encryption with a private key or decryption with a public key is not supported. The `BCryptEncrypt function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt>`_ and `BCryptDecrypt function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt>`_  do not allow it. Use the proper signing and verification interfaces instead. Only PKCS#1 v1.5 padding (``RSA_PKCS1_PADDING``) is supported, due to limitation of OpenSSL explained in :ref:`algorithms_rsa_issues` below.

See ``test_bcrypt_rsa.cpp`` for the RSA functional tests.

Note that the BCrypt EVP engine deals with ephemeral keys only. In particular, the private key for RSA `has to live in-memory in an OpenSSL EVP_PKEY containing an RSA key <https://www.openssl.org/docs/man1.1.1/man3/RSA_new.html>`_, which subsequently gets converted into a ``BCRYPT_KEY_HANDLE``. For signing with a key managed by a CNG store, use :ref:`store_rst` to lookup and load the ``EVP_PKEY``, which in that case encapsulates an opaque ``NCRYPT_KEY_HANDLE``.

Also, when selecting which message digest to use when signing, note that only those mentioned in :ref:`algorithms_md_rst` will result in the exclusive use of CNG crypto implementations.

Control commands
----------------

There are no RSA-specific control commands.


.. _algorithms_rsa_issues:

Known issues or limitations
---------------------------

See the OpenSSL issue `Engine's .rsa_sign and .rsa_verify methods are never invoked when using PSS padding mode <https://github.com/openssl/openssl/issues/7341>`_ for an explanation how the OpenSSL implementation of the RSA sign and verify functionality prevents any engine from providing padding other than PKCS#1 v1.5 padding (``RSA_PKCS1_PADDING``).
