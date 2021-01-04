.. _algorithms_cipher_rst:

Symmetric ciphers (``CIPHER``)
==============================

The OpenSSL engine interface provides `an opaque EVP_CIPHER type <https://www.openssl.org/docs/man1.1.1/man3/EVP_CIPHER_meth_new.html>`_ for supporting symmetric cipher implementations other than the built-ins. Via this mechanism, the BCrypt EVP engine provides authenticated encryption (AE) and authenticated encryption with associated data (AEAD) to simultaneously assure the confidentiality and authenticity of data. This is achieved by means of AES in GCM mode of operation, which is supports for cryptographic keys of 128, 192, and 256 bits. In OpenSSL terms, this corresponds to the ciphers with the identifiers ``NID_aes_128_gcm``, ``NID_aes_192_gcm`` and ``NID_aes_256_gcm``.

`The OpenSSL man page for the EVP cipher routines <https://www.openssl.org/docs/man1.1.1/man3/EVP_CipherInit.html>`_ explains its usage. For GCM specifically, see the section called *AEAD Interface*. Tests for this algorithm are found in the file ``test_bcrypt_aes_gcm.cpp``, showing example usage as well.


Control commands
----------------

Of the GCM-specific control commands documented in the aforementioned man page and section, only ``EVP_CTRL_AEAD_GET_TAG`` and ``EVP_CTRL_AEAD_SET_TAG`` are currently supported. Alternative identifiers for the same commands are ``EVP_CTRL_GCM_GET_TAG`` and ``EVP_CTRL_GCM_SET_TAG``.

Setting the IV size via the ``EVP_CTRL_AEAD_SET_IVLEN`` command, or its alternative ``EVP_CTRL_GCM_SET_IVLEN``, is currently not supported.


Known issues or limitations
---------------------------

`The functional tests for this algorithm are currently limited to 256 bits keys and they verify authenticated encryption and decryption only <https://github.com/rticommunity/openssl-cng-engine/issues/21>`_.
