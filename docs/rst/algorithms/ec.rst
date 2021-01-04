.. _algorithms_ec_rst:

Elliptic Curve cryptography (``ECC``)
=====================================

The opaque ``EC_KEY_METHOD`` type is used to plug in custom methods related to Elliptic Curve cryptography. This is how the BCrypt EVP engine provides Elliptic Curve variants of the Diffie-Hellman (ECDH) and Digital Signature Algorithm (ECDSA) operations. Currently, these can be used in conjunction with the P-256, P-384 and P-521 curves which, in OpenSSL terms, correspond to the curve identifiers ``NID_X9_62_prime256v1``, ``NID_secp384r1`` and ``NID_secp521r1``.

In their usage, the ECDH and ECDSA algorithms differ from DH and DSA only by how their respective key pairs are generated. Tests for both ECDH and ECDSA, found in the file ``test_bcrypt_ec.cpp``, illustrate this as well.

Note that the BCrypt EVP engine deals with ephemeral keys only. In particular, the private key for both ECDH and ECDSA `has to live in-memory in an OpenSSL EVP_PKEY containing an EC_KEY <https://www.openssl.org/docs/man1.1.1/man3/EC_KEY_new.html>`_, which subsequently gets converted into a ``BCRYPT_KEY_HANDLE``. For signing with a key managed by a CNG store, use :ref:`store_rst` to lookup and load the ``EVP_PKEY``, which in that case encapsulates an opaque ``NCRYPT_KEY_HANDLE``.

Also, when selecting which message digest to use in conjunction with ECDSA, note that only those mentioned in :ref:`algorithms_md_rst` will result in the exclusive use of CNG crypto implementations.

Control commands
----------------

There are no control commands specific to ECDH or ECDSA.


Known issues or limitations
---------------------------

The ``EC_KEY_METHOD`` type is not documented (anymore). This may be due to the fact that it is removed from the OpenSSL 3.0.0 branch.

For older Windows versions, the `BCryptDeriveKey function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey>`_ can not be invoked without a KDF. This is normally achieved using `BCRYPT_KDF_RAW_SECRET <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey#bcrypt_kdf_raw_secret-ltruncate>`_. This is a problem because OpenSSL expects raw key derivation for ECDH. To work around this, the BCrypt EVP engine will select some appropriate SHA, but this will break interoperability between engines that do support raw and those that don't. See ``e_bcrypt_secret.h`` for the definition of the preprocessor symbol ``B_NO_RAW_SECRET`` and look for references to find out where it is used. According to the documentation, raw key derivation is not supported for Windows 8, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP.
