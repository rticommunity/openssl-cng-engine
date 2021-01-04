.. _algorithms_dh_rst:

Diffie-Hellman shared secret (``DH``)
=====================================

The OpenSSL engine interface provides `an opaque DH_METHOD type <https://www.openssl.org/docs/man1.1.1/man3/DH_meth_new.html>`_ allowing for Diffie-Hellman operation implementations other than the built-ins. The BCrypt EVP engine supports generating DH key pairs. As documented for the `BCryptGenerateKeyPair function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair>`_, the key size must be greater than or equal to 512 bits, less than or equal to 4096 bits, and must be a multiple of 64.

Tests for this algorithm are found in the file ``test_bcrypt_dh.cpp``.


Control commands
----------------

There are no specific DH-related control commands.


Known issues or limitations
---------------------------

Based on experimenting with different test parameters, it seems that CNG's implementation only supports groups with 2 as their generator ``g``. This limitation does not seem to be documented publicly.

For older Windows versions, the `BCryptDeriveKey function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey>`_ can not be invoked without a KDF. This is normally achieved using `BCRYPT_KDF_RAW_SECRET <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey#bcrypt_kdf_raw_secret-ltruncate>`_. This is a problem because OpenSSL expects raw key derivation for DH. To work around this, the BCrypt EVP engine will select some appropriate SHA, but this will break interoperability between engines that do support raw and those that don't. See ``e_bcrypt_secret.h`` for the definition of the preprocessor symbol ``B_NO_RAW_SECRET`` and look for references to find out where it is used. According to the documentation, raw key derivation is not supported for Windows 8, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP.
