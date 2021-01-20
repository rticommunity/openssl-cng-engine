.. _limitations_rst:

Known limitations
=================

This section documents some limitations to the use of the OpenSSL CNG Engines. These are issues that are not planned to be resolved, for different reasons. This is why they do not show up in `the GitHub list of issues <https://github.com/rticommunity/openssl-cng-engine/issues>`_ and in stead are documented here. 


Limited padding support for RSA signing and verification
--------------------------------------------------------

The OpenSSL implementation of the RSA sign and verify functionality prevents any engine from supporting padding other than RSA-PKCS#1 v1.5 padding (``RSA_PKCS1_PADDING``). In particular, its recommended replacement, the `Probabilistic Signature Scheme RSA-PSS <https://en.wikipedia.org/wiki/Probabilistic_signature_scheme>`_ (``RSA_PKCS1_PSS_PADDING``), is not available.

See the OpenSSL issue `Engine's .rsa_sign and .rsa_verify methods are never invoked when using PSS padding mode <https://github.com/openssl/openssl/issues/7341>`_ for an explanation.


Limited generator support for Diffie-Hellman
--------------------------------------------

Based on experimenting with different test parameters, it seems that CNG's (classic) Diffie-Hellman implementation only supports groups with 2 as their generator ``g``. This limitation does not appear to be documented publicly.


Lack of Diffie-Hellman interoperability for older Windows versions
------------------------------------------------------------------

For older Windows versions, the `BCryptDeriveKey function <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey>`_ can not be invoked without a Key Derivation Function (KDF). This is normally achieved using `BCRYPT_KDF_RAW_SECRET <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey#bcrypt_kdf_raw_secret-ltruncate>`_ and OpenSSL expects this kind of raw key derivation for Diffie-Hellman. To work around this, the BCrypt EVP engine will in stead select some appropriate SHA, but this will break interoperability between engines that do support raw and those that don't. See ``e_bcrypt_secret.h`` for the definition of the preprocessor symbol ``B_NO_RAW_SECRET`` and look for references to find out where it is used. According to the documentation, raw key derivation is not supported for Windows 8, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP.


No code formatting support with Visual Studio 2017
--------------------------------------------------

Some of the ClangFormat options used are not supported by the toolchain that comes with Visual Studio 2017. The unrecognized formatting option ``AlignConsecutiveMacros`` prevents the IDE from doing in-place code formatting. Also, as a consequence of the lack of support for the ``--dry-run`` command line parameter, the ``msbuild-single.bat`` script can not verify whether formatting is correctly applied either.

It may be possible to achieve full code formatting support by upgrading ``clang-format`` to version 10+. This has not been tested. The Visual Studio 2019 toolchain already includes a sufficiently up-to-date version that is capable of executing with the desired options.


No support for creating or persisting certificates and keys
-----------------------------------------------------------

The NCrypt STORE engine provides "read and use" access only for objects found in the Windows certificate store. Although the CNG APIs expose methods for persisting newly created objects, this is not supported by the NCrypt STORE engine.

Note that ephemeral keys can be created on the fly using the BCrypt EVP engine, for both symmetric and asymmetric cryptography.
