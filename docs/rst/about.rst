.. _about_rst:

About RTI's OpenSSL CNG Engine
==============================

`OpenSSL <https://www.openssl.org>`_ is a widely used open source crypto suite that supports multiple operating systems. It includes `crypto <https://www.openssl.org/docs/man1.1.1/man7/crypto.html>`_, a library that implements a wide range of cryptographic algorithms used in various Internet standards. Several of these built-in implementations can be replaced by plugging in a different so-called engine.

This OpenSSL CNG Engine project implements an engine for transparently leveraging Windows' `Cryptography API: Next Generation <https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal>`_ (CNG) with OpenSSL. It supports CNG's `Cryptographic Primitives <https://docs.microsoft.com/en-us/windows/win32/seccng/cryptographic-primitives>`_ as well as some of its `Key Storage and Retrieval <https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval>`_ mechanisms and legacy `CryptoAPI <https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/>`_ (CAPI) functionality for certificates.

You may want to use this engine if you prefer to use the OpenSSL API over the Windows CNG API directly. The only OpenSSL branch supported is 1.1.1 and only the latest version, currently 1.1.1i, is CI-tested.


Functionality provided
----------------------

This engine actually consists of two different components, indicated for short here as EVP and STORE.

EVP (envelope)
******************

The first component is a "traditional" `engine <https://github.com/openssl/openssl/blob/OpenSSL_1_1_1i/README.ENGINE>`_ that redirects `the EVP high-level cryptographic functions <https://www.openssl.org/docs/man1.1.1/man7/evp.html>`_ to their equivalent algorithms implemented by `CNG Cryptographic Primitive Functions <https://docs.microsoft.com/en-us/windows/win32/seccng/cng-cryptographic-primitive-functions>`_. These functions are exposed via the ``bcrypt.h`` header file in the Windows SDK, and provided by the ``Bcrypt.dll`` library. Therefore, the associated naming convention for the CNG Engine is to use ``bcrypt`` in project names, like ``engine-bcrypt`` or ``lib-evp-bcrypt``.

.. list-table:: Supported algorithms
   :widths: 25 50
   :header-rows: 1

   * - Algorithm
     - Remarks
   * - :ref:`algorithms_cipher_rst`
     - AES-GCM with 128, 192 or 256 bits key
   * - :ref:`algorithms_dh_rst`
     - 512 bits ≤ key size ≤ 4096 bits
   * - :ref:`algorithms_dsa_rst`
     - Not yet implemented
   * - :ref:`algorithms_ec_rst`
     - ECDH and ECDSA with P-256, P-384 and P-521
   * - :ref:`algorithms_md_rst`
     - SHA-1, SHA-256, SHA-384 and SHA-512
   * - :ref:`algorithms_hmac_rst`
     - HMAC with SHA
   * - :ref:`algorithms_rand_rst`
     - Default CNG random number provider
   * - :ref:`algorithms_rsa_rst`
     - 512 bits ≤ key size ≤ 16384 bits

For a more comprehensive overview, see section :ref:`algorithms_rst`.

Note that cryptographic key material in the EVP engine is ephemeral, generated at runtime with the help of the random number generator.


STORE (ossl_store)
**********************

The second component is a CNG-based implementation of an `OpenSSL STORE <https://www.openssl.org/docs/man1.1.1/man7/ossl_store.html>`_. The store component currently supports enumerating over, addressing and using public key certificates and (private) keys. For that, the loader leverages, among others, `CNG Key Storage Functsion <https://docs.microsoft.com/en-us/windows/win32/seccng/cng-key-storage-functions>`_. These functions are exposed via the ``ncrypt.h`` header file in the Windows SDK, and provided by the ``Ncrypt.dll`` library. Therefore, the associated naming convention for the CNG Engine is to use ``ncrypt`` in project names, like ``engine-ncrypt`` or ``lib-store-ncrypt``. Additionally, it leverages `functions to interact with the Certificate Store <https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/>`_.

The URI addressing schema format aligns with the `PowerShell's Certificate Provider <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-7.1>`_. For a detailed overview of the supported store mechanisms, see section :ref:`store_rst`.

Note that the cryptographic material used by the STORE engine typically includes long-term keypairs as stored in the key storage.


Windows and toolchains versions
-------------------------------

Not all possible combinations of Windows OS, SDK and Visual Studio version combinations are tested. Windows 10 is currently assumed, although other versions may work as well. Due to the usage of ``C++17`` features in the test applications, Visual Studio versions older than 2017 will not be able to build those.

.. list-table:: Toolchain versions
   :widths: 20 20 20
   :header-rows: 1

   * - Visual Studio
     - SDK
     - Remarks
   * - VS2019 (v142)
     - 10.0.19041.0 (2004)
     - CI-tested
   * -
     - 10.0.18362.0 (1903)
     -
   * -
     - 10.0.17763.0 (1809)
     -
   * - VS2017 (v141)
     - 10.0.19041.0 (2004)
     -
   * -
     - 10.0.18362.0 (1903)
     - CI-tested
   * -
     - 10.0.17763.0 (1809)
     -

For more detailed information on the toolchain, including build-time and runtime dependencies on 3rd party components, see section :ref:`building_rst`. 
For some known limitations of certain Windows versions, see section :ref:`limitations_rst`.
