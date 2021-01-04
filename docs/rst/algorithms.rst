.. _algorithms_rst:

BCrypt EVP algorithms
=====================

The loadable library ``engine-bcrypt.dll`` is the component that plugs in a range of algorithms provided by the CNG's `Cryptographic Primitives <https://docs.microsoft.com/en-us/windows/win32/seccng/cryptographic-primitives>`_. This happens by means of a set of different opaque method types as exposed by the OpenSSL EVP (envelope) interface.

Section :ref:`algorithms_fips_rst` contains some information about FIPS compliance of the algorithm implementations used.

This table enumerates the different algorithms supported through the EVP engine, with links to the sections that provide more details. Any test code snippets in those sections are taken from source files in the ``gtest-engine-bcrypt`` project:

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


.. toctree::
   :maxdepth: 1
   :hidden:

   algorithms/fips
   algorithms/cipher
   algorithms/dh
   algorithms/dsa
   algorithms/ec
   algorithms/md
   algorithms/hmac
   algorithms/rand
   algorithms/rsa
