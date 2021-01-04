.. _algorithms_md_rst:

Message digests (``MD``)
========================


OpenSSL's `opaque EVP_MD type <https://www.openssl.org/docs/man1.1.1/man3/EVP_MD_meth_new.html>`_ enables replacing the built-in digest algorithm implementations. The BCrypt EVP engine supports SHA-1, SHA-256, SHA-384 and SHA-512. These are identified via the identifiers ``NID_sha1``, ``NID_sha256``, ``NID_sha384`` and ``NID_sha512``. All of these are tested in ``test_bcrypt_sha.cpp``.

As explained in section :ref:`algorithms_hmac_rst`, the BCrypt EVP engine provides keyed versions of these digests as well.


Control commands
----------------

The digests support the ``EVP_MD_CTRL_MICALG`` command, which is documented in the section *CONTROLS* in `the OpenSSL man page <https://www.openssl.org/docs/man1.1.1/man3/EVP_MD_type.html>`_. The value returned in ``p2`` has to be freed by the caller using `the OPENSSL_free function <https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_free.html>`_.


Known issues or limitations
---------------------------

See `the Wikipedia page on SHA-1 <https://en.wikipedia.org/wiki/SHA-1>`_ for references discussing the use of SHA-1. Many organizations have recommended its replacement but it is still considered secure for HMAC.
