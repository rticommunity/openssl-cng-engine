.. _algorithms_rand_rst:

Random Number Generation (``RAND``)
===================================

Strictly speaking, `the RAND method <https://www.openssl.org/docs/man1.1.1/man7/RAND.html>`_ is not part of the EVP interface. Engines do allow for modifying the random number generator though. The BCrypt EVP engine offloads random number generation to the CNG algorithm with the identifier `BCRYPT_RNG_ALGORITHM <https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers>`_. That is the default random number provider which complies with the NIST SP800-90 standard, specifically the CTR_DRBG portion of that standard.

Random number generation tests reside in ``test_bcrypt_rand.cpp``.


Control commands
----------------

There are no control commands for the random number generator.


Known issues or limitations
---------------------------

`The RNG test cases need to be improved <https://github.com/rticommunity/openssl-cng-engine/issues/18>`_
