.. _algorithms_fips_rst:

FIPS 140 compliance
===================

The algorithm implementations used in the BCrypt Engine have been validated by NIST to comply with FIPS 140-2. See `Cryptographic Module Validation Program Certificate #3197 <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3197>`_ for a detailed overview. Note that the latest version mentioned is 10.0.17763, which is the SDK version released as 1809 -- currently two versions ago.

Using the BCrypt EVP engine does not guarantee that your project meets any FIPS compliance requirements. It has not been tested while operating in FIPS mode. 
