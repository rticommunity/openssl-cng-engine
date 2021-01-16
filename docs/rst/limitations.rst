.. _limitations_rst:

Known limitations
=================

Known limitations

Todo...

Notes to self:
* The option to build the engines as static libraries is currently not provided by any of the Visual Studio projects. 
* For RSA, only PKCS#1 v1.5 padding is (or rather, can be) supported (insert link)
* Diffie-Hellman operations are not supported in the same way for some older versions of Windows (insert link)
* Completely disabling OpenSSL built-in algorithm implementations is tricky
* VS2017 does not know some of the ClangFormat options so it can not do formatting in the IDE


.. code-block:: none

    >openssl storeutl -engine engine-ncrypt -certs cert:/LocalMachine/My
    engine "engine-ncrypt" set.
    0: Name: cert:/LocalMachine/My/9b85e433216f91999362fe38d8729ee74a098950
    CN=RSAlice
    1: Name: cert:/LocalMachine/My/1cdb52270cde175e62e876551bcd56b21bad84c4
    CN=ECCharlie
    Total found: 2
    Assertion failed: lh_OSSL_STORE_LOADER_num_items(loader_register) == 0, file crypto\store\store_register.c, line 279
