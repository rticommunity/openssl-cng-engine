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
* The NCrypt STORE engine provides "read and use" access only, no creating or persisting of certificates and keys
