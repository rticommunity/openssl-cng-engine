.. _using_errors_rst:

Errors
======

Both engines follow the standard OpenSSL mechanisms of error reporting. When a call to the OpenSSL library fails, this is usually signalled by the return value, and an error code is stored in an error queue associated with the current thread. The `error interface <https://www.openssl.org/docs/man1.0.2/man3/err.html>`_ provides functions to obtain these error codes and textual error messages.

Debug messages are closely related and briefly mentioned here. Their details are discussed in section :ref:`using_debugging_rst`.

Error kinds and formats
-----------------------

Any errors occurring in the BCrypt and NCrypt engines fall into one of three categories: CNG Engine usage errors, Win API errors or OpenSSL API errors. The former two will emit messages that look similar, following the standard OpenSSL error message format.

CNG Engine usage errors
***********************

In some cases, the CNG Engine code encounters errors that indicate an incorrect usage. For example, invoking the ``Update()`` function before the ``Init()`` function or after the ``Final()`` function. The associated error message looks like this:

.. code-block:: none

    src/e_bcrypt_cipher.c(329): error:81068064:BCrypt Engine routines:bcrypt_cipher_update:Incorrect usage of the engine

The associated debug message will provide more information:

.. code-block:: none

    error: Can not invoke Update() before Init() or after Final() 

Win API errors
**************

Whenever a Windows API call invoked by the engine returns a value indicating failure, an error message of the following format is inserted into the OpenSSL error stack:

.. code-block:: none

    src/e_bcrypt_cipher.c(289): error:8106706B:BCrypt Engine routines:cipher_do_bcrypt:BCryptDecrypt failed, retval = 0xc000a002, msg = The computed authentication tag did not match the input authentication tag.

Note the ``retval`` and ``msg`` components, which are defined by the Windows SDK. The name of the failed function call appears before that, in this case as ``BCryptDecrypt failed``.

The associated debug message will provide more information. It is identified as a Win API error:

.. code-block:: none

    error: Win API: BCryptDecrypt failed (0xc000a002, "The computed authentication tag did not match the input authentication tag."): Decrypting with AES-GCM 

OpenSSL API errors
******************

All other errors that may happen relate to failing OpenSSL API invocations. In that case, the engines do not add any additional information to the error stack, since the OpenSSL functions themselves should already have done that. There will be an associated debug message that provides more information. It is identified as an OpenSSL API error, like this:

.. code-block:: none

    error: OpenSSL API: d2i_ECDSA_SIG failed: Verifying signed digest 


Example code for obtaining error messages
-----------------------------------------

The example code block below is not specific to the CNG engines, but work for any OpenSSL application. Taken from ``test_bcrypt.cpp``:

.. code-block:: c++

    #include <openssl/err.h>

    #include <iostream>
    #include <sstream>

    std::string
    bcrypt_testing::GetOpenSSLErrors()
    {
        std::stringstream ss;
        unsigned long ossl_err;
        bool first = true;
        char buf[500];
        const char *e_file = NULL;
        int e_line;
        const char *e_data = NULL;
        int e_flags;

        while (0 != (ossl_err = ERR_get_error_line_data(
            &e_file, &e_line, &e_data, &e_flags)))
        {
            ERR_error_string_n(ossl_err, buf, sizeof(buf));
            if (!first) ss << std::endl;
            ss << e_file << "(" << e_line << "): " << buf;
            if ((e_flags & ERR_TXT_STRING) && (NULL != e_data)) {
                ss << ", " << e_data;
            }
            first = false;
        }
        return ss.str();
    }