.. _store_certificate_verification_rst:

Certificate verification
========================

The OpenSSL store interface does not expose any standard mechanism for verification of certificate validity. The Windows certificate store is capable of doing that though. For that reason, the NCrypt STORE engine provides a custom command that cane be used to verify an OpenSSL X509 certificate with the Windows certificate store. In a nutshell, the certificate verification mechanism invokes several certificate store functions that try to build a certificate chain that ends at a certificate that is marked as "trusted" within the Windows certificate store.

Because of its custom nature, the verification mechanism can not be used with the generic OpenSSL tools.

Usage
-----

The verification functionality can be used through the STORE's command mechanism, via `OSSL_STORE_ctrl <https://www.openssl.org/docs/man1.1.1/man3/OSSL_STORE_ctrl.html>`_. This requires opening a Certificate store first, and which store that is depends on the requirements for the verification. Typically, the local computer's personal store is used for this. This does not require administrator privileges because it does not require the use of any private keys in that store.

Since the OpenSSL STORE interface does not have a string-based control function, it requires the numeric value of the ``CNG_STORE_CMD_VERIFY_CERT`` command. Its definition can be found in ``s_ncrypt.h`` in the ``lib-store-ncrypt`` project.

.. code-block:: c++

    /* Commands implemented by the store */
    /* NCRYPT_CMD_VERIFY_CERT: uses CNG functions to verify a certificate,
    *   with the Windows CertStore as the trust base. This is the same
    *   CertStore that was opened when opening the OSSL_STORE.
    *   This is similar to the X509_verify_cert function, and its prototype
    *   is modeled after that.
    * Usage: STORE_ctrl(store_ctx, STORE_CMD_VERIFY_CERT,
    *                   X509_STORE_CTX *ctx, int *result) */

    #define NCRYPT_CMD_VERIFY_CERT OSSL_STORE_C_CUSTOM_START

The example below is a concise transcript of the ``Verify`` test in ``test_ncrypt_certificates.cpp`` from the ``gtest-engine-ncrypt`` project. For the sake of brevity, return code checking is omitted. After a successful invocation of ``OSSL_STORE_ctrl``, the value of ``is_valid`` is ``1`` if the certificate was deemed valid, and ``0`` otherwise.

.. code-block:: c++

    /* Assuming cert is the X509 object to be verified */
    X509_STORE_CTX *x509_store_ctx = X509_STORE_CTX_new();
    X509_STORE *x509_store = X509_STORE_new();
    X509_STORE_CTX_init(x509_store_ctx, x509_store.get(), cert, NULL);
    /* Open the store for verification */
    OSSL_STORE_CTX *ctx = OSSL_STORE_open(
        "cert:/LocalMachine/My/", NULL, NULL, NULL, NULL);
    /* Do the actual verification */
    int is_valid;
    OSSL_STORE_ctrl(ctx, CNG_STORE_CMD_VERIFY_CERT, x509_store_ctx,
        &is_valid);


Convenience function
--------------------

For convenience, the ``engine-ncrypt`` library exports a function called ``e_ncrypt_x509_verify_helper`` that executed the steps required to verify a certificate. It expects an ``X509_STORE_CTX`` object and invokes the functions required to do the verification of the certificate in that store. It is hard coded to use the local computer's personal store. The implementation looks like this:

.. code-block:: c++

    const char *STORE_URI = "cert:/LocalMachine/My/";

    OPENSSL_EXPORT
    int
    e_ncrypt_x509_verify_helper(X509_STORE_CTX *x509_store_ctx)
    {
        CMN_DBG_API_ENTER;

        int result = 0;
        int ctrl_result = 0;
        OSSL_STORE_CTX *ossl_store_ctx = NULL;

        /* Get context from OSSL_STORE */
        ossl_store_ctx = OSSL_STORE_open(STORE_URI, NULL, NULL, NULL, NULL);
        if (ossl_store_ctx == NULL) {
            S_NCRYPT_osslerr(OSSL_STORE_open, "X509 certificate verification");
            goto done;
        }

        if (OSSL_STORE_ctrl(ossl_store_ctx, NCRYPT_CMD_VERIFY_CERT, x509_store_ctx,
                            &ctrl_result) != 1) {
            S_NCRYPT_osslerr(OSSL_STORE_ctrl, "X509 certificate verification");
            goto done;
        }

        result = ctrl_result;

    done:
        OSSL_STORE_close(ossl_store_ctx);

        CMN_DBG_API_LEAVE;
        return result;
    }
