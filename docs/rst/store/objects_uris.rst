.. _store_objects_uris_rst:

Objects and URIs
================

Of the different kinds of objects listed and explained in `the OpenSSL OSSL_STORE_INFO man page <https://www.openssl.org/docs/manmaster/man3/OSSL_STORE_INFO.html>`_, the NCrypt STORE engine currently only supports the ``NAME``, ``CERT`` and ``PKEY`` objects. ``NAME`` objects can be used for listing the different elements in the certificate store by name, similar to doing a ``dir`` command in a directory. The resulting list contents are fully qualified identifiers that can be used to retrieve the object that they represent, that is an ``X509`` certificate object or a ``PKEY`` private key object.

Any private key object obtained through the engine will not contain the actual key, but only the opaque NCrypt handle that represents the key object. This is the case even if a private key is marked as "exportable" in the certificate store. These private key objects can only be used for key-actions like signing. The public key component on the other hand will be present in its entirety, as obtained from the public key certificate.

URI schema
----------

The URI schema closely follows the path naming approach of `the PowerShell Certificate Provider <https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-7>`_. In both environments, the local computer's personal store is indicated by ``cert:/LocalMachine/My`` or ``cert:\LocalMachine\My``. Note that the engine is case sensitive with regard to the schema name ``cert:`` whereas the PowerShell provider is not.

Objects within the store are identified via their thumbprint, also known as fingerprint. This is defined by the SHA-1 digest of the DER encoded version of the entire certificate. An example of this is ``cert:/LocalMachine/My/1cdb52270cde175e62e876551bcd56b21bad84c4``. This URI can be used to indicate both the certificate and the private key. OpenSSL will decide which of the two it selects, based on which kind of object is expected. This can be indicated via the function `OSSL_STORE_expect <https://www.openssl.org/docs/man1.1.1/man3/OSSL_STORE_expect.html>`_. Alternatively, a suffix can be appended to the URI to unambiguously specify the kind of object. This suffix can be ``?object-kind=cert``, referring to the certificate itself, or ``?object-kind=pkey``, referring to the private key associated with the certificate. Using both ``OSSL_STORE_expect`` and a suffix at the same time will only succeed if the two are consistent. If none of the two are used, then a ``CERT`` kind is assumed.

Listing certificates
--------------------

This section illustrates the use of the URI schema explained above, comparing the PowerShell certificate provider with the NCrypt STORE engine component.

Listing the certificate elements in the local computer's personal store in PowerShell looks like this:

.. code-block:: none

    PS C:\> Get-ChildItem -Path cert:/LocalMachine/My


    PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\My

    Thumbprint                                Subject
    ----------                                -------
    9B85E433216F91999362FE38D8729EE74A098950  CN=RSAlice
    1CDB52270CDE175E62E876551BCD56B21BAD84C4  CN=ECCharlie

With the NCrypt STORE engine configured to be automatically loaded, the OpenSSL equivalent shows:

.. code-block:: none

    >openssl storeutl -certs cert:/LocalMachine/My
    0: Name: cert:/LocalMachine/My/9b85e433216f91999362fe38d8729ee74a098950
    CN=RSAlice
    1: Name: cert:/LocalMachine/My/1cdb52270cde175e62e876551bcd56b21bad84c4
    CN=ECCharlie
    Total found: 2

Further exploring the certificate using the URI obtained above with PowerShell:

.. code-block:: none

    > Get-Item cert:/LocalMachine/My/1cdb52270cde175e62e876551bcd56b21bad84c4 | Format-List -View ThumbprintList


    Subject      : CN=ECCharlie
    Issuer       : CN=rti-SVCS-PKI-W2016-CA, DC=rti, DC=com
    Thumbprint   : 1CDB52270CDE175E62E876551BCD56B21BAD84C4
    FriendlyName : Charlie
    NotBefore    : 2021-01-06 4:00:51 PM
    NotAfter     : 2022-01-06 4:10:51 PM
    Extensions   : {System.Security.Cryptography.Oid, System.Security.Cryptography.Oid, System.Security.Cryptography.Oid,
                System.Security.Cryptography.Oid...}

A similar one-liner for OpenSSL:

.. code-block:: none

    >openssl storeutl -certs cert:/LocalMachine/My/1cdb52270cde175e62e876551bcd56b21bad84c4 | openssl x509 -noout -subject -issuer -fingerprint -startdate -enddate
    subject=CN = ECCharlie
    issuer=DC = com, DC = rti, CN = rti-SVCS-PKI-W2016-CA
    SHA1 Fingerprint=1C:DB:52:27:0C:DE:17:5E:62:E8:76:55:1B:CD:56:B2:1B:AD:84:C4
    notBefore=Jan  6 21:00:51 2021 GMT
    notAfter=Jan  6 21:10:51 2022 GMT

For examples of OpenSSL API calls to achieve similar things, check out the ``gtest-engine-ncrypt`` test project.
