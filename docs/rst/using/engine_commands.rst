.. _using_engine_commands_rst:

Engine control commands
=======================

Both the BCrypt EVP engine and the NCrypt STORE engine support a small number of control commands to modify their behavior. Many of those are 

Generic engine control commands
----------------------------------

For generic engine control commands, the OpenSSL ``engine`` command is capable of printing the available information. In addition to the available commands, this prints the different methods implemented by the engine. For the BCrypt EVP engine, it looks like this:

.. code-block:: none

    > openssl engine dynamic -pre SO_PATH:engine-bcrypt -pre LOAD -vvv -t -c
    (dynamic) Dynamic engine loading support
    [Success]: SO_PATH:engine-bcrypt
    [Success]: LOAD
    Loaded: (engine-bcrypt) CryptoAPI: Next Gen (CNG) BCrypt EVP Engine
    [RSA, DH, RAND, id-aes128-GCM, id-aes192-GCM, id-aes256-GCM, SHA1, SHA256, SHA384, SHA512, HMAC]
        [ available ]
        debug_level: debug level (<0=nothing, 0=errors, 1=warnings, 2=api, 3+=trace)
            (input flags): NUMERIC

The generic engine commands for the NCrypt STORE engine confirm that it implements the STORE interface, for the ``cert`` URI schema:

.. code-block:: none

    >openssl engine dynamic -pre SO_PATH:engine-ncrypt -pre LOAD -vvv -t -c
    (dynamic) Dynamic engine loading support
    [Success]: SO_PATH:engine-ncrypt
    [Success]: LOAD
    Loaded: (engine-ncrypt) CryptoAPI: Next Gen (CNG) NCrypt STORE Engine
    [STORE(cert)]
        [ available ]
        debug_level: debug level (<0=nothing, 0=errors, 1=warnings, 2=api, 3+=trace)
            (input flags): NUMERIC

The ``debug_level`` command, for both engines, only has an effect for the debug builds. For more detailed explanation on the debugging mechanisms, see section :ref:`using_debugging_rst`.


Engine-specific control commands
--------------------------------

All other supported commands are specific to the different methods and the store. For the BCrypt EVP engine, these commands are the standard commands associated with the different crypto methods. They are explained in the OpenSSL documentation and the ``gtest-engine-bcrypt`` project contains several examples of their usage. The NCrypt STORE engine supports one custom command ``CNG_STORE_CMD_VERIFY_CERT`` for verifying certificates. The ``gtest-engine-ncrypt`` test contains an example and more details are given in section :ref:`store_certificate_verification_rst`.
