.. _using_dynamic_loading_rst:

Dynamically loading the engine(s)
=================================

The solution includes projects for building both the BCrypt EVP and NCrypt STORE engines as dynamically loadable libraries. This may not always be the preferred mode of operation, depending on the requirements. For leveraging the engine(s) with the OpenSSL commands, dynamic loading is more convenient and does not require any rebuilding of the ``openssl`` binary.

Engine loading mechanisms
-------------------------

The dynamically loadable versions of the engine libraries are called ``engine-bcrypt.dll`` and ``engine-ncrypt.dll``. They can be provided to the OpenSSL libraries via several mechanisms.

* Through settings in the OpenSSL configuration file, pointed to through the ``OPENSSL_CONF`` environment variable or otherwise located in its default location which depends on the OpenSSL installation
* Through OpenSSL function calls in code
* As command line parameter to OpenSSL commands

Note that the library's ``.dll`` suffix does not need to be provided. The OpenSSL functions will add that by themselves where needed.

When using the OpenSSL commands, and mostly when using the OpenSSL API directly as well, the OpenSSL functions will search in specific locations to locate the requested engine libraries. This behavior can be modified via different control commands and different engine-related function calls, but typically the following locations will be searched:

* The path in the ``OPENSSL_ENGINES`` environment variable, if it is set
* The ``engines-1_1`` directory under the OpenSSL ``lib`` directory, if ``OPENSSL_ENGINES`` is not set
* The directories found in the ``PATH`` variable
* The working directory

Any path-prefix to the requested engine name will be added when attempting to load it. The option to build the engines as static libraries is currently not provided by any of the Visual Studio projects.

The `man page for config - OpenSSL CONF library configuration files <https://www.openssl.org/docs/man1.1.1/man5/config.html>`_ contains a section *Engine Configuration Module* that describes additional mechanisms to dynamically load engines, through configuration as opposed to code.


Verifying the loading with the engine command
---------------------------------------------

To verify whether OpenSSL can find and load an engine, the `engine command <https://www.openssl.org/docs/man1.1.1/man1/engine.html>`_ can be leveraged. Keeping in mind the mechanisms for locating the engines outlined above, verifying that the BCrypt engine is available for dynamic loading happens like this:

.. code-block:: none

    >openssl engine dynamic -pre SO_PATH:engine-bcrypt -pre LOAD
    (dynamic) Dynamic engine loading support
    [Success]: SO_PATH:engine-bcrypt
    [Success]: LOAD
    Loaded: (engine-bcrypt) CryptoAPI: Next Gen (CNG) BCrypt EVP Engine

More functional examples of using the engines with other OpenSSL commands are given in section :ref:`using_openssl_commands_rst`.


Example engine loading code
---------------------------

Example code of how to load them can be found in the ``Test::SetUpTestCase`` methods of the BCrypt and NCrypt functional tests, in ``test_bcrypt.cpp`` and ``test_ncrypt.cpp``. Without checking the return code values (for the sake of brevity):

.. code-block:: c++

    static const char *ENGINE_NAME = "engine-bcrypt";
    ENGINE *e = ENGINE_by_id("dynamic");
    ENGINE_ctrl_cmd_string(e, "SO_PATH", ENGINE_NAME, 0);
    ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
    ENGINE_init(e);
    ENGINE_add(e);
    // Make the engine's implementations the default implementations
    ENGINE_set_default(e, ENGINE_METHOD_ALL));
    // Engine's structural refcount has been upped by ENGINE_by_id, lower it
    ENGINE_free(e);

For more details on OpenSSL functions to create, manipulate, and use cryptographic modules in the form of ENGINE objects, see `the ENGINE interface OpenSSL man page <https://www.openssl.org/docs/man1.1.1/man3/ENGINE_init.html>`_.