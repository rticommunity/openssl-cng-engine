.. _using_rst:

Using the engine(s)
===================

The main components that this project provides are two engines. The BCrypt EVP engine leverages the CNG Cryptographic Primitives through OpenSSL EVP methods. Its dynamically loadable version is called ``engine-bcrypt.dll``, its statically linkable version is ``lib-evp-bcrypt.lib``. The NCrypt STORE engine implements an OpenSSL STORE abstraction for Windows Certificate and Key Stores. Its dynamically loadable version is called ``engine-ncrypt.dll``, its statically linkable version is ``lib-store-ncrypt.lib``.

Both dynamic libraries are a thin wrapper around the static ones. They expose the required functions for them to be used as dynamically loadable OpenSSL Engines. For more details on how to do the loading, see section :ref:`using_dynamic_loading_rst`.

Section :ref:`using_static_linking_rst` explains how to use the engines when embedding them into your binaries via static linking.

The specific engine control commands implemented by each of the two libraries are described in section :ref:`using_engine_commands_rst`.

Both components have a number of error codes and associated messages defined. Whenever an error occurs, standard OpenSSL mechanism are used to communicate this to the invoking application. Section :ref:`using_errors_rst` gives an overview this.

Debug versions of the binaries support more extensive logging and tracing through standard Windows debugging message mechanisms. Section :ref:`using_debugging_rst` explains how to take advantage of this.

The OpenSSL suite comes with a number of commands, also called applications, that can be used to perform all kinds of tasks. The are invoked via the ``openssl`` executable. Section :ref:`using_openssl_commands_rst` explains how to leverage the engine(s) with those commands.

.. toctree::
   :hidden:

   using/dynamic_loading
   using/static_linking
   using/engine_commands
   using/errors
   using/debugging
   using/openssl_commands
