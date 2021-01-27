.. _using_static_linking_rst:

Statically linking the engine(s)
================================

The functionality provided by the engines can be statically embedded into your applications or libraries as well. This requires linking with the ``lib-bcrypt-evp.lib`` and/or ``lib-ncrypt-store.lib`` libraries.

Engine loading mechanisms
-------------------------

Even with the engines embedded in your binary, the OpenSSL crypto library still needs to learn about its presence. This happens via methods found in ``e_bcrypt.h`` and ``s_ncrypt.h`` in the ``include`` directory. After that, the engines can be looked up by their names.

Example code of how to load them in this situation can be found in the ``Test::SetUpTestCase`` methods of the BCrypt and NCrypt functional tests, in ``test_bcrypt.cpp`` and ``test_ncrypt.cpp``. Without checking the return code values (for the sake of brevity):

.. code-block:: c++

    static const char *ENGINE_NAME = "engine-bcrypt";
    engine_load_bcrypt_evp();
    ENGINE *e = ENGINE_by_id(ENGINE_NAME);
    ENGINE_init(e);
    // Make the engine's implementations the default implementations
    ENGINE_set_default(e, ENGINE_METHOD_ALL));
    // Engine's structural refcount has been upped by ENGINE_by_id, lower it
    ENGINE_free(e);
