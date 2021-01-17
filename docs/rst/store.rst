.. _store_rst:

NCrypt STORE operations
=======================

The loadable library ``engine-ncrypt.dll`` is the component that exposes the Windows certificate store to applications via the OpenSSL STORE interface. Certificate Stores can contain different kinds of objects. The NCrypt STORE engine currently supports reading and using of public key certificates present in the store and, if available and allowed, their associated private keys. Listing the names of the objects in the store is possible as well. Creating or persisting new objects is not supported.

A good starting point for using this component is the `OpenSSL man page for ossl_store <https://www.openssl.org/docs/manmaster/man7/ossl_store.html>`_. That page explains that objects are addressed through Uniform Resource Identifiers (URIs). Section :ref:`store_objects_uris_rst` describes the URI schema for the NCrypt STORE engine.

The Windows certificate store is capable of building so-called certificate chains to verify whether a certificate is ultimately, indirectly, issued by an authority that is trusted by the operating system. This process of certificate verification can be leveraged through the NCrypt STORE as well, as explained in :ref:`store_certificate_verification_rst`.

Some examples on how to use the NCrypt STORE engine with the ``openssl`` commands are given in the earlier section :ref:`using_openssl_commands_rst`.

.. toctree::
   :hidden:

   store/objects_uris
   store/certificate_verification
