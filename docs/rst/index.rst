.. _index_rst:

Welcome to RTI's OpenSSL CNG Engine
===================================

.. warning::

   This documentation is work in progress

This project implements an engine for leveraging Windows' `Cryptography API: Next Generation <https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal>`_ (CNG) with the `OpenSSL <https://www.openssl.org>`_ crypto suite, branch ``1.1.1``.

The OpenSSL CNG Engine source code is hosted `on Github as the openssl-cng-engine project <https://github.com/rticommunity/openssl-cng-engine>`_. It is brought to you by `Real-Time Innovations <https://www.rti.com>`_ under the `Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>`_. For questions related to using this engine in conjunction with RTI's Connext DDS Secure product, please contact .


Finding your way
----------------

For a high level introduction to this project, check out section :ref:`about_rst`, which identifies its functionality and outlines the different components involved.

Detailed build instructions as well as descriptions of the different build system elements are given in section :ref:`building_rst`. This includes an overview of the platform and toolchain components needed as well as their different versions that the project is being tested with.

Some elementary functional tests, based on the Google Test framework, are part of the project. Details are explained in setion :ref:`testing_rst`.

Using this engine is not different from using any other OpenSSL engine. Still, section :ref:`using_rst` provides descriptions of specific mechanisms for error handling, debugging and issuing control commands.

Section :ref:`algorithms_rst` describes some details for each of the supported EVP algorithms that are good to know when using them. Some of those are specific to BCrypt's implementation, others are related to OpenSSL, or a combination of the two.

Looking up and using identity certificates and cryptographic keys is provided through OpenSSL's STORE interface. Details are explained in section :ref:`store_rst`.

For several reasons, the use of this engine comes with a number of caveats. Check out section :ref:`limitations_rst` to learn about them.

In order to maintain code and documentation quality, the software development process leverages CI techniques and follows conventions outlined in section :ref:`process_rst`.


.. toctree::
   :hidden:

   about
   building
   testing
   using
   algorithms
   store
   limitations
   process
