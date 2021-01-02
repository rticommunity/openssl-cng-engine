.. _testing_functional_tests_rst:

Functional tests
================

The project's functional tests are intended to verify the workings of the CNG Engine components by invoking OpenSSL methods that use them. The tests themselves rely on `GoogleTest <https://github.com/google/googletest/blob/master/googletest/docs/primer.md>`_, Google's C++ test framework. A fairly recent version (currently 1.8.1.3) of that framework is natively integrated with VS2017 and VS2019 installations. The mechanisms provided by this framework are convenient and choosing C++ as the programming language allows for taking advantage of more modern programming techniques (compared to the plain C API provided by OpenSSL). For optimal code reuse, virtually all test cases leverage so-called `Value-Parameterized Tests <https://github.com/google/googletest/blob/master/googletest/docs/primer.md>`_.

For both the BCrypt (EVP) and NCrypt(STORE) tests, verification of memory usage correctness is currently done through standard Visual Studio and CRT memory debugging mechanisms, for Debug builds only. These mechanisms are explained in the article `<https://docs.microsoft.com/en-us/visualstudio/debugger/finding-memory-leaks-using-the-crt-library?view=vs-2019>`_. The 1.8.1.3 version of the GoogleTest framework, which is currently distributed with Visual Studio, results in a known false-positive memory test for 4 (x86) or 8 (x64) bytes of non-freed normal memory. The tests contain a hard-coded work around to ignore this issue.


BCrypt (EVP) engine tests
-------------------------

All algorithms discussed in section :ref:`algorithms_rst` are tested by the project called ``gtest-engine-bcrypt``. By means of the `text-fixture construct <https://github.com/google/googletest/blob/master/googletest/docs/primer.md#test-fixtures-using-the-same-data-configuration-for-multiple-tests-same-data-multiple-tests>`_, all GoogleTest test classes are derived from the ``bcrypt_testing::Test`` base class. The latter is responsible for loading, initializing, finalizing and unloading the CNG BCrypt Engine for every test executed. Additionally, the ``bcrypt_testing::Environment`` singleton class takes care of memory usage checking. If any non-freed memory allocation is detected, it will be reported at the end of the test run. The ``bcrypt_testing::Test`` class itself is derived from GoogleTest's ``testing::Test`` class.

The BCrypt Engine test is entirely self-contained in the sense that it can run entirely on its own without preparation steps. Test parameters have been hardcoded into the test projects. This may change to a file configuration approach in the future.


NCrypt (STORE) tests
--------------------

Testing of the mechanisms described in  :ref:`store_rst` is done by the project called ``gtest-engine-ncrypt``. Similar to the BCrypt tests, the `text-fixture construct <https://github.com/google/googletest/blob/master/googletest/docs/primer.md#test-fixtures-using-the-same-data-configuration-for-multiple-tests-same-data-multiple-tests>`_ is used for all test classes. They are derived from the ``ncrypt_testing::Test`` base class which takes care of loading, initializing, finalizing and unloading the CNG NCrypt Engine for every test executed. The ``ncrypt_testing::Environment`` singleton class takes care of memory usage checking. If any non-freed memory allocation is detected, it will be reported at the end of the test run. The ``ncrypt_testing::Test`` class itself is derived from GoogleTest's ``testing::Test`` class.

The NCrypt Engine test by default relies on the certificate store with the URI ``cert:/LocalMachine/My/`` (the Local Computer's Personal store) to contain at least one (1) certificate which has its associated private key pair installed as well. If no such certificate is present in that store, the tests will fail. This can be resolved by populating that store with an example certificate, using the Widows PKI. Alternatively, the URI used can be overridden via the environment variable ``GTEST_N_CERT_STORE_URI``, to point to a different store location that does meet the needs.
