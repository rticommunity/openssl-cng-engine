.. _testing_command_line_rst:

Running tests from the command line
===================================

After a successful build of the solution (either using Visual Studio or using the batch script in the ``msbuild`` directory, the output directory should contain all artifacts needed to run the test:

.. code-block:: none

    >dir /B /A-D bld\x64-Release-v142
    engine-bcrypt.dll
    engine-ncrypt.dll
    gtest-engine-bcrypt.exe
    gtest-engine-ncrypt.exe
    libcrypto-1_1-x64.dll


Basic test runs
---------------

Running the BCrypt and NCrypt tests just requires executing the ``gtest-engine-bcrypt.exe`` and ``gtest-engine-ncrypt.exe`` binaries respectively. Their exit value is 0 in case of success and 1 otherwise. This is exactly what the AppVeyor CI scripts do, for both Visual Studio 2017 and 2019 the test script includes the following commands (visible in the configuration file ``.appveyor.yml``):

.. code-block:: none

    IF "%APPVEYOR_BUILD_WORKER_IMAGE%"=="Visual Studio 2019" SET VNAME=v142
    IF "%APPVEYOR_BUILD_WORKER_IMAGE%"=="Visual Studio 2017" SET VNAME=v141
    bld\x64-Release-%VNAME%\gtest-engine-bcrypt.exe
    bld\x64-Release-%VNAME%\gtest-engine-ncrypt.exe
    bld\x86-Release-%VNAME%\gtest-engine-bcrypt.exe
    bld\x86-Release-%VNAME%\gtest-engine-ncrypt.exe


Advanced test runs
------------------

Since these test projects are based on the GoogleTest framework, they support all standard gtest features. The different options can be selected via command line parameters or environment variables, as documented in `Running Test Programs: Advanced Options <https://github.com/google/googletest/blob/master/googletest/docs/advanced.md#running-test-programs-advanced-options>`_. A concise version of this information can be obtained by running the executable with the ``--help`` flag. You can also use ``-h``, ``-?``, or ``/?`` for short.

.. code-block:: none

    >bld\x64-Debug-v142\gtest-engine-bcrypt.exe --help
    This program contains tests written using Google Test. You can use the
    following command line flags to control its behavior:

    Test Selection:
    --gtest_list_tests
        List the names of all tests instead of running them. The name of
        TEST(Foo, Bar) is "Foo.Bar".
    --gtest_filter=POSTIVE_PATTERNS[-NEGATIVE_PATTERNS]
        Run only the tests whose name matches one of the positive patterns but
        none of the negative patterns. '?' matches any single character; '*'
        matches any substring; ':' separates two patterns.
    --gtest_also_run_disabled_tests
        Run all disabled tests too.

    Test Execution:
    --gtest_repeat=[COUNT]
        Run the tests repeatedly; use a negative count to repeat forever.
    --gtest_shuffle
        Randomize tests' orders on every iteration.
    --gtest_random_seed=[NUMBER]
        Random number seed to use for shuffling test orders (between 1 and
        99999, or 0 to use a seed based on the current time).

    Test Output:
    --gtest_color=(yes|no|auto)
        Enable/disable colored output. The default is auto.
    --gtest_print_time=0
        Don't print the elapsed time of each test.
    --gtest_output=(json|xml)[:DIRECTORY_PATH\|:FILE_PATH]
        Generate a JSON or XML report in the given directory or with the given
        file name. FILE_PATH defaults to test_details.xml.

    Assertion Behavior:
    --gtest_break_on_failure
        Turn assertion failures into debugger break-points.
    --gtest_throw_on_failure
        Turn assertion failures into C++ exceptions for use by an external
        test framework.
    --gtest_catch_exceptions=0
        Do not report exceptions as test failures. Instead, allow them
        to crash the program or throw a pop-up (on Windows).

    Except for --gtest_list_tests, you can alternatively set the corresponding
    environment variable of a flag (all letters in upper-case). For example, to
    disable colored text output, you can either specify --gtest_color=no or set
    the GTEST_COLOR environment variable to no.

    For more information, please read the Google Test documentation at
    https://github.com/google/googletest/. If you find a bug in Google Test
    (not one in your own code or tests), please report it to
    <googletestframework@googlegroups.com>.