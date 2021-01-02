.. _testing_vstest_console_rst:

Using VSTest.Console
====================

VSTest, the `Visual Studio Test Platform <https://github.com/microsoft/vstest>`_, is an open and extensible test platform that enables running tests, collecting diagnostics data and reporting results. It is distributed with the vS2017 and VS2019 deployments and can be selected during the installation process. It can be used in conjunction with Google Test applications via the `Google Test Adapter extension <https://github.com/csoltenborn/GoogleTestAdapter>`_, abbreviated from this point on as GTA. This extension is `available via NuGet <https://www.nuget.org/packages/GoogleTestAdapter/>`_ and normally should get restored into the ``packages`` subdirectory during the build process.

To fully leverage the VSTest features, debugging information is required. Examples provided in this section will therefore focus on Debug-enabled configurations. These are equivalent for both the BCrypt and the NCrypt test executables.


Basic test runs
---------------

Running the BCrypt and NCrypt with the VSTest framework is similar to executing the ``gtest-engine-bcrypt.exe`` and ``gtest-engine-ncrypt.exe`` binaries from the command line. However, additional options need to be provided, for example the location of the GTA. As configured in the ``msbuild/packages.config`` file, NuGet is requested to install those into a subdirectory called ``packages``. The AppVeyor CI script illustrates the use of VSTest (visible in the configuration file ``.appveyor.yml`` -- note the (optional) AppVeyor-specific logger used to allow for proper collection of the test results within the AppVeyor framework):

.. code-block:: none

    IF "%APPVEYOR_BUILD_WORKER_IMAGE%"=="Visual Studio 2019" SET VNAME=v142
    IF "%APPVEYOR_BUILD_WORKER_IMAGE%"=="Visual Studio 2017" SET VNAME=v141
    VSTest.Console.exe --Logger:AppVeyor --TestAdapterPath:packages\GoogleTestAdapter.0.18.0\build\_common bld\x64-Debug-%VNAME%\gtest-engine-bcrypt.exe
    VSTest.Console.exe --Logger:AppVeyor --TestAdapterPath:packages\GoogleTestAdapter.0.18.0\build\_common bld\x64-Debug-%VNAME%\gtest-engine-ncrypt.exe
    VSTest.Console.exe --Logger:AppVeyor --TestAdapterPath:packages\GoogleTestAdapter.0.18.0\build\_common bld\x86-Debug-%VNAME%\gtest-engine-bcrypt.exe
    VSTest.Console.exe --Logger:AppVeyor --TestAdapterPath:packages\GoogleTestAdapter.0.18.0\build\_common bld\x86-Debug-%VNAME%\gtest-engine-ncrypt.exe


Advanced test runs
------------------

An interesting option available with the Enterprise edition of Visual Studio is the code coverage collection, via the option ``/Enablecodecoverage``. Since AppVeyor images only have the Community edition installed, the CI setup currently does not include any coverage numbers. Some mechanism like this will have to be enabled with the CNG Engine test code soon though, this is work in progress.

For additional advanced test run options, see the documentation page `VSTest.Console.exe command-line options <https://docs.microsoft.com/en-us/visualstudio/test/vstest-console-options>`_
