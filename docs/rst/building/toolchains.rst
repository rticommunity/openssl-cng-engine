.. _building_toolchains_rst:

Toolchains
==========

This section describes what toolchain components are needed to build the CNG Engine with Visual Studio version 2019 or 2017. Each components appears in its own subsection. Note that older versions of Visual Studio will not be able to build the test projects, since those leverage some C++17 features not supported by older compilers. The actual engine code is written and C and will therefore still be buildable by older VS versions. Such setups are not tested though, whereas building and running tests with VS2019 as well as VS2017 is part of the CI process.


Using Visual Studion 2019
-------------------------

The CNG Engine can be built with all editions of VS2019. To fully leverage the Google Test functionality, make sure to select the installation option for native Google Test integration. Also enable the Clang toolchain to fully leverage ClangFormat for code format checking.


Using Visual Studion 2017
-------------------------

The CNG Engine can be built with all editions of VS2017. To fully leverage the Google Test functionality, make sure to select the installation option for native Google Test integration. Compared to the newer version, VS2017 comes with fewer pre-installed components, or with versions that have less functionality. Therefore, `the nuget.exe CLI needs to be installed separately <https://docs.microsoft.com/en-us/nuget/consume-packages/package-restore#restore-using-the-nugetexe-cli>`_. Additionally, this VS version comes with an older ClangFormat which is not capable of running  dry-runs for detecting format compliance issues.


Windows SDK versions
--------------------

Orthogonally to the Visual Studio version, different Windows SDK versions are supported.

.. list-table:: Windows SDK versions
   :widths: 20 20 20
   :header-rows: 1

   * - SDK version number
     - Version number based on release date
     - Symbolic version name
   * - 10.0.19041
     - 2004
     - VB 
   * - 10.0.18362.0
     - 1903
     - 19H1
   * - 10.0.17763.0
     - 1809
     - RS5

Building the CNG Engine is not possible without any of these SDK versions installed.


OpenSSL version and installation location
-----------------------------------------

The CNG Engine can only be used in conjunction with the ``1.1.1`` branch of OpenSSL, due to differences in API definitions for the different versions. Several commonly used installation directories are supported out of the box. For other locations, use an environment variable or MSBuild property called ``OpenSSLDir`` to indicate the OpenSSL installation location.

Whichever installation directory is used, the CNG Engine projects will try to find the associated OpenSSL debug binaries in the same directory but suffixed with the character ``d``. If no such directory is found, then no debug information will be available.

.. list-table:: Supported OpenSSL setups
   :widths: 20 30
   :header-rows: 1

   * - Installation location
     - Remarks
   * - ``C:\Program Files\OpenSSL``
     - Standard OpenSSL 64-bits build installation directory
   * - ``C:\Program Files (x86)\OpenSSL``
     - Standard OpenSSL 32-bits build installation directory
   * - ``C:\OpenSSL-v111-Win64``
     - Standard AppVeyor 64-bits installation directory
   * - ``C:\OpenSSL-v111-Win32``
     - Standard AppVeyor 32-bits installation directory
   * - ``OpenSSLDir`` environment variable
     - Custom OpenSSL installation directory, independent of CPU architecture
   * - ``OpenSSLDir`` MSBuild property
     - Custom OpenSSL installation directory, independent of CPU architecture


GoogleTest components
---------------------

The CNG Engine functional tests leverage `the GoogleTest C++ test framework <https://github.com/google/googletest>`_, currently version ``1.8.1.3``. This dependency is captured in the Visual Studio project files as well as the NuGet configuration. For the best IDE experience, please make sure to select the GoogleTest components as part of Visual Studio during the installation process. A dependency on `the GoogleTestAdapter <https://github.com/csoltenborn/GoogleTestAdapter>`_ (GTA) ``0.18.0`` is confgured as well.


NuGet
-----

The GoogleTest components described in the previous subsection may need to be installed before building or as part of the building process. MSBuild version 16.5+, which comes with VS2019, has `builtin support for restoring NuGet packages <https://docs.microsoft.com/en-us/nuget/consume-packages/package-restore#restore-using-msbuild>`_. As explained before, the VS2017 toolchain does not have that same capability and in that case, the CNG Engine build scripts will only work if `the nuget.exe CLI has been installed separately <https://docs.microsoft.com/en-us/nuget/consume-packages/package-restore#restore-using-the-nugetexe-cli>`_ manually.


ClangFormat
------------

To ensure that the CNG Engine code follows the `OpenSSL code formatting rules <https://www.openssl.org/policies/codingstyle.html>`_, a file called ``.clang-format`` is present in the ``src`` directory. Whenever the build script is run, a ClangFormat dry run is executed to verify that the formatting has been applied correctly. This requires a version 10+ of ClangFormat, as installed with VS2019. For VS2017, ClangFormat does not have the appropriate version number and the dry-tun test is not supported.

For more details concerning the code formatting, see section :ref:`process_rst`.


Sphinx
------

The documentation for this project is written in reStructuredText and found in the directory ``docs\rst``. A python script for locally building the HTML-formatted version is provided as ``doc\build_html.py``. Running this requires Python 3.6+ with the `Sphinx <https://pypi.org/project/Sphinx/>`_ and `sphinx-rtd-theme <https://pypi.org/project/sphinx-rtd-theme/>`_ packages installed.

Note that the principal location of the documentation is `on Read the Docs <https://openssl-cng-engine.readthedocs.io/en/latest/>`_. That version is rebuilt whenever updates are pushed to the project's ``develop`` branch - and probably the one you are currently reading :-).
