.. _building_scripts_rst:

Convenience scripts
===================

The ``msbuild`` directory contains batch scripts that can execute specific tasks conveniently.

Scripts for building solutions
------------------------------

The scripts ``msbuild-single.bat`` and ``msbuild-all.bat`` can be used for building the solution in a headless mode, from the command line. Using these scripts still requires a complete toolchain to be installed, as explained in :ref:`building_toolchains_rst`. However, the Visual Studio IDE is not started. The scripts (try to) figure out by themselves where the different toolchain components are located. Consequently, it is possible (or rather, recommended) to run them from a plain Command Prompt. This is the approach taken in the AppVeyor CI environment.

``msbuild-single.bat``
**********************

This script executes the following steps:

* Parses the (optional) parameters provided to identify the target and toolchain requested for this build
* Finds and invokes the right development environment script, depending on the requested toolchain
* Uses CLangFormat (if version 10+ is present) to verify code formatting compliance
* Restores any NuGet packages needed (explicitly, using NuGet, or implicitly, using MSBuild)
* Runs MSBuild for the Debug and Release configurations, both for x86 and x64 platforms

.. code-block:: none

    >msbuild\msbuild-single.bat help

    This is msbuild-single
    A convenience script for building the CNG Engine plugins.

    Usage: msbuild-single [[target [sdk_name [vs_version]]]

        target
        Optional MSBuild target to build for.
        Recognized values are:

            Clean
            Compile
            Build
            Rebuild
            DEFAULT will build the default target

        sdk_name
        Optional identifier of SDK version to build with.
        SDK names are hard to remember and referenced to in
        several ways by MicroSoft. The following values are
        currently recognized and supported (with values in
        the same column referring to the same SDK version)

            10.0.19041.0  10.0.18362.0  10.0.17763.0
            2004          1903          1809
            VB            19H1          RS5
            DEFAULT will use the latest installed SDK

        vs_version
        Optional Visual Studio toolchain version to use
        Recognized values are:

            VS2019
            VS2017
            DEFAULT will use the latest installed toolset

        If settings are omitted, that is if less than three
        arguments have been given, their default values will be
        inserted.

    Done

``msbuild-all.bat``
*******************

This script will try to build all currently known configurations by repeatedly invoking the above script ``msbuild-single.bat`` with all possible configurations. If not all SDKs or Visual Studio versions are installed, this will emit errors. Note that this is mostly for testing purposes to see if everything builds fine. You probably do not want to use this script for any other purposes.


Scripts for running tests
-------------------------

Todo...