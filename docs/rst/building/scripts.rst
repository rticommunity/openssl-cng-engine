.. _building_scripts_rst:

Build scripts
=============

The ``msbuild`` directory contains the batch scripts ``msbuild-single.bat`` and ``msbuild-all.bat`` for conveniently building the solution in a headless mode, from the command line. Using these scripts still requires a complete toolchain to be installed, as explained in :ref:`building_toolchains_rst`. However, the Visual Studio IDE is not started. The scripts (try to) figure out by themselves where the different toolchain components are located. Consequently, it is possible (or rather, recommended) to run them from a plain Command Prompt as opposed to some Visual Studio command prompt. This is the approach taken in the AppVeyor CI environment as well.

``msbuild-single.bat``
----------------------

This script executes the following steps:

* Parses the (optional) parameters provided to identify the target and toolchain requested.
* Finds and invokes the right development environment script for the requested toolchain.
* Uses CLangFormat to verify code formatting compliance, in VS2019 environments only.
* Restores any NuGet packages needed, explicitly using NuGet, or implicitly using MSBuild.
* Runs MSBuild for the Debug and Release configurations, both for x86 and x64 platforms.

The MSBuild commands executed by this script contain options for writing log files to the ``log`` subdirectory. The exact locations of these files, as well as the output binaries, is printed when the script is run. This is illustrated by the following example run:

.. code-block:: none

    >msbuild\msbuild-single.bat

    Running script msbuild-single invoked with:
    target =
    sdk_version =
    vs_version =

    MSBuild target :
    SDK info       : latest installed
    VS version     : VS2019 (v142)
    VS solution    : openssl-cng-engine.sln
    Log files      : log\<CPU>-<Config>-v142-<Level>.log
    Build dir      : bld\<CPU>-<Config>-v142

    **********************************************************************
    ** Visual Studio 2019 Developer Command Prompt v16.8.3
    ** Copyright (c) 2020 Microsoft Corporation
    **********************************************************************

    Verifying code formatting
    MSBuild-ing x86|Debug   into bld\x86-Debug-v142
    MSBuild-ing x64|Debug   into bld\x64-Debug-v142
    MSBuild-ing x86|Release into bld\x86-Release-v142
    MSBuild-ing x64|Release into bld\x64-Release-v142

    Done

To get more information about the available command line options for this script, execute it with ``help`` as its first argument, like so:

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
-------------------

This script will try to build all currently known configurations by repeatedly invoking the above script ``msbuild-single.bat`` with all possible configurations. If not all SDKs or Visual Studio versions are installed, this will emit errors. Note that this is mostly for testing purposes to see if everything builds fine. You probably do not want to use this script for any other purposes.
