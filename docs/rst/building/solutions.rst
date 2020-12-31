.. _building_solutions_rst:

Visual Studio solutions
=======================

The starting point for opening the CNG Engine project in the Visual Studio IDE is the solution file ``openssl-cng-engine.sln``, found in the root directory of the project. It loads several projects from the ``msbuild`` subdirectory -- each of which is explained in section :ref:`building_projects_rst`. Also check out that section for some tips if you intend to modify project configuration settings.


Using different Windows SDK versions
------------------------------------

When using the main solution file ``openssl-cng-engine.sln``, the loaded projects will automatically try to figure out what the latest installed Windows SDK version is and select it for building.

In some cases, it may be needed to build with a different SDK version. Visual Studio solutions do not have any convenient way of selecting that, other than through project settings. To avoid proliferation of projects for supporting multiple SDK versions, several solutions have been created with the original name suffixed with ``-2004``, ``-1903`` or ``-1809``. These numbers are indications for the SDK versions, see the `Windows SDK and emulator archive <https://developer.microsoft.com/en-us/windows/downloads/sdk-archive/>`_ page for more details. When loading these alternative solutions, the loaded projects will use the suffix number to select the SDK accordingly. If that particular SDK is not installed, then Visual Studio will issue an error at build time.


Configurations and platforms
----------------------------

Like most solutions, ``openssl-cng-engine.sln`` supports Release and Debug configurations on both x86 and x64 platforms for all its projects. Any of these combinations can be selected and built via the usual Visual Studio IDE mechanisms.


Output directories
------------------

All final binaries are placed under he directory ``bld``, in a subdirectory with a name derived from the platform, configuration and toolchain, and possibly SDK version if it was explicitly selected. Examples are ``bld\x64-Release-v142`` or ``bld\x86-Debug-v141-1903``. Intermediate binaries are placed below that, in a subdirectory called ``all``. More details are provided in section :ref:`building_projects_rst`.
