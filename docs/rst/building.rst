.. _building_rst:

Building the solution
=====================

Please read section :ref:`building_toolchains_rst` first, to learn about the Visual Studio version prerequisites as well as the 3rd party components required.

Building the CNG Engine should be easy, if all prerequisites are met. If you prefer to use the Visual Studio IDE, just (double) clicking the solution ``openssl-cng-engine.sln`` should open your installed version of Visual Studio or, if you have multiple versions installed, will let you select which version to use. As long as you have some edition of VS2017 or VS2019, you should be good. With this approach, the latest installed version of the Window SDK should automatically be configured as well. From there, build the solution as usual. If that does not work, or if you want to learn about the nitty gritty details, check out section :ref:`building_solutions_rst`.

The Visual Studio solutions refer to several `MSBuild <https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2019>`_ project files found in the ``msbuild`` directory. In most cases, there is no need to know anything about them. Sometimes, for example if you want to select different compiler or linker settings, you may want to modify them. In that case, see section :ref:`building_projects_rst` for the details.

For headless building, a batch script ``msbuild-single.bat`` has been provided in that same ``msbuild`` directory. It is used by the CI setup for checking the build as well. Section :ref:`building_scripts_rst` explains how to use it.

.. toctree::
   :maxdepth: 1
   :hidden:

   building/toolchains
   building/solutions
   building/projects
   building/scripts
