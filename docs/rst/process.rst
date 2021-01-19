.. _process_rst:

Development process
===================

This section highlights a few development conventions and mechanisms followed for this project.


Code style and formatting
-------------------------

The core elements of this project, the BCrpyt and NCrypt engines are written in C. The style and formatting are expected to follow the `OpenSSL Coding Style <https://www.openssl.org/policies/codingstyle.html>`_.

The OpenSSL project achieves code formatting via the GNU ``indent`` tool, as explained in `Code Reformat Finished <https://www.openssl.org/blog/blog/2015/02/11/code-reformat-finished/>`_. In addition to the fact that this tool seems practically obsolete -- its last stable release was in 2008 --, it is cumbersome to get it on Windows.

Instead, this project leverages ClangFormat with settings that seem to have the same result. For the settings used, see ``.clang-format`` in ``src``. Visual Studio will pick this up automatically and is able to execute the reformatting. However, it seems that support for the ClangFormat option ``AlignConsecutiveMacros`` is not available for the version that is shipped with VS2017.

When using the build script ``msbuild-single.bat`` in ``msbuild``, the code format checking will be executed as well for VS2019. To do so, the options ``--dry-run --Werror`` are used. If the check fails, the script will fail as well. For VS2017, these options are not available and code formatting checking is skipped.

Checking the code style is done by review.


CI on AppVeyor
--------------

For any pull request on the ``develop`` branch as well as actual merges into that branch, the steps as captured in `.appveyor.yml <https://github.com/reiniert/openssl-cng-engine/blob/develop/.appveyor.yml>`_ are executed on  `AppVeyor <https://www.appveyor.com>`_ Visual Studio 2017 as well as 2019 instances. In a nutshell, they are:

* Run script ``msbuild-single.bat``. For details on what it does, see section :ref:`building_scripts_rst`
* For both x64 and x86, run ``gtest-engine-bcrypt`` and ``gtest-engine-ncrypt`` in release build.
* Execute the same tests in debug build, within the ``VSTest.Console`` framework.

Failure of each of these steps will cancel the execution and mark the build as failed. The result is visible via the GitHub check indicator, which also contains a hyperlink to all console output and the test results as obtained by AppVeyor. For the latest build results, see `AppVeyor's main openssl-cng-engine page <https://ci.appveyor.com/project/fgaranda/openssl-cng-engine/branch/develop>`_.


Automatic documentation building on Read the Docs
-------------------------------------------------

For any pull request on the ``develop`` branch, `Read the Docs <https://readthedocs.org>`_ will create a temporary build of the documentation found in the ``docs`` directory, to check for any irregularities. The result is communicated back to GitHub. The temporary documentation is visible on Read the Docs with an indication that it is created from a pull request.

For every actual push into the ``develop`` branch, the documentation will be rebuilt. Is is accessible via `Read the Docs' landing page for openssl-cng-engine <https://openssl-cng-engine.readthedocs.io/en/latest/index.html>`_.


Git usage conventions
---------------------

There is currently no strict flow with regard to the usage of git, other than the following conventions:

* The ``main`` branch contains released versions only and its ``HEAD`` should therefore always be buildable and stable.
* The ``develop`` branch is for the latest rolling version. Its state should always be without failed checks on AppVeyor and Read the Docs, but ``HEAD`` may not always be entirely stable due to evolution.
* Development is done in forks of the main repository. Contributions are accepted through pull requests from such forks.
* Branch names are expected to be derived from the title of the issue they resolve, with all characters in lowercase and spaces replaced by dashes. This should be prefixed by the issue number.
* To avoid loss of commit details, pull requests are not rebased but (squash-)merged.
