.. _testing_rst:

Testing the build
=================

After completing the build using one of the mechanisms outlined in :ref:`building_rst`, all elements needed to run the functional tests included with the project should be present. This includes 3rd party components, either installed (or rather, restored) with NuGet as part of the build process, or provided by the Visual Studio installation. Successful completion of the build step is a necessary and sufficient prerequisite for running the tests.

Currently, both the BCrypt (EVP) and NCrypt (STORE) engine components have associated functional tests based on the Google Test framework. For explanations and details concerning these tests, see section :ref:`testing_functional_tests_rst`.

These tests can be run directly from the command line, as explained in section :ref:`testing_command_line_rst`. Both the EVP and STORE test applications allow for leveraging the `VSTest <https://github.com/microsoft/vstest>`_ platform as well, see section :ref:`testing_vstest_console_rst` for that. Another way to run the tests is from the Visual Studio IDE. Some guidelines for that are given in section :ref:`testing_visual_studio_rst`.

.. toctree::
   :hidden:

   testing/functional_tests
   testing/command_line
   testing/vstest_console
   testing/visual_studio
   