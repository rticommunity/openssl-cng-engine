# Welcome to RTI's OpenSSL CNG Engine

This OpenSSL CNG Engine project implements an engine for transparently leveraging Windows' [Cryptography API: Next Generation](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal) (CNG) with OpenSSL 1.1.1. It supports CNG's [Cryptographic Primitives](https://docs.microsoft.com/en-us/windows/win32/seccng/cryptographic-primitives) as well as some of its [Key Storage and Retrieval](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval) mechanisms and legacy [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/>) (CAPI) functionality for certificates.

For questions related to using this engine in conjunction with RTI's Connext DDS Secure product, please contact .

This README provides some minimal pointers only. For a complete overview of how to build, test and use this CNG Engine, check out [the User's Manual on Read the Docs](https://openssl-cng-engine.readthedocs.io/en/latest/index.html).

## Current build status

Whenever a modification is pushed to the `develop` branch of this repository, the solution is built on both VS2017 and VS2019 AppVeyor instantiations, followed by test runs on each of them.

[![Build Status](https://ci.appveyor.com/api/projects/status/github/rticommunity/openssl-cng-engine?branch=develop&svg=true&passingText=passing%20%F0%9F%A5%B3)](https://ci.appveyor.com/project/rticommunity/openssl-cng-engine/branch/develop)

## Quickstart

This section provides some minimal pointers only. For a complete overview of how to build, test and use this CNG Engine, check out [the User's Manual on Read the Docs](https://openssl-cng-engine.readthedocs.io/en/latest/index.html).

The main components that this project provides are two dynamically loadable libraries called `engine-bcrypt.dll`, glueing the CNG Cryptographic Primitives through OpenSSL EVP methods, and `engine-ncrypt.dll`, implementing an OpenSSL STORE abstraction for the Windows Certificate and Key Stores. They can be built and tested from Visual Studio, or via a provided command line script.

### Using Visual Studio

Building the CNG Engine should be easy, if all prerequisites are met. One option is to use the Visual Studio IDE, just (double) clicking the solution `openssl-cng-engine.sln` should open your installed version of Visual Studio or, if you have multiple versions installed, will let you select which version to use. As long as you have some edition of VS2017 or VS2019, you should be good. With this approach, the latest installed version of the Window SDK should automatically be configured as well. From there, build the solution as usual.

If the build was successful, the tests can be run in the debugger. The test projects are based on GoogleTest and called `gtest-engine-bcrypt` and `gtest-engine-ncrypt`. The former is a standalone test and should succeed without failures. The latter depends on the presence of certificates with their associated private keys in the Windows certificate store. By default, it will try to access the personal certificates in the local computer store. Using its keys, like needed for the signing tests, requires running with administrator privileges.

### Using the command prompt

A convenient way to build the solution is provided through the `msbuild-single.bat` script in the `msbuild` directory. This can be run in a plain CMD box, no need to start a Visual Studio shell. The scripts will try to figure out the appropriate toolchain locations. Running it will output, among others, the following lines:

    MSBuild-ing x86|Debug   into bld\x86-Debug-v142
    MSBuild-ing x64|Debug   into bld\x64-Debug-v142
    MSBuild-ing x86|Release into bld\x86-Release-v142
    MSBuild-ing x64|Release into bld\x64-Release-v142

After successfully completing the build, all elements needed to run a set of functional tests should appear in the folders mentioned here. With the above setup, the following command is an example of how to run the BCrypt EVP tests from the command line:

    >bld\x64-Debug-v142\gtest-engine-bcrypt.exe

As explained above, `gtest-engine-ncrypt` requires administrator privileges to succeed because it tries to use private keys from the local computer's personal store for its signing functionality.

This completes the Quickstart. From this point on, it is recommended to read [the User's Manual on Read the Docs](https://openssl-cng-engine.readthedocs.io/en/latest/index.html).

## Thanks

Many thanks go to

- [AppVeyor](https://www.appveyor.com) for their great Continuous Integration (CI) service used to continuously monitor the quality of this project
- [Read the Docs](https://www.readthedocs.org) for building and hosting the documentation for this project.