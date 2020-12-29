[![Build Status](https://ci.appveyor.com/api/projects/status/github/rticommunity/openssl-cng-engine?branch=develop&svg=true&passingText=passing%20%F0%9F%A5%B3)](https://ci.appveyor.com/project/rticommunity/openssl-cng-engine/branch/develop)

# Welcome to RTI's OpenSSL CNG Engine

> :warning: This repository is work in progress. Check back soon for its first release.

This OpenSSL CNG Engine project implements an engine for transparently leveraging Windows' [Cryptography API: Next Generation](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal) (CNG) with OpenSSL `1.1.1`. It supports CNG's [Cryptographic Primitives](https://docs.microsoft.com/en-us/windows/win32/seccng/cryptographic-primitives) as well as some of its [Key Storage and Retrieval](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval) mechanisms and legacy [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/>) (CAPI) functionality for certificates.

For questions related to using this engine in conjunction with RTI's Connext DDS Secure product, please contact .

## Getting started

Check out [the User's Manual](https://openssl-cng-engine.readthedocs.io/en/latest/index.html) to get started.
