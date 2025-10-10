# ietf124-teep-attester 

This repository hosts the Attester implementation used in the TEEP demo planned for IETF 124. 
The TAM and Verifier components live in separate repositories; here we focus on building and running the Attester (teep_wasm_get). 
By combining this Attester with the matching TAM, you can replay the full TEEP provisioning

Notes: This sample does not currently run inside a Trusted Execution Environment. Enabling a real TEE integration (e.g., OP-TEE, Intel SGX) remains future work.

## Architecture

![architectureFig](doc/images/architecture-fig.png)

## Directory Structure

````
📁 ietf124-teep-attester 
├── 📁 third_party (TEEP dependencies tracked as git submodules)
│   ├── 📁 libcsuit
│   ├── 📁 libteep 
│   ├── 📁 QCBOR 
│   ├── 📁 t_cose 
├── 📁 src (attester sources)
└── 📁 bin (build output directory created after running make)
└── 📁 tests (CBOR fixtures and the TAM mock server utilities)
````

TEEP Attester uses the following libraries.
* [libcsuit](https://github.com/kentakayama/libcsuit)
* [libteep](https://github.com/kentakayama/libteep)
* [QCBOR](https://github.com/laurencelundblade/QCBOR)
* [t_cose](https://github.com/laurencelundblade/t_cose)



## Getting started

### Prerequisites

- Docker is required for the sample build flow (See [README](../README.md)).


### Run TAM Mock Server
- The TAM mock server listens on port 8080 and serves `app.wasm`. Start it before running the attester client so the binary can fetch the application payload.

```
host$ cd tests
host$ ./tam_server.sh
```
- Stop the mock server with `Ctrl+C` when finished.


### Attester Client
- After launching the TAM mock server, run `teep_wasm_get install app.wasm` from the attester directory so the binary fetches `app.wasm` from the mock endpoint.

```
host$ docker build -t teep-attester .
host$ docker run -it teep-attester:latest bash

(container)$ ls -la # nothing appears
(container)$ teep_wasm_get install app.wasm -u http://172.17.0.1:8080/tam
(container)$ ls -la # appears "app.wasm" and "manifest.app.wasm.0.suit"
(container)$ iwasm app.wasm 
```


## Running & CLI Options
- After building the attester (see the [Attester Client section](#attester-client)), you can use the `teep_wasm_get` command located in `/usr/bin/` to install the application.


```
Usage: ./teep_wasm_get install <application_name> [--tam-url <url>]
```

- `install`: Current supported mode that requests the TAM to provision the selected application.
- `<application_name>`: File or manifest seed located according to your TAM configuration.
- `--url <url>` / `-u <url>`: Override TAM base URL when connecting. Default is `http://localhost:8080/tam`.
- `TAM_URL`: Environment variable that also sets the TAM base URL; the CLI flag takes priority when both are provided.


## License(TODO:Must be revised)

BSD 2-Clause License

Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.