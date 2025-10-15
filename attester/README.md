# ietf124-teep-attester 

This repository hosts the Attester implementation used in the TEEP demo planned for IETF 124. 
The TAM and Verifier components are maintained in separate repositories; this repository focuses on building and running the Attester. 
By combining this Attester with the corresponding TAM, you can simulate the full TEEP provisioning flow.

Note: This sample does not currently run inside a Trusted Execution Environment. Enabling a real TEE integration (e.g., OP-TEE, Intel SGX) is planned as future work.

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
└── 📁 tests (CBOR fixtures and the TAM mock server utilities)
````

The TEEP Attester uses the following libraries.
* [libcsuit](https://github.com/kentakayama/libcsuit)
* [libteep](https://github.com/kentakayama/libteep)
* [QCBOR](https://github.com/laurencelundblade/QCBOR)
* [t_cose](https://github.com/laurencelundblade/t_cose)
* [OpenSSL](https://packages.debian.org/sid/libcurl4-openssl-dev)



## Getting started

### Prerequisites

- Docker is required for the sample build flow. (See [README](../README.md).)
- To run this program as part of the complete architecture, please refer to the [README](../README.md).


### Run TAM Mock Server
- The TAM mock server listens on port 8080 and serves `app.wasm`. Start it before running the attester client so that the Attester can fetch the application payload.
- Stop the mock server with `Ctrl+C` when finished.

```
host$ cd tests
host$ ./tam_server.sh
```



### Attester Client
- After launching the TAM mock server, run `teep_wasm_get install app.wasm` from the attester directory so the binary fetches `app.wasm` from the mock endpoint.
- The address `http://172.17.0.1:8080/tam` corresponds to the Docker host. Verify your environment settings and modify this address as appropriate.


```
host$ docker build -t teep-attester .
host$ docker run -it teep-attester:latest bash

(container)$ ls -la # nothing appears
(container)$ teep_wasm_get install app.wasm -u http://172.17.0.1:8080/tam
(container)$ ls -la # appears "app.wasm" and "manifest.app.wasm.0.suit"
(container)$ iwasm app.wasm 
```

- If you want to run the program using Docker only, execute the following command. In this configuration, the TAM mock server runs in the background, and then the TEEP Agent is executed.

```
host$ docker build -t teep-attester .
host$ docker run teep-attester:latest 
```





## Running & CLI Options
- After building the attester (see the [Attester Client section](#attester-client)), you can use the `teep_wasm_get` command located in `/usr/bin/` to install the application.


```
Usage: ./teep_wasm_get install <application_name> [--tam-url <url>]
```

- `install`: Currently supported mode that requests the TAM to provision the selected application.
- `<application_name>`: Specifies the name of the application to install.
- `--url <url>` / `-u <url>`: Override TAM base URL when connecting. Default is `http://localhost:8080/tam`.
- `TAM_URL`: Environment variable that also sets the TAM base URL; the CLI flag takes priority when both are provided.
