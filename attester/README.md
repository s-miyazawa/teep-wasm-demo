# ietf124-teep-attester 

This repository contains the Attester implementation used in the TEEP demo planned for IETF 124. 
The TAM and Verifier components are maintained in separate repositories.
This repository focuses on building and running the Attester. 
By combining this Attester with the corresponding TAM, you can simulate the full TEEP provisioning flow.

Note: This sample currently does not run inside a Trusted Execution Environment (TEE). Enabling a real TEE integration (e.g., OP-TEE, Intel SGX) is planned as future work.

## Architecture

![architectureFig](doc/images/architecture-fig.png)

## Directory Structure

````
📁 attester 
├── 📁 third_party (TEEP dependencies tracked as git submodules)
│   ├── 📁 libcsuit
│   ├── 📁 libteep 
│   ├── 📁 QCBOR 
│   ├── 📁 t_cose 
├── 📁 src (attester sources)
├── 📁 scripts (building third_party libraries)
└── 📁 tests (CBOR fixtures and the utilities for TAM mock server) 
````

The TEEP Attester uses the following libraries.
* [libcsuit](https://github.com/kentakayama/libcsuit)
* [libteep](https://github.com/kentakayama/libteep)
* [QCBOR](https://github.com/laurencelundblade/QCBOR)
* [t_cose](https://github.com/laurencelundblade/t_cose)
* [OpenSSL](https://packages.debian.org/sid/libcurl4-openssl-dev)



## Getting started

### Prerequisites
Docker is required for the sample build process. (See [README](../README.md).) \
To run this program as part of the complete architecture, please refer to the [README](../README.md).

```
host$ git clone --recursive https://github.com/s-miyazawa/teep-wasm-demo.git
host$ cd /path/to/teep-wasm-demo/attester
```

### Run TAM Mock Server
- The TAM mock server listens on port 8080 and serves `app.wasm` file. Start it before running the attester client so that the Attester can fetch the application payload.
- Stop the mock server with `Ctrl+C` when finished.

```
host$ cd /path/to/teep-wasm-demo/attester/tests
host$ ./tam_server.sh
```


### Attester Client

The Attester client can be built and executed in two ways:  
(1) using Docker for an isolated environment, or  
(2) building directly on the host machine. 

The Docker-based method is recommended for first-time users or for quickly running the demo.

#### Docker environment
- After launching the TAM mock server, run `teep_wasm_get install app.wasm` from the attester directory so the binary fetches `app.wasm` from the mock endpoint.
- The address `http://172.17.0.1:8080/tam` corresponds to the Docker host. Check your environment settings and update this address if necessary.


```
host$ cd /path/to/teep-wasm-demo/attester
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

#### Host environment
- The host build has been tested on **Ubuntu 22.04 LTS**. Other Linux distributions may work but have not been verified.
- For a host-only workflow, install dependencies locally, build the project, launch the mock server, and then run the attester CLI from the host environment.

```
# install dependencies (Ubuntu example)
host$ sudo apt-get update
host$ sudo apt-get -y install libcurl4-openssl-dev git gcc \
        make libssl-dev cmake g++ netcat-openbsd

# install wasm-micro-runtime CLI
host$ git clone --depth 1 https://github.com/bytecodealliance/wasm-micro-runtime
host$ cd wasm-micro-runtime/product-mini/platforms/linux
host$ mkdir build && cd build
host$ cmake .. 
host$ make
host$ sudo make install   # installs iwasm under /usr/local/bin

# fetch submodules and build
host$ cd /path/to/teep-wasm-demo/attester
host$ make
host$ sudo make install  # installs teep_wasm_get under /usr/local/bin

# run the attester CLI on the host
host$ teep_wasm_get install app.wasm
host$ iwasm app.wasm
```



## Running & CLI Options
After building the attester (see the [Attester Client section](#attester-client)), you can use the `teep_wasm_get` command located in `/usr/local/bin/` to install the application.


### CLI Options

```
Usage: ./teep_wasm_get install <app_name> [--url <url> | -u <url>] [--profile <profile> | -p <profile>]
```

| Option | Description |
|---------|--------------|
| `install` | The currently supported mode; it requests the TAM to provision the selected application. |
| `<app_name>` | Specifies the name of the application to install. |
| `--url <url>` / `-u <url>` | Override the TAM base URL when connecting. Default: `http://localhost:8080/tam`. |
| `--profile <profile> ` / `-p <profile>` | Specifies the Entity Attestation Token (EAT) profile used by the Attester when generating evidence. Supported profiles are `psa` and `generic`. Default: `psa`. |

---

### Environment Variables

| Variable | Description |
|-----------|--------------|
| `TAM_URL` | Sets the base URL of the TAM. The CLI `--url` option takes precedence if both are provided. |



