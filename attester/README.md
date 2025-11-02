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



## Running with Docker

### Prerequisites

- Docker is required for the sample build flow. (See [../README](../README.md).)


### Build

```bash
$ docker build -t teep-attester .
```

### Run

```bash
$ docker run -t teep-attester:latest
```

### Run Step by Step

```bash
$ docker run -it teep-attester:latest bash

(container)$ ls -la # nothing appears
(container)$ /root/ietf124-teep-attester/tests/tam_server.sh > /dev/null &
(container)$ teep_wasm_get install app.wasm -u http://localhost:8080/tam
(container)$ ls -la # appears "app.wasm" and "manifest.app.wasm.0.suit"
(container)$ iwasm app.wasm 
```

If you run the TAM in host environment (referring [Run TAM Server](#run-tam-server)), you may specify the TAM URL with `teep_wasm_get install app.wasm -u http://172.17.0.1:8080/tam` for example.

## Running Natively

### Prerequisites

- OpenSSL, C compiler, make are required

### Build Attester Client

> [!WARNING]
> Make sure you cloned this repository recursively. Otherwise, `git submodule update --init --recursive` before running.

```bash
$ make
```

> [!NOTE]
> In addition to building the attester (see the [Attester Client section](#build-attester-client)), you may install the `teep_wasm_get` command with `make install`.

### Run TAM Server

In the [tam](../tam) directory, `make run-tam-server` to start the TAM.
You can terminate it with `Ctrl+C`.

Instead, you can run the mock TAM server with `./tests/tam_server.sh` in this directory.
It just replies prebuilt TEEP messages of the TAM without parsing the message from attester.


### Run Attester Client
- After launching the TAM server, run `make run` from the attester directory to fetch `app.wasm` from the TAM server.


## CLI Options

```
Usage: teep_wasm_get install <application_name> [--tam-url <url>]
```

- `install`: Currently supported mode that requests the TAM to provision the selected application.
- `<application_name>`: Specifies the name of the application to install.
- `--url <url>` / `-u <url>`: Override TAM base URL when connecting. Default is `http://localhost:8080/tam`.
- `TAM_URL`: Environment variable that also sets the TAM base URL; the CLI flag takes priority when both are provided.
