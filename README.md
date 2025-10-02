
- [SUIT for IETF124 Demo](#suit-for-ietf124-demo)
  - [Generate SUIT Manifest](#generate-suit-manifest)
  - [Build SUIT Manifest Processor](#build-suit-manifest-processor)
    - [Install requirements](#install-requirements)
    - [Build](#build)
  - [Process app.wasm SUIT Manifest](#process-appwasm-suit-manifest)
    - [Install WasmRuntime](#install-wasmruntime)
    - [Run](#run)

# SUIT for IETF124 Demo

> [!NOTE]
> Tested only in Ubuntu 22.04LTS
```sh
git clone --recursive https://github.com/kentakayama/ietf124
cd ietf124
```

## Generate SUIT Manifest

Install requirements (Ruby and Rust)
```sh
sudo apt install ruby ruby-rubygems
sudo gem install cbor-diag cbor-diag-e cbor-diag-ref cddl

curl https://sh.rustup.rs -sSf | sh
```

```sh
make -C manifest test
```

## Build SUIT Manifest Processor

### Install requirements
```sh
sudo apt install openssl openssl-dev gcc
make -C QCBOR libqcbor.a
make -C t_cose -f Makefile.ossl libt_cose.a
make -C libcsuit -f Makefile libcsuit.a
```

### Build
```sh
make -C process
```

## Process app.wasm SUIT Manifest

### Install WasmRuntime
We chose WAMR, wasm-micro-runtime which provides `iwasm` command.
```sh
git clone https://github.com/bytecodealliance/wasm-micro-runtime
cd wasm-micro-runtime/product-mini/platforms/linux/
mkdir build && cd build
cmake ..
make
sudo make install
```

### Run
```sh
make -C run
```

> [!TIP]
> The SUIT Manifest Processor consumes `manifest/app.wasm.envelope.cbor`, and extract the `app.wasm` file in current directory.
> Additionally, it stores also the manifest itself as `manifest.app.wasm.0.suit`, because the manifest contains the id in `suit-manifest-component-id`.
