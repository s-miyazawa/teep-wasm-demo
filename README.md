[[_TOC_]]

# SUIT for IETF124 Demo

## Generate SUIT Manifest

Install requirements
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

