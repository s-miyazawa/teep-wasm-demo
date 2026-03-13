# Testvectors for IETF125 Hackathon

> [!NOTE]
> This directory is only for the Hackathon collaborators to implement TAM and TEEP Broker&Agent.

## For Collaborators

### To TAM operator

The [prebuilt/text.0.envelope.cbor](./prebuilt/text.0.envelope.cbor) is the **untagged** SUIT Manifest to be transferred in the TEEP Protocol, and [manifest/text0/](./manifest/text0/text.0.manifest.rediag) is the manifest core in diagnostic notation.

Please send it to the TEEP Agent in TEEP Update messages.

> [!WARNING]
> The manifest uses ESP256 (alg id -9), which is not widely supported by most COSE libraries.
> If you use SUIT Manifest Processor other than one using libcsuit, please confirm that it supports the algorithm.

### To TEEP Agent implementor

The TAM would send the [prebuilt/text.0.envelope.cbor](./prebuilt/text.0.envelope.cbor) or other SUIT manifests in TEEP Update message, process it using `suit_process_envelope()` libcsuit function.

> [!NOTE]
> The libcsuit parses the manifest and triggers some callback functions, like suit_condition_callback and suit_store_callback, depending on the manifest.
> After processing, the SUIT Report should be sent to the TAM in TEEP Success/Error messages.

### To Both TAM and TEEP Agent implementors

The prebuilt TEEP Protocol messages are in the `prebuilt/` directory.
You can print them with:

```sh
cbor2diag.rb -e prebuilt/query_request.tam.esp256.cose
cbor2diag.rb -e prebuilt/query_response.agent.esp256.cose
cbor2diag.rb -e prebuilt/update.tam.esp256.cose
cbor2diag.rb -e prebuilt/teep_success.agent.esp256.cose
cbor2diag.rb -e prebuilt/teep_error.agent.esp256.cose
```

To run these commands, you have to install cbor-diag (refer [Install requirements (Ruby)](#install-requirements-ruby)).

## Generate Customized testdata

Following commands are guidance for Ubuntu/Linux.
Replace them appropriately for you environment.

### Install requirements (Ruby)
```sh
sudo apt install ruby ruby-rubygems
sudo gem install cbor-diag cbor-diag-e cbor-diag-ref cddl
```

### Install requirements (Rust)
```sh
curl https://sh.rustup.rs -sSf | sh
```

### Build WAMR (Required for yolov8 build)

```sh
cd wasm-micro-runtime/product-mini/platforms/linux/
mkdir build && cd build
cmake ..
make
```

### Generate
```sh
make -C cddl/
make -C manifest/
make -C rats/
make -C teep/ test
```
