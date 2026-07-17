# TAWS on an Azure VM with Intel SGX

For an overview of TAWS, its components, and the demo lifecycle, see [TAWS](../implementations/taws.md). This page is the complete procedure for reproducing the current demo on an SGX-capable Azure VM.

The build and run commands on this page follow the documentation and Dockerfile in the TAWS submodule pinned by this repository.

## Participants and Components

See the [Common Architecture](../architecture.md#common-architecture) diagram. This Azure demo uses the TAWS, AttesTAM, embedded Intel QVL, and Intel PCS or PCCS path shown there.

- **Device User** operates the TAWS Console.
- **TAM Administrator** operates the AttesTAM Console or administration APIs.
- **TAWS** runs on the Azure VM as the device-side TEEP implementation and communicates with AttesTAM.
- **AttesTAM** registers and distributes the YOLOv8 Trusted Components and acts as the Relying Party.
- **AttesTAM embedded Intel QVL** verifies the SGX DCAP Quote against Intel collateral. AttesTAM then verifies the challenge and TEEP Agent key binding.
- **Intel PCS or PCCS** supplies the SGX collateral used by the verifier backend.

## Requirements

The Azure VM must provide:

- Intel SGX-capable hardware;
- Linux SGX driver support with `/dev/sgx_enclave` and `/dev/sgx_provision` available to the TAWS container.

## Recommended Docker Workflow

The TAWS Dockerfile installs the Intel SGX SDK, the Azure DCAP Client, the DCAP runtime packages, Go, and the third-party TAWS libraries. It then builds TAWS with `SGX_MODE=HW SGX_DEBUG=1`.

### 1. Build　and Run the TAWS Image for Azure VMs

Run this command from the root of `teep-wasm-demo`:

```sh
docker build \
  --build-arg TAWS_DCAP_PROVIDER=azure \
  -t taws:azure \
  ./taws

docker run --rm -it \
  --network host \
  --device /dev/sgx_enclave:/dev/sgx_enclave \
  --device /dev/sgx_provision:/dev/sgx_provision \
  -e TAWS_LOG_LEVEL=info \
  taws:azure
```
Supported log levels are `error`, `info`, and `debug`. The image starts the TAWS Web server on `0.0.0.0:8181`.

Please refer to the [TAWS](https://github.com/yuma-nishi/taws/blob/main/README.md) for detailed information.

### 2. Build and Run AttesTAM with Intel QVL

Build the experimental SGX verifier image from the repository root:

```sh
docker build \
  -f AttesTAM/docker/sgx-verifier.Dockerfile \
  -t attestam-sgx \
  ./AttesTAM

docker run --rm --network host \
  -e ATTESTAM_INSECURE_DEMO_MODE=true \
  attestam-sgx
```

For AttesTAM build, deployment, and Intel collateral configuration, see the [AttesTAM documentation](https://github.com/kentakayama/AttesTAM/blob/main/README.md).

The embedded Intel QVL path is experimental. 
It validates the SGX Quote against Intel collateral but does not by itself appraise Target Environment identity values such as `MRENCLAVE`, `MRSIGNER`, or `ISV_SVN`.

## Demo Scenario

### 1. Register the First Model

As the TAM Administrator:

1. open the AttesTAM Console or use the SUIT Manifest Service API;
2. register [`yolov8.wasm.0.envelope.cbor`](https://github.com/s-miyazawa/teep-wasm-demo/blob/main/assets/manifest/yolov8.wasm.0.envelope.cbor);
3. confirm that `yolov8.wasm: ver0` appears in the managed Trusted Component list.

### 2. Activate the Device

As the Device User:

1. open the TAWS Console;
2. click `Activate (TEEP)`;
3. confirm that the device is activated;
4. confirm that the device appears in AttesTAM Console.

Activation triggers the TEEP exchange in which TAWS can return SGX DCAP Evidence in the QueryResponse.

### 3. Install and Run the First Model

1. In the TAWS Console, click `Install (TEEP)`.
2. Confirm that version 0 is installed for the device in AttesTAM.
3. Upload [`surveillance.jpg`](https://github.com/s-miyazawa/teep-wasm-demo/blob/main/assets/demo-images/surveillance.jpg).
4. Click `Run detector`.
5. Confirm that the result image contains object-detection rectangles.

The current detector accepts JPEG input. The TAWS Web API rejects uploads larger than 128 KiB, and some complex JPEG images may fail during inference even below that limit.

### 4. Register and Install the Updated Model

As the TAM Administrator, register [`yolov8.wasm.1.envelope.cbor`](https://github.com/s-miyazawa/teep-wasm-demo/blob/main/assets/manifest/yolov8.wasm.1.envelope.cbor) and confirm that version 1 appears in AttesTAM.

As the Device User, click `Install (TEEP)` again and confirm that version 1 is installed for the device.

### 5. Run the Updated Model

Upload the same sample image and run the detector again. Confirm that the output reflects the updated application behavior expected for version 1.
