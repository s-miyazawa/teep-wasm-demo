# TAWS on an Azure VM with Intel SGX

This track provisions and updates a YOLOv8 Wasm application through TAWS running on an SGX-capable Azure VM. The build and run commands on this page follow the documentation and Dockerfile in the TAWS submodule pinned by this repository.

> **Environment status:** The TAWS and AttesTAM build procedures are defined. The final IETF 126 report must still record the Azure VM details and the end-to-end Intel QVL result observed in the demo environment.

## Participants and Components

- **Device User** operates the TAWS Console.
- **TAM Administrator** operates the AttesTAM Console or administration APIs.
- **TAWS** provides the device-side TEEP Agent, TEEP Broker, WAMR integration, and Console.
- **AttesTAM** registers and distributes the YOLOv8 Trusted Components and acts as the Relying Party.
- **AttesTAM embedded Intel QVL** verifies the SGX DCAP Quote against Intel collateral. AttesTAM then verifies the challenge and TEEP Agent key binding.
- **Intel PCS or PCCS** supplies the SGX collateral used by the verifier backend.

## Requirements

The Azure VM must provide:

- Intel SGX-capable hardware;
- Linux SGX driver or kernel support;
- `/dev/sgx_enclave` and `/dev/sgx_provision`;
- Docker for the recommended workflow;
- network connectivity to AttesTAM and the TAWS Console;
- a recursively initialized checkout of this repository.

Confirm the SGX device nodes before building TAWS:

```sh
test -c /dev/sgx_enclave
test -c /dev/sgx_provision
ls -l /dev/sgx_enclave /dev/sgx_provision
```

Initialize this repository and the nested TAWS dependencies with:

```sh
git submodule update --init --recursive
```

## Recommended Docker Workflow

The TAWS Dockerfile installs the Intel SGX SDK, the Azure DCAP Client, the DCAP runtime packages, Go, and the third-party TAWS libraries. It then builds TAWS with `SGX_MODE=HW SGX_DEBUG=1`.

The old IETF 125 `prepare_sgx_base_image.sh` step is not used by this workflow.

### 1. Build the Azure Image

Run this command from the root of `teep-wasm-demo`:

```sh
docker build \
  --build-arg TAWS_DCAP_PROVIDER=azure \
  -t taws:azure \
  ./taws
```

The `TAWS_DCAP_PROVIDER=azure` build argument selects Azure DCAP Client instead of the PCCS-backed image configuration.

### 2. Build and Start AttesTAM with Intel QVL

The normal AttesTAM image is built without the `intel_qvl` build tag and cannot verify `application/sgx-quote3-teep-bundle`. Build the experimental SGX verifier image from the repository root:

```sh
docker build \
  -f AttesTAM/docker/sgx-verifier.Dockerfile \
  -t attestam-sgx \
  AttesTAM
```

For a same-host demo, start AttesTAM with host networking so that TAWS can reach port 8080 and the administrator can reach the Console on port 9090:

```sh
docker run --rm --network host \
  -e ATTESTAM_INSECURE_DEMO_MODE=true \
  attestam-sgx
```

This command uses AttesTAM's public demo keys and is not a production configuration. The Console currently has no user authentication or authorization; access it only through loopback, an SSH tunnel, or another explicitly controlled route.

By default, AttesTAM obtains SGX collateral from Intel PCS. If the deployment requires a subscription key, add `ATTESTAM_INTEL_COLLATERAL_SUBSCRIPTION_KEY`. To use a compatible PCCS instead, set `ATTESTAM_INTEL_COLLATERAL_SERVICE_URL` to its SGX certification v4 base URL. See the AttesTAM documentation for collateral cache and TLS options.

The embedded Intel QVL path is experimental. It validates the SGX Quote against Intel collateral but does not by itself appraise Target Environment identity values such as `MRENCLAVE`, `MRSIGNER`, or `ISV_SVN`.

### 3. Prepare the TAM URL

TAWS uses `http://localhost:8080/tam` by default. Set the URL explicitly when AttesTAM is hosted elsewhere.

```sh
export TAWS_TAM_URL=http://127.0.0.1:8080/tam
```

The Docker commands on this page use host networking and therefore assume that this URL is reachable from the Azure VM host network. If AttesTAM runs on another host, replace `127.0.0.1` with a controlled reachable address and ensure AttesTAM listens on that interface.

The repository's existing `docker-compose.yaml` publishes the AttesTAM Console on port 9090 but keeps the TAM endpoint on port 8080 inside its Docker network. A host-networked TAWS container therefore cannot use `http://127.0.0.1:8080/tam` with that topology unless port 8080 is explicitly published. Alternatively, attach TAWS to the same Docker network and use `http://container_tam:8080/tam`.

### 4. Run TAWS

```sh
docker run --rm -it \
  --network host \
  --device /dev/sgx_enclave:/dev/sgx_enclave \
  --device /dev/sgx_provision:/dev/sgx_provision \
  -e TAWS_TAM_URL="${TAWS_TAM_URL}" \
  -e TAWS_LOG_LEVEL=info \
  taws:azure
```

Supported log levels are `error`, `info`, and `debug`. The image starts the TAWS Web server on `0.0.0.0:8181`.

Open the TAWS Console through the network path selected for the Azure VM, for example an SSH tunnel or an explicitly permitted inbound rule. Do not expose the Console more broadly than required for the demo.

## Native Workflow

The Docker workflow is the shortest path. A native build is also supported on Ubuntu 24.04 with Go 1.22 or later, the Intel SGX SDK/PSW, DCAP quote-generation packages, and Azure DCAP Client.

Install Azure DCAP Client using the Microsoft package repository as described by the TAWS submodule, then build from `taws`:

```sh
cd taws
source /opt/intel/sgxsdk/environment
./scripts/build_third_party.sh
make SGX_MODE=HW SGX_DEBUG=1 SGX_EVIDENCE=1
```

Run the Web server with an explicit bind address and TAM URL:

```sh
./build/go/taws web \
  --addr 0.0.0.0:8181 \
  --url http://127.0.0.1:8080/tam \
  --log-level info
```

See the [TAWS README](https://github.com/yuma-nishi/taws/blob/main/README.md#getting-started) for the complete native package list and Azure DCAP Client installation commands.

## Attestation Configuration

TAWS builds use `SGX_EVIDENCE=1` by default. In this mode, the TEEP Agent places an `application/sgx-quote3-teep-bundle` in the QueryResponse attestation payload. The bundle contains:

- the raw SGX DCAP Quote3;
- raw report data containing the TEEP Agent public-key coordinates and the QueryRequest challenge.

TAWS hashes the raw report data with SHA-384 and binds the digest into SGX `report_data` before requesting the Quote3.

`SGX_EVIDENCE=0` selects the generic EAT development and compatibility path. It is not the configuration documented for the Azure SGX hardware demo.

## SGX and DCAP Tests

The TAWS User Manual defines the following SGX/DCAP integration tests:

```sh
cd taws
make -f Makefile.sgx.test SGX_MODE=HW create-evidence-dcap-integration-test
make -f Makefile.sgx.test \
  SGX_MODE=HW \
  SGX_EVIDENCE=1 \
  process-query-request-dcap-integration-test
```

The tests can report `[SKIP]` when SGX hardware or the quote provider is unavailable. Set `REQUIRE_DCAP=1` when an unavailable DCAP environment must fail the test rather than skip it.

## Demo Scenario

### 1. Start the Server-Side Infrastructure

Start the `attestam-sgx` image described above. Confirm that AttesTAM can retrieve the required Intel collateral and that the TAM endpoint configured in `TAWS_TAM_URL` is reachable from TAWS. External VERAISON is not used for the SGX Quote3 TEEP bundle.

### 2. Start TAWS

Build and run TAWS using the Azure Docker workflow above. Confirm that both SGX device nodes are passed into the container and that the TAWS Console is reachable on port 8181.

### 3. Register the First Model

As the TAM Administrator:

1. open the AttesTAM Console or use the SUIT Manifest Service API;
2. register [`yolov8.wasm.0.envelope.cbor`](../../assets/manifest/yolov8.wasm.0.envelope.cbor);
3. confirm that `yolov8.wasm: ver0` appears in the managed Trusted Component list.

### 4. Activate the Device

As the Device User:

1. open the TAWS Console;
2. click `Activate (TEEP)`;
3. confirm that the device is activated;
4. confirm that the device appears in AttesTAM.

Activation triggers the TEEP exchange in which TAWS can return SGX DCAP Evidence in the QueryResponse.

### 5. Install and Run the First Model

1. In the TAWS Console, click `Install (TEEP)`.
2. Confirm that version 0 is installed for the device in AttesTAM.
3. Upload [`surveillance.jpg`](../../assets/demo-images/surveillance.jpg).
4. Click `Run detector`.
5. Confirm that the result image contains object-detection rectangles.

The current detector accepts JPEG input. The TAWS Web API rejects uploads larger than 128 KiB, and some complex JPEG images may fail during inference even below that limit.

### 6. Register and Install the Updated Model

As the TAM Administrator, register [`yolov8.wasm.1.envelope.cbor`](../../assets/manifest/yolov8.wasm.1.envelope.cbor) and confirm that version 1 appears in AttesTAM.

As the Device User, click `Install (TEEP)` again and confirm that version 1 is installed for the device.

### 7. Run the Updated Model

Upload the same sample image and run the detector again. Confirm that the output reflects the updated application behavior expected for version 1.

### 8. Inspect Evidence and Results

Record the following outputs from the final demo environment:

- proof that TAWS used SGX hardware mode;
- the SGX DCAP Quote3 bundle returned by TAWS or its diagnostic identifier;
- the Intel QVL Quote verification result produced by AttesTAM's embedded backend;
- the Intel PCS or PCCS collateral source and relevant result status;
- the result of AttesTAM's `report_data`, `raw-report-data`, challenge, and Agent-key binding checks;
- the resulting TEEP Agent trust or activation decision.

TAWS implements DCAP Evidence generation and AttesTAM implements the matching Intel QVL backend, but the final IETF 126 report must still record that the complete TAWS and AttesTAM path succeeded in the demonstrated Azure environment.

### 9. Stop the Demo

Stop TAWS and AttesTAM. Remove or stop the Azure resources according to the final cleanup procedure to avoid leaving chargeable resources running.

## Expected Outcome

The track is successful when TAWS runs in SGX hardware mode, produces the documented SGX DCAP Evidence, AttesTAM's embedded Intel QVL backend verifies the Quote, AttesTAM validates the challenge and Agent-key binding, and the Device User can install, execute, update, and re-execute the YOLOv8 Wasm application through TEEP. Target Environment identity appraisal, if required by the demo policy, must be recorded separately.
