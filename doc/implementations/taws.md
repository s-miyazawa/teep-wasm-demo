# TAWS

TAWS is the first TEEP Agent implementation developed for this project. It provides the device-side functions used by the original building-security scenario.

## Components

TAWS contains:

- a TEEP Broker that communicates with AttesTAM over HTTP;
- a TEEP Agent that processes TEEP messages and manages Trusted Components;
- WAMR for executing provisioned Wasm applications;
- the TAWS Console for device activation, application installation, update, and execution.

## Workload

The TAWS track provisions a YOLOv8 object-detection application as a Wasm Trusted Component. Two model versions demonstrate both initial installation and update.

The Device User performs the following lifecycle:

1. activate the device;
2. install the first model version;
3. run object detection;
4. install the newer model version;
5. run object detection again.

The TAM Administrator registers the corresponding Trusted Components and inspects device state through the AttesTAM Console or administration APIs.

## IETF 125 and IETF 126 Environments

The IETF 125 demo used Intel SGX simulation mode. The IETF 126 track deploys TAWS on an SGX-capable Azure VM so that the TEEP Agent environment and Wasm workload execute using real SGX hardware.

The final demo documentation will record:

- Azure VM type and operating-system version;
- SGX driver, runtime, and device configuration;
- how hardware mode is verified;
- confirmation that the implemented DCAP Quote3 path produced Evidence in the demo environment;
- confirmation that AttesTAM's embedded Intel QVL backend verified the SGX Quote against Intel collateral;
- how the TEEP Agent key is bound to the attested environment.

TAWS builds use `SGX_EVIDENCE=1` by default and implement an `application/sgx-quote3-teep-bundle` containing a raw DCAP Quote3 and report data. AttesTAM selects its experimental embedded Intel QVL backend for this format. Hardware enclave execution, Evidence generation, Quote verification, and the final AttesTAM trust decision are recorded as separate results.

## Build Modes

TAWS supports Docker and native workflows. The recommended Azure Docker build uses:

```sh
docker build \
  --build-arg TAWS_DCAP_PROVIDER=azure \
  -t taws:azure \
  ./taws
```

The Azure image installs Azure DCAP Client and builds TAWS with `SGX_MODE=HW SGX_DEBUG=1`. SGX simulation remains available only as a development option with `make SGX_MODE=SIM`.

## User Interface

The TAWS Console is a browser-based interface used to activate the device, install or update the model, upload an input image, and run the detector.

![TAWS Console](../img/taws-image.png)

See [TAWS on an Azure VM with Intel SGX](../demos/taws-azure.md) for the IETF 126 scenario.
