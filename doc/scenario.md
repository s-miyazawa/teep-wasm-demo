# Running the Demos

The IETF 126 project contains two independent demo tracks. Their setup and operation procedures are documented separately because they use different hardware, user interfaces, and workloads.

## Choose a Track

### TAWS on an Azure VM with Intel SGX

Choose this track to demonstrate:

- TAWS on real Intel SGX hardware;
- browser-based device activation and application management;
- initial installation and update of a YOLOv8 Wasm application;
- the attestation path demonstrated by the Azure deployment.

Continue to [TAWS on an Azure VM with Intel SGX](./demos/taws-azure.md).

### TWEP-SYSTEM on NVIDIA Jetson with OP-TEE

Choose this track to demonstrate:

- a TEEP Agent implemented as a portable Wasm application;
- execution on NVIDIA Jetson with OP-TEE;
- command-oriented Trusted Wasm Apps through `twep-cli`;
- a fixture-backed AttesTAM challenge-response and VERAISON Generic EAT appraisal;
- installation and execution through a resident `twepd` daemon.

Continue to [TWEP-SYSTEM on NVIDIA Jetson with OP-TEE](./demos/twep-jetson.md).

## Common TAM Administration

Both tracks require a TAM Administrator to prepare the Trusted Components required by the selected scenario.

The administrator uses the AttesTAM Console or the SUIT Manifest Service and TEEP Agent Service APIs to:

1. register a Trusted Component and its SUIT manifest;
2. inspect registered Trusted Components;
3. inspect devices that have contacted AttesTAM;
4. confirm installation or update status.

The exact artifact names differ between the tracks. The TAWS track uses the YOLOv8 artifacts in this repository. The TWEP-SYSTEM track uses its own Catalog and application component identifiers.

The Console is a browser-oriented BFF for the administration APIs. Its current implementation does not authenticate or authorize Console users, so expose port 9090 only through a controlled local route or tunnel.

## Previous Simulation Demo

The complete IETF 125 TAWS flow in SGX simulation mode remains available from the [`ietf125` tag](https://github.com/s-miyazawa/teep-wasm-demo/tree/ietf125).
