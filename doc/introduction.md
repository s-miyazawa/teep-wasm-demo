# Introduction

The IETF 126 TEEP Wasm Demo explores secure Wasm application provisioning with TEEP and device trust establishment through RATS-based remote attestation.

The demo has two independent, complementary tracks:

- **TAWS on an Azure VM with Intel SGX** moves the original TEEP Agent implementation from SGX simulation mode to real SGX hardware.
- **TWEP-SYSTEM on NVIDIA Jetson with OP-TEE** introduces a second TEEP Agent implementation that separates portable TEEP and application logic from its OP-TEE-specific backend.

Both tracks use AttesTAM as the Trusted Application Manager and Relying Party. AttesTAM selects an embedded Intel QVL backend for the TAWS SGX Quote3 bundle and an external VERAISON verifier for other Evidence formats. The tracks share the protocol architecture, but they use different device-side implementations, user interfaces, workloads, and deployment environments.

## Goals

The IETF 126 work has two main goals:

1. Demonstrate TAWS and its Wasm workload in an enclave on real Intel SGX hardware.
2. Demonstrate an architecture designed for portability by separating platform-specific TEE behavior from the TEEP Agent and Trusted Wasm Apps.

These goals address different questions. The TAWS track asks how the existing SGX-oriented implementation behaves on hardware. The TWEP-SYSTEM track demonstrates an architecture that separates portable TEEP and application logic from the OP-TEE-specific backend. Porting and validating the implementation on other TEE platforms remain future work.

## Two Independent Demo Tracks

The tracks are not interchangeable front ends for the same workload.

The TAWS track uses a browser-based console and provisions a YOLOv8 object-detection Wasm application. The TWEP-SYSTEM track uses `twep-cli` and initially demonstrates command-line Trusted Wasm Apps such as HelloWorld, CalcAdd, and NegaPosi.

The complete setup and operation procedures are therefore documented separately:

- [TAWS on an Azure VM with Intel SGX](./demos/taws-azure.md)
- [TWEP-SYSTEM on NVIDIA Jetson with OP-TEE](./demos/twep-jetson.md)

## Documentation Scope

This book separates demonstrated behavior from work that is still in progress. In particular:

- the IETF 126 TAWS track demonstrated both execution in an SGX hardware enclave and end-to-end DCAP Evidence verification by AttesTAM; these are recorded separately because hardware enclave execution and remote attestation verification are distinct checks;
- a platform backend listed as future porting work is not a completed or security-validated port;
- TWEP-SYSTEM's fixture-backed Generic EAT flow on Jetson has been demonstrated through an external VERAISON `affirming` result, but remains distinct from production-grade final verified mode.

See [Implementation Status](./status.md) for the current distinction between demonstrated, implemented, in-progress, and future-work capabilities.
