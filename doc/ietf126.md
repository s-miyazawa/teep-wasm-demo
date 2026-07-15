# What Is New for IETF 126

The IETF 125 demo established the initial end-to-end scenario with TAWS, AttesTAM, VERAISON, and a Wasm object-detection application. TAWS ran in Intel SGX simulation mode.

IETF 126 extends that work in two directions.

## From SGX Simulation to SGX Hardware

TAWS was deployed on an SGX-capable Azure VM. This moved the device-side implementation and Wasm workload from SGX simulation mode to an enclave on real SGX hardware.

The IETF 126 demo demonstrated the following verification points, which the documentation records separately:

1. TAWS starts in SGX hardware mode.
2. The Wasm workload executes inside the enclave.
3. Hardware-backed Evidence is generated.
4. AttesTAM's embedded Intel QVL backend verifies the SGX Quote against Intel collateral.
5. AttesTAM verifies the challenge and TEEP Agent key binding before making its trust decision.

All five points were exercised. The attestation exchange used the `application/sgx-quote3-teep-bundle` path and AttesTAM's embedded Intel QVL backend. Keeping the results separate makes the hardware-execution, Evidence-generation, Quote-verification, and Relying Party checks independently reviewable.

## A Second, Portable TEEP Agent Implementation

TWEP-SYSTEM is a second TEEP Agent implementation introduced for IETF 126. It implements not only general Trusted Wasm Apps but also the TEEP Agent itself as a Rust `no_std` Wasm application.

This is the key portability benefit of TWEP-SYSTEM. Platform-dependent operations are separated into hostcalls and backend implementations, reducing the amount of TEEP Agent and application logic that must be rewritten for each TEE platform. The same Wasm binaries are intended to be reusable across platform backends, although this has not yet been validated on multiple TEEs. Platform-dependent operations include:

- protected storage;
- Evidence generation;
- communication that must cross the TEE boundary;
- runtime and resource policy;
- platform-specific commands and C ABI integration.

The IETF 126 device target is NVIDIA Jetson with OP-TEE, which provides a TEE based on Arm TrustZone. A Linux backend is also used for development and testing. The IETF 126 implementation demonstrates the separation between portable Wasm logic and the OP-TEE-specific backend; porting and validating TWEP-SYSTEM on other TEEs remain future work.

The Jetson Orin Nano Super port has exercised the direct TA, public C ABI, and normal CLI/daemon paths on hardware. The IETF 126 demonstration also forces an AttesTAM challenge for an unregistered development Agent key, returns Generic EAT Evidence signed through the OP-TEE TA, obtains an `affirming` result from VERAISON, and proceeds to Trusted Wasm App installation and execution. Because the flow uses development keys and matching fixtures, it is not presented as production-grade final verified mode.

## IETF 125 and IETF 126 Demo Tracks

| Area | IETF 125 TAWS | IETF 126 TAWS | IETF 126 TWEP-SYSTEM |
| --- | --- | --- | --- |
| TEEP Agent implementation | TAWS | TAWS | TWEP-SYSTEM |
| Execution environment | Intel SGX simulation mode | Intel SGX hardware on an Azure VM | OP-TEE on NVIDIA Jetson |
| User interface | TAWS Console | TAWS Console | `twep-cli` |
| Wasm runtime | WAMR in the simulated SGX enclave | WAMR in the SGX hardware enclave | WAMR in the OP-TEE TA |
| Workloads | YOLOv8 object detection | YOLOv8 object detection | HelloWorld, CalcAdd, and NegaPosi |
| Attestation path | Development path with VERAISON | SGX DCAP Quote3 with AttesTAM's embedded Intel QVL | Generic EAT with AttesTAM and VERAISON |
| Portability approach | SGX-oriented implementation | SGX-oriented implementation | Wasm TEEP Agent and Trusted Wasm Apps with an OP-TEE backend |

The previous demo remains available from the [`ietf125` tag](https://github.com/s-miyazawa/teep-wasm-demo/tree/ietf125).
