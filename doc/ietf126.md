# What Is New for IETF 126

The IETF 125 demo established the initial end-to-end scenario with TAWS, AttesTAM, VERAISON, and a Wasm object-detection application. TAWS ran in Intel SGX simulation mode.

IETF 126 extends that work in two directions.

## From SGX Simulation to SGX Hardware

TAWS is being deployed on an SGX-capable Azure VM. This moves the device-side implementation and Wasm workload from SGX simulation mode to an enclave on real SGX hardware.

The documentation treats the following as separate verification points:

1. TAWS starts in SGX hardware mode.
2. The Wasm workload executes inside the enclave.
3. Hardware-backed Evidence is generated.
4. AttesTAM's embedded Intel QVL backend verifies the SGX Quote against Intel collateral.
5. AttesTAM verifies the challenge and TEEP Agent key binding before making its trust decision.

The final demo report will state which of these points were demonstrated and identify the Evidence format and verification path used.

## A Second, Portable TEEP Agent Implementation

TWEP-SYSTEM is a second TEEP Agent implementation introduced for IETF 126. Its TEEP Agent and general Trusted Wasm Apps are Rust `no_std` Wasm applications.

The portability objective is to use the same Wasm binaries across different TEE platforms. Platform-dependent behavior is placed behind hostcalls and platform backends, including:

- protected storage;
- Evidence generation;
- communication that must cross the TEE boundary;
- runtime and resource policy;
- platform-specific commands and C ABI integration.

The IETF 126 device target is NVIDIA Jetson with OP-TEE, which provides a TEE based on Arm TrustZone. A Linux backend is also used for development and testing.

The Jetson Orin Nano Super port has exercised the direct TA, public C ABI, and normal CLI/daemon paths on hardware. The IETF 126 demonstration also forces an AttesTAM challenge for an unregistered development Agent key, returns Generic EAT Evidence signed through the OP-TEE TA, obtains an `affirming` result from VERAISON, and proceeds to Trusted Wasm App installation and execution. Because the flow uses development keys and matching fixtures, it is not presented as production-grade final verified mode.

## Evolution from IETF 125

| Area | IETF 125 | IETF 126 |
| --- | --- | --- |
| TEEP Agent implementation | TAWS | TAWS and TWEP-SYSTEM |
| TAWS execution environment | Intel SGX simulation mode | Intel SGX hardware on an Azure VM |
| Additional device target | None | NVIDIA Jetson with OP-TEE |
| Portability approach | SGX-oriented implementation | Wasm TEEP Agent with platform backends |
| TAWS user interface | TAWS Console | TAWS Console |
| TWEP-SYSTEM user interface | Not applicable | `twep-cli` |
| Example workloads | YOLOv8 object detection | YOLOv8 and command-line Trusted Wasm Apps |

The previous demo remains available from the [`ietf125` tag](https://github.com/s-miyazawa/teep-wasm-demo/tree/ietf125).
