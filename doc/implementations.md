# TEEP Agent Implementations

IETF 126 includes two independent device-side implementations of the common architecture.

## TAWS

TAWS is the original implementation. It combines a TEEP Agent, TEEP Broker, WAMR integration, and a browser-based console for an Intel SGX-oriented device.

For IETF 126, the focus is moving TAWS from SGX simulation mode to an SGX-capable Azure VM and documenting the hardware and attestation path that is actually demonstrated.

See [TAWS](./implementations/taws.md).

## TWEP-SYSTEM

TWEP-SYSTEM is the second implementation. It uses a command-oriented interface and implements the TEEP Agent as a Rust `no_std` Wasm application.

Its architecture separates portable Wasm logic from platform-specific operations. The IETF 126 device target is NVIDIA Jetson with OP-TEE, while a Linux backend supports development and testing.

See [TWEP-SYSTEM](./implementations/twep-system.md).

## Design Comparison

| Aspect | TAWS | TWEP-SYSTEM |
| --- | --- | --- |
| Primary IETF 126 platform | Azure VM with Intel SGX | NVIDIA Jetson with OP-TEE |
| User interface | TAWS Console | `twep-cli` |
| TEEP Agent form | SGX-oriented implementation | Rust `no_std` Wasm application |
| General application runtime | WAMR | WAMR |
| Initial workload | YOLOv8 object detection | HelloWorld, CalcAdd, and NegaPosi |
| Portability approach | Run Wasm workloads in the SGX implementation | Keep both Agent and application Wasm binaries platform-independent |

This comparison describes design intent and demo scope. It is not a claim that both implementations currently provide identical security properties or lifecycle behavior. See [Implementation Status](./status.md) for maturity details.
