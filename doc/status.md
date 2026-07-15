# Implementation Status

This page distinguishes completed demonstrations from implemented features, work in progress, and future work.

## Status Definitions

- **Demonstrated**: exercised in the documented end-to-end environment with recorded results.
- **Implemented**: present in code and covered by an implementation-specific test, but not necessarily exercised in the final IETF 126 environment.
- **In progress**: under active development or awaiting final integration evidence.
- **Future work**: planned or potential work that is not claimed as a completed port.

## TAWS

| Capability | Status | Notes |
| --- | --- | --- |
| SGX simulation demo | Demonstrated | Preserved in the `ietf125` tag |
| YOLOv8 installation and update | Demonstrated | Demonstrated by the IETF 125 TAWS flow |
| Azure VM with SGX hardware | Demonstrated | TAWS was exercised in hardware mode on an SGX-capable Azure VM |
| Wasm execution in an SGX hardware enclave | Demonstrated | The TAWS Wasm workload was exercised in the Azure SGX enclave |
| DCAP Evidence generation | Demonstrated | TAWS produced an `application/sgx-quote3-teep-bundle` in the Azure environment |
| SGX Quote verification with AttesTAM Intel QVL | Demonstrated (experimental) | AttesTAM verified the Quote and validated the challenge and TEEP Agent key binding |
| Target Environment identity appraisal | To be determined | Intel QVL does not by itself appraise values such as `MRENCLAVE`, `MRSIGNER`, or `ISV_SVN` |

## TWEP-SYSTEM

| Capability | Status | Notes |
| --- | --- | --- |
| Linux CLI, daemon, and WAMR path | Demonstrated | Used for development and live AttesTAM integration tests |
| NVIDIA Jetson direct TA and public C ABI paths | Demonstrated | Exercised on a Jetson Orin Nano Super Developer Kit |
| Jetson `twep-cli` / resident `twepd` path | Demonstrated | Normal CLI/daemon IPC reaches the TrustZone backend and TA-local WAMR |
| HelloWorld, CalcAdd, and NegaPosi on Jetson | Demonstrated | All three applications exercised through the TrustZone backend |
| Fixture-backed Generic EAT and VERAISON appraisal | Demonstrated | Unregistered alternate Agent key triggers a challenge; VERAISON returns `affirming` and AttesTAM proceeds through Update and Success |
| AttesTAM insecure demo configuration | Demonstrated | Uses development TAM, Agent, and attester keys plus a matching CoRIM fixture |
| Final verified mode | In progress | Device-specific claims, production key provisioning, protected trust anchors, verifier policy, and final promotion policy remain incomplete |
| SGX backend | Future work | Porting has not been completed or security-validated |
| Keystone backend | Future work | Porting has not been completed or security-validated |
| Other TEE backends | Future work | Additional TEE architecture ports remain future work |

## Updating This Page

Before the IETF 126 demo is described as complete:

1. replace each relevant `In progress` or `To be determined` entry with the observed result;
2. link to the exact setup and verification step in the corresponding demo page;
3. record software versions and the hardware environment;
4. distinguish development bypass modes from verified security modes;
5. avoid using `supported` for a platform whose port remains future work.
