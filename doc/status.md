# Implementation Status

This page distinguishes completed demonstrations from implemented features, work in progress, and future work.

## Status Definitions

- **Demonstrated**: exercised in the documented end-to-end environment with recorded results.
- **Implemented**: present in code and covered by an implementation-specific test, but not necessarily exercised in the final IETF 126 environment.
- **In progress**: under active development or awaiting final integration evidence.
- **Future work**: planned or potential work that is not claimed as a completed port.

## AttesTAM

AttesTAM is the common TAM and Relying Party used by both implementation tracks.

| Capability | Status | Notes |
| --- | --- | --- |
| TEEP-over-HTTP endpoint | Demonstrated | Used by both TAWS and TWEP-SYSTEM |
| TAM administration APIs and Console | Demonstrated | Trusted Component registration and device inspection |
| VERAISON Generic EAT verification | Demonstrated | Used by the TWEP-SYSTEM attestation flow |
| Intel QVL SGX Quote verification | Demonstrated (experimental) | Verifies the SGX Quote3 bundle used by TAWS |
| Challenge and TEEP Agent key binding | Demonstrated | Checked after successful appraisal |
| Target Environment identity appraisal | To be determined | Appraisal policy for values such as `MRENCLAVE`, `MRSIGNER`, and `ISV_SVN` is not finalized |
| Production authentication, authorization, and trust policy | In progress | The current demo uses insecure/development configuration |

## TAWS

| Capability | Status | Notes |
| --- | --- | --- |
| SGX simulation demo | Demonstrated | Preserved in the `ietf125` tag |
| YOLOv8 installation and update | Demonstrated | Demonstrated by the IETF 125 TAWS flow |
| Azure VM with SGX hardware | Demonstrated | TAWS was exercised in hardware mode on an SGX-capable Azure VM |
| Wasm execution in an SGX hardware enclave | Demonstrated | The TAWS Wasm workload was exercised in the Azure SGX enclave |
| DCAP Evidence generation | Demonstrated | TAWS produced an `application/sgx-quote3-teep-bundle` in the Azure environment |
| End-to-end attestation flow | Demonstrated (experimental) | TAWS completed the AttesTAM challenge, Quote verification, and TEEP Agent key-binding flow |

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
| Other TEE backends | Future work | Porting to SGX, Keystone, and other TEE architectures has not been completed or security-validated |
