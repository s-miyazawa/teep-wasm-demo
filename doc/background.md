# Background

A TEE (Trusted Execution Environment) is an isolated execution environment protected against external tampering and observation. TEEP (Trusted Execution Environment Provisioning) manages the lifecycle of TCs (Trusted Components) that run in a TEE.

The TEEP protocol operates between a TAM (Trusted Application Manager), which distributes Trusted Components, and a TEEP Agent associated with the TEE Device. A TEEP Broker provides transport between the TEEP Agent and the TAM when the Agent cannot communicate directly over the device network stack.

## Trust Establishment

Provisioning a Trusted Component requires more than message delivery. The TAM must decide whether it trusts the TEEP Agent and the environment in which the component will be installed.

The TEEP specifications do not mandate one mechanism for establishing that trust or provisioning all required keys. This demo combines TEEP with RATS (Remote ATtestation ProcedureS):

1. the Attester produces Evidence about the device or TEE environment;
2. AttesTAM selects a verifier backend from the Evidence format;
3. the selected backend evaluates the Evidence and returns a result;
4. AttesTAM uses that result as the Relying Party and validates the challenge and TEEP Agent key binding before making its trust decision.

The TAWS SGX Quote3 bundle is verified by the experimental Intel QVL backend embedded in AttesTAM. Other Evidence formats are routed to the external VERAISON challenge-response verifier. Intel QVL consumes Intel-native collateral from PCS or a compatible PCCS service rather than CoRIM endorsements.

The exact Evidence and key-binding mechanism depends on the device implementation. The documentation therefore describes the verified path for each track instead of assuming that enclave execution automatically implies end-to-end remote attestation.

## Why Wasm

TEE implementations differ across CPU architectures and platform vendors. A Wasm runtime provides a common application execution format above those differences.

The two implementations use Wasm at different architectural boundaries:

- TAWS runs provisioned Wasm applications in an SGX-oriented environment.
- TWEP-SYSTEM also implements the TEEP Agent itself as a Wasm application and moves platform-dependent behavior behind hostcalls and backends.

## Related IETF Technologies

### TEEP

TEEP carries lifecycle-management messages between AttesTAM and the device. The demo focuses on installing and updating Wasm Trusted Components.

### SUIT

SUIT manifests describe Trusted Components, versions, identifiers, digests, and payloads. A SUIT Manifest Processor applies the installation and update policy.

### RATS

RATS supplies the roles and message flow used to evaluate Evidence and deliver an Attestation Result to the Relying Party.

### EAT and CoRIM

EAT provides token formats and claims used by applicable attestation flows. CoRIM can supply reference values and endorsements to VERAISON. The AttesTAM Intel QVL path instead uses Intel-native SGX collateral.

The exact formats demonstrated by each IETF 126 track are recorded in [Implementation Status](./status.md).
