# Background

A TEE (Trusted Execution Environment) is an isolated execution environment protected against external tampering and observation. The TEEP (TEE Provisioning) protocol is used to provision TCs (Trusted Components) that run inside a TEE.
The TEEP protocol takes place between a TAM (Trusted Application Manager), which distributes TCs, and a TEEP Agent running inside the TEE.

The security of this model depends on establishing trust between the TAM and the TEEP Agent.
However, the TEEP specifications do not define how that trust is established or how the required keys are agreed upon and provisioned.
In this demo, the TEEP Agent is pre-configured to trust the specific TAM, while the TAM authenticates the TEEP Agent using RATS.

In addition, because TEE implementations differ across CPU architectures, running a Wasm (WebAssembly) runtime inside the TEE makes it possible to use trusted applications written in Wasm across a wider range of devices.

## Features

Implemented features related to IETF WGs.

- RATS
  - Generate key inside the TEE
  - Bind it to hardware Evidence with a nonce
  - Adopt EAT as attestation result
- TEEP
  - Install and update Wasm applications
  - Use Intel SGX simulation mode as TEE
  - Run actual Wasm applications in the TEE
- SUIT
  - Run SUIT Manifest Processor

<!-- ## Outcomes

- We provide mature implementations of TEEP Protocol combined with SUIT Manifest Processor, RATS EAT, EAT Measured Component and EAT Attestation Results (EAR)
- We've shared feedback on the TEEP mailing list and RATS meeting based on the findings during hackathon
 -->
## Next Plan

- Expand the supported range of TEEs
  - Run on actual Intel SGX
  - Run on other architectures
- Expand the supported range of applications
  - Support Trusted Components other than the anomaly detection model
  - Implement authentication and authorization for the consoles
