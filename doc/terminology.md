# Terminology

## Common Actors and Components

### Device User

A person who operates a TEE Device through the device-side user interface. The TAWS track uses the TAWS Console; the TWEP-SYSTEM track uses `twep-cli`.

### TAM Administrator

A person or operational role that manages AttesTAM. The TAM Administrator registers Trusted Components and inspects managed devices through the AttesTAM Console or administration APIs.

This generic role replaces use-case-specific names such as Security Service Provider in the common architecture.

### TEE Device

A device containing or using a Trusted Execution Environment and participating in the TEEP protocol.

### Trusted Component

Software and associated metadata managed through TEEP. In this project, Trusted Components include Wasm applications and, for TWEP-SYSTEM, its Catalog.

### Trusted Wasm App

A Trusted Component implemented as a Wasm application and executed by WAMR.

In the TWEP-SYSTEM documentation, a Wasm Trusted App is distinct from an OP-TEE `.ta` binary. The demo provisions Wasm payloads into the TWEP Catalog and application cache; it does not use AttesTAM to install OP-TEE `.ta` files into the platform TA directory.

### TEEP Agent

The device-side component that processes TEEP messages and manages Trusted Components. TAWS and TWEP-SYSTEM provide different implementations.

### TEEP Broker

The device-side component that transports TEEP messages between the TEEP Agent and AttesTAM.

### AttesTAM Core

The Trusted Application Manager server. It distributes Trusted Components over TEEP and acts as the Relying Party in the attestation flow.

### AttesTAM Console / Administration APIs

The AttesTAM Console is a browser-oriented backend-for-frontend. It calls the SUIT Manifest Service API and TEEP Agent Service API and converts their CBOR records into browser-oriented JSON and HTML responses. These administration interfaces are separate from the device-facing TEEP-over-HTTP endpoint at `/tam`.

### VERAISON

External attestation verification software used for Evidence formats other than AttesTAM's SGX Quote3 TEEP bundle.

### Intel QVL

Intel DCAP Quote Verification Library. AttesTAM embeds an experimental Intel QVL backend for SGX Quote3 TEEP bundles and manages the collateral supplied to it.

### TAWS

The first TEEP Agent implementation in this project. The IETF 126 track deploys it on an Azure VM with Intel SGX.

### TWEP-SYSTEM

The second TEEP Agent implementation. It implements the TEEP Agent and general Trusted Wasm Apps as portable Wasm applications. The IETF 126 track targets NVIDIA Jetson with OP-TEE.

### WAMR

Wasm Micro Runtime, used to load and execute the Wasm applications in both tracks.

## TEEP Correspondence

| TEEP term | Common demo role | TAWS track | TWEP-SYSTEM track |
| --- | --- | --- | --- |
| TEE | Trusted execution environment | Intel SGX | OP-TEE / Arm TrustZone |
| Trusted Component | Managed software component | YOLOv8 Wasm application | Catalog and command-oriented Trusted Wasm Apps |
| TAM | Trusted Application Manager | AttesTAM Core | AttesTAM Core |
| TEEP Agent | Device-side lifecycle manager | TAWS TEEP Agent | TEEP Agent Wasm application |
| TEEP Broker | Device-side transport | TAWS broker | TWEP-SYSTEM rich-OS broker path |
| Device | TEE Device | Azure VM with Intel SGX | NVIDIA Jetson with OP-TEE |
| Device User | Device operator | TAWS Console user | `twep-cli` user |
| TAM Administrator | TAM operator | AttesTAM administrator | AttesTAM administrator |

## RATS Correspondence

| RATS term | Demo role |
| --- | --- |
| Attester | TEE Device and its attestation-producing environment |
| Relying Party | AttesTAM Core |
| Relying Party Owner | Organization operating AttesTAM |
| Verifier | External VERAISON or the Intel QVL backend embedded in AttesTAM |
| Evidence | Attestation data generated for the selected device path |
| Attestation Result | Verifier output consumed by AttesTAM |

The exact Attester boundary and Evidence format must be documented separately for each implementation.
