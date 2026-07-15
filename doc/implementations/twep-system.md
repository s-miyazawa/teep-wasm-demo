# TWEP-SYSTEM

TWEP-SYSTEM is the second TEEP Agent implementation introduced for IETF 126. It provides a command-oriented environment for securely acquiring, updating, loading, and executing Trusted Wasm Apps.

## Components

The architecture contains the following layers:

```text
User
  |
  v
twep-cli
  |
  | Unix domain socket + CBOR
  v
twepd
  |
  | C ABI
  v
twep-wr + WAMR
  |
  +--> TEEP Agent Wasm application
  |
  +--> General Trusted Wasm App
```

- `twep-cli` is the user-facing command-line client.
- `twepd` is a daemon that receives CBOR requests over a Unix domain socket.
- `twep-wr` provides the C ABI and WAMR integration.
- the TEEP Agent is a Rust `no_std` Wasm application with privileged hostcalls;
- general Trusted Wasm Apps use a CBOR input/output ABI and do not receive the TEEP Agent's administrative hostcalls.

On the Jetson production public path, the normal call chain is:

```text
twep-cli
  -> resident twepd
  -> cgo / internal twep-wr wrapper
  -> TrustZone libtwep_wr.so
  -> libteec
  -> TWEP OP-TEE TA
  -> TA-local WAMR
  -> TEEP Agent or Trusted Wasm App
```

The direct TA smoke path and public C ABI smoke path are retained for focused boundary tests, but the IETF 126 user demonstration uses `twep-cli` and a resident `twepd` Unix-domain socket.

## Portability Model

The TEEP Agent and general Trusted Wasm Apps are intended to remain the same Wasm binaries across platform backends.

Platform-specific implementations provide:

- protected storage;
- Evidence generation;
- HTTP or other rich-OS communication crossing the TEE boundary;
- runtime and resource policy;
- platform-specific C ABI or TEE commands.

For IETF 126, the main device path uses a Jetson Orin Nano Super Developer Kit with OP-TEE. OP-TEE supplies a Trusted Execution Environment based on Arm TrustZone. A Linux backend is used for development and testing.

The Jetson basic port is complete for the demonstrated scope. Direct TA smoke tests, public C ABI tests, and the normal `twep-cli` / `twepd` E2E path have run on the physical device. HelloWorld, CalcAdd, and NegaPosi have all executed through the TrustZone backend and TA-local WAMR.

Porting TWEP-SYSTEM to SGX, Keystone, and other TEE architectures is future work. These platforms are not currently claimed as completed or security-validated ports.

## Runtime Separation

TWEP-SYSTEM separates the TEEP Agent execution context from general application execution contexts.

The TEEP Agent requires capabilities such as HTTP transport, Evidence access, protected storage, randomness, time, and logging. General Trusted Wasm Apps do not receive those capabilities by default. This prevents an ordinary application from inheriting the management authority required by the TEEP Agent.

## Initial Applications

The initial Trusted Wasm Apps are:

- **HelloWorld**: returns a greeting;
- **CalcAdd**: adds integer arguments;
- **NegaPosi**: reads JPEG input and produces a color-inverted JPEG image.

## AttesTAM Integration

The demonstrated Jetson integration deliberately selects an alternate development Agent key that is not in AttesTAM's initial keyring. AttesTAM therefore treats the Agent as unauthenticated and issues a fresh challenge.

The fixture-backed flow is:

1. `twep-cli` sends the application request to a resident `twepd` socket;
2. `twepd` uses TEEP-over-HTTP to start a session with AttesTAM;
3. AttesTAM issues a challenge for the unregistered Agent key;
4. the Rust/Wasm TEEP Agent constructs Generic EAT claims with the challenge as nonce and the TEEP Agent public key as `cnf.key`;
5. the OP-TEE TA signs the Evidence with ES256 through the TEEP Agent signing hostcall;
6. AttesTAM sends the Evidence to the external VERAISON Generic EAT verifier;
7. after an `affirming` result and successful key binding, AttesTAM sends the Update;
8. TWEP verifies and installs the requested Wasm payload, returns Success, and executes the application.

Evidence signing and TEEP message signing use different keys and algorithms. The Generic EAT Evidence uses an attester ES256 key, while QueryResponse and other TEEP messages use the TEEP Agent key with ESP256.

## Demonstration Boundary

The live flow demonstrates Generic EAT and protocol integration, not production device attestation. It uses:

- AttesTAM insecure demo mode;
- an alternate development TEEP Agent key;
- a development attester key stored through the OP-TEE TA path;
- fixed development UEID and measurement claims;
- a matching Generic EAT CoRIM fixture provisioned to VERAISON.

The result shows that challenge freshness, Evidence forwarding, `cnf.key` binding, Update, Success, installation, and execution work together in the demonstrated environment. It does not yet prove a production Jetson or OP-TEE platform identity.

Final verified mode must replace development keys with device-specific or manufacturing-provisioned keys, add Jetson and OP-TEE identity claims, enforce corresponding VERAISON policy, protect the TEEP and SUIT trust anchors, and integrate the complete TEEP/COSE/SUIT and Catalog promotion policy. That mode is still under development.

TWEP-SYSTEM is included as the `twep-system` submodule, currently pinned from the private `docs/jetson-twep-demo-setup` branch. The submodule URL will be updated when the source repository moves to the public GitHub account.
