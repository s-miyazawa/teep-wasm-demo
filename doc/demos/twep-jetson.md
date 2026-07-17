# TWEP-SYSTEM on NVIDIA Jetson with OP-TEE

This track demonstrates a portable Wasm TEEP Agent and command-oriented Trusted Wasm Apps on a Jetson Orin Nano Super Developer Kit using OP-TEE.

> **Source:** [TWEP-SYSTEM](https://github.com/s-miyazawa/twep-system) is included as the `twep-system` submodule, pinned from the [`docs/jetson-twep-demo-setup` branch](https://github.com/s-miyazawa/twep-system/tree/docs/jetson-twep-demo-setup).

> **Security status:** This is a fixture-backed development demonstration. It exercises an AttesTAM challenge, Generic EAT Evidence, an external VERAISON `affirming` result, Update, Success, installation, and execution. It does not claim production-grade final verified mode.

## What the Demo Shows

The main demonstration starts with a clean Jetson TWEP state and shows:

1. `twep-cli` connecting to a resident `twepd` Unix-domain socket;
2. `twepd` communicating with AttesTAM over TEEP-over-HTTP;
3. an alternate unregistered demo Agent key causing AttesTAM to issue a challenge;
4. the Wasm TEEP Agent returning Generic EAT Evidence signed through the OP-TEE TA;
5. AttesTAM forwarding that Evidence to VERAISON;
6. an `affirming` appraisal allowing AttesTAM to send the requested Wasm Trusted Component;
7. installation and execution of HelloWorld or CalcAdd through the TrustZone backend.

The operator compares the application output with the AttesTAM log. Jetson daemon, socket, state, and Linux-side logs are inspected only when troubleshooting. Stable capture of OP-TEE TA `DMSG` and `IMSG` over the Jetson serial path is outside the demonstrated scope.

## Participants and Components

- **Device User** invokes Trusted Wasm Apps through `twep-cli`.
- **TAM Administrator** registers manifests and observes managed state through AttesTAM.
- **Resident `twepd`** receives CLI requests through `/run/twep-installed/twepd.sock`.
- **TrustZone `twep-wr` backend** crosses the REE/TEE boundary through `libteec`.
- **TWEP OP-TEE TA** hosts WAMR and the TEEP Agent or application execution path.
- **TEEP Agent Wasm application** constructs Generic EAT, processes TEEP and SUIT data, and decides application installation.
- **AttesTAM** acts as TAM and Relying Party.
- **VERAISON** appraises the Generic EAT Evidence used by this track.

The Trusted Components delivered in this demo are Wasm payloads. They are not OP-TEE `.ta` files installed into a platform TA directory.

## Validated Environment

The recorded IETF 126 setup uses:

- a Jetson Orin Nano Super Developer Kit;
- an OP-TEE-enabled Jetson image;
- an Ubuntu build and control host;
- USB networking with the host at `192.168.55.100` and Jetson at `192.168.55.1`;
- SSH alias `jetson`;
- AttesTAM on host port 8080;
- AttesTAM Console on host port 9090;
- VERAISON challenge-response on port 8443 and provisioning on port 9443;
- a resident Jetson daemon socket at `/run/twep-installed/twepd.sock`;
- TWEP state under `/home/demo/.local/state/twep`.

Record the exact Jetson image, OP-TEE, toolchain, WAMR, AttesTAM, VERAISON, and TWEP commit versions used for the final presentation.

## Host Workspace Variables

The validated lab keeps TWEP-SYSTEM, AttesTAM, and the Jetson integration scripts in one workspace. Set variables for the local checkout rather than copying a developer-specific absolute path:

```sh
export JETSON_OPTEE_DEV_DIR=/path/to/jetson-optee-dev
export TWEP="$JETSON_OPTEE_DEV_DIR/workloads/twep-system"
export ATTESTAM_DIR="$JETSON_OPTEE_DEV_DIR/workloads/AttesTAM"
export VERAISON_DEPLOYMENT=/path/to/veraison-deployment
export JETSON_ATTESTAM_URL=http://192.168.55.100:8080/tam
```

The latest TWEP reset script accepts environment overrides such as `ATTES_TAM_DIR`, `JETSON_OPTEE_DEV_DIR`, `JETSON_SSH`, `JETSON_ATTESTAM_URL`, and `JETSON_RECOVER_USB_NETWORK`.

## Prepare the Demonstration

### 1. Prepare Two Host Terminals

Use one terminal for operation and one for the AttesTAM log.

In the operation terminal:

```sh
cd "$TWEP"
```

In the log terminal:

```sh
tail -F /tmp/twep-attestam-api.log
```

The log file may not exist until the reset step starts AttesTAM.

### 2. Start VERAISON

Start the native VERAISON deployment used by the lab and confirm the challenge-response and provisioning listeners:

```sh
"$VERAISON_DEPLOYMENT/bin/veraison" start-services
ss -ltnp | rg ':8443|:9443|:10443|:11443'
```

The exact deployment helper command can differ by VERAISON checkout. The required services are the VTS, provisioning, verification, and management services with the Generic EAT scheme active.

### 3. Install the Current Jetson Build

Install a build that contains the challenge-response, host-I/O resume, and resident-daemon thread-affinity fixes:

```sh
cd "$JETSON_OPTEE_DEV_DIR"

REMOTE_INSTALL=1 \
TWEP_REMOTE_CLI_COMMANDS=helloworld \
TWEPD_EXTRA_ARGS="--resolver-mode attestam-insecure --attestam-url $JETSON_ATTESTAM_URL --insecure-demo-mode --insecure-demo-agent-key alternate" \
./scripts/smoke_jetson_twep_cli_e2e.sh
```

Expected output includes:

```text
Remote OP-TEE TWEP CLI E2E smoke ok: helloworld
Jetson TWEP CLI installed: /home/demo/.local/bin/twep-cli /home/demo/.local/bin/twepd
```

An older `twepd` can fail on its second WAMR call with `abi=call-failed`; reinstall the current build if that occurs.

### 4. Reset AttesTAM and Jetson TWEP State

Run the reset target from TWEP-SYSTEM:

```sh
cd "$TWEP"
ATTES_TAM_DIR="$ATTESTAM_DIR" \
JETSON_OPTEE_DEV_DIR="$JETSON_OPTEE_DEV_DIR" \
JETSON_ATTESTAM_URL="$JETSON_ATTESTAM_URL" \
make reset-twep-attestam-demo
```

The target:

- stops and rebuilds the AttesTAM API and Admin Console;
- starts AttesTAM on `:8080` with a fresh database;
- starts the Console on `:9090`;
- removes the Jetson `apps`, `catalog`, `components`, `teep-agent`, and temporary state;
- starts the resident Jetson `twepd` on `/run/twep-installed/twepd.sock`;
- configures `attestam-insecure` mode with the alternate Agent key.

The alternate key is intentionally absent from AttesTAM's initial keyring, which forces the challenge path. This mode uses development keys and is not a production configuration.

Confirm the services and resident socket:

```sh
ss -ltnp | rg ':8080|:9090|:8443|:9443|:10443|:11443'
ssh jetson 'pgrep -af "twepd|run-optee-test-ca"; sudo -n ls -l /run/twep-installed/twepd.sock'
```

### 5. Provision the Generic EAT Fixture

Provision the matching CoRIM fixture to VERAISON:

```sh
cd "$TWEP"
make provision-veraison-generic-eat-fixture \
  VERAISON_PROVISION_TOOL=docker-cocli
```

The validated environment explicitly selects `docker-cocli`. An unauthenticated `curl` request can receive `401 Unauthorized` from the provisioning endpoint.

### 6. Register Trusted Wasm Apps

Register the HelloWorld and CalcAdd SUIT envelopes with AttesTAM:

```sh
make register-attestam-helloworld-fixture \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest

make register-attestam-calcadd-fixture \
  ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest
```

These fixtures use TWEP component identifiers such as `[bstr("twep-app-v1"), bstr("helloworld")]`. If manifest registration fails, the subsequent CLI request cannot reach a successful Update.

## Run the Demonstration

### 1. Run HelloWorld

Always specify the resident daemon socket in the main demonstration:

```sh
ssh jetson '/home/demo/.local/bin/twep-cli --socket /run/twep-installed/twepd.sock helloworld'
```

Expected output:

```text
Hello, World!!
```

In the AttesTAM log, observe the following sequence:

1. an empty request starts the TEEP session and returns a token;
2. the alternate Agent key is not authenticated;
3. a QueryResponse requests `twep-app-v1/helloworld`;
4. AttesTAM saves and returns a challenge;
5. the Agent returns Generic EAT Evidence;
6. AttesTAM sends the Evidence to VERAISON;
7. VERAISON returns an `affirming` Generic EAT result;
8. AttesTAM authenticates the bound Agent key and sends the Update;
9. TWEP returns Success and executes HelloWorld.

Inspect state only when needed:

```sh
ssh jetson 'sudo -n find /home/demo/.local/state/twep -maxdepth 3 -type f -printf "%P %s bytes\n" 2>/dev/null | sort | rg "apps/|helloworld|components|teep-agent" || true'
```

Expected artifacts include `apps/helloworld.wasm`, component installation status, the last resolve status, the development Agent public key, and the verified Evidence result.

### 2. Reuse the Same Resident Daemon

Run HelloWorld again through the same socket:

```sh
ssh jetson '/home/demo/.local/bin/twep-cli --socket /run/twep-installed/twepd.sock helloworld; /home/demo/.local/bin/twep-cli --socket /run/twep-installed/twepd.sock helloworld; echo rc=$?'
```

Expected output:

```text
Hello, World!!
Hello, World!!
rc=0
```

This distinguishes the demonstrated resident-daemon flow from the convenience wrapper that starts a one-shot daemon on a separate socket.

### 3. Run CalcAdd

Use the same resident daemon:

```sh
ssh jetson '/home/demo/.local/bin/twep-cli --socket /run/twep-installed/twepd.sock calcadd 3 4 5'
```

Expected output:

```text
12
```

When CalcAdd is not installed, the same TEEP and attestation flow requests the `twep-app-v1/calcadd` component and installs `apps/calcadd.wasm` before execution.

### 4. Optional NegaPosi Check

NegaPosi has been exercised on the Jetson TrustZone backend, but it is not required for the two-terminal challenge-response presentation. The remote CLI smoke target validates it with a JPEG input and output file.

## Evidence and Trust Boundary

In the demonstrated flow:

- the Rust/Wasm TEEP Agent constructs the Generic EAT claims;
- the AttesTAM challenge is carried as the EAT nonce;
- `cnf.key` carries the TEEP Agent public COSE key;
- the OP-TEE TA supplies ES256 Evidence signing;
- the QueryResponse is separately signed with the TEEP Agent ESP256 key;
- VERAISON appraises the Evidence against a matching development CoRIM fixture.

The demo can claim that the resident CLI/daemon path, TEEP-over-HTTP, challenge freshness, Evidence forwarding, VERAISON appraisal, Agent-key binding, Update, installation, and execution work together.

It cannot yet claim production Jetson platform attestation. Production work includes:

- replacing development keys with device-specific or manufacturing-provisioned keys;
- adding Jetson and OP-TEE-specific identity claims;
- enforcing corresponding VERAISON appraisal policy;
- protecting TEEP and SUIT trust anchors and associated freshness and revocation state;
- defining transport protection;
- completing the final TEEP/COSE/SUIT and Catalog/application promotion policy.

The trust chain ultimately depends on the Jetson boot chain starting the expected OP-TEE image and on OP-TEE protecting Agent, attester, and trust-anchor material. Secure Storage roundtrips alone do not establish final verified status.

## Troubleshooting

### The Second HelloWorld Call Fails

Inspect:

```sh
ssh jetson 'sudo -n cat /home/demo/.local/state/twep/teep-agent/last-resolve-status.txt 2>/dev/null || true'
```

If it reports `abi=call-failed`, reinstall the current build. Older resident daemons did not keep the WAMR call on a suitable locked OS thread.

### The TEEP Flow Stops After the Challenge

Check the AttesTAM log and Jetson state. In particular, inspect:

```text
teep-agent/last-resolve-status.txt
teep-agent/verified-evidence-result.cbor
teep-agent/evidence-status.txt
```

If the manifest was not registered, AttesTAM cannot send the requested component. If VERAISON provisioning failed, the Generic EAT result will not become `affirming`.

### Jetson State Appears Empty

State can be root-owned. Use `sudo -n` when inspecting `/home/demo/.local/state/twep`.

### SSH Cannot Reach Jetson

The Jetson USB network may need to be recovered. Use the workspace recovery helper configured by `JETSON_RECOVER_USB_NETWORK`, then confirm connectivity to `192.168.55.1` and the `jetson` SSH alias.

## Cleanup

Stop the resident daemon and the host-side AttesTAM and VERAISON services according to the lab cleanup procedure. Remove temporary TWEP state only when it is no longer needed as demonstration evidence.

## Expected Outcome

The track succeeds when a fresh Jetson state causes an unregistered development Agent to receive an AttesTAM challenge, the Agent returns fixture-backed Generic EAT Evidence, VERAISON reports `affirming`, AttesTAM proceeds to Update, and the requested Wasm application is installed and executed through the resident `twepd` and OP-TEE TrustZone path. The result is recorded as a demonstrated development integration, not as production-grade final verified mode.
