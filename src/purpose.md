# Demo Purpose

This demo presents a system that securely distributes and updates an anomaly detection model (a Wasm application) running inside a TEE by using the TEEP protocol.

## Situation
The specific scenario is as follows:

- A security service provider offers security devices that detect intrusions by installing equipment in customers' buildings.
- The building security devices embed a proprietary anomaly detection model that identifies suspicious persons from surveillance camera footage.
- The security service provider is concerned about model leakage and tampering, and wants to protect the model by using a TEE.
- The provider also operates many variations of security devices (different CPU architectures), so common TEE provisioning (TEEP) that is independent of specific TEE architectures is required.

This demo aims to show a mechanism that addresses the challenges above.

## Use Case

The following use case diagram shows interactions between the building owner and security service provider in the demo system.

```mermaid
flowchart LR
  A_DeviceUser([Building Owner])
  A_ServiceProvider([Security Service Provider])

  subgraph G_System[Demo System]
    subgraph G_Device[Device Functions]
      U_DeviceActivate[Activate Device]
      U_CheckUpdate[Update Anomaly Detection Model]
      U_DeviceUse[Use Anomaly Detection Model]
    end

    subgraph G_TAM[TAM Functions]
      U_TCRegister[Register TC to TAM]
      U_TCInstall[Distribute TC to Device]
      U_ListDevices[List Managed Devices]
      U_ListTCs[List Managed TCs]
      U_DeviceAttest[Verify Device]
    end
  end

  A_DeviceUser --> U_DeviceActivate
  A_DeviceUser --> U_CheckUpdate
  A_DeviceUser --> U_DeviceUse

  U_DeviceActivate -. include .-> U_TCInstall
  U_CheckUpdate -. include .-> U_TCInstall
  U_TCInstall -. include .-> U_DeviceAttest

  A_ServiceProvider --> U_TCRegister
  A_ServiceProvider --> U_ListDevices
  A_ServiceProvider --> U_ListTCs
```

## Architecture

The following diagram shows the logical architecture in this demo.

```mermaid
flowchart LR
  User(["Building Owner"])
  Admin(["Security Service Provider"])

  UserConsole["User Console"]
  AdminConsole["Admin Console"]

  subgraph Device["Building Security Device"]
    Tee["TEE"]
    Daemon[secm?]
  end

  Tam["AttesTAM"]
  Verifier["VERAISON"]

  User -->|Web access| UserConsole
  Admin -->|Web access| AdminConsole
  UserConsole -->|"API"| Daemon
  Daemon --- Tee
  Daemon -->|"TAM API of AttesTAM"| Tam
  AdminConsole -->|"Admin API of AttesTAM"| Tam
  Tam -->|?| Verifier
```
