# Introduction

This demo shows a building security service provider provisioning a Wasm-based anomaly detection model to a building security device using TEEP, with device trust established through RATS-based remote attestation.

| Console | Role | Screenshot |
| -- | -- | -- |
| TAWS Console | Used by the building owner to activate the device, install the model, and run detection. | ![TAWS Console](img/taws-image.png) |
| AttesTAM Console | Used by the security service provider to register and manage trusted components and devices. | ![AttesTAM Console](img/attestam-image.png) |

## Use Case and Security Concern
The specific situation is as follows:

- Use case
  - A security service provider offers security devices that detect intrusions by installing equipment in customers' buildings.
  - The building security devices embed a proprietary anomaly detection model that identifies suspicious persons from surveillance camera footage.
- Security concern
  - The security service provider is concerned about model leakage and tampering, and wants to protect the model by using a TEE.

The operational flow demonstrated in this project is described in [Demo Scenario](./scenario.md).

The following use case diagram shows interactions between the building owner and security service provider in the demo system.

```plantuml
@startuml demo-usecase-operation
left to right direction
skinparam actorStyle awesome
title Demo Use Case

actor "Building Owner" as A_DeviceUser
actor "Security Service Provider" as A_ServiceProvider

rectangle "Demo System" as G_System {
  package "Device Functions" {
    usecase "Activate Device" as U_DeviceActivate
    usecase "Install and Update Anomaly Detection Model" as U_CheckUpdate
    usecase "Use Anomaly Detection Model" as U_DeviceUse
  }
  package "TAM Functions" {
    usecase "Register TC to TAM" as U_TCRegister
    usecase "Distribute TC to Device" as U_TCInstall
    usecase "List Managed Devices" as U_ListDevices
    usecase "List Managed TCs" as U_ListTCs
    usecase "Verify Device" as U_DeviceAttest
  }
}

A_DeviceUser -- U_DeviceActivate
A_DeviceUser -- U_CheckUpdate
A_DeviceUser -- U_DeviceUse
U_DeviceActivate ..> U_DeviceAttest : <<include>>
U_CheckUpdate ..> U_TCInstall : <<include>>
A_ServiceProvider -up- U_TCRegister
A_ServiceProvider -up- U_ListDevices
A_ServiceProvider -up- U_ListTCs
@enduml
```

## Architecture of the demo system

The following diagram shows the architecture of the demo system.

```plantuml
@startuml demo-architecture
left to right direction
skinparam actorStyle awesome
title Demo Architecture

actor "Building Owner" as User
actor "Security Service Provider" as Admin

rectangle "TAWS" as TawsSystem {
  component "TAWS Core" as Taws
  component "TAWS Console" as UserConsole
}
rectangle "AttesTAM" as AttestamSystem {
  component "AttesTAM Core" as Tam
  component "AttesTAM Console" as AdminConsole
}
rectangle "VERAISON" as Verifier

User --> UserConsole : Web access
Admin --> AdminConsole : Web access
UserConsole <--> Taws : HTTP
Taws <-left-> Tam : TEEP protocol over HTTP
AdminConsole <--> Tam : HTTP
Tam <--> Verifier : HTTP
@enduml
```

- `TAWS` is a TEEP agent for Intel SGX.
- `AttesTAM` is a TAM (Trusted Application Manager).
- `VERAISON` is the verifier used for attestation.

## Related Repositories

- [teep-wasm-demo](https://github.com/s-miyazawa/teep-wasm-demo)
  - Repository for the IETF 125 hackathon demo
- [AttesTAM](https://github.com/kentakayama/AttesTAM)
  - Repository for AttesTAM and the AttesTAM Console
- [TAWS](https://github.com/yuma-nishi/taws)
  - Repository for TAWS and the TAWS Console
