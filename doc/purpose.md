# Demo Purpose

This demo was created to demonstrate how to provision a WebAssembly (Wasm) application running in a Trusted Execution Environment (TEE).
As a security service situation, this demo distributes and updates a Wasm-based anomaly detection model to Intel SGX devices using TEE Provisioning (TEEP).

## Situation
The specific situation is as follows:

- A security service provider offers security devices that detect intrusions by installing equipment in customers' buildings.
- The building security devices embed a proprietary anomaly detection model that identifies suspicious persons from surveillance camera footage.
- The security service provider is concerned about model leakage and tampering, and wants to protect the model by using a TEE.
- The provider also operates many variations of security devices (different CPU architectures), so common TEEP that is independent of specific TEE architectures is required.

This demo aims to show a mechanism that addresses the challenges above.

## Use Case

The following use case diagram shows interactions between the building owner and security service provider in the demo system.

```plantuml
@startuml demo-usecase-operation
left to right direction
skinparam actorStyle awesome
title Demo Usecase

actor "Building Owner" as A_DeviceUser
actor "Security Service Provider" as A_ServiceProvider

rectangle "Demo System" as G_System {
  package "Device Functions" {
    usecase "Activate Device" as U_DeviceActivate
    usecase "Update Anomaly Detection Model" as U_CheckUpdate
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
U_DeviceActivate ..> U_TCInstall : <<include>>
U_CheckUpdate ..> U_TCInstall : <<include>>
U_TCInstall ..> U_DeviceAttest : <<include>>
A_ServiceProvider -up- U_TCRegister
A_ServiceProvider -up- U_ListDevices
A_ServiceProvider -up- U_ListTCs
@enduml
```

## System Component

The following diagram shows the components of the demo system.

```plantuml
@startuml demo-component
left to right direction
skinparam actorStyle awesome
title Demo Component

actor "Building Owner" as User
actor "Security Service Provider" as Admin
component "User Console" as UserConsole
component "Admin Console" as AdminConsole

database "Building Security Device" as Device {
  component "TAWS" as Taws
}
component "AttesTAM" as Tam
component "VERAISON" as Verifier

User --> UserConsole : Web access
Admin --> AdminConsole : Web access
UserConsole <--> Taws : HTTP
Taws <-left-> Tam : TEEP protocol over HTTP
AdminConsole <--> Tam : HTTP
Tam <--> Verifier : HTTP
@enduml
```

## Terminology in Demo

### Building Owner

Uses the security service for building protection.
- Activate the building security device.
- Use the anomaly detection model.
- Update the anomaly detection model.

### Security Service Provider

A company that provides building security services.
- Manage the building security device.
- Manage the AttesTAM.
- Develop and register to AttesTAM the anomaly detection model.

### Building Security Device

A security device that executes the anomaly detection model.
- Operated from the user console by building owner.
- Installed TAWS at manufacturing.
- Not installed the anomaly detection model until activation.

### Anomaly Detection Model

Object detection Wasm application based on YOLOv8.

### TAWS

TEE middleware for Intel SGX.
- Install/update/execute Wasm application for TEE.
- Interacts with building owner via user console.
- Interacts with AttesTAM using TEEP protocol.

### AttesTAM

Trusted Application Manager (TAM) server supporting TEEP over HTTP.
- Stores and distributes the trusted component.
- Manages the distribution status of the trusted components to TAWS.
- Interacts with security service provider via admin console.
- Interacts with TAWS using TEEP protocol.

### VERAISON

Attestation verification software built by Project VERAISON.

### User Console

Web application for operating TAWS.

### Admin Console

Web application for operating AttesTAM.

## Terminology Mapping

### TEEP

|TEEP|Demo|
|--|--|
|TEE|Intel SGX|
|Trusted Component|Anomaly Detection Model|
|TAM|AttesTAM|
|TEEP Agent<br>TEEP Broker|TAWS|
|Device|Building Security Device|
|Device User|Building Owner|
|Device Administrator|Security Service Provider|

### RATS

|RATS|Demo|
|--|--|
|Attester|Building Security Device|
|Relying Party|AttesTAM|
|Relying Party Owner|Security Service Provider|
|Verifier|VERAISON|
