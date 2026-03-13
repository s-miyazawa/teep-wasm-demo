# Terminology

## Actor and Subsystem

### Building Owner

Uses the security service for building protection.
- Activate the building security device.
- Use the anomaly detection model.
- Update the anomaly detection model.

### Security Service Provider

A company that provides building security services.
- Manage the building security device.
- Manage the AttesTAM.
- Develop and register the anomaly detection model in AttesTAM.

### Building Security Device

A security device that executes the anomaly detection model.
- Operated from the TAWS Console by the building owner.
- TAWS is installed during manufacturing.
- The anomaly detection model is not installed until activation.

### Anomaly Detection Model

Object detection Wasm application based on YOLOv8.

### TAWS

TEE middleware for Intel SGX.
- Installs, updates, and executes Wasm applications in the TEE.
- Interacts with the building owner via the TAWS Console.
- Interacts with AttesTAM using TEEP protocol.

### AttesTAM

Trusted Application Manager (TAM) server supporting TEEP over HTTP.
- Stores and distributes trusted components.
- Manages the distribution status of the trusted components to TAWS.
- Interacts with the security service provider via the AttesTAM Console.
- Interacts with TAWS using TEEP protocol.

### VERAISON

Attestation verification software built by Project VERAISON.

### TAWS Console

Web application for operating TAWS.

### AttesTAM Console

Web application for operating AttesTAM.

## TEEP and RATS Terminology Correspondence

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
