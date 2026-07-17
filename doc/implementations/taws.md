# TAWS

In the current IETF 126 demo, [TAWS](../terminology.md#taws) runs on an Azure VM as the device-side [TEEP Agent](../terminology.md#teep-agent) implementation and communicates with [AttesTAM](../terminology.md#attestam-core). It demonstrates activation, installation, execution, and update of the YOLOv8 object-detection workload.

For the complete current-demo procedure, including prerequisites, build and run steps, SGX configuration, verification, and troubleshooting, see [TAWS on an Azure VM with Intel SGX](../demos/taws-azure.md).

## Components

TAWS contains:

- a [TEEP Broker](../terminology.md#teep-broker) that communicates with AttesTAM over HTTP;
- the TEEP Agent that processes TEEP messages and manages [Trusted Components](../terminology.md#trusted-component);
- [WAMR](../terminology.md#wamr) for executing provisioned Wasm applications;
- the TAWS Console for device activation, application installation, update, and execution.

## Demo Overview

The TAWS track provisions a YOLOv8 object-detection application as a [Trusted Wasm App](../terminology.md#trusted-wasm-app). Two model versions demonstrate both initial installation and update.

The [Device User](../terminology.md#device-user) performs the following lifecycle:

1. activate the device;
2. install the first model version;
3. run object detection;
4. install the newer model version;
5. run object detection again.

The [TAM Administrator](../terminology.md#tam-administrator) registers the corresponding Trusted Components and inspects device state through the AttesTAM Console or administration APIs.

## Console

The TAWS Console is a browser-based interface used to activate the device, install or update the model, upload an input image, and run the detector.

![TAWS Console](../img/taws-image.png)

This page describes the current demo for IETF 126. For the historical IETF 125 environment, see the [`ietf125` tag](https://github.com/s-miyazawa/teep-wasm-demo/tree/ietf125).
