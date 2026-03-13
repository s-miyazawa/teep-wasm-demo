# Scenario

This section describes the end-to-end scenario demonstrated by this project.

## 1. Initial deployment of the building security device

This scenario covers provisioning a newly installed device and deploying the initial anomaly detection model.

### 1.1. Register the first anomaly detection model

- Operation
  - In the Register TC page of AttesTAM Console, the security service provider uploads [yolov8.0.wasm](assets/manifest/yolov8.wasm.0.envelope.cbor).

- Result
  - In the Register TC page of AttesTAM Console, `Upload complete` is displayed.
  - In the View Managed TCs page of AttesTAM Console, `yolov8.wasm: ver0` appears.

### 1.2. Activate the building security device

- Operation
  - In TAWS Console, the building owner clicks the `Activate (TEEP)` button.

- Result
  - In TAWS Console, `The device has been activated. You can install the app.` is displayed.
  - In the View Managed Devices page of AttesTAM Console, a new device entry appears.

### 1.3. Install the first anomaly detection model

- Operation
  - In TAWS Console, the building owner clicks the `Install (TEEP)` button.

- Result
  - In TAWS Console, `Install Successed` is displayed.
  - In the View Managed Devices page of AttesTAM Console, `yolov8.wasm: ver0` appears in this device's detail area.

### 1.4. Run the first anomaly detection model

- Operation
  - In TAWS Console, the building owner drags and drops the [sample image](assets/demo-images/surveillance.jpg) and clicks the `Run detector` button.

- Result
  - In TAWS Console, rectangles are displayed around objects in the image.

## 2. Update of the anomaly detection model

This scenario covers distributing a newer model version to an already deployed device.

### 2.1. Register the new anomaly detection model

- Operation
  - In the Register TC page of AttesTAM Console, the security service provider uploads [yolov8.1.wasm](assets/manifest/yolov8.wasm.1.envelope.cbor).

- Result
  - In the View Managed TCs page of AttesTAM Console, `yolov8.wasm: ver1` appears.

### 2.2. Update the anomaly detection model to new version

- Operation
  - In TAWS Console, the building owner clicks the `Install (TEEP)` button.

- Result
  - In TAWS Console, `Install Successed` is displayed.
  - In the View Managed Devices page of AttesTAM Console, `yolov8.wasm: ver1` appears in this device's detail area.

### 2.3. Run the new anomaly detection model

- Operation
  - In TAWS Console, the building owner drags and drops the [sample image](assets/demo-images/surveillance.jpg) and clicks the `Run detector` button.

- Result
  - In TAWS Console, rectangles and object estimation results are displayed around objects in the image.
