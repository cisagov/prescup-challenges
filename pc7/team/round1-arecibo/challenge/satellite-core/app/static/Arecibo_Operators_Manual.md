# Arecibo Orbital Observatory
## MQTT Control & Telemetry Interface Overview (Excerpt)

---

## 1. System Overview

The **Arecibo Orbital Observatory** is a simulated satellite-based targeting and energy-projection platform. Ground operators interact with the system via an MQTT message broker, using a publish/subscribe model to issue commands and receive telemetry, diagnostics, and system status updates.

The system is **stateful**. Certain commands are only accepted when the observatory is in the appropriate operational mode. Invalid or out-of-sequence commands may be ignored or logged without explicit error responses.

Operators are expected to monitor telemetry and log topics continuously to understand system behavior and confirm successful configuration changes.

---

## 2. MQTT Architecture

### 2.1 Broker

- **Protocol:** MQTT v3.1.1  
- **Transport:** TCP  
- **Authentication:** None (assumed trusted control network)

---

### 2.2 Topic Hierarchy

The observatory uses a structured topic namespace:

satellite/
├── core/
│ └── control
├── logs/
│ ├── status
│ └── telemetry
└── dashboard/
└── state


Not all topics publish data continuously. Some emit messages only in response to internal state changes, configuration updates, or periodic system events.

---

## 3. Control Interface (`satellite/core/control`)

The `satellite/core/control` topic accepts **JSON-encoded command objects**. Messages must be valid JSON to be processed.

Commands may be ignored if they are malformed, unsupported, or issued while the system is in an incompatible operational state.

---

### 3.1 Supported Control Fields

| Field Name | Type   | Description |
|----------|--------|-------------|
| `mode`   | string | Sets the satellite’s operational mode |
| `angle` | string | Targeting orientation in degrees (float encoded as string, e.g. `"45.0"`) |
| `coords` | string | Target coordinates in `lat,long` format |
| `cmd`    | string | Executes a supported system command |
| `hmac`   | string | Submits a validation or integrity value |

Multiple fields may be present in a single message. Unsupported or conflicting field combinations may be ignored without error.

---

### 3.2 Operational Modes

The observatory operates in multiple modes, including but not limited to:

- **idle** — passive telemetry only  
- **calibration** — accepts orientation changes  
- **attack** — accepts targeting and firing parameters  

Certain control fields are **only processed** when the system is in the appropriate mode.

Mode transitions are not always acknowledged directly and may need to be inferred through telemetry or dashboard state updates.

---

## 4. Telemetry & Logs

### 4.1 Status Logs (`satellite/logs/status`)

This topic may emit:

- Configuration acknowledgements  
- Validation or integrity events  
- Periodic system messages  
- Security-related output  

Not all accepted commands produce immediate responses. Some confirmations are emitted asynchronously.

---

### 4.2 Telemetry (`satellite/logs/telemetry`)

Telemetry messages may include:

- Orientation and alignment data  
- Targeting calculations  
- Internal state summaries  
- Diagnostic output  

Telemetry should be used to **confirm system behavior**, not merely command submission.

---

## 5. Targeting Parameters

### 5.1 Angle

- Expressed in degrees  
- Valid range: **0.0 – 180.0**  
- Precision beyond one decimal place may be ignored  
- Changes may not take effect unless the system is in a compatible mode  

---

### 5.2 Coordinates

- Format: `latitude,longitude`  
- Decimal degrees  
- Coordinates outside acceptable targeting bounds may be silently rejected  

The system does not explicitly return validation errors for invalid coordinates. Operators must infer success or failure from system behavior and emitted telemetry.

---

## 6. Command Interface

The `cmd` field may be used to request internal system actions.

Supported command categories include:

- Diagnostic output  
- Target enumeration  
- System state reporting  

Command results are typically emitted via telemetry or status topics rather than returned directly.

---

## 7. Observability & Operator Expectations

Operators are expected to:

- Maintain persistent subscriptions to relevant log and telemetry topics  
- Correlate multiple message streams to determine system state  
- Identify successful configuration through **behavioral changes**, not explicit confirmations  

The system prioritizes realism over verbosity. Absence of error messages does not imply success.

---

## 8. Authorization & Validation Notes

This simulation does not enforce cryptographic authentication. However, certain control actions may require submission of validation material (such as integrity values) that can be observed during normal system operation.

---

**End of Document**

