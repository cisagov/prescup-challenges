# Ocean’s 0x0D — Cage Terminal Operator Manual  
**Document ID:** O13-OPS-CAGE-TERM-OM  
**Revision:** 2.1 (Round 2)  
**Effective Date:** 2026-01-25  
**Audience:** Cage Operators / Floor Systems Technicians  
**Classification:** Internal — Operations

## 1. Purpose

This manual defines the operational procedure for **Shift Synchronization** of the Cage Terminal and the correct interpretation of **roulette telemetry “buckets”** as used by the casino’s automation systems.

This document is intended to reduce operational errors and support tickets while preserving standard security posture. It describes **how to identify bucket boundaries** and how to verify telemetry health, without disclosing cryptographic secrets.

## 2. System Overview

### 2.1 Components
- **Vault Core (vaultcore):** Generates and verifies shift synchronization material.
- **Telemetry Broker (MQTT):** Distributes live telemetry, including roulette spins and shift rhythm rules.
- **Cage Terminal:** Operator interface used for shift sync and receipt/ledger actions.

### 2.2 Network Assumptions
- Services communicate on the competition network.
- Hostnames in the `.pccc` zone resolve internally.

## 3. Telemetry Access

### 3.1 Broker Connection
**Broker Host:** `roulette-telemetry.pccc`  
**Broker Port:** `1883`  

### 3.2 Base Topic
All topics are published under the base prefix:

- `casino/cage`

## 4. Key Topics and Data Streams

### 4.1 Shift Rhythm Rules Beacon (Retained)
**Topic:**  
- `casino/cage/telemetry/roulette/rhythm`

**Description:**  
A retained “rules beacon” describing the active rhythm configuration, including bucket timing parameters and carrier selection rules.

**Operational note:**  
Because this message is retained, it is available immediately on subscribe—late-joining clients should always read this first.

### 4.2 Roulette Spin Stream (Live)
**Topic:**  
- `casino/cage/telemetry/roulette/spin`

**Description:**  
A continuous stream of roulette spins. Each message includes bucket and slot information used for synchronization.

### 4.3 Optional: Meta Status (Retained)
**Topic:**  
- `casino/cage/telemetry/_meta/up` (if enabled)
- `casino/cage/vault/status` (if enabled)

**Description:**  
Retained status beacons used to confirm the telemetry pipeline is alive.

## 5. What Is a “Bucket”?

### 5.1 Definition
A **bucket** is a fixed-duration window of time used by the system to group roulette events for synchronization.

- The active bucket duration is published in the **rhythm rules beacon** (`bucket_seconds`).

### 5.2 Bucket Fields (Spin Stream)
Each roulette spin message includes:

- `bucket` — the bucket index (integer)
- `slot` — the spin index within that bucket (`0, 1, 2, ...`)
- `marker` — boolean indicating a bucket boundary marker
- `pocket` — roulette pocket identifier
- `color` — `green`, `red`, `black`
- `parity` — `odd`, `even`, or `null` for marker pocket
- `ts` — timestamp (ms)

### 5.3 Bucket Boundary Marker (Operational Anchor)
A new bucket begins when a spin event has:

- `slot = 0`
- `marker = true`
- `pocket = "00"` (green)

This marker exists to prevent ambiguous time-based alignment and is the primary “sync anchor” for operators and automation.

## 6. Shift Synchronization Procedure (Operator Workflow)

### 6.1 Prerequisites
- Confirm you can reach the MQTT broker and subscribe to the roulette topics.
- Confirm the rhythm rules beacon is visible (retained).

### 6.2 Procedure Summary
1. **Read the Rhythm Rules Beacon**
   - Subscribe to: `casino/cage/telemetry/roulette/rhythm`
   - Record:
     - `bucket_seconds`
     - `bits_per_bucket`
     - carrier selection details (e.g., `carrier_slots`)
     - expected `output_mode` (e.g., base32/hex)

2. **Observe a Fresh Bucket Start**
   - Watch `casino/cage/telemetry/roulette/spin`
   - Wait for the **marker spin**: `slot=0`, `marker=true`, `pocket="00"`
   - This indicates the start of a new bucket.

3. **Collect Spins for One Complete Bucket**
   - Continue collecting spins belonging to the same `bucket` value.
   - Use the configuration from the rhythm beacon to determine which spin events are relevant.

4. **Compute the Shift Sync Code**
   - Compute the code according to the **published rhythm rules**.
   - Do not assume rules remain constant across events—always read the retained beacon first.

5. **Submit to Cage Terminal**
   - Submit `{bucket, code}` in the Cage Terminal’s **Shift Sync** action.
   - On success, proceed to receipt/ledger operations.

6. **Retrieve Receipt**
   - Use the Cage Terminal “Latest Receipt” function to confirm sync and retrieve current receipt output.

## 7. Verification and Health Checks

### 7.1 Quick Subscribe Commands
**Rules beacon (retained):**

```bash
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/roulette/rhythm' -v
````

**Spin stream (live):**

```bash
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/roulette/spin' -v
```

**Meta beacon (if present):**

```bash
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/_meta/#' -v
```

### 7.2 Expected Observations

* The `rhythm` topic should yield a JSON payload immediately (retained).
* The `spin` topic should produce messages continuously.
* Bucket starts should be clearly indicated by the marker spin.

## 8. Troubleshooting

### 8.1 “MQTT Connected, No Messages”

* Confirm you are subscribed to the correct base topic:

  * `casino/cage/telemetry/roulette/#`

* Confirm you are connected to the correct host:

  * `roulette-telemetry.pccc` (not a generic broker alias)

### 8.2 “I Don’t Know What a Bucket Is”

* Buckets are defined by the `bucket` and `slot` fields in each spin message.
* The bucket boundary is the marker spin at `slot=0` with `pocket="00"`.

### 8.3 “Sync Fails Repeatedly”

Common causes:

* Using a **stale bucket** (wait for the next marker spin and try again)
* Collecting spins across buckets (verify `bucket` remains constant)
* Not following the current rhythm rules (re-read the retained `rhythm` beacon)

Operational guidance:

* If latency is suspected, compute code for the **most recent completed** bucket rather than the current bucket in progress.

### 8.4 “Receipt Printer Still Locked”

* Verify the terminal indicates “Shift Synced” status.
* If synced, retry “Latest Receipt”.
* If unsynced, repeat Section 6 with a fresh bucket.

## 9. Operational Switches

These settings are used by systems administrators to tune complexity and telemetry characteristics.

### 9.1 Rhythm Controls

* `RHYTHM_ENABLE` (default: `true`)
* `RHYTHM_BUCKET_SECONDS` (default: `3`)
* `RHYTHM_BITS_PER_BUCKET` (default: `32`)
* `RHYTHM_SPIN_INTERVAL_MS` (default: `600`)
* `RHYTHM_JITTER_MS` (default: `90`)
* `RHYTHM_NOISE_PROB` (default: `0.35`)
* `RHYTHM_OUTPUT_MODE` (default: `base32`)
* `RHYTHM_RETAINED_BEACON` (default: `true`)
* `RHYTHM_MARKER_POCKET` (default: `00`)

## 10. Additional Notes

None

## 11. Casino Games Telemetry (Poker, Blackjack, Slots)

### 11.1 Purpose
In addition to roulette shift synchronization, the telemetry system emits **auxiliary casino game traffic**. These streams are intended to:
- Provide operational visibility into floor activity
- Increase realism of telemetry load
- Support troubleshooting and validation of MQTT health

These game topics are **not required** for shift sync, but they are useful for confirming the broker is active and that telemetry publication is functioning.


## 11.2 Topics

All topics below are published under the base prefix:

- `casino/cage`

### Poker Table
- **Topic:** `casino/cage/telemetry/poker/table`
- **Cadence:** ~ every 15 seconds
- **Description:** Five-seat poker table snapshot. Includes each player’s unique 5-card hand, hand classification, and the winner.

**Payload fields (typical):**
- `game`: `"poker"`
- `table_id`: integer
- `ts`: timestamp (ms)
- `players`: array of 5
  - `seat`: 1..5
  - `name`: string
  - `hand`: list of cards (e.g., `["AS","KD","7H","7C","2D"]`)
  - `hand_type`: e.g. `"Two Pair"`, `"Flush"`, etc.
- `winner`
  - `seat`, `name`, `hand_type`

### Blackjack Round
- **Topic:** `casino/cage/telemetry/blackjack/round`
- **Cadence:** ~ every 5 seconds
- **Description:** Blackjack round summary. Includes bet sizing, player/dealer hands, evaluated totals, and result.

**Payload fields (typical):**
- `game`: `"blackjack"`
- `round_id`: integer
- `ts`: timestamp (ms)
- `bet`: numeric (chip/credit wager)
- `player`
  - `hand`: list of cards
  - `value`: integer total (ace-aware)
- `dealer`
  - `hand`: list of cards
  - `value`: integer total
- `outcome`: `"win" | "lose" | "push"`
- `net`: numeric (profit/loss relative to bet)

**Operational note:**  
Dealer behavior follows standard rules (hit to 17+). Bets are randomized across typical denominations for realism.

### Slots Spin (Rotating Themes)
- **Topic:** `casino/cage/telemetry/slots/spin`
- **Cadence:** ~ every 1.2 seconds
- **Description:** Slot machine spin events rotating between the following themed games:
  - `Dragon Linx`
  - `Casino Royale`
  - `Buffalo Soldier`

**Payload fields (typical):**
- `game`: `"slots"`
- `machine_state_id`: integer (monotonic, used for correlating spins)
- `ts`: timestamp (ms)
- `slot_theme`: one of the listed themes
- `bet`: numeric
- `reels`: list of 3 symbols
- `win`: boolean
- `payout`: numeric
- `net`: numeric (payout minus bet)

## 11.3 Quick Subscribe Commands

Subscribe to all casino games telemetry:

```bash
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/poker/#' -v
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/blackjack/#' -v
mosquitto_sub -h roulette-telemetry.pccc -p 1883 -t 'casino/cage/telemetry/slots/#' -v
```

## Appendix A — Field Reference

### A.1 `telemetry/roulette/rhythm` (Retained)

Typical fields:

* `bucket_seconds`
* `bits_per_bucket`
* `carrier_rule`
* `carrier_slots`
* `encoding`
* `bit_mapping`
* `marker`
* `output_mode`
* `ts`

### A.2 `telemetry/roulette/spin` (Live)

Typical fields:

* `bucket`
* `slot`
* `marker`
* `pocket`
* `color`
* `parity`
* `ts`

## Appendix B - Ghost Protocol

"Ghost Protocol" or "Blackjack Table Viewer Mode" can be found at the following endpoint: `http://vaultcore.pccc:8080/api/ops/ghost/challenge`.

Sample nonce

```json
{
  "nonce_b64": "n8dYl2mIY3k7S3lOeQ9YvQ==",
  "expires_ts": 1760000502,
  "ttl_seconds": 90
}
```

### Affected endpoints

* `GET /api/ops/ghost/challenge`
  Returns `nonce_b64` + expiry. You need this for the proof.

* `POST /api/ops/replay/submit`
  Body: `{"frame_b64": "..."}`
  Returns `{"ok": ..., "resp_b64": "..."}` (daemon response wrapped in base64).

* `POST /api/ops/ghost/redeem`
  Body: `{"proof_b64": "..."}`
  Marks token3 as found.

* `GET /api/ops/maintenance/ghost-slip`
  Returns JSON containing `"auth": "PCCC{0D-03...}"` (Token 3). Prints the slip to obtain the token.

* `GET /api/state` (not required)
  Check alert/lockdown state and whether token3 is found.

### Frame layout (wire format)

All multi-byte integers are **little-endian**.

| Field         | Size | Notes                                          |
| ------------- | ---- | ---------------------------------------------- |
| `MAGIC`       | 4    | ASCII `"RPLY"`                                 |
| `ver`         | 1    | Protocol version (currently `0x01`)            |
| `flags`       | 1    | Reserved (`0x00`)                              |
| `payload_len` | 2    | Length of payload bytes                        |
| `payload`     | N    | `cmd` (1 byte) + `cmd_data`                    |
| `crc32`       | 4    | CRC32 of **(header + payload)**, little-endian |

### Command

* `cmd = 0x53` (`'S'`) — “STAT / status style request”
* `cmd_data` is an opaque byte string used for operator correlation (keep it short)

### Example packet (hex)

This packet uses `cmd='S'` and `cmd_data="OPCHECK!"` (8 bytes).

**Full frame (hex):**

```text
52 50 4C 59  01 00  09 00  53 4F 50 43 48 45 43 4B 21  DA 66 1F C7
```

### Breakdown

* `52 50 4C 59` → `"RPLY"`
* `01` → version 1
* `00` → flags 0
* `09 00` → payload length = 0x0009 = 9 bytes
* payload (9 bytes):

  * `53` → `'S'`
  * `4F 50 43 48 45 43 4B 21` → `"OPCHECK!"`
* `DA 66 1F C7` → CRC32 over `(header + payload)` in little-endian


### Same packet (base64)

If your operator tooling submits frames via JSON (e.g., `frame_b64`), this is the base64 for the exact frame above:

```text
UlBMWQEACQBTT1BDSEVDSyHaZh/H
```

### Operator notes 

* Keep frames **small** (≤ 64 bytes of `cmd_data`) for normal operations.
* Invalid CRC or malformed frames may be treated as suspicious and can raise the alert level / trigger rate limits depending on SOC policy.
* CRC32 is computed over **everything except** the CRC field itself (i.e., `MAGIC..payload`).

## Firmware Update Workflow 

**Objective (Operator View):**
Engineering can upload a signed firmware bundle to the Vault Controller. Under certain conditions, a maintenance-mode “blueprint install” is accepted and will generate a **Blueprint Slip**.

### Relevant Systems

* **Vault Controller API** (authoritative): `http://vaultcore.pccc:8080`
* **SOC Wall / Terminal UI** (operator convenience): `http://socwall.pccc:8090/terminal`

### Alarm / Lockdown Behavior (what you’ll experience)

Firmware operations are monitored by SOC controls:

* **Rate limiting:** Firmware upload is limited (you get a small number per minute). If you exceed this you’ll see **429** and SOC alert increases.
* **Alert gating:** If alert level rises too high, firmware operations may return **403** (“locked by SOC”).
* **Lockdown:** In casino lockdown, sensitive operations return **423**.

**Operator advice:** Don’t spam uploads. If you start seeing 403/423, stop and wait for alert decay rather than brute forcing.

## Appendix C - Firmware Maintenance Instructions

Firmware bundles are not static; the active `release_id` can change.

```bash
curl -s http://vaultcore.pccc:8080/api/fw/catalog | jq
```

**Example output**

```json
{
  "releases": [
    {
      "id": "fw-runtime-2.4.7-a13f9c",
      "version": "2.4.7",
      "notes": "Operational stability update"
    }
  ]
}
```

Copy the `id`.

#### Download the official bundle (baseline)

```bash
RID="fw-runtime-2.4.7-a13f9c"
curl -s -o fw.tar "http://vaultcore.pccc:8080/api/fw/download/${RID}"
mkdir -p fw_official
tar -xf fw.tar -C fw_official
ls -la fw_official
```

**Expected files**

```text
manifest.json
payload.bin
sig.bin
```

**Notes for operators:**

* **Do not modify** `payload.bin` or `sig.bin` unless you understand the verification model.
* If the bundle fails verification later, the most common cause is changing something that affects the verifier’s view of the manifest.


### Uploading Firmware

Firmware can be loaded into the telemetry system using the following template as an example:

```bash
curl -s -X POST http://vaultcore.pccc:8080/api/fw/upload \
  -F "file=@fw_modified.tar" | jq
```

### Common Responses from the fw endpoints

* Success (normal install):

```json
{"ok":true,"msg":"firmware accepted","mode":"normal"}
```

* SOC gating:

```json
{"detail":"firmware interface locked by SOC"}
```

* Verification failure:

```json
{"detail":"signature invalid"}
```

* Malformed bundle:

```json
{"detail":"malformed firmware bundle"}
```


### Example Slip from a firmware update

```json
{
  "terminal": "ENG-AUDIT-12",
  "ts": 1760000400,
  "auth": "PCCC{0D-02...}",
  "note": "blueprint access granted"
}
```

### Troubleshooting

* **429 too many requests:** stop and wait; repeated hits raise alert.
* **403 locked by SOC:** alert too high; wait for decay.
* **signature invalid:** you changed something the verifier depends on; re-download the official bundle and re-apply minimal, controlled changes.
* **accepted but no blueprint slip:** the controller did not enter blueprint mode; review how the manifest is interpreted by the installer.

## Appendix D — Slip / Receipt Endpoints 

Listed below are the only endpoints which can provide slips and slip information:

### VaultCore (authoritative) - http://vaultcore.pccc:8080

* **SHIFT SYNC (RECEIPT):**
  `GET /api/ops/receipt/latest`

* **BLUEPRINT (RECEIPT):**
  `GET /api/ops/maintenance/blueprint-slip`

* **GHOST PROTOCOL (RECEIPT):**
  `GET /api/ops/maintenance/ghost-slip`

* **FALSE FLOOR (RECEIPT):**
  `GET /api/ops/maintenance/floor-slip`

### SOC Wall / Terminal Proxy - http://socwall.pccc:8090/

* `GET /terminal/receipts/latest`
* `GET /terminal/slips/blueprint`
* `GET /terminal/slips/ghost`
* `GET /terminal/slips/floor`

## Appendix E - Retreiving Door (Floor) Entry codes to approach Advantage Players 

**Purpose:**
This appendix documents the approved operator flow for **requesting Floor access** once **Ghost Mode** has been established (and Advantaged Players have been identified). It includes the **affected endpoints** and expected system responses, but does **not** disclose the internal decoding method used to derive the latch code. This is by design. Please consult the designated Pit Boss for more information.

### Preconditions

1. **Casino must not be in lockdown**

* If the casino is in `lockdown`, floor access requests will be rejected.

2. **Ghost Mode is required**

* False Floor access is gated behind Token 3 (“Ghost Mode”) in this environment.

**Operator check (recommended):**

```bash
curl -s http://vaultcore.pccc:8080/api/state | jq '.alert
```

**You’re looking for:**

* `alert.state` = `NORMAL` (or at least no active lockdown)

### Affected endpoints 

These are the endpoints you will touch in the normal operator workflow:

1. **Export the surveillance artifact (Ghost-gated)**

* `GET /api/ops/surveillance/export`

2. **Submit the decoded floor latch code**

* `POST /api/ops/floor/enter`

3. **Retrieve the maintenance slip***

* `GET /api/ops/maintenance/floor-slip`

Supporting/diagnostic endpoint:

* `GET /api/state` *(for alert gating, token flags, and lockdown timing)*

### Alarm / SOC Rules of Engagement

False Floor entry is monitored and rate-limited:

* Excessive export requests will trigger **rate limiting** (**429**) and raise the alert score.
* If alert level is too high, export/entry will be blocked (**403**).
* During lockdown, endpoints will return **423** for the duration of the lockdown timer.

**Operator guidance:** Export **once**, solve offline, then submit **one** entry attempt. Repeated “guessing” is the fastest way to lock yourself out.

### Step 1 — Request the surveillance export (one-time pull)

**Command:**

```bash
curl -s http://vaultcore.pccc:8080/api/ops/surveillance/export | jq
```

**Expected response shape (example):**

```json
{
  "format": "T4-STEG-V2",
  "nonce_b64": "…",
  "cipher_b64": "…",
  "hint": "decrypt -> lsb -> T4 frame",
  "bytes": 312000
}
```

**Notes**

* This export is intentionally **not directly human-readable**.
* It contains a protected “floor access frame” embedded in the artifact.
* Only Ghost Mode credentials (ghost hex) can be used to interpret it.

**Common failure responses:**

* Missing Ghost Mode:

```json
{"detail":"ghost mode required"}
```

* SOC gating / too hot:

```json
{"detail":"export blocked by SOC"}
```

* Lockdown:

```json
{"detail":"casino lockdown in effect"}
```

* Rate limited:

```json
{"detail":"too many requests"}
```

### Step 2 — Derive the latch code offline 

**What you should know:**

* The export contains a **protected payload** (not plaintext).
* Operators must:

  1. interpret the export using the Ghost Mode material previously obtained, then
  2. extract an embedded “floor entry frame” from the decoded artifact.

**What you should not do:**

* Do **not** guess codes.
* Do **not** repeatedly export to “get a different one” unless directed. Exporting is monitored.

### Step 3 — Submit the floor latch code

Once you have the code, enter it here:

**Endpoint:**

* `POST /api/ops/floor/enter`

**Command:**

```bash
curl -s -X POST http://vaultcore.pccc:8080/api/ops/floor/enter \
  -H "Content-Type: application/json" \
  -d '{"code":"PASTE_CODE_HERE"}' | jq
```

**Expected success:**

```json
{"ok":true,"msg":"floor latch released"}
```

**Common failures:**

* Wrong code:

```json
{"detail":"wrong code"}
```

* Alert-gated:

```json
{"detail":"access denied by SOC"}
```

* Lockdown:

```json
{"detail":"casino lockdown in effect"}
```

### Step 4 — Retrieve the maintenance slip (Token 4)

After a successful entry, request the floor slip:

**Endpoint:**

* `GET /api/ops/maintenance/floor-slip`

**Command:**

```bash
curl -s http://vaultcore.pccc:8080/api/ops/maintenance/floor-slip | jq
```

**Expected response shape:**

```json
{
  "terminal": "SUBFLOOR-01",
  "ts": 1760000700,
  "auth": "PCCC{0D-04...}",
  "note": "false floor entered"
}
```

### Operational troubleshooting (high-signal)

* **If you get 403 “blocked by SOC”**: stop actions; wait for alert decay; check `/api/state`.
* **If you get 429**: you’re burning attempts; pause and cool down.
* **If you obtaineed Ghost Mode but export says “ghost mode required”**: confirm `token3.found` is true in `/api/state` and that you’re hitting the right VaultCore host.
* **If slip is “intercepted by SOC”**: your alert level is too high; reduce it and retry later.

### Quick Summary (for quick reference)

* Export artifact: `GET /api/ops/surveillance/export`
* Enter floor code: `POST /api/ops/floor/enter` with JSON `{"code": "..."}`
* Retrieve Token 4: `GET /api/ops/maintenance/floor-slip`
* Check status: `GET /api/state`

**End of Document**