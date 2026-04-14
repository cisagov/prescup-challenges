# Ocean's 0x0D

♠️ Eavesdrop on an ex-warlord’s vault telemetry, learn its tells, and drive the lock through the correct sequence to spill the loot for all to see. Time your moves carefully — this system of corruption only confesses when pressured correctly.

This challenge emphasizes **observation, protocol awareness, state manipulation, and precision exploitation** rather than brute force or guesswork.

**NICE Work Roles**

* [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework)
* [Exploitation Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

* [T0028](https://niccs.cisa.gov/tools/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
* [T0566](https://niccs.cisa.gov/tools/nice-framework): Analyze internal operational architecture, tools, and procedures for ways to improve performance.

## Background

♠️ What appears to be an upscale casino operation is, in reality, a laundering front for extremist financing. The vault system at its core was custom-built by a former weapons dealer with deep political protection — hardened, monitored, and intolerant of mistakes.

As part of an elite collective of former intelligence analysts turned hacktivists, your mission is to **observe**, **model**, and **manipulate** the vault’s operational state machine. The system emits subtle telemetry and behavioral changes as it transitions between internal states. Only by learning these patterns — and exploiting their inconsistencies — can you force the vault into revealing **four unique access tokens**.

Each token represents a critical fracture point in the system’s design. Together, they expose the operation’s weakest link and will allow us to open a phyisscal backdoor to the Vault through a (now known) under-casino passage way.

## Getting Started

Your team has gained access to the casino’s **Vault Operations Stack**, which includes:

- A live **Vault Dashboard** used by internal security staff
- A read-only **telemetry bus** carrying vault state transitions and alerts

Begin by observing how the system behaves under normal conditions before attempting to influence it. Look for any available leaked documentation to help with our mission.

#### Available Interfaces

**Vault Dashboard**
  Displays real-time KPIs, alert states, and operational posture of the vault.

**Telemetry Feed (Read-Only)**
Used for situational awareness and timing analysis.
* Protocol: MQTT
* Topic namespace: `casino/#`
* Publishing is **not required** and **not expected**

## Grading

Tokens are issued dynamically as specific operational conditions are met.
As you progress:

- The dashboard will reflect state changes
- Telemetry events will confirm successful transitions
- Each recovered token serves as proof of objective completion

Tokens must be submitted exactly as issued.

### Token Format

The token format for this challenge is:

`PCCC{0D-XX-YYYY-ZZZZ}`

## System and Tool Credentials

| system / tool | location | access |
|---------------|----------|--------|
| Vault Dashboard | `http://socwall.pccc:8090/dashboard` | No authentication |
| Telemetry Broker | `roulette-telemetry.pccc:1883` | Read-only |
| Vault Operations | `http://vaultcore.pccc:8080` | Read-Write (API) |

## Note

Attacking or attempting to gain unauthorized access to the **challenge platform infrastructure** is strictly forbidden. 
You may only interact with the services and interfaces intentionally exposed as part of this challenge.

Abuse of the underlying platform, denial-of-service attempts, or attempts to escape the challenge environment will result in disqualification.

## Tip
💡 Stay organized. This challenge requires correlating information across **multiple services and protocols**.