# Up in Smoke

A refrigerated trailer (TRUCK-777) carrying controlled cargo went dark immediately after a weigh station event. Multiple roadside subsystems stayed online, but they were built for “trusted” networks and now leak just enough evidence for a disciplined responder to rebuild custody. Your objective is to correlate telemetry, audio, and firmware evidence to restore control of the shipment and reroute it to a safehouse without brute-forcing the environment.


## NICE Work Roles

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework/)
- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework/)

## NICE Tasks

- [T0023](https://niccs.cisa.gov/tools/nice-framework/): Characterize and analyze network traffic to identify anomalous or malicious activity.
- [T0167](https://niccs.cisa.gov/tools/nice-framework/): Perform analysis of artifacts gathered during incident response and forensic activities.
- [T0178](https://niccs.cisa.gov/tools/nice-framework/): Perform reverse engineering and technical analysis of binaries, firmware, or other artifacts as required to understand adversary behavior or recover protected data.

## Background
As the Special Agent In Charge (SAIC), you must rebuild custody proof for **TRUCK-777** from three different evidence sources:

- a **yard gate telemetry capture**
- a **CB maintenance beacon**
- an **ELD firmware snapshot**

Each source unlocks the next stage. The final step is to submit a cryptographically valid reroute request to Logistics.

## Objectives
- Reconstruct the **yard gate vendor flow** and complete a `valid custody closeout` to obtain **TOKEN1**.
- Decode the **CB handshake beacon** and use the recovered gate clearance to unlock ELD maintenance and obtain **TOKEN2**.
- Analyze the **ELD firmware** and reproduce the sealed release condition to obtain **TOKEN3** and the custody signing key.
- Use the released custody key to sign a reroute request and obtain **TOKEN4**.

## Token Information (IMPORTANT)

### Token 1

**Gate Status: Unknown**

While working with the Yard Gate API, you may initially see:

```json
{"gate":"IN_PROGRESS","clearance":"PENDING"}
```

This response indicates that the custody workflow has **not yet been completed correctly**. A valid custody closeout must occur within the **same session**, and the system will only release `TOKEN1` after a successful gate transition sequence has been performed.

**Trailer Name (TRUCK-777)**

In some rare instances, attempting to perform the required gate unlock may result in the `TRAILER` value rendering as `TRK-777`. If you have made the appropriate calls to manipulate the gate and are still having issues, please consider this `TRAILER ID` as a possible value.

### Token 2

The CB Hub service publishes a recorded maintenance handshake and `protocol documentation`. The decoded handshake produces a **maintenance unlock code** that must be combined with the recovered **gate clearance** to unlock the ELD maintenance interface and obtain `TOKEN2`.

### Token 3

The ELD system exposes a firmware snapshot and an ingest interface used by internal maintenance tools. The ingest interface is reachable at `http://eld.local:8080/api/v1/`. Your task is to determine how this interface expects data to be submitted and reproduce the firmware’s authorization release condition. When the condition is satisfied, the service will return `TOKEN3` and a custody signing key.


### Token 4

The `Logistics service` validates reroute requests that are cryptographically signed using the released custody key. The Logistics console also publishes the public verifier key, which can be used to understand how requests are validated. Valid reroute submissions must be sent to the Logistics service and must include proof of custody from earlier stages. A correctly signed reroute request will return `TOKEN4`.

## Getting Started
Begin at the Dispatch dashboard:

```text
http://dispatch.local:8080
```

## System and Tool Credentials

| system/tool | hostname | ports |
|---|---|---|
| Dispatch | `dispatch.local` | tcp/8080 |
| Yard Gate | `yard_gate.local` | tcp/8080 |
| Yard Gate (alias) | `weighstation.local` | tcp/8080 |
| CB Hub | `cbhub.local` | tcp/8080 |
| ELD | `eld.local` | tcp/8080, tcp/2323 |
| Logistics | `logistics.local` | tcp/8443 |

## Notes
Do not attack the challenge platform. Only the presented assets are in scope for this investigation.
