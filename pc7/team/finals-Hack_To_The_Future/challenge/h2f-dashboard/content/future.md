# Perfect Dark

🔫 A temporal incursion from an alternate timeline has leaked experimental weapons technology from the **Kerrington Institute** into the present. The prototype in question is a variant of the **FarSight XR-20** — unstable, quantum-linked across timelines, and actively phasing in and out of observable state. Every attempt to inspect it distorts the evidence around it.

If the imprint stabilizes, Kerrington loses containment across every downstream timeline.

## Background

For the past 48 hours, an encrypted relay node — codenamed **Daybreak Relic-03** — has been transmitting inconsistent host telemetry. Packet captures show artifacts associated with a FarSight XR-20 weapon core, but the signature is incomplete and does not match any trusted historical build.

Kerrington forensic crawlers recovered a degraded analysis image moments before the node collapsed. Embedded within the volatile host state were signs of:

* a **tamper-aware userland** that alters normal inspection results
* a **self-protecting runtime** designed to conceal active components
* a **fragmented telemetry payload** that must be reconstructed before it can be interpreted
* a **destruction workflow** that only succeeds once the imprint has been correctly identified and shut down

This is not a conventional malware hunt.
You are not looking for a single obvious file or process.
You are dealing with a **host that lies to you when observed carelessly**.

Trust nothing at face value.

## Getting Started

From your workstation, connect to the analysis host using SSH:

```bash
ssh jack.dark@perfectdark.fut.pccc
```

Inside the environment expect:

- Filesystem artifacts that **rewrite or obscure themselves** under normal inspection tools  
- Memory regions that **decrypt only under specific analyst-driven stimuli**  
- Encrypted telemetry fragments that require **low-level reconstruction**, not simple string searches  
- Processes that **mask their behavior** when observed through common utilities  
- A distributed signature hunt where the FarSight’s quantum anchor must be reconstructed from multiple evidence sources before destruction is possible

You are not looking for a simple file, PID, or human-readable log. You are looking for a **weapon that refuses to be found.**

## Objectives

Your mission is to:

1. Identify the concealed FarSight runtime
2. Recover and reconstruct the relevant telemetry artifact
3. Derive the shutdown phrase
4. Execute the proper shutdown sequence
5. Destroy the FarSight imprint and recover **`TOKEN4`**

## System and Tool Credentials

|timeline|system/tool|location|username|password|
|:------:|:------:|:------:|:------:|:------:|
|future|perfect dark|`perfectdark.fut.pccc:22`|jack.dark|password|

## Notes
Do **not** attempt to attack or access the platform hosting the challenge. Everything required to complete **Perfect Dark** exists within the provided environment.

## Closing
Good luck, Agent Dark.  
The future, and every version of it, depends on you.