# Blind Trust

🛰️ A flawed deployment. A layered defense. Four secrets buried in static — only the bold can decrypt the chaos.

**NICE Work Roles**
* [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
* [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)


**NICE Tasks**
* [T0280](https://niccs.cisa.gov/tools/nice-framework): Identify and validate vulnerabilities in the system	
* [T0653](https://niccs.cisa.gov/tools/nice-framework): Identify and recommend methods for exploiting target systems	
* [T0269](https://niccs.cisa.gov/tools/nice-framework): Conduct exploitation of targets using identified vulnerabilities	
* [T0650](https://niccs.cisa.gov/tools/nice-framework): Conduct target and technical analysis of systems and vulnerabilities	

## Background

🛰️ In the wake of a major whistle blower leak, a shadowy government contractor — Nebula Dynamics — accidentally deployed a test version of its internal document processing system to a public-facing server. Intelligence suggests it parses sensitive XML-based threat reports. You're tasked with infiltrating the system and extracting the classified tokens buried deep within the code.

## Getting Started

The target website can be found at `http://nebula:5000`. Begin your hunt - enumerate the application and find its secrets (tokens).

**Token Format**  

```text
e.g. ✅ TOKEN1: PCCC{BLT-alphanumeric_string}
```

**Discovery Phase Operations**
Everything is not as it seems. Thoroughly investigate all presented functionality to determine the vulnerabilities in the Telemetry system.

## Objectives
* Inspect the site's XML-driven components for unusual behavior.
* Discover indirect access methods through lesser-known routes.
* Demonstrate control over backend communications by crafting non-standard HTTP payloads.
* Collect all four embedded access tokens hidden across the app’s layers.

## System and Tool Credentials

|system/tool|location|
|-----------|--------|
|Nebula|`http://nebula:5000`|

## Note

You do not need root access to the server to complete this challenge. Tokens are awarded through completion of the objectives.
