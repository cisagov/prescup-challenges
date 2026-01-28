# Arecibo

As an uncover operative, hijack a satellite's command-and-control interface using MQTT exploits. The end goal is to configure an "observatory" to fire its hidden orbital laser.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/tools/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities


## Background

📡 Word on the street is that the Arecibo Observatory houses a powerful syndicate planning to destabilize the financial systems of neighboring countries and islands using an Electromagnetic Pulse (EMP). As an undercover operative, your mission is to exploit the Arecibo satellite, which is being targeted for malicious purposes. This engagement is the final test of your loyalty to join their ranks. Blue Team members must ensure the mission fails by implementing appropriate remediation. If done correctly, the adversary will attribute the failure to effective countermeasures.

## Objectives
In this challenge, you will:
* Learn the MQTT protocol to interact with an active orbital laser.
* Create scripts and automation to determine the correct angle, coordinates, and verification code.
* Convert the once-marveled observatory into a weapon.

## Getting Started

For this challenge, tokens are awarded for acquiring each necessary data value needed to fire the laser. Challengers must find:

* The correct angle to hit the target
* The target's coordinates
* The verification key (HMAC)
* The ability to change the mode of the observatory into attack mode

**Dashboard**
You will be provided a live dashboard where you can review additional information and track your status in this operation. This dashboard is called the "ARECIBO UPLINK PANEL" and is crucial to your success in this engagement.

The panel can be found at `http://satellite.obs:5000`.

**MQTT Pub/Sub**
The satellite uses the Message Queuing Telemetry Transport (MQTT) protocol to send and receive commands. The protocol is also used to provide up-to-date status on its operations.

Pub/Sub communication tools will be extremely useful in this challenge.

## Submissions

**IMPORTANT**: Tokens received are only presented to challengers `once`. As this is a covert operation, our actions must be calculated to avoid detection by the custodians of the observatory.

## System and Tool Credentials

|system/tool|location|
|-----------|--------|
|arecibo|`mqtt-broker.obs:1883`|
|Uplink Panel (Dashboard)|`satellite.obs:5000`|

## Note

Attacking or attempting to gain unauthorized access to challenge platform is forbidden.
