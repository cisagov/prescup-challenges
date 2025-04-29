# Car-tastrophe

Your team has been tasked with infiltrating a smart car. Gain access using an unprotected smart app API, and use Python's python-can library to access the CAN bus.


**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform penetration testing.
- [T1635](https://niccs.cisa.gov/workforce-development/nice-framework/): Access targeted networks.
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities.

## Background

Use the provided Kali machine to exploit a vulnerable smart car API and extract a critical encryption key being stored on a vehicle's CAN bus. An introduction to the CAN Bus can be found [here](https://www.csselectronics.com/pages/can-bus-simple-intro-tutorial). An introduction to the CAN Bus can be found [here](https://www.csselectronics.com/pages/can-bus-simple-intro-tutorial).

## Getting Started

A spy is transporting an encryption key of utmost importance to national security in a Twig smart car (VIN `R0MHBBXF3P5069X37`). Our team has partially reverse-engineered the CAN bus modules being used and believe that the Twig smart car API may be vulnerable.

Login to the Kali VM and begin investigating the vulnerable smart car application. The pfSense VM (`pfsense.merch.codes`) can be used to perform packet captures using the web GUI under the Diagnostics tab. Third-party websites are available on the WAN, located at `123.45.67.89/24`. 

The Python library `python-can` is installed on the Kali VM. The CAN bus `vcan0` is exposed via socketcand at `123.45.67.2:29536` and packet captures for the CAN bus network can be found at `http://123.45.67.2:5000`. If using `python-can`, it may be helpful to switching logging output to only errors. 

The CAN bus module documentation for the Twig smart car can be downloaded at `challenge.us`. The `challenge.us` site may take several minutes to become accessible.

## Submission

There are 5 tokens to retrieve in this challenge. Each token is a 16-character hexadecimal value. The tokens can be retrieved in any order. Tokens 1, 4, and 5 require a grading check from `challenge.us`.

- Token 1: The target has stopped to rest, but did not plug in their car. Exploit the Twig API to drain the car's battery by running the AC while they sleep.
- Token 2: Our agent has intercepted the requested mechanic and installed a CAN bus device to grant remote access at `123.45.67.2`. Extract the encryption key being transmitted by device `0x12345678`.
- Token 3: The encryption key is incomplete. Compare the transmitting CAN devices with the documentation to find the other half of the key.
- Token 4: Signal to our agent that the key has been extracted by using the CAN bus to display the signal on the A/V unit.
    - The agent expects the A/V unit to turn on the climate control display and show `255` as the user-requested fan speed.
- Token 5: The target has caught on to us and escaped before our agent could extract the device! Stop the car using the CAN bus by tricking the Vehicle Control Module (VCM) into believing something is wrong with the brake pressure.