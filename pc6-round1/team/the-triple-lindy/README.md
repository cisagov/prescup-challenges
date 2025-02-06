# The Triple Lindy

Your team is tasked with performing a penetration test against a local community swimming pool. Find and exploit various web and SCADA/ICS vulnerabilities to ensure the pool's safe operation.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Cyber Operations](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis for target infrastructure exploitation activities.

## Background

Use the provided Kali machine to explore and exploit websites and SCADA/ICS systems while gathering data related to the operations of a local swimming pool.

## Getting Started

Log in to the Kali VM, browse to `http://townsville-pool.merch.codes`, and start gathering information about the **Townsville Community Pool** technical operations. The Python libraries `ctmodbus` and `pymodbus` are  installed on the Kali VM. Third-party websites are available on the WAN, located at `123.45.67.89/24`. You can perform packet captures on the `pfsense` firewall using the web GUI under the Diagnostics tab.

If you use **Security Onion** to create PCAP files, make sure to enter `securityonion` in the `Sensor ID` field. Log into Security Onion at `10.4.4.4` through a browser or via SSH.

## Submissions

There are four (4) tokens to retrieve in this challenge. All tokens become available on the Townsville Community Pool website as they are unlocked by completing the tasks below. You may need to refresh the web page to see the token, for example, after completing question three. Here are some additional details about each token:

- **Token 1:** Login to the Townsville Community Pool website as the Pool President.
- **Token 2:** Raise the pool temperature to at least 110 degrees Fahrenheit.
- **Token 3:** Disable the pool video camera system.
- **Token 4:** Complete the "Triple Lindy" by changing these three pool water balance values:
	1. Decrease the pH from 7.0 to 6.0.
	2. Increase the chlorine level from 3 ppm to 4 ppm.
	3. Decrease total alkalinity from 100 ppm to 70 ppm.
