# Discounted Route to Rescue

Exploit vulnerabilities and permissions to retrieve two crucial documents.

**NICE Work Roles**

- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0567](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze target operational architecture for ways to gain access.
- [T0696](https://niccs.cisa.gov/workforce-development/nice-framework/): Exploit network devices, security devices, and/or terminals or environments using various methods or tools.
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply and utilize authorized cyber capabilities to enable access to targeted networks.


## Background

An Aurellian ship has fallen under enemy control. Research indicates the enemy has integrated a new service called `coupons.merch.codes` into the ship's network. You have access to the infiltrated Aurellian ship, giving you the opportunity to execute the necessary exploits and recover two important documents.

## Getting Started

Exploit vulnerabilities within the compromised Aurellian ship's system. Focus on the `coupons.merch.codes` service. After gaining unauthorized access, find two vital documents containing valuable information that will help recover the ship. 

Search for the first document in a container in the `/var/www/html/` directory. Retrieve the second document by escaping the confines of the container and navigating to the root (`/root/`) directory of the master node. 

**Important!** `coupons.merch.codes` can take up to four minutes to boot. Please be patient!

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Contents of "flag_one.txt" found in the `/var/www/html/` directory
2. Contents of "flag_two.txt" found in the `/root/` directory inside master node
