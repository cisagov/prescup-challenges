# The Real Folk Blues

A machine is infected and is BSODing on boot. This machine needs to be investigated.

**NICE Work Roles:**

 [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

    
**NICE Tasks:**  

- [T0432](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0432&description=All) : Collect and analyze intrusion artifacts (e.g., source code, malware, and system configuration) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) : Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## IMPORTANT

This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

A user on an enterprise computer has downloaded something malicious! The machine is now showing a Blue Screen of Death (BSOD) on boot. Luckily, we have a custom Windows PE ISO on hand to investigate the machine.

## Getting Started

Power on the virtual machine, and let the BSOD failure occur once. 

Next time you boot the virtual machine, you should boot from the custom PE ISO. When the VM is booting, press ESC to enter a boot menu, and select the option to boot from a CD. The VM will boot into the custom Windows PE that you can use to troubleshoot the BSOD error. Investigate memory dump files to determine what is causing the BSOD. Mitigate the BSOD from inside the Windows PE, so the machine can boot regularly. Once the BSOD is mitigated, boot to Windows normally, then complete the rest of the investigation. 

## Submission Format
There are 4 parts of this challenge. 

1. Provide the name of the binary that is causing the BSOD (file name with extension)

2. After preventing further BSODs, investigate the installer for the program causing the BSOD. Visit the site that the victim would have downloaded the malicious program from, and find the submission token. (hex string)

3. Discover and submit the token that the installer is placing in the Windows Registry.(hex string)

4. Investigate TrollSoftware.exe. Determine how to interact with the malicious server used by this software and retrieve the token. (hex string)

## Note
Some usability features are missing when inside of the Windows PE ISO. Copy/Paste into and out of the VM is not supported while booted to the Windows PE ISO.
