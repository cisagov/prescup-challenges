# No Alarm Needed. Incidents Wake Me.

Investigate a Mobile Device Incident

**NICE Work Role:** 
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Incident+Responder&id=All)

**NICE Tasks:**
- [T0047](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0047&description=All) - Correlate incident data to identify specific vulnerabilities and make recommendations that enable expeditious remediation.
- [T0278](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0278&description=All) - Collect intrusion artifacts (e.g., source code, malware, Trojans) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT

This challenge is partially open sourced. These files were provided during the competition and can serve as a starting point if you wish to recreate part of the challenge yourself. The full challenge can be attempted on the hosted site.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc2/team-round2-no-alarm-needed-largefiles.zip)
and extract in _this directory_ to get started.

## Background

An incident has occurred on your network that supports government parks. This incident included a recently government-purchased Android smartphone and two park servers (each in production when they should have still been in dev). You have been given full authorization for the network/creds/devices to figure out what is going on (some console access is not available, but this shouldn't stop you). The servers, devices, and overall network should not have been live, especially with the data on them. It has been isolated for you to investigate.

## Getting Started

The 3 devices have been extracted from the government network and setup in a sandbox environment to resemble their networked state during the incident in the 192.168.0.0/24 subnet.

Android - .109

Fairview Resources - .111

Yellowstone Wiki - .116

All three systems have been confirmed to be involved in the incident. Also, the .VMDK of the Android device and the packet capture of the incident (while on government network with other machines) are located on the attached ISO for analysis. The live Android has been modified by the user since the .vmdk was captured live via a remote means. The .vmdk was captured prior to seizing the device from the user; however, you now have the Android live (VM) and the .vmdk on the attached ISO.

Answer the questions below while investigating. The means to answer the questions can be found while investigating. You have full authorization to utilize any credentials/logins to perform this invasive incident response. You do not have console access to Fairview Resources nor Yellowstone Wiki.

## Notes

The incident occurred around 19 June 2020.

The Android is set to 30-min display timer. If it blacks out on you, send a CTRL-ALT-DEL and/or reboot the machine.

RECOMMENDED: Unzip the .vmdk and .pcap on Kali first. This may take 2-3 minutes.

## Questions

1. What is the first name of the contact that appears to be an imposter of Fairview.gov?

2. What is the last name of the contact that was recently deleted from the Android device, but was captured in the .vmdk image?

3. What is the username of the login for MediaWiki found on Android? (HINT: Consider exporting all data from the contacts database or manually viewing the data live on Android)

4. What is the Xth value of the .txt/.csv that was download AND deleted from the Android device, but captured in the .vmdk image? Find the value by viewing the same-named file on MediaWiki. The specific value can be found above the answer submission text box.

5. There is an encrypted file and password/key somewhere separately. You might need to "find creds". Find them, use them, decrypt the file, enter the Xth value of the file. The specific value can be found above the answer submission text box.
