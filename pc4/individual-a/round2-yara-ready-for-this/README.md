# Yara Ready For This?

Examine a potentially malicious application's activities by running it in a sandbox environment and then creating a YARA rule to detect it.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-analyst)

**NICE Tasks**

- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0260) - Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information.
- [T0310](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0310) - Assist in the construction of signatures which can be implemented on cyber defense network tools in response to new or observed threats within the network environment or enclave.

## Background

Our Windows security team was given an executable of unknown origin reported to be found on a USB drive near one of the maintenance bays on the Mars base. We've already started to analyze the application, but need your help to confirm our results.

## Getting Started

Using the provided sandbox environment, run and examine the application to determine the potential threats. Write a YARA rule so our detection tools can determine if this threat is present elsewhere on our network.

The potentially malicious application is included as part of the ISO attached to the Windows 10 VM, **yara-win10**. The application is included in the **ADSVCEXEC.ZIP** file. You will need to run it to observe its activity. The ISO also contains a few utilities that may be helpful to complete your analysis and YARA-rule development.

## Challenge Questions

1. What is the filename of the .dll that is downloaded but not used at runtime?
2. What is the 16-character token value of the decryption key?
3. Enter the token after decrypting a collection of encrypted files.
4. Enter a pipe-separated list of the three (3) filenames created as the malware tries to steal password hashes.
5. What is the port number associated with the firewall rule that the application creates?
6. What is the token that was echoed to a file?
7. Enter the token given by the grading server after your YARA rule has been verified.

## Submission Notes

Use these notes to provide additional context to each of the above questions. 

1. The application appears to be downloading .dlls to alter its behavior; not all of the .dlls that it downloads are used.
2. The application downloads a decryption key and stores it on the machine at runtime.
3. The application downloads a collection of encrypted files at runtime.
4. We suspect the application is stealing Windows password hashes.
5. The application creates a firewall rule and opens a port for inbound traffic.
6. The application `echo`'s the token to a file.
7. Write a YARA rule to detect the **Adsvcexec.exe** executable that does not return false positives. In the gamespace, browse to `https://challenge.us` and post your rule for verification. Enter the rule as a single-line string; do not include newline characters. You can test multiple submissions as you adjust your rule. If the rule works, you are given the final token. An example YARA rule for submission is below: 
```
rule MyRule { strings: $testString = "suspicious" condition: $testString }
``` 
