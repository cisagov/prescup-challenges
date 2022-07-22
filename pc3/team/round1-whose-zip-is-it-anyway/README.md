
# Whose ZIP is it anyway?

A ZIP file has been intercepted and contains files that have been altered and encoded. Determine how to return them to their original state, and extract the information they hold.


**NICE Work Role:** 

  - [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks:**

  - [T0049](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0049&description=All) - Decrypt seized data using technical means
  - [T0167](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0167&description=All) - Perform file signature analysis.
  - [T0179](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0179&description=All) - Perform static media analysis.
  - [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0532&description=All) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## Background

The security team has been monitoring ongoing traffic from a known threat actor who has been communicating with their associates about a file containing a secret passphrase needed to access their secret internal network.

Since then, they have intercepted a ZIP file that they believe contains the secret passphrase. Upon inspection, there are various files in the ZIP that all seem to have been altered and/or modified from their original state.

It is believed that each file contains a part of the secret phrase; solve how to decode/decrypt each file. Analyze each file's code to determine the EXACT type/extension, extract each file's part of the secret passphrase, and then determine how to put them together to create the secret passphrase.

## Getting Started

The zip file `AtomicElements.zip` can be found in the challenge folder. There are five files that will need to be altered and decoded to solve this challenge.

## Answer Parts
This challenge has six parts consisting of:

- Finding the extension of five files.
- Determining the final concatenated decoded string.

For any ZIP type files, make sure to use the extension and not the algorithm. Example:

| ZIP algorithm| extension|
|-------------|----------|
| 7zip | .7z|
|Bzip2 | .bz2|
| gzip | .gz |
| lzip | .lz |

