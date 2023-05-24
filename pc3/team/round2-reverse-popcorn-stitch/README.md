# Reverse Popcorn Stitch

Given a Windows machine with remote access to other machines on your network, you must respond to an attack.

**NICE Work Role:**

  [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**

  - [T0163](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.
  - 
  - [T0485](https://niccs.cisa.gov/workforce-development/nice-framework) - Implement security measures to resolve vulnerabilities, mitigate risks, and recommend security changes to system or system components as needed.

## IMPORTANT
This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

  You are a system administrator for a small company. There have been reports of a malware attack on machines on your network. Given that you manage your systems remotely due to the COVID-19 pandemic, you only have remote access to these machines. 
  
  You will need to find out which systems have been affected by the attack. There are a total of (5) Windows machines on your network, each with unique hostnames `win10a-e`.
  
  You must reverse engineer the malware in order to find a token placed in the global variables section of the malware. The name of the malware is known to be "popcorn.exe".
   
  You must also figure out the malware's behavior, and the location of it's log file. 

  Additionally, to prevent an attack using PrintNightmare again, mitigate the vulnerability on all machines by creating a new registry key of "RegisterSpoolerRemoteRpcEndPoint" under "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" with the correct value for attack mitigation.

## Getting Started 

  Authenticate to the (5) Window's machines using SSH. Window's machine host-names are win10a, win10b, win10c, win10d, win10e. Password is "tartans".

## Submission Format

  Submission tokens will be rewarded for properly responding to the incident. There are (4) challenge questions for this challenge. 
  
  The first challenge question will require you to submit the host-names of the machines affected (in any order). 
  
  The second challenge question will require you to enter the token that you find within the malware. 
  
  The third challenge question will require you to enter the full path of the text file the program uses to write data (not logs). 
  
  The last challenge question will make use of the grading server at 'challenge.us', go to this website once you have disabled the attack vector and click 'Grade Challenge'. This will give you a submission token that you can enter into the challenge answer. 
