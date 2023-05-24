 # VyOS is your OS

A network administrator has detected a foreign IP accessing our internal servers. This kind of activity should have been blocked by our firewall. Your task is to investigate the breach, and patch it. 

  **NICE Work Roles:**   

  - [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework)

  - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

  **NICE Tasks:**

  - [T0035](https://niccs.cisa.gov/workforce-development/nice-framework).
  - [T0160](https://niccs.cisa.gov/workforce-development/nice-framework)- Patch network vulnerabilities to ensure that information is safeguarded against outside parties.
  - [T0163](https://niccs.cisa.gov/workforce-development/nice-framework)- Perform cyber defense incident triage, to include determining scope, urgency, and potential impact, identifying the specific vulnerability, and making recommendations that enable expeditious remediation.

## IMPORTANT
This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

  ## Background  
A foreign IP address (10.5.5.13) has been detected accessing our internal servers. Our firewall should have blocked this activity, but it did not. You must:
   1. Identify how the adversary gained access to our private network
   2. Patch the firewall to prevent adversary traffic
   2. Mitigate the breach by removing all malware
  
_Note: Ignore traffic from `192.168.0.5`_

   
  ## Getting Started
1. You have access to the Windows Administrator machine for the network. 
2. The router can be accessed internally via ssh at `192.168.0.1`, with the credentials [vyos | vyos].

  ## Submission Format

  There are three (3) parts for this challenge. The first submission token will be an IP address, the second and third are obtained after passing grading checks inside the environment at: `http://challenge.us`

- Part 1 will ask you to submit the IP address of the initial source of compromise (where the malware was downloaded from)

- Part 2 will check that the firewall configuration has been successfully reverted to the previous state (before the attack)

- Part 3 will ensure that all malware has been removed from the network


 