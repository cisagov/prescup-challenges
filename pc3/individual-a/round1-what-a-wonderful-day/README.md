# What a Wonderful Day
  
  Given a Windows VM, you must analyze a ransomware attack and force devices into a desired state.


  **NICE Work Role:**

  [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

  [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


  **NICE Tasks:**

  - [T0160](https://niccs.cisa.gov/workforce-development/nice-framework) - Patch network vulnerabilities to ensure that information is safeguarded against outside parties.
  - [T0162](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform backup and recovery of databases to ensure data integrity. 
  - [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information.


  ## IMPORTANT

  This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.


  ## Background

  Your company stores critical files on Company-PC at `C:\Users\Public\CompanyFiles`. Unfortunately, the company has fallen victim to a ransomware attack which has encrypted the files, and is preventing regular business from proceeding. The attackers are known to use powershell for their malicious activities and any running powershell processes should be investigated.

  Luckily, the company performs regular backups that are at located at the network path: `\\host1\c\Users\Public\Recovery`. You will need to use this backup to restore the files to a state from before they were encrypted.  

  To deter an attack like this from happening again, you will need to alter the firewall rules. Close the port the attacker is using on the host-based firewall. All other ports/rules on the firewall must remain "as-is". 

  The attackers also implemented a backdoor by adding a Local User to the machine, you will need to find which username they added and remove the account. 


  ## Getting Started

  Intel about the attack says analyzing powershell process memory may yield critical information (ex. encryption password) about the malicious actions. Logon to the Windows VM and take a memory dump of the powershell processes that are running. Investigate the memory dump and, based on your findings, implement any necessary firewall rules to the host-based firewall, remove the appropriate local user and restore files to it's original state.

  ## Submission Format

 Visit the grading site inside the challenge environment at `http://challenge.us`. This is where you can see the challenge completion status and receive submission tokens. Submission tokens will be 16 hex characters.

  There are 4 parts of this challenge. 2 of these parts are grading checks for this challenge from the grading server. The `File Restoration Check` will ensure that files have the correct data and are no longer encrypted. The `Network State Check` ensures the machine is still online and has blocked the ports that have been attacked. You will be required to submit the two tokens from the grading check into the game board. 
  
  There are two other tokens that you will find within the machine. The `Encrypted Password Token` is the password that was used to encrypt the files. The `Username Token` is the username that the attacker added to the machine.
