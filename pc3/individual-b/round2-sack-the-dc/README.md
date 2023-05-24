# Sack the DC
  
Use existing access to continue a penetration test. Escalate privileges and pivot to the high value target.

  **NICE Work Role:**

  - [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


  **NICE Tasks:**

  - [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
  - [T0696](https://niccs.cisa.gov/workforce-development/nice-framework) - Exploit network devices, security devices, and/or terminals or environments using various methods or tools. 

  ## IMPORTANT
  This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

  ## Background

  You are stepping into the middle of a penetration test. A malicious executable using the Metasploit payload `windows/x64/meterpreter_reverse_http` on port 80 is regularly reaching out to your Kali machine from a domain-joined Windows machine. The objective is to use the tools provided on your Kali machine to escalate privileges on the domain joined machine, then gain administrative access to the domain controller.


  Note: 
    - Payload is continuously running on a domain-joined machine.
    - Mimikatz and Rubeus are ready to be used on the domain-joined machine.
    - Tools on the Kali machine are located at /home/user/Desktop/ExploitTools.
    
  ## Getting Started 

  Setup Metasploit to establish a connection with the domain-joined machine that is calling back to you. Use this session and the tools provided on the Kali desktop to elevate privileges and gain access to the domain controller. 

  ## Submission Format

  There are two (2) submission tokens for this challenge. The first token is located on the Desktop of the local admin on the domain-joined Windows 10 machine. The second token is located on the Administrator's desktop on the domain controller. 
