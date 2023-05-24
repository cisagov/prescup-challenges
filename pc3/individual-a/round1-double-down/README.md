# Double Down
There has been reports of suspicious traffic occurring in your network that may include sensitive data. Having only an old packet capture, you must gather any information you can in order to determine what is going on.

**NICE Work Roles:** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework) - Decrypt seized data using technical means
- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework) - Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.
- [T0258](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.

# IMPORTANT

This challenge requires a hosted environment to fully solve as it was intended.  
The files provided in the [challenge folder](challenge) are provided as part of open sourcing. Use these files as a starting point if you want to build your own version of this challenge.

## Background  

There has been suspicious activity going on in your network. It is unknown what is happening, but there is a rumor that two machines on the network have been discussing something in secret and are planning to transfer data that contains information on secret phrases used by your organization to access highly sensitive information.

This has happened recently while the organization has been undergoing virtual and physical re-structuring. So it seems that these threat actors thought that they may get away with their nefarious plan while machines were being moved around and hosted on  different servers. Due to this you may have difficulty sniffing any of the ongoing traffic and so you must figure out how to overcome this. 

Your job is to determine which machines are involved, how to capture the ongoing traffic between them, intercept the file being exchanged and determine the content of the files being sent. There is an old packet capture that is believed to contain traffic that will point you to the ones behind this.


## Getting Started

Open the packet capture that is attached to the CD Drive of the Kali workstation to begin analyzing it. Please note that the organizations network uses DHCP, so the IPs used may not accurately represent the current layout of the environment. You will need to determine how to spoof the relevant hosts in order to intercept traffic.  


## Submission Format
There are two submissions for this challenge. The requirements for each submission is as follows:

- Name of the file being transferred
- The contents of the decrypted file 
