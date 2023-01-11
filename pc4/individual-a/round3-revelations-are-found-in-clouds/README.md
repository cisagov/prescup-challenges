# Revelations are Found in Clouds

Investigate an incident in the Azure cloud platform.

**NICE Work Roles:** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst)

 **NICE Tasks:**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0027) -  Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.

## Background

The _Dauntless_ utilizes some Azure services to communicate with ground stations on Earth. Data that was present in the Azure subscription is now posted on the internet. Investigate how that may have happened. 

## Getting Started

You're provided access to an  **SOF-ELK** and an **Analyst** VM. **SOF-ELK** stands for "Security Operations and Forensics Elasticsearch, Logstash, Kibana." Read more about this VM [here](https://github.com/philhagen/sof-elk/blob/main/VM_README.md). 

You're also provided access to logs from an Azure subscription under investigation. The file **logs.zip** contains sign-in, audit, activity, storage, metrics, and netflow logs. Logs are attached to the CD-ROM drive on the SOF-ELK and Analyst VMs. 

### Additional Notes:

To use the CD-ROM drive on the SOF-ELK VM, you must properly mount the file system.

Kibana in the SOF-ELK VM can be accessed from the Analyst VM by browsing to `http://sof-elk:5601` from a gamespace resource.

## Challenge Questions

1. A user's credentials may have been compromised. What is the name of that user?  
2. What is the name of the blob container from which the unauthorized user using stolen credentials downloaded a file?  
3. What is the private IP address of the Linux virtual machine that was created most recently in the subscription?  
4. Based on the Azure netflow logs, how many times did an SSH flow with the attacker's IP address as the destination begin?  
