# AWeSome

Investigate an incident in AWS cloud

**NICE Work Roles:** 

- [Cyber Defense Forensics Analyst](https://niccs.us-cert.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)


 **NICE Tasks:**
- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0027&description=All) -  Conduct analysis of log files, evidence, and other information to determine best methods for identifying the perpetrator(s) of a network intrusion.


<!-- cut -->

## Background

You're provided CloudTrail and VPC Flow logs from an AWS account. The account owners believe that some important internal documents that were present on one of the EC2 instance are now posted on the internet. You're tasked to investigate how that may have happened. 

## Getting Started
You're provided logs for three days 14th - 16th November, 2021. Your task is to analyze the log files and answer the following questions - 
1. Provide the IP address from where the users of this AWS account usually login to AWS web console. 
2. Our suspicion is that one of the API keys associated with the IAMUser had been stolen and was utilized in the incident. How many files did the unauthorized user download from the S3 bucket?
3. The unauthorized user accessed a number of EC2 instances. Provide the instance ID of the EC2 instance that was accessed the most or for the longest duration overall. (The unauthorized user is using 2 different IPs in /10 network to connect to AWS resources)
4. The unauthorized user exfiltrated ~10MB of data from the EC2 instance (identified in the previous question) to a system on the internet. Provide the IP address of the remote system.
