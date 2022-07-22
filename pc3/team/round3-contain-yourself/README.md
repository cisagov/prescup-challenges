# Contain Yourself
Harden the configuration of a Kubernetes cluster.

**NICE Work Role:**

[Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Vulnerability+Assessment+Analyst&id=All)

[Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)

[Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Infrastructure+Support+Specialist&id=All)

[Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist&id=All)

**NICE Tasks:**

- [T0142](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0142&description=All) - Maintain knowledge of applicable cyber defense policies, regulations, and compliance documents specifically related to cyber defense auditing.
- [T0160](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0160&description=All) - Patch network vulnerabilities to ensure that information is safeguarded against outside parties.

# Underground Cluster

## Background

NSA / CISA report threats to Kubernetes environments and provide configuration guidance to minimize risk.

Kubernetes is commonly targeted for data theft, computational power theft, or denial of service. Primary actions include vulnerability and misconfiguration scanning, and making changes to the PodSecurityPolicy Configuration to harden the cluster. This will include changing the cluster to a read-only file system, preventing privilege containers, preventing privilege escalation, making sure container only runs as user and as non-root, setting hostIPC and hostIPD to false, enabling audit logging, configuring encryption, enabling container limit range, and denying ingress and egress.


## Getting Started

`psp.yaml` can be found in the challenge folder. It is the PodSecurityPolicy file. All security changes must be made inside of that file.

## Submission Format

There will be (6) grading checks for this challenge. [GradingScript.sh](GradingScript.sh) can be used to check your progress (reading this script will give away challenge answers). Running it will state success or failure for each part depending on the changes made to the `.yaml` file.
- The first check will verify if the cluster is on a read-only file system, privileged is set to false, and privilege escalation is not allowed.   
- The second check will verify if the policy is set to run as non-root & user and hostIPC & hostPID are set to false.  
- The third check will verify if audit logging is enabled. 
- The fourth check will verify if the encryption configuration was set. 
- The fifth check will verify that the limit range was set. 
- The sixth check will verify that ingress and egress was denied. 
