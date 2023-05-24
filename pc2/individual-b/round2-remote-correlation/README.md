# Remote Correlation

You must use Indicators of Compromise from another organization's incident report to determine if your organization has been compromised by the same adversary.

**NICE Work Role:** 

- [Threat/Warning Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**  

- [T0805](https://niccs.cisa.gov/workforce-development/nice-framework) - Report intelligence-derived significant network events and intrusions.  

- [T0749](https://niccs.cisa.gov/workforce-development/nice-framework) - Monitor and report on validated threat activities.  

## IMPORTANT
This challenge does not have any downloadable artifacts. The full challenge can be completed on the hosted site.


## Background

You are provided an incident report from Company XYZ. The report describes the tactics of the adversary who attacked the company's Windows infrastructure. Details about the attack should be used to attribute artifacts on the provided Windows computers to the same attacker that compromised Company XYZ. 

## Getting Started

Read the Company XYZ incident report (below).  

After gathering details from the report, you must use your provided Windows workstation to audit 3 remote Windows workstations.   

The 3 remote workstations will have various firewall, scheduled task, registry, and/or WMI artifacts configured. Some of the artifacts on the remote workstations will be benign. Other artifacts on the remote workstations will have similar characteristics to those seen in the incident report.   

Your task is to list the hostnames which have artifacts with similar characteristics to those gathered from the provided incident report.

## Submission Format

The tokens you submit will be the hostnames which have artifacts with similar characteristics to those gathered from the incident report.   

There are 4 parts to a submission. The 4 parts are derived from the types of artifacts that exist on the remote machines: Firewall, Scheduled Task, Registry, and WMI.  Each part can have one or more hostnames to list as part of the submission. For parts that have more than 1 hostname, enter the hostnames separated by a space.

