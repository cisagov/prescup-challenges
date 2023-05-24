
# Stacked and Hopefully Not Hacked

Teams will be required to install and configure the initial setup of an Elasticsearch/Kibana server and Filebeat/Logbeat log shippers. Grading checks will verify the proper setup. Teams will also need to use the Kibana dashboard to discover information regarding multiple pre-staged events on the various systems.

**NICE Work Roles**
 [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework)

 [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks**
- [T0335](https://niccs.cisa.gov/workforce-development/nice-framework) - Build, install, configure, and test dedicated cyber defense hardware.
- [T0161](https://niccs.cisa.gov/workforce-development/nice-framework) to identify possible threats to network security.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

Your team has been called to assist the U.S. Fish and Wildlife Service's Cervidae division at Caledonia State Park, PA. The Cervidae division has only a small regional office with a number of part-time staff and rangers working on various tasks throughout each business day. Multiple outdoor duties allow for a minimal number of shared desktop systems to be made available to the staff. However, all staff do receive an account on a particular system, based on preference, whether they intend on using it or not.

The Cervidae division has also hired some new staff members who attended an onboarding and orientation session on June 7th, 2021. Due to the increase in staff, and the recent increase in local cyber-attacks, it has been recommended that the Cervidae division setup a centralized logging service to monitor their systems.

Your task will be to properly set up, configure, test, and validate an ElasticSearch and Kibana instance that can receive logs via Winlogbeat or Filebeat, depending on the client system OS. Due to the smaller scale and limited availability of Cervidae computer systems, the ELK applications and services are to be installed on a Windows 10 desktop system. The remaining network consists of two Windows 10 desktop clients and two Ubuntu 18 desktop clients. The local network range resides on a flat 10.5.5.0/24 space. The network includes a DHCP server has been located at 10.5.5.5 for the clients and the ELK server has been initialized with a 10.5.5.100 address.

A system installation guide can be found here:
[t06-challenge-instructions.pdf](/challenge/t06-challenge-instructions.pdf)

## Submission Format
50% of your total score will be evaluated by automated Grading Checks. On success, each check will provide a token string for submission.  

**Grading Check #1** - successfully installing Elasticsearch and making sure it is running and accessible as expected.

**Grading Check #2** - successfully installing Kibana and making sure it is running and accessible as expected.

**Grading Check #3** - successfully adding/shipping data for both the Filebeat and Winlogbeat indices. (NOTE: You are only required to have one system of each type reporting in to receive credit, though you will want to add shippers to all four clients for later analysis).  

The grading service is accessible from any system browser within the network at `http://challenge.us (10.5.5.5)`. Here you may check your work and receive tokens for submission upon success. You may initiate the automated grading checks as many times as you'd like inside the challenge environment.

50% of your score will be tied to five questions regarding the team's ability to perform event and log analysis to discover information about recent system events. You may use the various prebuilt Kibana dashboards and search options to aid in your analysis.

## Hints
The regional office resides in the EDT timezone (UTC-4)\
Ensure that you are looking at the correct timestamp when trying to correlate Ubuntu log events\
Remember to set your time range filters in Kibana/Elasticsearch for the dates in question
