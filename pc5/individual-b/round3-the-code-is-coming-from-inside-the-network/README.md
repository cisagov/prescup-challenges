# ...The Code is Coming from Inside the Network

A merchant spaceship of dubious renown is collaborating with a client of equally suspicious reputation. Infiltrate the spaceship's network to gather information about this project.

**NICE Work Roles**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0009](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze information to determine, recommend, and plan the development of a new application or modification of an existing application.
- [T0057](https://niccs.cisa.gov/workforce-development/nice-framework/): Design, develop, and modify software systems, using scientific analysis and mathematical models to predict and measure outcome and consequences of design.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform analysis for target infrastructure exploitation activities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/): Lead or enable exploitation operations in support of organization objectives and target requirements.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.


## Background 

This merchant ship of unsavory reputation specializes in creating and deploying web services for its clients. Rumors say a new client is paying an exorbitant rate for a “standard” project. Could this project have hidden nefarious motives? Analyze the ship’s internal network, find vulnerabilities, and leverage them to gain access to their public website and pertinent information about the project.

## Getting Started 

Log into the `kali` VM and enumerate the spaceship's network to discover hosts and network services present. It has been confirmed that subnets present are: `10.3.3.0/24`, `10.0.0.0/30`, and `10.7.7.0/24`.

## Challenge Questions

1. What is the hex token received in the response when retrieving data from the network's internal repository?
2. What is the hex token received in the response when uploading data to the network's internal repository?
3. What is the hex token found on the website associated with the project that has the highest price?
