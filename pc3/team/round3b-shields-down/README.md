# Shields Down!

We've launched a rocket carrying a nuclear warhead at the aliens' moon base, however they have some sort of energy shield protecting it. Our sensors indicate three energy sources - we suspect each of these provides some of the power to the shield. Disable the shield before the missile arrives (10 minutes before the end of the exercise). Use the moonbase network gateways you identified to pivot into their network; you are cleared to gain access and shut down the shield generators by any means necessary. 

**NICE Work Role**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background

You have done a great job so far defending against the aliens' advances while also gathering information on their network. Now we begin the final phase of our plan. 

With the moonbase network gateways pinpointed, a nuclear warhead has been launched and is estimated to hit the moon base approximately 10 minutes before the end of the exercise. Within that time, we will need you and your team to access the moonbase network gateways previously found and bring down their three(3) internal shield generators. If any of their shields are up by the time that nuke hits, all of this will be for nothing. 

The shield generators are only accessible via the moonbase network gateways you found previously (in `We Must Go Deeper`). You will need to determine how to gain access to each of those servers and then pivot in order to gain access to the internal shield generator. We've found that each network gateway only has access to one shield generator within their network.

You will need to gather information on their network, determine how to infiltrate it, and then gain access to the three shield generators and shut them down by any means necessary. It will be up to your team to determine how to complete your objective in time so that your attack is a successful one. 

## Getting Started

PLEASE NOTE: During your teams initial reconnaissance, they found that the aliens intentionally set up their network with a defense mechanism to hinder attempts at sniffing the traffic. You will need to figure out how to spoof the network to get past this.

With that information in mind, log onto the `kali` machine and start to gain any information you can about the network, the machines on it, and the moonbase network gateways you previously got the IPs of. 

## Submission Format

This challenge will be automatically graded throughout the exercise. As such there is no submission required from the players.

All three shield generators must be turned off by the time the nuke hits (10 minutes before the end of the exercise) in order to gain full points. No more grading will occur after that time, and if any of the generators are still running then our attack will be pointless.
