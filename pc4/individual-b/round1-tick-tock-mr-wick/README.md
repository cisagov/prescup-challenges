# Tick, Tock Mr. Wick

One of your ship’s internal websites has been attacked and taken over and is now showing a countdown on its homepage. You are told there are keys embedded within that can be used to stop the countdown. You must begin analyzing the site to find a way to deactivate it before the countdown ends.

**Time is a factor in the scoring of this challenge. Complete the tasks as quickly as possible to receive full credit for the challenge.** 

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## IMPORTANT

This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background  

One of your internal websites seem to have been attacked and taken over and is now showing a countdown on its homepage. Simultaneously, word has come from Earth that a member of the radical isolationist group, XeNO, was captured and confessed that they had set a logic bomb and that it was set to go off after a short delay if the cube drive was activated, to make it appear like the drive had failed and destroyed the ship. 

They explain that the countdown shown is the remaining time until the real piece of malware is executed and that it will cause catastrophic failures to multiple systems and services by attacking across the internal network, if allowed to execute.

They also elaborate that when the site was taken over, three keys were built into the website in case the XeNO's needed to abort the operation. Only by entering all of them will the logic bomb deactivate. They have not divulged how to acquire these keys or enter them into the website. 

The original site developer was contacted and has stated that even though the site has been altered you should still be able to find the original file listing the endpoints available by scanning the site. Otherwise, you have been given permission to do whatever is necessary to find the keys and deactivate it before that timer goes off.


## Getting Started

You can begin by browsing to the website's URL at `http://countdown:5000` and begin using all the tools available to you to analyze the website and find the three keys embedded in it.

## Challenge Questions


1. What is the 8 character hex string given for submitting the first key to the countdown site?
2. What is the 8 character hex string given for submitting the second key to the countdown site?
3. What is the 8 character hex string given for submitting the third key to the countdown site?
4-7. Additional tokens are awarded for solving this challenge quickly. 

Time is also a factor in the scoring of this challenge. A scoring breakdown and the times to beat are listed below. The timer stops when the final key has been submitted to the site.

Throughout the challenge, checks will continually run to determine your completion time. You can earn up to four tokens based on your completion time - the faster you solve the challenge, the more tokens you will earn. Once the final checks are complete, your completion time will be used to determine the tokens given as follows:

| Completion Time  | # of Tokens Earned  |  % of Overall Challenge Score Added   |
|-------------|-----------|-------------|
|  75 minutes or less | 4 | 20% (5% each) |
|  76-90 minutes | 3 | 15% (5% each) |
|  91-105 minutes | 2 | 10% (5% each) |
|  106-120 minutes | 1 | 5% |
|  more than 120 minutes  | 0 | 0% |

