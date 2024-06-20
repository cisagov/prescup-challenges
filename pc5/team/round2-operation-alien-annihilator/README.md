# Operation Alien Annihilator

Exploit software vulnerabilities and gain access to an enemy spaceship's network assets.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework): Apply and utilize authorized cyber capabilities to enable access to targeted networks.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework): Perform analysis for target infrastructure exploitation activities.
- [T0695](https://niccs.cisa.gov/workforce-development/nice-framework): Examine intercept-related metadata and content with an understanding of targeting significance.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

An enemy spaceship has announced its intention to attack your ship and steal your goods! You can prevent this by infiltrating the enemy spaceship’s network services and taking action.

## Submissions

There are four (4) tokens to retrieve in this challenge. The tasks you must complete to retrieve tokens are:

- **Task 1:** Take over another user account to escalate your privileges within the management portal located at `10.7.7.172`.
- **Task 2:** Explore the management portal located at `10.7.7.172` and exploit it to access information located on other servers inside the network.
- **Task 3:** Within the network are two API's that handle requests to control the temperature of various server sensors. The only information about these sensors that is known at this time is that one lives in the `10.7.7.0/24` network and the other is in `10.3.3.0/24`. Intercept and prevent any related traffic sent to them so you can access the API's and cause six servers to overheat and go offline.
- **Task 4:** Find and gain access to a file hosted on an internal website containing information on future endeavors of a user located on the `10.3.3.0/24` network.

## Getting Started

Log into the Kali machine, enumerate the network, and begin your attack. 
