# Compliance Rules Everything Around Me

Scan and fix the network topology of *Daunted*, an Aurellian spaceship, so that it complies with the security measures documented in its *Security Controls Guide*. 

**NICE Work Roles**

- [Vulnerability Assessment Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
- [T0010](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze organization's cyber defense policies and configurations and evaluate compliance 
- [T0142](https://niccs.cisa.gov/workforce-development/nice-framework/): Maintain knowledge of applicable cyber defense policies, regulations, and compliance documents specifically related to cyber defense auditing.

## Background

Your team must identify and remediate security weaknesses in *Daunted*'s network, including: default application passwords, unauthorized open ports, firewall rules, and misconfigured files -- all the while ensuring that the network environment works.

## Getting Started

Using the provided Kali machine, perform a series of steps to bring the network into compliance with *Daunted*'s Security Controls Guide. Here is a high-level explanation of tasking to complete this challenge: 

- Change default application passwords to meet required uniqueness and complexity. If a password already meets complexity and uniqueness, don't change it. 
- Address sensitive information
- Close or disable unauthorized open ports and firewall rules
- Ensure configuration files meet required standards
- Verify the environment is operational after performing changes

**K3s manifests** can be found under: `/home/user/default/`. Each application has its own directory. 

The *Daunted*'s *Security Controls Guide* can be found [here](./challenge/SecurityGuide.pdf). 

## Compliance Assistant

In the gamespace, browse to `challenge.us` and read the **Compliance Assistant**. The Compliance Assistant verifies the changes made to the network environment and gives you tokens for submission. Follow the instructions carefully!

## Challenge Tasks

1. Meet the Password Management Control.
2. Meet the Kubernetes Secrets Management Control.
3. Meet the Network Security Control.
4. Meet the Configuration Security Control.
5. Your Environment must be Verified as Fully Compliant and Functional.
