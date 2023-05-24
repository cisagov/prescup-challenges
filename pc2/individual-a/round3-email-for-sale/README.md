# Email For Sale

  You must track down and identify the source of rouge email accounts in your enterprise.

**NICE Work Role:**

  - [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

  - [T0041](https://niccs.cisa.gov/workforce-development/nice-framework) - Coordinate and provide expert technical support to enterprise-wide cyber defense technicians to resolve cyber defense incidents.

  - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).

  - [T0233](https://niccs.cisa.gov/workforce-development/nice-framework) - Track and document cyber defense incidents from initial detection through final resolution.

  - [T0278](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

  - [T0510](https://niccs.cisa.gov/workforce-development/nice-framework) - Coordinate incident response functions.

## IMPORTANT

There are no downloadable artifacts for this challenge. The full challenge can be completed on the hosted site.

## Background

  You are a cyber incident responder working for the ACK-ME Corporation. During a routine audit, it was noticed that there were a number of email accounts on ACK-ME's Exchange server which do not match the names of any ACK-ME employees.
  It is suspected that email accounts in the ack-me.com domain are being sold on the dark web, so that people can sign up for online retail and streaming services at a discounted price using ACK-ME's employee discount. The Exchange Administrator has tried to delete these accounts, but they soon re-appear. ACK-ME needs your help in tracking down the source of the accounts and the person responsible for creating them!

## Getting Started

  You can view the [challenge guide](challenge-guide.pdf) here.

  Your task is to identify the rogue email accounts in the ack-me.com domain, the source of the account creation, and the user responsible for creating the accounts.

  Use any tools installed on the management workstation, the domain controller, and the exchange server that you'd like to solve the challenge. ACK-ME first noticed the rogue accounts appearing on 14 OCT, 2020.

  You may write scripts and adjust audit logging, policies, etc. as you see fit. However you may not interrupt the operations of any ACK-ME servers.

## Example submission

  Note: all submissions should be in lowercase.

  | Question      | Flag         |
  |:-------|:-------------|
  | Username that created the rogue email accounts | `jane_smith` |
  | Short hostname of the workstation used to create the accounts | `user8` |
  | Filename of the script used to create the accounts | `hacker.bat` |
  | Number of rogue email accounts created | `432` |
