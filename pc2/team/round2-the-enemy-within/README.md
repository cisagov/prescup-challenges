# The Enemy Within

Use tools to analyze a malware sample.

**NICE Work Role:**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0296](https://niccs.cisa.gov/workforce-development/nice-framework) - Isolate and remove malware.
- [T0260](https://niccs.cisa.gov/workforce-development/nice-framework) - Analyze identified malicious activity to determine weaknesses exploited, exploitation methods, effects on system and information."


## IMPORTANT

This challenge has no downloadable artifacts. You may complete this challenge in the hosted environment.

## Background


  You've intercepted a piece of probable malware from within a spam email. It does not match known signatures, but judging by the attack method, we don't believe it is sophisticated. Please examine it, and determine if it was trying to steal information, and if so, what information.


## Getting Started


  In this challenge, you will use tools to analyze a piece of malware. The malware is contained on a mounted ISO, and you are given a virtual machine to conduct your analysis.


  You should focus on dynamic analysis of the running malware instead of static analysis of its machine code.


## Submission Format


  The flags for this challenge are wrapped 16-character hex strings.


  Example submission:


  **(Part 1 of 2)** Local flag

  ```

  prescup{0123456789abcdef}

  ```

  **(Part 2 of 2)** Remote flag

  ```

  prescup{fedcba9876543210}

  ```
