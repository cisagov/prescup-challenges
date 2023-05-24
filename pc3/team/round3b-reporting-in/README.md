# Reporting In

Operative, we've recovered an executable file that we believe is being used by alien agents to send reports to handlers. We need you to reverse engineer it so that we can locate all of the remote targets.

**NICE Work Role:**

  - [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)
  - [Cyber Defense Forensic Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


**NICE Tasks:**

  - [T0641](https://niccs.cisa.gov/workforce-development/nice-framework) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
  - [T0432](https://niccs.cisa.gov/workforce-development/nice-framework) and use discovered data to enable mitigation of potential cyber defense incidents within the enterprise.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

Source code for the [prescup3-reportingin.exe](./challenge/reporting-in/prescup3-reportingin.exe) is provided [here](./challenge/reporting-in/source/) as part of open sourcing, but was not provided to competitors during the competition. 

Source code and build files for the [reporting-in-server](./challenge/server/) is provided as part of open sourcing, but was not provided to competitors during the competition. This server is what the provided exe communicates with as part of the challenge. 


## Mission III Briefing

<div class="embed-responsive embed-responsive-16by9">
    <video controls controlslist="nodownload" >
        <source src="https://files-presidentscup.cisa.gov/04_MISSION_III-35292823.mp4" type="video/mp4">
    </video>
</div>

<br>
<br>

## Background

  We were able to recover an executable file from an alien agent. We suspect that it enables their agents to report to their handlers. We would like you to analyze this file and see if it contains useful intelligence. We're hoping for at least an IP address to which it reports, but it's entirely possible that it could try to contact more than one.

## Getting Started

  Examine [the challenge file](./challenge/reporting-in/prescup3-reportingin.exe). Burp Suite Community has been installed in the environment for convenience, but it isn't necessary to solve the challenge.

## Submission

  Submission for this challenge is within the challenge environment. Navigate to `http://challenge.us` or `http://202.128.10.5` in a browser to begin submission.


## Note

  Attacking or unauthorized access to 202.128.10.1 or 202.128.10.5 is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
