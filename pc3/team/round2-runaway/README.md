# Runaway
 
  Provide a security assessment of a newly discovered GitLab CI/CD server.
  
  **NICE Work Role:**

  [Cyber Defense Analyst](https://niccs.us-cert.gov/workforce-development/nice-framework/workroles?name_selective=Cyber+Defense+Analyst&fwid=All)


  **NICE Tasks:**

  - [T0187](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=All&description=T00187): Plan and recommend modifications or adjustments based on exercise results or system environment

  - [T0292](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=All&description=T0292): - Recommend computing environment vulnerability corrections.


## Background

  Recent scans of your network have turned up an undocumented GitLab server instance. No documentation on the system exists and the DevOps team hasn't responded to any of your requests on the current configuration. Due to recent vulnerability disclosures, IT would like to determine if this instance is fully up to date and patched against remote code execution vulnerabilities. The IT Director is also concerned that a Solarwinds style attack would be possible at your company and would like to know the security posture of this GitLab instance.

## Getting Started

  Your team's job is to gain administrative access to the GitLab server, setup CI/CD pipelines to each of the GitLab runners, and canvas the build systems for any artifacts (aka "tokens") left over from prior builds to provide proof of access.

  You can access the GitLab server from inside the challenge environment at the following address:

  http://gitlab.challenge.us

## Submission Format

  Scoring for this challenge will consist of five tokens, one from each of the GitLab runners.
