# TODO: Better Code Auditing

Exploit a poor code auditing pipeline to gain indirect access to a web server.

**NICE Work Roles:**

[Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Software+Developer&id=All)

[Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)


**NICE Tasks:**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Conduct and/or support authorized penetration testing on enterprise network assets.

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0266&description=All) - Perform penetration testing as required for new or updated applications.

- [T0324](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0324&description=All) - Direct software programming and development of documentation.

## IMPORTANT

This challenge could only be partially open sourced, since it requires significant networking and host configuration. This challenge guide, and the solution guide, were written for the version of the challenge that was available during the competition. In the competition, two repositories were accessible through an internal GitLab server within the challenge. These repositories are made available below, but other important parts of the challenge could not be made available in this repository.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/pc3/team-round1-todo-better-code-auditing-largefiles.zip)
and extract in _this directory_ to get started.

## Background

You've gained access to a software developer's workstation within Big Software, Inc. You've been able to determine that you have access to the company's internal GitLab server and their web store from here. Maybe you can find some interesting things...

## Getting Started

You can reach `int-gitlab.bigsoftware.com` and `store.bigsoftware.com` from the system you're given. You should expect to use both during the challenge, but you will primarily focus on the GitLab instance. It's recommended to explore the publicly-accessible projects and their code auditing pipelines.

Note: The GitLab instance may take a few minutes to fully come online, so you may want to start with the store. There also can be up to a one minute delay before code changes fully propagate through the deployment process.

## Submission

There are two tokens in this challenge. One is contained in the "build-flag.txt" file in the "deployer" user's home directory on the system hosting GitLab, while the other is in the "deploy-flag.txt" file in the "webapp" user's home directory on the system hosting the store app. Both are 16-character hex strings.
