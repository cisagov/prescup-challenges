 # Git Outta Here
 
 Delve into a version control repository to unearth insecure development practices. Familiarity with git, GitLab, Java, and mySQL expected.

**NICE Work Role:** 

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0014](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply secure code documentation.

## IMPORTANT

During the competition competitors interacted with a GitLab Server that hosted the relevant git repository. In the open source version of this challenge, you are simply provided with the git repository.

## Background

Software developers often place sensitive information into source code and configuration files. This can lead to

the compromise of the application under development as well as other critical assets. As part of an incident response,

your team has discovered a git repository available to anyone on the network. Your task is to assess the repository

to determine if the programmer potentially leaked any sensitive data.


## Getting Started

  
1. Unzip [clientservices.wiki.git.zip](.\challenge\client-service.wiki.git.zip) to a folder on your machine.
2. Navigate in a command prompt to the folder containing the .git file
3. checkout the git repo

```
git checkout main
```



Using the tools at your disposal, gather evidence that the developer negligently included privileged information in his project repository that would allow an insider threat to access sensitive customer records. You are specifically looking for a password associated with the host `indb1.lcl`.


## Submission Format

The submission for this challenge is an 8-digit hexadecimal string.

