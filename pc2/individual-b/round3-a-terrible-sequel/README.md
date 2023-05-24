# A Terrible Sequel

  Assess and exploit vulnerabilities in software written in Python 3.6.


  **NICE Work Role:**


  - [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)


  **NICE Tasks:**


  - [T0111](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify basic common coding flaws at a high level.

  - [T0176](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.

## IMPORTANT

This challenge has no downloadable artifacts. You may complete this challenge in the hosted environment.

## Background


  There's a Gitea server running in the internal network. The client has asked you to evaluate the software being hosted in this repository and find any vulnerabilities. There is currently only one Python 3 project being tracked by this git server.


## Getting Started

  You can view the [challenge guide](challenge-guide.pdf) here.

  From `KaliLan`, you have access to a wide range of systems in this round. For this particular challenge, the only system of relevance is `git.makestuff.company`. This system is hosting Gitea—a git server—to make source code available to you.


  This same system is also serving the Python 3 application that is being tracked by the git server on a different port. This Python application is the main focus of this challenge. If you cause it to crash, it will automatically restart.


  There are two flags in this challenge.

  - One flag is in the database the Python server is communicating with, as the only row in the `prescup` table.

  - One flag is in the home directory of the user account running the Python server, in a file named `flag.txt`.


## Submission Format


**Part 1/2** - Database

```

0123456789abcdef

```

**Part 2/2** - Home Directory

```

fedcba9876543210

```


Make sure you supply the flags in the correct submission fields.
