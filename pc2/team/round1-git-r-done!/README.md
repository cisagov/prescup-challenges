# Git 'R Done!

Delve into a version control repository to unearth insecure development practices. Familiarity with git, GitLab, Java, and mySQL is helpful.

**NICE Work Role:**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0014](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply secure code documentation.

## IMPORTANT

During the competition competitors interacted with a GitLab Server that hosted the relevant git repository. In the open source version of this challenge, you are simply provided with the git repository.


## Background
Software developers often place sensitive information into source code and configuration files. This can lead to the compromise of the application under development as well as other critical assets. As part of an incident response, your team has discovered a git repository available to anyone on the network. Your task is to assess the repository to determine if the programmer potentially leaked any sensitive data.


## Getting Started

**NOTE** You must have MySQL and Git installed.

[Installing Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

[Installing MySQL](https://dev.mysql.com/doc/mysql-installation-excerpt/5.7/en/)



1. Unzip [clientservices.git.zip](.\challenge\client-service.git.zip) to a folder on your machine.
2. Navigate in a command prompt to the folder containing the .git file
3. checkout the git repo

```

git checkout main

```

4. Copy the clientdev.sql file to your computer
5. run the dbimport.sh script 

```

./sh dbimport.sh

```


 Using the tools at your disposal, gather evidence that proves the developer negligently included privileged information in his project repository. This may allow a malicious insider to access sensitive customer records.

While browsing the repository, identify a software error that affects how data is stored in the database. Your success depends on finding the bug and accessing the database. There is a single row in the database that has been affected by the bug in the code. The token for this challenge will be derived from the last name saved in the affected row. You will be able to identify it because it will be encoded with ROT13. For example, the element Arsenic would appear in the database as Nefravp. 
