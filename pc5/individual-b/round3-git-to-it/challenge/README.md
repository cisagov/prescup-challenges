# Git to It

_Challenge Artifacts_

- These startup scripts run to configure the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
  - [internalGitChange.sh](./internalGitChange.sh) - Script to update the internalproject repository.
  - [triggerGitChange.sh](./triggerGitChange.sh) - Script to update the private-project repository.
  - [triggerJobs.sh](./triggerJobs.sh) - Repeatedly polls and triggers a git respoitory pipeline.
  - [runJobs.sh](./triggerJobs.sh) - Used to support the hijacking the CI/CD pipeline. 

- [internalproject.zip](./internalproject.zip) - Local copy of internalproject repository.

- [private-project.zip](./private-project.zip) - Local copy of private-project repository.

- [db.sql](./db.sql) - Gitlab database script.

