# The Train Job

Exploit a train scheduling server to gain access.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.

## Background

The Arellians want us to move a train to a remote unoccupied station; there is something they want to grab from the cargo. We don't have a way to gain authorized access -- so we are resorting to other means. In the interest of safety for the colonists and the ship's crew, we need to access the system remotely.

Fortunately, a small part of the scheduling server code is available for you if you undertake this task.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the required files from [here](https://presidentscup.cisa.gov/files/pc4/individualb-round2-the-train-job-largefiles.zip) and follow the instructions in the [challenge/server](./challenge/server) directory to configure the server needed for this challenge. The zipped file is ~115MBs and will be imported into `Docker`.

## Getting Started

Examine the (client.py)[./challenge/server/client.py] and (runner.py)[./challenge/server/runner.py] files in the [challenge directory](./challenge/server) to gain an understanding of how the train scheduling system works. Use what you find to upload a new schedule which moves the train to the desired location.

## Submission Format

There are two submissions for this challenge. 

1. The signing key the scheduling server uses to authenticate with the train operation server.
2. The token returned by the train operation server upon moving the train to the destination **Miracle Colony**.

The offline version of this challenge uses the string `Success!` in place of flags.

## Challenge Questions

1. What is the signing key the scheduling server uses to authenticate with the train operation server?
2. What is the token returned by the train operation server upon moving the train to the destination Miracle Colony?
