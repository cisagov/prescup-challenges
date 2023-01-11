# The Train Job

Exploit a train scheduling server to gain access.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0266) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0591) - Perform analysis for target infrastructure exploitation activities.

## Background

The Arellians want us to move a train to a remote unoccupied station; there is something they want to grab from the cargo. We don't have a way to gain authorized access -- so we are resorting to other means. In the interest of safety for the colonists and the ship's crew, we need to access the system remotely.

Fortunately, a small part of the scheduling server code is available for you if you undertake this task.

## Getting Started

In the gamespace, browse to `https://challenge.us`. Download the `client.py` and `runner.py` files. Examine the code provided to gain an understanding of how the train scheduling system works. Use what you find to upload a new schedule which moves the train to the desired location.

## Submission Format

There are two submissions for this challenge. 

1. The signing key the scheduling server uses to authenticate with the train operation server.
2. The token returned by the train operation server upon moving the train to the destination **Miracle Colony**.

Each submission is a 16-character lowercase hex string of the format `0123456789abcdef`.

## Challenge Questions

1. What is the signing key the scheduling server uses to authenticate with the train operation server?
2. What is the token returned by the train operation server upon moving the train to the destination Miracle Colony?