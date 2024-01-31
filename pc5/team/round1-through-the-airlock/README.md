# Through the Airlock

Cut off a rogue user machine from accessing an API and then repair the damage caused.

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0296](https://niccs.cisa.gov/workforce-development/nice-framework/): Isolate and remove malware.
- [T0500](https://niccs.cisa.gov/workforce-development/nice-framework/): Modify and maintain existing software to correct errors, to adapt it to new hardware, or to upgrade interfaces and improve performance.

## Background

There is a problem machine within our ship's user network attacking our central controller system on the `app-server` machine. No machine in the user network should access the controller API. Unfortunately, the machine belonged to the controller system's developer, who was last seen screaming: "*Nooo! My perfect state machine!*" just before jumping into the cargo bay through its airlock.

Also unfortunately, the cargo bay is not pressurized and they were not wearing a suit. Now, the controller system is reporting that the cargo airlock has both doors open while being pressurized--which is a physical impossibility.

## Getting Started

There are two parts to this challenge.

**Part 1:** First, find the problem machine and stop it from attacking its target. While cutting off its access, do not cut off access to the API from other machines on the network.

**Part 2:** Second, inspect the controller system on the `app-server` machine (accessible through SSH or direct console access). Learn how it controls the various devices on the ship and reset the cargo airlock to its default state: pressurized with both doors closed.

Both parts are graded at `challenge.us`, which returns a token for each completed part.

## Challenge Tasks

1. Isolate the rogue system.
2. Fix the cargo airlock sensor.
