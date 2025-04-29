# Wake-A-Mole

⚔️ **Please wait five minutes before starting the challenge**

🕹️ Mid mission, one of our best red team operators has gone missing. In this offensive security campaign, challengers must use post-exploitation frameworks to manage his implants and expand access where possible to finish the job.

**NICE Work Roles**

* [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/exploitation-analysis)
* [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/cyberspace-operations)

**NICE Tasks**

* [T1760](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/cyberspace-operations): Maintain functionality of organic operational infrastructure
* [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/exploitation-analysis): Perform analysis for target infrastructure exploitation activities
* [T1262](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify programming code flaws.


## Background

Our red team operator has unexpectedly gone off the grid, leaving behind an active post-exploitation operation. While their official objectives were clear, recent findings suggest they were working on additional implants and initiatives beyond the scope of their assigned mission.

Your task is to pick up where they left off—manage their implants, investigate their activities, and determine the full extent of their operation. Some of what they left behind may be outside the bounds of our usual red team engagement. Proceed with caution.

## Getting Started

**Primary Objective**  
From your ``kali-workstation``, access and assess our running operation on the ``sliver-c2``. Use the provided credentials to ``ssh`` onto the ``sliver-c2`` server.

Read over the operation notes from the last engagement in the user's home directory: ``/home/user/logs/operations.log``.

When you're ready, start Sliver by running ``sudo sliver`` and start an mTLS listening job by running ``mtls`` to catch the call-back and answer the challenge questions! Note: Catching the beacon might take 1-2 minutes to connect.

## System and Tool Credentials

| system/tool            |    IP      | username | password |
| ---------------------- | --------   | -------- | -------- |
| kali-workstation       | dynamic    | user     | tartans  |
| sliver-c2              | 10.5.5.149 | user     | tartans  |
| arcade                 | ???        | ???      | N/A      |

**The Night Before - Arcade**  
Before this incident, the operator was sighted at an arcade. The game they were playing at the time appears to still be open to play and might harbor a secret linking to their disappearance.

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

Please note that in the `arcade`, `root` access is **not required** to beat the game.
