# Under Siege

Teams must monitor for and respond to anomalous traffic destined for their protected web sites, given access only to their firewall web console tools. 

**Time is a factor in the scoring of this challenge. Team members must work together to be as quick and as accurate in their actions as possible to receive full credit for the challenge.** 

**NICE Work Roles**
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)
- [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Infrastructure+Support+Specialist&id=All)

**NICE Tasks**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0023&description=All#) - Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.
- [T0259](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0259&description=All#) - Use cyber defense tools for continual monitoring and analysis of system activity to identify malicious activity.
- [T0438](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0438&description=All#) - Create, edit, and manage network access control lists on specialized cyber defense systems (e.g., firewalls and intrusion prevention systems).

## IMPORTANT
This challenge does not have any downloadable artifacts. You may complete this challenge in the hosted environment.

## Background
Your websites are under attack!

![network_diagram](https://files-presidentscup.cisa.gov/69957b45-networkDiagram.png)

Each time you identify a malicious/anomalous traffic source, you should block (not reject) it by its source address immediately at the respective firewall as specifically as possible. Blocking entire networks will prevent legitimate traffic from accessing your sites and pause challenge progression.

**For the purpose of this challenge anything that does not look like the other "normal" web traffic should be considered anomalous.**

The challenge consists of five(5) levels. In each level, three(3) sources will send suspicious or anomalous traffic to your sites at random. As you block each source, the next will pop up, until you block all three(3) for a given level. The traffic can hit any firewall at any time, and is not simply confined to each firewall once per level. After you block the third source from each level the next level will begin. You MUST keep all previous blocks in place throughout the challenge to pass each new level. Track this information for later in case you accidentally remove something.

From your Windows 10 workstations (Seagal 1-3), you have access to each firewall's web GUI at the LAN side address (e.g. `10.0.11.1`). Each firewall is also running NTOP on the WAN interface. The NTOP web GUI is accessible at the LAN interface IP over port 3000 (e.g. `https://10.0.11.1:3000`). You may also access NTOP from the firewall web GUI by browsing to Diagnostics -> ntopng.

If any of the firewall tools or GUIs fail to load after a few minutes, consider redeploying the challenge or notify support.

## Grading
Each level is passed by blocking (do not reject) the traffic from the three(3) suspicious or anomalous sources per level. Upon successful completion of each level, a token will be provided via the grading site found at `http://challenge.us (http://10.5.5.5)` which is accessible from any in-game system. This grading table will be automatically updated as you proceed. You must submit these tokens in their respective submission field to receive points towards your overall score. There are five(5) levels and five(5) tokens maximum for accurate traffic blocks.

Note that the blocking of legitimate sources of traffic will cause all grading and traffic to halt until the source is no longer blocked. You will be warned on the grading site if this occurs. Speed and accuracy are key, but you can't simply block everything and expect to finish, or do so quickly.

Time is a factor in the scoring of this challenge. A scoring breakdown and the times to beat are listed below. The timer stops when the final level or stage of the challenge has been completed, which includes the time it takes the grading script to run its final checks. You are not required to submit previously awarded tokens to stop the timer. You may submit your tokens at any time after completing the challenge, as long as it is still actively deployed.

`There is a roughly 5 minute grace period between the booting of the virtual machines and the starting of the timer. Traffic will not start until the grace period ends, and this is when your timer begins. A notice on the grading site will tell you if you are still without the grade period window. You can still earn up to 60% of the total score for the challenge, regardless of how long it takes to finish.`

An example grading table is provided below:
- "Running" simply means that you are working in the associated level
- "Success" followed by a token means you have passed all traffic blocking checks for that level
- "Running/Passed Final Check" means that the grader is reverifying all of your prior rules before awarding time tokens. If one of these gets stuck, you might want to check that you did not accidentally alter/remove a previous rule.
- Note the elapsed time in the bottom left. This is the timer that is used for awarding further tokens.

![GradingTable](https://files-presidentscup.cisa.gov/3268863e-gradingTable.png)

Once all five levels have been passed a final check will reverify all of your changes. If you have accidentally removed or changed a previous rule, you will have to find this traffic in NTOP again to re-block it. You will know the type by the level next to the notice in the grading table. Once the final checks are complete, your overall challenge time will be used to add additional tokens towards as follows:

| Completion Time  | # of Tokens Earned  |  % of Overall Challenge Score Added   |
|-------------|-----------|-------------|
|  less than or equal to 60 minutes | 4 | 40% (10% each) |
|  more than 60 but less than or equal to 70 minutes | 3 | 30% (10% each) |
|  more than 70 but less than or equal to 80 minutes | 2 | 20% (10% each) |
|  more than 80 but less than or equal to 90 minutes | 1 | 10% (10% each) |
|  more than 90 minutes  | 0 | 0% |

## Note
Attacking or unauthorized access to challenge.us (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Hints
Remember to BLOCK, not REJECT (this could affect grading responses)

Each successful block will trigger a new source within the level, up to three. This is a clue that you blocked the correct thing. Level 5 may differ.

Level 4's traffic will take longer to fully stop than previous levels. This is normal. As long as you see throughput has eventually dropped to 0, your rule is working.
