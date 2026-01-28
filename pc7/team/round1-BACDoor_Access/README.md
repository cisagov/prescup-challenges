# BACDoor Access

Hunched over your laptop in a cramped and dirty maintenance room, you've obtained access to a university's building automation system. Using BACnet, exploit this access to break into a secure research lab and steal sensitive research documents. 

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing.
- [T1635](https://niccs.cisa.gov/tools/nice-framework): Access targeted networks.
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities.

## Background

An engineering professor at Some State University (SSU) has decided to keep their vulnerability research private, and your spy organization could desperately use those new techniques. 
You've been tasked with breaking into the engineering lab at SSU and retrieving any and all documents related to the research. Traveling to SSU, you've located the lab and server 
on the third floor of the engineering building, but both doors are locked. Hearing someone about to leave the lab, you tuck yourself into a nearby maintenance closet. 

Peeking out the door, you see a student leaving the lab, with someone in the lab angrily yelling "The class is in the lecture hall. Give the intro lecture on BACnet, and we will continue 
discussing your poor password habits afterward."  Looking around, the closet contains an exposed Ethernet port; connecting, you realize this gives you access to the building automated 
control system! Use this to get the professor out of the lab, unlock both doors, and escape with the research.

## Getting Started

On the provided Kali machine, you have access to the network exposed in the engineering building maintenance room. You can also reach `http://ssu.edu`, the SSU homepage, on the campus-wide network.

Note that the SCADA dashboard can take 5+ minutes to launch, import, and ensure all BACnet devices have launched and been configured. 
If you reset your challenge after completing Token 2 and immediately log in, the dashboard may be blank; log out, wait a minute for the import, and then log back in.

## Tokens

The tokens are formatted as `PCCC{some_words_here}`.

Tokens 1-3 are sequential; the other tokens may be completed in any order, although completing tokens 1-3 first may make them easier.

Tokens 1, 3, 5, and 6 require a grading check. Visit `http://challenge.pccc` to perform the grading check. For Token 1, enter the username into the available text box before hitting Grade. For the other tokens, you may leave the text box empty.

- Token 1: Investigate `http://ssu.edu` and find the username of the graduate student who was just getting scolded. 
    - Submit the username to the grading server.
- Token 2: Find the SCADA control dashboard and log in as the graduate student. The token is displayed on the HMI in the maintenance room you are hiding in.
- Token 3: Get the professor to leave the lab by causing chaos; disable all the lights in the main lecture room. 
- Token 4: Find a token hidden in one of the BACnet devices in the engineering building.
- Token 5: You need to grab any physical documents from the lab. Use the BACnet access to unlock the lab door.
- Token 6: The server room is much more secure. Use BACnet to get into the server room by tampering with the fire and server room devices.
    - Be careful not to start a fire drill! You don't need that kind of *heat*.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|

## Note

Attacking or unauthorized access to `challenge.pccc` is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
