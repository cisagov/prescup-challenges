# Relay in Decay (on Tape Delay?)

Analyze a communication relay's running code to determine how it works, how to access its files, and replace signal files with your own crafted packet captures to send the proper mission codes to the receiver. *Be warned!* The relay system is degrading fast, and you'll need to account for signal decay along the way.

**NICE Work Roles**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0046](https://niccs.cisa.gov/workforce-development/nice-framework): Correct errors by making appropriate changes and rechecking the program to ensure that desired results are produced.
- [T0298](https://niccs.cisa.gov/workforce-development/nice-framework): Reconstruct a malicious attack or activity based off network traffic.
- [T0436](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct trial runs of programs and software applications to ensure that the desired information is produced and instructions and security levels are correct.
- [T0616](https://niccs.cisa.gov/workforce-development/nice-framework): Conduct network scouting and vulnerability analyses of systems within a network.


## Background

A communications relay, accessible over the WAN network, is slowly decaying. Signal strengths are degrading and transmissions are no longer received correctly. However, we must ensure that the three 10-character code words are properly received by the communications receiver.

## Getting Started

***Warning!** Do not initiate the grading script until you are ready to advance with Phase 1 of the challenge.*

Copies of the relay program, an example of the receiver's parser, and a template for crafting your own captures are available at `https://challenge.us./files`.

Using this relay code, determine the following:

- How and where the relay stores its traffic captures
- How the relay captures then replays traffic to the receiver
- How you can insert your own capture file to "boost" the original signal
- How the receiver's parser interprets the data it receives as messages

After doing so, gain access to the relay's capture storage and review the test pattern currently replayed. The test pattern helps you determine the initial character mapping required within the packets. Future codes will also be stored here, which you must adjust as directed below.

The recently received values at the receiver can be found at `https://challenge.us/files` each time you run the grading check. Use this output to determine the pattern or function of each phase's respective decay. Then, craft your own packet generation script to account for the varying levels of decay.

To save your generated traffic, do the following:

- Use the destination IP of a second Kali system in your network
- On that second Kali, start a listener and capture traffic in Wireshark
- Send the traffic with your packet generation script to the second Kali system
- Export only the relevant relay traffic as a capture file

There are **three** phases to this challenge: each phase is progressive and iterates the previous one, meaning whatever updates you apply in one phase will carry over to some degree in the next phase. The relay is in a somewhat linear state of decay, but other failures might occur along the way.

## Grading

Grading checks are performed at `https://challenge.us`.

The communications relay remains in its test pattern of the alphabet until you initiate the grading check for the first time. If you initiate the grading check *by mistake* before determining the character mapping values, you will have to restart the challenge.

Once you initiate the grading check for the first time, the challenge will advance to Phase 1. You may initiate the check as many times as necessary, but it may take a moment to complete. Each successive solve will advance the challenge by one phase until all three phases are solved.

The previously received signal values for each phase will be copied to `https://challenge.us/files` when you run the grading script.

The grading script tracks which parts have been solved and what tokens have been earned. Transmitted/replayed codes or values from a solved phase are no longer needed.

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Kali | Kali | user | tartans|

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the token found within the relay's transmission storage directory? 
2. What is the token given for passing grading check 1 and successfully sending code 1 to the receiver?
3. What is the token given for passing grading check 2 and successfully sending code 2 to the receiver?
4. What is the token given for passing grading check 3 and successfully sending code 3 to the receiver?
