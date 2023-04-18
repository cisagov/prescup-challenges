# Xeno Cult

## Background
A group of cultists revere the ancient Seelax, collecting numerous records and artifacts. The Aurelian's have hunted them for years, narrowing down their home base to somewhere in this asteroid system, but never finding it...  

## IMPORTANT
This challenge is only partially open sourced. The files are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download [here](https://presidentscup.cisa.gov/files/pc4/team-round3b-xeno-cult-largefiles.zip) to get started. The zip file contains a collection of `.pcap` files that the user must analyze to complete the challenge and a text file with a list of probe locations. The zipped file is ~578MBs and the extracted artifact is ~2.1GBs.

## Getting Started
The Aurellian security forces have been sending out probes to search for the hidden base of a cult of ancient alien worshippers; however, the cultists jam their probes as they travel, preventing them from reporting their location. The Aurellian security provides your team access to some files so that your team can attempt to find the hidden base. Your team must discover coordinates to their location.

Coordinates consist of 2 sets of 3 case insensitive alphanumeric characters. (i.e 123/abc, a2n/3ib)

## Part 1 Tasks
- The packet captures are hosted on an SMB share located at `10.10.10.140`.
- Analyze the packet captures and discover where the home base is located at by discovering when/where the probe communications were being jammed as they came in contact with ships coming/going to/from their home base.

## Video
[Contact](https://presidentscup.cisa.gov/files/719c9a3bc831a6ffeaa71928e1ad9abc-VIDEO-07-P01.mp4) the Aurellian security.

After some analysis, your team manages to find the hidden base and proceeds with establishing communication with “The Followers”.  You ask them for the location of the Shrine.

## Video
- [Watch](https://presidentscup.cisa.gov/files/673bf7fdc090770b6060ff7715ecc254-VIDEO-07-P02.mp4) initial communication with The Followers.
- [Watch](https://presidentscup.cisa.gov/files/36325b8c29c9c612b7df44af323b4f7b-VIDEO-07-P03.mp4) access to the Shrine.

### Part 2 Tasks
- Access the Shrine's computer system and transfer the file `codex_d.zip`.
- The file can be found on an SMB share located at `10.10.10.143`.
