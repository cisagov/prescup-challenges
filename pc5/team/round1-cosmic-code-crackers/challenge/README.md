# Cosmic Code Crackers


_Challenge Artifacts_

- [clienta.sh](./challengeserver/clienta.sh) -- This is the script that controls generating the artifacts for questions 1-3 on the network A (10.1.1.0/24) client system. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [secret.o](./challengeserver/secret.o) -- This is the malware analyzed during questions 1-3. The clienta.sh script will modify the name for each deployment.
- [clientb.sh](./challengeserver/clientb.sh) -- This is the script that controls generating the artifacts for question 4 on the network B (10.2.2.0/24) client system. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [sub.sh](./challengeserver/sub.sh) -- This scripts supports clientb.sh for question 4 by replacing the dynamic values into the uncompiled code files. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [crypto.c](./challengeserver/crypto.c) -- This is the precompiled code used by clientb.sh and sub.sh. This code is duplicated as user.c, pwd-p1.c and pwd-p2.c and then compiled during the clientb.sh setup script after random values are inserted by the sub.sh script.
- [stealer.sh](./challengeserver/stealer.sh) -- This is the script that controls generating the artifacts for question 5. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [traffic.pcapng](./challengeserver/traffic.pcapng) -- This is the pcap file that is modified with stealer.sh and imported into SecurityOnion.

_Competitor Artifacts_

In lieu of accessing the challenge's virtual environment, you may use the artifacts listed below to conduct the major tasks of the challenge. The filesystem artifacts have been condensed to only what is needed. The alerts and packet capture files can be analyzed directly without the need for SecutiyOnion. An answer key can be found [here](./competitor/answers.md).

- [alerts.log](./competitor/alerts.log) -- contains the logs needed to identify the suspicious files on the client systems.
- [part1.zip](./competitor/part1.zip) -- contains the artifacts necessary to solve questions 1-3. The zip contains the suspicious code file and the possible token files in the original client filesystem structure.
- [part2.zip](./competitor/part2.zip) -- contains the artifacts necessary to solve questions 4. The zip contains the suspicious code files and the possible user directories in the original client filesystem structure.
- [part3.zip](./competitor/part3.zip) -- contains the artifacts necessary to solve questions 5. The zip contains the packet capture (traffic.pcapng) and a malware list in .csv format. You will need to cross reference data from the packet capture with open source information from VirusTotal (https://www.virustotal.com).
- While not absolutely required, the latest version of Cutter (at the time of publishing) can be retrieved at (https://cutter.re/).
