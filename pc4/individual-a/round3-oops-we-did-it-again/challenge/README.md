# Oops! ...we did it again

_Challenge Artifacts_

The Compromised virtual machine and the web server are not available offline. All relevant files and necessary outputs that can be provided are included, as is a copy of the ransomware payment website's html directory contents.

Begin by downloading the following files from the [challenge directory](./challenge)

 * [malware watchlist](./challenge/malware-watchlist.md) - a malware watchlist

## Compromised System Files

 * [Ransom Files](./challenge/compromised/ransom-files/) - the ransomware notice found on the Desktop and a set of encrypted files, including the encrypted flag
 * [bashrc.txt](./challenge/compromised/bashrc.txt) - a bashrc file
 * [sslkeys.2022.09.09](./challenge/compromised/sslkeys.2022.09.09) - an sslkey file
 * [filesystem.zip](./challenge/compromised/filesystem.zip) - the compromised system's /etc/ directory (the malware folder has been heavily redacted for safe offline viewing)
 * [aptlist-installed.txt](./challenge/compromised/aptlist-installed.txt) - "apt list -installed" output
 * [service-list.txt](./challenge/compromised/service-list.txt) - "systemctl list-units" output
 * [p3rs1st.service](.challenge/compromised/p3rs1st.service) - the persistence service file
 * [p3rs1st.timer](.challenge/compromised/p3rs1st.timer) - the persistence service timer file

## Web Server Files

 * [website](./challenge/website/) - the contents of the ransomware payment website's html directory

During offline play of the challenge, the script used to grade question 3 during a hosted version of the challenge cannot be executed. Please refer to the files provided above and reference the [solution guide](./solution/README.md) to review the intended processes.
