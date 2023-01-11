## For Pieces of Eight, They'll Steal Your Freight

_Challenge Artifacts_

Question 1 can be solved offline using the following files:
 - [password-hash](./challenge/password-hash) - Ridley's password hash value
 - [wordlist.txt](./challenge/wordlist.txt) - the list of possible passwords in use

Question 2 can be solved offline but will require that you build the Wordpress server and site following the [build guide](./challenge/wp/README.md). You will need to use a second Kali virtual machine that can access the Wordpress site in order to test/execute the exploit. You will also need information about [CVE-2022-1329](https://nvd.nist.gov/vuln/detail/CVE-2022-1329) and the [exploit for that vulnerability](https://github.com/Grazee/CVE-2022-1329-WordPress-Elementor-RCE/blob/dab76877bf97b4a83f809ea52e4eb921f4346c72/README.md).

Question 3 cannot be solved in the offline version of the challenge, as no grading server will exist. This check only serves to initiate the remote client connection. However, you can test the same process on your Kali system in order to validate your solution works.

Question 4 can be solved even though the remote client virtual machine is not available offline. The Cypher user's files are included in the [fn-2187 directory](./challenge/fn-2187).
