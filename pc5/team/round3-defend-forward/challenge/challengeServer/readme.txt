Please wait up to 5 minutes for the APT reports to appear (apts.tar.gz).

Once you submit the three IPs to challenge.us, you will receive the password in three parts to decrypt the encrypted file (apts-and-ips.tar.gz.ctr). This will give you the IP range of where you must gain access to the machine (Achilles Heel) of that country. There you will find tokens 1-3 on each of the three machines. Submit those for points.

The command to decrypt is "openssl enc -aes-256-ctr -d -salt -pbkdf2 -in apts-and-ips.tar.gz.ctr -out apts-and-ips.tar.gz" and you can enter the 30 character password to decrypt (given to you in three parts).
