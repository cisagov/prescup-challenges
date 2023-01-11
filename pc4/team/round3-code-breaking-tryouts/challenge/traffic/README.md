Potential trainee:

To get the password to the encrypted zip within secret.txt, you'll need key.pcapng file. Extract the message contents out of the password.pcapng file in the right order based on the sequence of key.pcapng. Only look for packets sent by me from 10.10.10.100. Convert the resulting HEX to ASCII afterwards to recover a password string. Pay attention to the types, order, and contents of the packets in the key file to get the right sequence and repeat as necessary. When you recover the password it will be something recognizable. If you end up with illegible junk, try again.

I've corrupted the secret.txt pcap file as well so you will need to reassemble it properly to get the secret.zip file out and use the password found above to retrieve the third passcode from the zip file contained within. Hint: this passcode will be a 12-character hexadecimal string in the end.

Mercury
