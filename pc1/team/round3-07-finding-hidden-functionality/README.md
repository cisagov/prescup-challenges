<img src="../../pc1-logo.png" height="250px"/>

# Finding Hidden Functionality

## Background

The network administrator, annoyed with dirty cheaters finding a way to exploit his game, has fixed the bug that was
used. He also overhauled the networking and rewrote the client in order to better obfuscate communication between the
client and server. Unfortunately, he forgot to remove some test functionality from the server program...

## Getting Started

`required/block7-t3-server.exe` must be running on the same system you intend to work on. For this challenge, you will
reverse engineer `challenge/block7-t3-client.exe`. You will need to determine what opcodes it sends to the server for
each command the user can run.

The opcodes are in a simple pattern that will emerge once you've mapped out a few of them. The server recognizes
**eight** opcodes, while the client is only programmed to use **seven**. There is no zero-valued opcode. While you
probably will not need to, if you map out all seven of the opcodes, the eighth will be immediately apparent. 

Sending the hidden opcode to the server gets the server to return the encrypted flag. The decrypted flag will be
geographic coordinates of the format `01°02'03"N 04°05'06"W`.

Sending malformed data or an invalid opcode to the server causes the server to sleep for 60 seconds. During this time,
the client is unable to make a connection to the server and tells you to report an error. There is no need to report
this error if you may have sent bad data to the server during this period. If the server doesn't wake up after 60
seconds, or you encounter this error without sending any modified data to the server, then please do report this error.

## Hint

There are several functions that look very similar to each other in assembly.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
