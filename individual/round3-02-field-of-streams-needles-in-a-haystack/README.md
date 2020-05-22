<img src="../../logo.png" height="250px">

# Field of Streams: Needles in a Haystack

## Background
Two machines on the network have been sending data back and forth. Within this traffic are multiple files sent via FTP, as well as other types of traffic that should seem abnormal, atypical, or unusual based on the largest types of traffic in use. Note that none of the traffic you need to find is encrypted, and thus, all data can be found in clear text.

You have been provided with one large 15-minute packet capture and the following hash value:
`b2fff077e5e43839d433328c0e7144fa`

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://cisaprescup.blob.core.usgovcloudapi.net/prescup19/individual-round3-02-largefiles.zip)
and extract in _this directory_ to get started.

## Getting Started

1. Search the capture for the various zip files sent via FTP and determine which zip file matches the hash value provided. This file contains your flag but is password protected. Once you find a match, you can safely assume the other zip files are useless. There is one more critical file found in the FTP data that you need in order to determine the password.
2. Next, look for three unique types of traffic, all sent in clear text (i.e., not encrypted). Be on the lookout for traffic that might be of a typical protocol but doesn't look like it should, or maybe it uses an odd port. It may be traffic that stands out from the rest or is one of a kind. Each protocol can only be used once to send data. The Statistics menu in Wireshark is your friend.
3. Once you find the hidden data in the three streams or conversations above, place the protocols in alphabetical order to discover the order in which the hidden data should be used or applied. For example: if you discover three suspicious streams containing relevant data via SSH, FTP, and HTTP, the data would be applied in the order of 1: FTP, 2: HTTP, 3: SSH. This information in the correct order will allow you to assemble the password and open the zip file.
There are no false flags or red herrings in this challenge. If it looks useful, it probably is.

### Network Information

The local network is considered to be the 10.9.8.0/24 network.

Clients are allowed to access the web.

The network uses only public DNS servers at 8.8.8. and 8.8.4.4.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.