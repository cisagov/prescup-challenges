#! /usr/bin/python3

"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

import binascii
file_object = open('mft.dd', 'rb')
i = 0
flag = "the flag is: "
while 1:
    chunk = file_object.read(1024) # read 1024 bytes: mft record size
    if not chunk: break
    timestamp = bytes(chunk[88:92]) # return the 4 least significant bytes of modified timestamp
    # The flag lies in MFT entries 862 thru 872 ( 10 files after the 1st in directory. 1st file is length)
    if i in range (862,872):
        #Do some reversing for LittleEndian, and convert to INT
        timestampDword = int(binascii.hexlify(timestamp[::-1]),16)
        flagParts = timestampDword & 0xFFFF
        flagChar1 = chr((flagParts>>8) & 0xFF)
        flagChar2 = chr(flagParts & 0xFF)
        #print(flagChar1, flagChar2)
        flag += flagChar1 + flagChar2
    i = i + 1
print(flag)
file_object.close(  )
