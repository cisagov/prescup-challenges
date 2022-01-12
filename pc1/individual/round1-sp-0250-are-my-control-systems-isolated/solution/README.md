<img src="../../../pc1-logo.png" height="250px">

# Are My Control Systems Isolated?

## Solution

1. Open the given pcap file in Wireshark.
2. Apply the display filter `ip.addr != 10.0.0.0/24 && modbus`.
3. This should cut the number of packets down to 2: the attacker's Query, and the PLC Response.
4. Examine the Response packet, expand the `Modbus` section of the packet payload, and then expand `Register 3 (UINT16)`
5. The flag is the four-digit code in the `Register Value`.

## Flag

For the variant given in this repository, the flag would be `1157`.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
