<img src="../../../pc1-logo.png" height="250px">

# Follow the map

## Solution

### Finding the counts of each OS

Search for the terms `Linux` and `Windows` for each subnet and determine how many there are of each, and the one with
the higher number will be the flag piece.

Be careful not to double-count hosts. Using `grep` blindly will give you incorrect results. You should end up with
**15** total Linux systems in the scans for this variant.

### Finding the most vulnerable system

Search for the phrase `Not shown` for each subnet scan. This will immediately precede the list of open ports. Be careful
**NOT** to count ports listed as `open|filtered`. This means that nmap was not able to determine whether a port is open
or filtered.

In this variant, the host **`172.168.13.104`** (in `subnet_13.nmap`) has the most open ports.

### Finding the number of machines that do not allow port 443 traffic

Search for the phrase `closed https` for each subnet. Again, make sure to beware of duplicates when counting hosts.

You should find **3** machines with this port closed in this variant.

### Finding the number of machines that allow MSRPC

Search for the phrase `msrpc` in each subnet. Just like the previous questions, beware of duplicates.

You should count **8** such systems:
1. 10.104
2. 10.105
3. 11.105
4. 11.106
5. 12.110
6. 12.111
7. 13.104
8. 14.103

### Flag

The correct flag in this variant would have been:

`15,172.168.13.104,3,8`

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
