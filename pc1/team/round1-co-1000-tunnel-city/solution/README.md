<img src="../../../pc1-logo.png" height="250px">

# Tunnel City

The given version of this challenge is one of four variants. The tunnel is the same in each variant, but the flag is
different for each one.

## Solution

In order to retrieve the two scripts that can be used to solve this challenge, run 
`download-solver-scripts-mac-linux.sh` if you are on a Mac or Linux, or `download-solver-scripts-windows.ps1` on
Windows. These scripts will download and patch the solver script mentioned below.

The tunnel is an iodine DNS tunnel, which uses various types of DNS queries to tunnel TCP/IP over DNS. In this case,
iodine is set to use null queries to the DNS domain of a1a.net to establish the tunnel. The tunnel originates from a
client IP address of 10.0.20.2.

After opening the packet capture in Wireshark, apply the display filter `dns.qry.name contains "a1a.net"`. This filter
reveals the tunneled traffic. Save the displayed packets `File -> Export Specified Packets`, and choose to save only
the displayed packets as a `pcap`, not `pcapng`.

Run the `extract_dns.py` script in this directory on the saved PCAP to generate a new PCAP file, which contains a small
number of ICMP packets. The flag is contained in the payload of one of these packets.

## Flag

a3d584c69039ff0971337862ece3f2e5

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
