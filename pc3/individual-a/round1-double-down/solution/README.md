# Double Down Solution

## Analyze PCAP file
1. Inside the traffic there is a conversation occurring between two hosts via ICMP. You can filter the traffic by ICMP, and then start sifting through it until you find a conversation that discusses 
the transfer of SSH keys and a file from one host to another.  You will see that the receiving host seems to have ran into a issue with his computer where he will need to update & reboot. This is where you come in
2. Since this is a DHCP network, you should try to map the IPs to hostnames. This can be done by analyzing the IPs in the ICMP conversation and then cross-comparing them to the DNS traffic in the packet. The hosts mapping should look like:
    - 10.5.5.91 hostname is `hearts`. They are sending the SSH key
    - 10.5.5.118 hostname is `spades`. THey are receiving the SSH key
3. NOTE: Since the network uses DHCP, IPs in the packet capture may NOT match what is currently assigned.

## Determining who to spoof
You will need to run a DNS Spoofing attack that will allow you to capture all traffic on the network and imitate that machine that went down. You can us the information obtained in the preceding section, or alternatively scan the network to determine the hostname of each machine.  You may note that the machines `hearts`, `clubs`, and `diamonds` are all up which implies that `spades` is the one that was having to be rebooted. 

## Run DNS Spoofing
To do the DNS spoofing I used `ettercap`, although you may use any tool you feel comfortable with. In order to do it with Ettercap, follow these steps:
1. Edit /etc/ettercap/etter.conf and set these:
    - Ec_uid = 0
    - Ec_gid = 0
    - Uncomment IPv4 and IPv6 iptables rules under “Linux” section at bottom
2. run command `sudo echo “1” > /proc/sys/net/ipv4/ip_forward`
    - If you find that the user permissions do not allow for redirection, log into the root shell and run this command
3. Edit /etc/ettercap/etter.dns
    - Insert these lines so that traffic intended for spades is sent to your machine  
        - spades.us	PTR	<your IP address>
        - *spades.us	A	<your IP address>
        - *spades		A	<your IP address>
4. Run ettercap with command
    - `Sudo ettercap -T -Q -i eth0 -P dns_spoof -M arp /// ///`
5. Let it run for a bit and then it should start showing messages that the spoofing is running and working.
6. Open wireshark and start capturing traffic
    - Eventually you will capture traffic that will contain the SSH key 
    - Copy SSH key and append it to your `.ssh/authorized_keys` file
7. Let this sit for a while and eventually a file will be SCP'd to your desktop
    - This file name will be the `first submission` 
8. It will be a file encrypted via AES with GPG
9. Open up your ongoing wireshark capture
10. There will be a message regarding the AES key and that you need to remember how to assemble it.
    - the AES key is 16 characters long, and is sent in 4 packets consisting of 4 characters each.
    - They will all come from the same host so it is just a matter of finding the ICMP packets 
11. reassemble the AES key by concatenating the 16 characters together in the order that they were sent
12. Use the key to unlock the encrypted file you receive.
13. Get secret passphrase
    - This will be the `second submission`
