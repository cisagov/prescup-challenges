# Interplanetary Internet Interception

_Setup_

### Router

1. On an Ubuntu Server, enable IPv4 forwarding.
2. This router must have three interfaces attached to three different networks. Assign the appropriate IPv4 address to each interface according to the topology. 
3. Set the one IP address (in the Kali subnet) that will allow SSH connections to the router in the `/etc/hosts.allow` (e.g., sshd: 172.17.6.87)
4. Block all other IP addresses from connecting via SSH in the `/etc/hosts.deny` (e.g., sshd: ALL)

### Ground Station Mission Web server - [Spaceship](./spaceship)

1. On an Ubuntu system, ensure the IPv4 address is set correctly and the default gateway is set to the router's eth2.
2. Ensure the [https_server.py](./spaceship/https_server.py), [server.cert](./spaceship/server.cert), and [server.key](./spaceship/server.key) are in the same directory. Set the number value to the correct MissionID for the lab. Run the `https_server.py` script. Ensure the web server remains running. 

### Mission Workstation - [ship-ws](./ship-ws)

1. On an Ubuntu system, ensure the IPv4 address is set correctly and the default gateway is set to the router's eth0.
2. Ensure the [requester.sh](./ship-ws/requester.sh) and [mission-details.txt](./ship-ws/mission-details.txt) are in the same directory. Ensure the [requester.sh](./ship-ws/requester.sh) script remains running.

### Kali

1. On a Kali system, ensure the IPv4 address is set correctly and the default gateway is set to the router's eth1.
2. This is the only system the competitors had GUI/console access to.
