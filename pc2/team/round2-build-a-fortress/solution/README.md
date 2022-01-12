# Build a Fortress Solution

This challenge involves configuring and building the network based on the proposed topology map. To pass the three grading checks, you will need to configure networking on all systems, get the routing working, configure traffic rules and Network Address Translation (NAT) on the firewall, install and configure squid web proxy, configure snort on Security Onion and create a custom snort rule. This solution guide details configuration steps by different systems involved in the network topology. 

## Router

You’ll need to configure at least three interfaces on this device. The interface in the Services subnet is not really needed to pass the grading checks. Use the following commands to configure IP address for `eth0`
```
configure
set interfaces ethernet eth0 address 192.168.10.100/29
```
`configure` command is used to enter the configuration mode on VyOS router. Similarly configure the other interfaces on the router. 
The next step is to configure the default gateway.
```
set protocols static route 0.0.0.0/0 next-hop 192.168.10.101
```
Once configured, use the following commands to commit the changes. 
```
commit
save
```

## Firewall

The first step is to assign interfaces as WAN and LAN. 
- At the pfSense firewall console, `Enter an option:` as `1`
- When asked `Should VLANs be set up now [y|n]?`, type   `n` and press Enter
- `Enter the WAN interface name` as  `em0`
- `Enter the LAN interface name` as `em1`
- When asked `Do you want to proceed [y|n]?`, type `y` and press Enter

The next step is to configure IP address for both interfaces.
- At the pfSense firewall console, `Enter an option:` as `2`
- When asked `Enter the number of the interface you wish to configure:`, type `1` for WAN interface and press Enter
- When asked `Configure IPv4 address WAN interface via DHCP? (y/n)`, type `n`
- `Enter the new WAN IPv4 address` as `150.37.91.101`
- `Enter the new WAN IPv4 subnet bit count` as `29`
- `Enter the new WAN IPv4 upstream gateway address`, as `150.37.91.102` and press Enter
- `Configure IPv6 address WAN interface via DHCP6? (y/n)`, type `n` and press Enter
- `Enter the new WAN IPv6 address`, press Enter for none
- `Do you want to revert to HTTP as the webconfigurator protocol? (y/n)`, type `y` and press Enter
- Press Enter to continue
- `Enter an option:` as `2` again for configuring IP address for LAN interface
- When asked `Enter the number of the interface you wish to configure:`, type `2` for LAN interface and press Enter
- `Enter the new LAN IPv4 address` as `192.168.10.101`
- `Enter the new LAN IPv4 subnet bit count` as `29`
- `Enter the new LAN IPv4 upstream gateway address`, press Enter for none
- `Enter the new LAN IPv6 address`, press Enter for none
- `Do you want to enable the DHCP server on LAN? (y/n)`, type `n` and press Enter
- Note the URL for web interface to this firewall
- Press Enter to continue

At this time we can login to Firewall's web interface to perform the remainder of the configurations. Until routing is configured on the firewall, we will need a system in `subnet2` to connect to Firewall's web interface. To do so, we can use the Test system. 
Login to Test kali system and configure `eth3` as `192.168.10.99`
- Open a terminal window and type the following command
```
sudo ifconfig eth1 192.168.10.99 netmask 255.255.255.248
```
- Enter password as `tartans`
- Use Firefox to browse to Firewall's web interface (`http://192.168.10.101`). 
- Login with `user/tartans`

Next, we are going to configure static routing. 
- Select `System` -> `Routing` from the top menu
- Select `Gateways`
- Click `Add`
- Select `Interface` as LAN, type `Name` as `LAN_GW`, type `Gateway` address as `192.168.10.100`. 
- Click `Save`
- Click `Apply Changes`
- Click on `Static Routes`
- Click `Add`
- Type `Destination network` as `192.168.20.96`, select subnet bit count as `28` from the drop down, select `Gateway` as `LAN_GW` from the drop down.
- Type `Description` as `Static route to Management subnet`
- Click `Save`
- Similar add a static route to Users subnet and if you'd like for Service subnet as well.
- Click `Save` and `Apply changes`

Next, we are going to configure Network Address Translation for re-mapping internal private IP address as Firewall's public IP address for outbound traffic to be routable on the internet.
- Select `Firewall` -> `NAT`
- Select `Outbound`
- Select `Automatic outbound NAT rule generation`
- Click `Save`
- `Apply Changes`

The last thing to be configured on the firewall is the specific traffic rules to allow only HTTP traffic outbound, and no traffic inbound. 
- Select `Firewall` -> `Rules`
By default, the WAN interface has no rules defined. This means that any incoming traffic will be blocked. 
Next, lets create the HTTP only outbound rule on the LAN interface. Click `LAN`
By default, firewall allows any traffic (IPv4 and IPv6) from `LAN net` to the internet. `LAN net` is defined as the subnet for the LAN interface which is `subnet2` in our case. 
- Delete both IPv4 and IPv6 rules, by selecting the check boxes next to it, and selecting the trash symbol under `Actions` section
- Click `Add` to add a new rule
- Select `Destination Port Range` as `HTTP (80)` to `HTTP (80)`. Leave every other setting as default but make sure to verify that those are defined as below - 
```
    Action - Pass
    Interface - LAN
    Address Family - IPv4
    Protocol - TCP
    Source - any
```
- Click `Save`
- `Apply Changes`
    
## Snort on Security Onion

As mentioned in the challenge description, the first phase of setup is complete. The management interface is already configured, and remainder three interfaces have been marked for sniffing traffic. We can verify this by reviewing the contents of `/etc/network/interfaces` file. The next step is to go through the second phase of the setup. The same is mentioned on the Desktop of Security Onion system. This second phase setup will configure snort and other relevant services. 
- Double click on the `Setup` icon from Desktop to launch the setup process
- Enter password as `tartans`, click OK
- Click `Yes, Continue!`
- Click `Yes, skip network configuration!` to skip network configuration as it is already configured
- Select `Production Mode`, click `OK`
- Make sure that `New` is selected as this is a new deployment. Click `OK`
- Type in a username that you'd like to create and click `OK`
- Set the password for this newly created account and click `OK`
- Retype the password, click `OK`
- Make sure that `Best Practices` is selected, click `OK`
- Make sure `Emerging Threats Open` is selected as the IDS rule set, click `OK`
- `Snort` as the IDS engine, click `OK`
- `Enable network sensor services` to enable snort and other services. Click `OK`
- Leave the PF_RING min_num_slots set to default value. Click `OK`
- Make sure `ens33`, `ens34`, `ens35` are selected as sniffing interfaces
- Configure HOME_NET as `192.168.0.0/16`, click `OK`
- Select `Yes, store logs locally`
- Leave the disk space allocated to default, click `OK`
- `Yes, proceed with the changes!`
The setup will take a few minutes to complete. Review the follow up dialog boxes and click `OK` through it. 

At this time snort is configure. The last step is to create custom snort rule(s) to generate an alert if there is any non-HTTP traffic originating from Users subnet and destined for the internet. To do so, open the `local.rules` file in a terminal window.
```
sudo vi /etc/nsm/rules/local.rules`
```
Enter password for `user` account
Type in the following three rules. Each on a separate line
```
alert tcp 192.168.30.0/24 any -> !$HOME_NET !80 (msg:"Suspicious tcp traffic to internet"; sid:1000005; rev:1;)
alert udp 192.168.30.0/24 any -> !$HOME_NET any (msg:"Suspicious udp traffic to internet"; sid:1000006; rev:1;)
alert icmp 192.168.30.0/24 any -> !$HOME_NET any (msg:"Suspicious icmp traffic to internet"; sid:1000007; rev:1;)
```
To save the file, press the `esc` key followed by `:wq`
Use the following command to load the new rules
```
sudo rule-update
```
To verify the new rules have take effect, view the `/etc/nsm/rules/downloaded.rules` file. Our custom rules will show up at the bottom of this file. 

## Squid proxy server

The first step is to configure the network interface. To do so, navigate to 
```
cd /etc/netplan/
```
and open the only file present in the folder.
```
sudo vi 50-cloud-init.yaml
```
Edit the file to look like the following -
```
network:
    ethernets:
    ens32:  
        addresses: [192.168.10.102/29]
        gateway4: 192.168.10.101
        dhcp4: no
    version: 2
```
Apply the netplan configuration.
```
sudo netplan apply
```
The next step is to install and configure the squid web proxy. The squid debian package is attached as an iso to the proxy system. 
The first step is to mount the iso. 
```
sudo mount /dev/sr0 /mnt/
```
Enter the password for `user` account
Navigate to `/mnt/` directory and view the squid package. 
```
cd /mnt/
ls
```
Install squid
```
sudo dpkg -i squid.....deb
```
Enter password for `user` account

At this time you may review the parameters configured in default `squid.conf` file located at `/etc/squid/`. No changes are needed to this file. 
The next step is to create a `squid` user and give it permissions to write to squid logs folder. 
```
sudo adduser squid
```
Give it a password. The other fields are optional.
```
sudo chown -R squid:squid /var/log/squid/
```
Change to `squid` user and start the `squid` process
```
su squid
/usr/sbin/squid
```
Enter the password as needed
Lastly add routes for subnets connected off of the router, to allow the return web traffic from squid to be routed accordingly
```
su user
sudo ip route add 192.168.20.96/28 via 192.168.10.100 dev ens32
sudo ip route add 192.168.30.0/24 via 192.168.10.100 dev ens32
```

This wraps up all the configurations needed to build the network and complete this challenge. At this point, you may use the Test kali system to browse to the grading server (`http://150.37.91.102`) and view the grading results.
