# Exit Strategy Solution

#### To check http://challenge.us (and the pfsense dashboard after fixing the network issues), use the windows 10 workstation

NetworkCheck1 - Configure BGP Advertisement in PfSense BGP settings to 128.2.3.0/24

* Please note, in order to log into the pfsense dashboard, the mtu issue must be fixed. This can be done by solving network check 2 first*
* Log into pfsense gui (10.0.0.1 user/tartans)
* Go to Services, FRR BGP settings
* Change network advertisement from 128.2.3.10/32 to 128.2.3.0/24

NetworkCheck2 - Configure PFSense OSPF settings to ignore MTU mismatch, or set MTU of VyOS1 eth0 to 1500
* Connect to pc3t09-vyos1 (vyos/vyos)
* Run the following commands
* config
* set interface ethernet eth0 mtu 1500
* commit
* save
* Alternatively, connect to pfsense gui (10.0.0.1 user/tartans)
* Go to Services, FRR OSPF settings
* Check the Ignore MTU Mismatch box

NetworkCheck3 - on VyOS2, add the network 10.0.2.0/24 to OSPF Area 0
* Connect to pc3t09-vyos2 (vyos/vyos)
* Run the following commands
* config
* set protocols ospf area 0.0.0.0 network 10.0.2.0/24
* commit
* save

NetworkCheck4 - Create an outbound NAT rule for 10.0.3.0/24
* Connect to pfsense gui (user/tartans)
* Go to Firewall, Outbound NAT
* Add a manual rule for the 10.0.3.0/24 network. Masquerade to WAN address.

Exfiltrated file:
* Connect to IIS on the win2019-web1
* View IIS logs to discover team7.jpg is being repeatedly accessed by an external IP. This is the obfuscated SQL dump of the employees database

Non-obfuscated filename:
* Connect to pc3t09-db (user/tartans)
* view Faith Schrader's bash history
* sudo vi /home/fschrader/.bash_history

