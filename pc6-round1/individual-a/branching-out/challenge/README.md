# Branching Out

*Challenge Artifacts*

## Grading Scripts:
- [gradingScript.py](./gradingScript.py): The script that checks for network connectivity between challenge machines.
- [vyos_arp_checker.py](./vyos_arp_checker.py): A helper Python script which is called by [gradingScript.py](./gradingScript.py). It verifies that the `vyos-branch` router is reachable. If so, it then connects to the router and does an ARP lookup on `eth2`. It looks for the IP addresses `192.168.2.11` and `192.168.2.12`. It returns True if both IP addresses are found in the ARP table. If both addresses are not found, it returns False.

## Configurations
- [pfsense-branch.xml](./configs/pfsense-branch.xml): XML backup file of the configurations on the pfSense Branch firewall
- [pfsense-main.xml](./configs/pfsense-main.xml): XML backup file of the configurations on the pfsense Main firewall
- [vyos-branch-set-commands.conf](./configs/vyos-branch-set-commands.conf): Set commands needed to configure the VyOS Branch router

## Configurations on `wan-ubuntu`
The `wan-ubuntu` system was added to create more realistic WAN conditions between Main office and Branch office. Below are the configurations used to accomplish this.

### Allow IPv4 Packet Forwarding:
- Edit `/etc/sysctl.conf` and uncomment `net.ipv4.ip_forward=1`
- This allows packets to be forwarded between the two interfaces

### Add Delay
On `wan-ubuntu`

1. Create a service with oneShot start for `tc` (traffic control) service. `sudo nano /etc/systemd/system/trafficControl.service`

```service
[Unit]
Description= Run tc Command at Startup
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/tc qdisc add dev ens32 root netem delay 100ms 10ms 25%
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

This sets ens32 to have a 100ms delay +/- 10ms and the next packet delay value will be biased by 25% on the most recent delay. Since all traffic routes between the two interfaces, setting on just one interface will apply to all traffic we are concerned with in this challenge.

2. Enable the service: `sudo systemctl enable trafficControl.service`