# Configure NAT for LAN and DMZ out to WAN
set nat source rule 100 outbound-interface 'eth0'
set nat source rule 100 source interface eth1
set nat source rule 100 translation address masquerade

set nat source rule 100 outbound-interface 'eth0'
set nat source rule 100 source interface eth2
set nat source rule 100 translation address masquerade

# Firewall for WAN_IN (block all unsolicited inbound)
set firewall name WAN_IN default-action drop
set firewall name WAN_IN description 'Block inbound from WAN'
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 state established enable
set firewall name WAN_IN rule 10 state related enable

# Firewall for WAN_LOCAL (allow established, related)
set firewall name WAN_LOCAL default-action drop
set firewall name WAN_LOCAL description 'Local services from WAN'
set firewall name WAN_LOCAL rule 10 action accept
set firewall name WAN_LOCAL rule 10 state established enable
set firewall name WAN_LOCAL rule 10 state related enable

# Create firewall for LAN_IN (allow all)
set firewall name LAN_IN default-action accept

# DMZ Firewall rule
set firewall name DMZ_IN default-action accept

# Apply the rules
set interfaces ethernet eth0 firewall in name 'WAN_IN'
set interfaces ethernet eth0 firewall local name 'WAN_LOCAL'
set interfaces ethernet eth1 firewall in name 'LAN_IN'
set interfaces ethernet eth2 firewall in name 'DMZ_IN'

# Enable IP forwarding
set system ip forwarding
set system ipv6 disable-forwarding


commit
save