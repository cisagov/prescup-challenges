interfaces {
    ethernet eth0 {
        address 2001:0db8:abcd:4d6b::2/64
        hw-id 00:50:56:b6:87:02
    }
    ethernet eth1 {
        address 2001:0db8:abcd:2f8a::2/64
        hw-id 00:50:56:b6:6c:c8
    }
    ethernet eth2 {
        address 2001:0db8:abcd:af17::1/64
        hw-id 00:50:56:b6:a4:bf
    }
}
protocols {
    bgp {
        address-family {
            ipv6-unicast {
                network 2001:0db8:abcd:2f8a::/64
                network 2001:0db8:abcd:4d6b::/64
                network 2001:0db8:abcd:af17::/64
            }
        }
        local-as 65008
        neighbor 2001:0db8:abcd:2f8a::1 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 80
                }
            }
            remote-as 65006
        }
        neighbor 2001:0db8:abcd:4d6b::1 {
            address-family {
                ipv6-unicast {
                    disable-send-community {
                    }
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 120
                }
            }
            remote-as 65005
        }
        neighbor 2001:0db8:abcd:af17::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 80
                }
            }
            remote-as 65009
        }
        parameters {
            router-id 10.8.8.8
        }
    }
}
service {
    ssh {
        port 22
    }
}
system {
    config-management {
        commit-revisions 100
    }
    console {
        device ttyS0 {
            speed 115200
        }
    }
    host-name vyos
    login {
        user vyos {
            authentication {
                encrypted-password $6$NEU6jIkTVB2L81AH$oeZniQ10mhZiUifJobtlwbXzdf9lTXrsj31nDm0BXfRFLKCzpo5BVivZlUYY1eP.MKj33U17V2p3lECzdue/J1
            }
        }
    }
    ntp {
        server 0.pool.ntp.org
        server 1.pool.ntp.org
        server 2.pool.ntp.org
    }
    syslog {
        global {
            facility all {
                level info
            }
            facility protocols {
                level debug
            }
        }
    }
}
// Warning: Do not remove the following line.
// vyos-config-version: "bgp@1:broadcast-relay@1:cluster@1:config-management@1:conntrack@2:conntrack-sync@2:dhcp-relay@2:dhcp-server@5:dhcpv6-server@1:dns-forwarding@3:firewall@5:https@2:interfaces@20:ipoe-server@1:ipsec@5:isis@1:l2tp@3:lldp@1:mdns@1:nat@5:nat66@1:ntp@1:pppoe-server@5:pptp@2:qos@1:quagga@9:rpki@1:salt@1:snmp@2:ssh@2:sstp@3:system@20:vrf@2:vrrp@2:vyos-accel-ppp@2:wanloadbalance@3:webproxy@2:zone-policy@1"
// Release version: 1.4-rolling-202105152149
