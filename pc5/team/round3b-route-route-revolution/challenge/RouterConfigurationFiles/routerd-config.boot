interfaces {
    ethernet eth0 {
        address 2001:0db8:abcd:b6d2::2/64
        hw-id 00:50:56:b6:bb:02
    }
    ethernet eth1 {
        address 2001:0db8:abcd:f578::1/64
        hw-id 00:50:56:b6:ab:bd
    }
    ethernet eth2 {
        address 2001:0db8:abcd:1b7c::1/64
        hw-id 00:50:56:b6:e1:65
    }
    ethernet eth3 {
        address 2001:0db8:abcd:3333::1/64
        hw-id 00:50:56:b6:81:c0
    }
}
protocols {
    bgp {
        address-family {
            ipv6-unicast {
                network 2001:0db8:abcd:3333::/64
            }
        }
        local-as 65004
        neighbor 2001:0db8:abcd:1b7c::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        outbound {
                        }
                    }
                    weight 40
                }
            }
            remote-as 65007
        }
        neighbor 2001:0db8:abcd:b6d2::1 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        outbound {
                        }
                    }
                    weight 30
                }
            }
            remote-as 65002
        }
        neighbor 2001:0db8:abcd:f578::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 150
                }
            }
            remote-as 65005
        }
        parameters {
            router-id 10.4.4.4
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
                encrypted-password $6$HUawQVmi4rZUmxsW$BEz2w5GZA7euBP5u43QN3B6vGXr0PsvtXkeMkSuy4ypATg7q0z5KMSgoQrbyXtz/hqglxEHmQpUH7iLLM36un/
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
