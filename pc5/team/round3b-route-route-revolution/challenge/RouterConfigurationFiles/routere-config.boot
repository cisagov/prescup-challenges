interfaces {
    ethernet eth0 {
        address 2001:0db8:abcd:c8f1::2/64
        hw-id 00:50:56:b6:77:b6
    }
    ethernet eth1 {
        address 2001:0db8:abcd:6a2d::2/64
        hw-id 00:50:56:b6:fe:32
    }
    ethernet eth2 {
        address 2001:0db8:abcd:d7b1::2/64
        hw-id 00:50:56:b6:29:9a
    }
    ethernet eth3 {
        address 2001:0db8:abcd:f578::2/64
        hw-id 00:50:56:b6:f9:38
    }
    ethernet eth4 {
        address 2001:0db8:abcd:a983::1/64
        hw-id 00:50:56:b6:72:83
    }
    ethernet eth5 {
        address 2001:0db8:abcd:8e34::1/64
        hw-id 00:50:56:b6:99:d6
    }
    ethernet eth6 {
        address 2001:0db8:abcd:4d6b::1/64
        hw-id 00:50:56:b6:37:32
    }
    ethernet eth7 {
        address 2001:0db8:abcd:e124::1/64
        hw-id 00:50:56:b6:5d:6f
    }
}
protocols {
    bgp {
        address-family {
            ipv6-unicast {
                network 2001:0db8:abcd:4d6b::/64
                network 2001:0db8:abcd:6a2d::/64
                network 2001:0db8:abcd:8e34::/64
                network 2001:0db8:abcd:a983::/64
                network 2001:0db8:abcd:c8f1::/64
                network 2001:0db8:abcd:d7b1::/64
                network 2001:0db8:abcd:e124::/64
                network 2001:0db8:abcd:f578::/64
            }
        }
        local-as 65005
        neighbor 2001:0db8:abcd:4d6b::2 {
            address-family {
                ipv6-unicast {
                    disable-send-community {
                    }
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 100
                }
            }
            remote-as 65008
        }
        neighbor 2001:0db8:abcd:6a2d::1 {
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
            remote-as 65002
        }
        neighbor 2001:0db8:abcd:8e34::2 {
            address-family {
                ipv6-unicast {
                    disable-send-community {
                    }
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 30
                }
            }
            remote-as 65007
        }
        neighbor 2001:0db8:abcd:a983::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 120
                }
            }
            remote-as 65006
        }
        neighbor 2001:0db8:abcd:c8f1::1 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 30
                }
            }
            remote-as 65001
        }
        neighbor 2001:0db8:abcd:d7b1::1 {
            address-family {
                ipv6-unicast {
                    disable-send-community {
                    }
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 30
                }
            }
            remote-as 65003
        }
        neighbor 2001:0db8:abcd:e124::2 {
            address-family {
                ipv6-unicast {
                    weight 30
                }
            }
            remote-as 65009
        }
        neighbor 2001:0db8:abcd:f578::1 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 120
                }
            }
            remote-as 65004
        }
        parameters {
            router-id 10.5.5.5
        }
    }
}
service {
    router-advert {
        interface eth0
        interface eth1
        interface eth2
        interface eth3
        interface eth4
        interface eth5
        interface eth6
        interface eth7
    }
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
                encrypted-password $6$5BlhDtYATek1wNyq$VmV1kibxHoHdv5VZVOUuyflCF.CdfC0adJAi2TvJ2OnEyoVV6k6WPi9024/64IoNjfbrdHte1sO1xVw2xkawd0
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
