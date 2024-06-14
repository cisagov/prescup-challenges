interfaces {
    ethernet eth0 {
        address 2001:0db8:abcd:3a7f::1/64
        hw-id 00:50:56:b6:d9:55
    }
    ethernet eth1 {
        address 2001:0db8:abcd:9e4a::1/64
        hw-id 00:50:56:b6:1e:20
    }
    ethernet eth2 {
        address 2001:0db8:abcd:c8f1::1/64
        hw-id 00:50:56:b6:e6:44
    }
    ethernet eth3 {
        address 2001:0db8:abcd:1111::1/64
        hw-id 00:50:56:b6:ef:07
    }
}
protocols {
    bgp {
        address-family {
            ipv6-unicast {
                network 2001:0db8:abcd:1111::/64
            }
        }
        local-as 65001
        neighbor 2001:0db8:abcd:3a7f::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 150
                }
            }
            remote-as 65002
        }
        neighbor 2001:0db8:abcd:9e4a::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 80
                }
            }
            remote-as 65003
        }
        neighbor 2001:0db8:abcd:c8f1::2 {
            address-family {
                ipv6-unicast {
                    soft-reconfiguration {
                        inbound {
                        }
                    }
                    weight 30
                }
            }
            remote-as 65005
        }
        parameters {
            router-id 10.1.1.1
        }
    }
}
service {
    dhcpv6-server {
        shared-network-name COMP {
            subnet 2001:0db8:abcd:1111::/64 {
                address-range {
                    start 2001:0db8:abcd:1111::0100 {
                        stop 2001:0db8:abcd:1111::ffff
                    }
                }
            }
        }
    }
    router-advert {
        interface eth3 {
            prefix 2001:0db8:abcd:1111::/64
        }
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
                encrypted-password $6$a.9PeSKSRzbzoSQq$97/dbD1FfeBK1mS/B4Kw2spQh6aCH.5aKQqvwZgWdzu5AWNasb58O/sdEDS2YWg8PCeWw9HrooIIAltVz.VOK/
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
