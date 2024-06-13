
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

/sbin/ip -6 route add 2001:0db8:abcd:1111::/64 via 2001:0db8:abcd:2222::1 dev ens33
/sbin/ip -6 route add 2001:0db8:abcd:3333::/64 via 2001:0db8:abcd:4444::1 dev ens32

