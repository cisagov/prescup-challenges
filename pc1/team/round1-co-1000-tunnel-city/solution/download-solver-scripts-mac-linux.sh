#!/bin/bash

# President's Cup Cybersecurity Competition 2019 Challenges
#
# Copyright 2020 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
# FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
# OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
# MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# DM20-0347

curl -O https://raw.githubusercontent.com/RPISEC/HackTheVote/master/forensics/hc_emails/sol/base128_iodine.py
curl -O https://raw.githubusercontent.com/RPISEC/HackTheVote/master/forensics/hc_emails/sol/extract_dns.py

if [[ $(man -P cat sed | head -n 2 | grep '\S') == *"BSD"* ]]; then
  sed -i '' "s/\.\.\/handout\/hillary.pcap/filtered.pcap/g" extract_dns.py
  sed -i '' "s/\.hillary\.clinton\.io\./.a1a.net./g" extract_dns.py
else
  sed -i'' "s/\.\.\/handout\/hillary.pcap/filtered.pcap/g" extract_dns.py
  sed -i'' "s/\.hillary\.clinton\.io\./.a1a.net./g" extract_dns.py
fi
