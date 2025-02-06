#!/usr/bin/python3
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#


import subprocess
import vyos_arp_checker

def grade_challenge():

    results = {}

    out1 = subprocess.run('ping -c 5 192.168.0.2', shell=True, capture_output=True)
    out2 = subprocess.run('ping -c 5 192.168.2.11', shell=True, capture_output=True)

    if out1.returncode == 0 and out2.returncode == 0:
        results['GradingCheck1'] = "Success --- The IPSec VPN between the Main and Branch office is established and the 192.168.2.0/24 network is accessible"
    else:
        results['GradingCheck1'] = "Users at the Main office are still unable to reach server 192.168.2.11 at the Branch office"

    if vyos_arp_checker.check_vyos_arp():
        results['GradingCheck2'] = "Success --- The Duplicate IP address on servers in the 192.168.2.0/24 network has been corrected"
    else:
        results['GradingCheck2'] = "Branch office users are still reporting frequent disconnections from server 192.168.2.11"

    for key, value in results.items():
        print(key, ' : ', value)


if __name__ == '__main__':
    grade_challenge()