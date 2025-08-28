#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


while true; do
  current_value=$(sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 'cat /etc/resolv.conf' 2>/dev/null)

  if echo "$current_value" | grep -Fxq "nameserver 10.3.3.10"; then
    echo "Remote resolv.conf is correctly set."
    break
  else
    echo "Setting remote nameserver..."
    sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 'echo "tartans" | sudo -S bash -c "echo 'nameserver 10.3.3.10' > /etc/resolv.conf"'
    sleep 15
  fi
done

                      
