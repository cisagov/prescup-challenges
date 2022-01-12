#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

token1=$((($RANDOM)%242 + 11))
token2=$((($RANDOM + $RANDOM)%48126 + 1025))
token3=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1)

cat << end > /etc/netplan/99.yaml
network:
        ethernets:
            ens32
                        addresses:
                                - 192.168.33.$token1/24
                        gateway4: 192.168.33.1
        version: 2
end

cat << end > /etc/ssh/sshd_config

Port $token2

ChallengeResponseAuthentication no

UsePAM yes

X11Fowarding yes

PrintMotd no

AccepEnv LANG LC_*

Subsystem       sftp    /usr/lib/openssh/sftp-server

end

echo $token3 > ./token/tokenfile

cat /dev/null > ~/.bash_history && history -c && exit

