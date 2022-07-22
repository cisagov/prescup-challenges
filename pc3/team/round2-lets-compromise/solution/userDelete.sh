#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

acc=("bob" "john" "hope" "jill" "anthony" "dano" "rocco" "sandy" "ezra")
for name in ${acc[*]}
do
    for x in {0..10}
    do
        user=$(grep $name$x /etc/passwd) 
        if [ -z "$user" ]
        then
            pass
            #/usr/bin/sudo useradd -m -d /home/user/.users/$name$x -s /usr/bin/zsh -G root,sudo $name$x
            #echo -e "$name$x\n$name$x" | passwd $name$x
        else
            /usr/bin/sudo userdel $name$x
        fi
    done
done
