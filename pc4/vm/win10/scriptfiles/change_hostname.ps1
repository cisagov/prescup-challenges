 #!Powershell

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#############################
###### Change Hostname ######
#############################

 $name = & 'C:\Program Files\VMware\VMware Tools\rpctool.exe' "info-get guestinfo.hostname"
 $currentName = hostname
 if ($currentName -ne $name){
    Rename-Computer -NewName $name -Restart -Force
}
