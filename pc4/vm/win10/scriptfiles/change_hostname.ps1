 #!Powershell

#############################
###### Change Hostname ######
#############################

 $name = & 'C:\Program Files\VMware\VMware Tools\rpctool.exe' "info-get guestinfo.hostname"
 $currentName = hostname
 if ($currentName -ne $name){
    Rename-Computer -NewName $name -Restart -Force
}