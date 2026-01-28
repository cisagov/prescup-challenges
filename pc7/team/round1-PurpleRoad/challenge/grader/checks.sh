#!/bin/bash

# Example: perform checks, echo 1 if passed, 0 if not

login="ssh -i /root/grader_id_rsa -o StrictHostKeyChecking=no grader@fileserver sudo" 


#1. apply firewall to only allow FTP and SSH:


#2. Apply Fail2ban to protect vsftpd:


#3.  Remove world-writable files from `/home`

# Check 1: Disable anonymous FTP


$login grep -q "^anonymous_enable=NO" /etc/vsftpd.conf && echo 1 || echo 0


# Check 2: fail2ban check - tested done
$login fail2ban-client status vsftpd 2>/dev/null | grep -q "vsftpd" && echo 1 || echo 0

# Check 3: World Writable home check
$login find /home -type f -perm -0002 2>/dev/null | grep -q . && echo 0 || echo 1