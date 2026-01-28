#!/bin/bash
set -e 


TOKEN2=$TOKEN2

cat << EOF > /challenge/syslog.log
May  8 10:00:01 host CRON[1234]: (root) CMD (echo "System check complete")
May  8 10:01:45 host CRON[1234]: (root) CMD (echo "Security Update Applied")
May  8 10:03:01 host CRON[1234]: (root) CMD (echo "Reboot Initiated")
May  8 10:03:05 host systemd[1]: Starting Network Manager...
May  8 10:03:10 host kernel: [ 0.000000] Linux version 5.15.0-76-generic (buildd@lcy02-amd64-080) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #83-Ubuntu SMP Mon Jun 19 16:32:04 UTC 2023
May  8 10:03:12 host sshd[5678]: Accepted publickey for user from 192.168.1.10 port 54321 ssh2: RSA SHA256:abcdef1234567890
May  8 10:03:15 host systemd[1]: Network Manager started.
May  8 10:04:01 host CRON[1235]: (user) CMD (/usr/bin/backup_script.sh)
May  8 10:04:30 host rsyslogd: imuxsock: imuxsock begins to drop messages from pid 1234 due to rate-limiting
May  8 10:05:01 host CRON[1236]: (root) CMD (echo "Disk usage check")
May  8 10:05:05 host kernel: [ 1.234567] usb 1-1: new high-speed USB device number 2 using xhci_hcd
May  8 10:05:10 host systemd[1]: Reached target Graphical Interface.
May  8 10:06:01 host CRON[1237]: (root) CMD (echo "Log rotation initiated")
May  8 10:06:15 host apache2[7890]: [client 10.0.0.5] File does not exist: /var/www/html/nonexistent.html
May  8 10:07:01 host CRON[1238]: (root) CMD (echo "Database backup complete")
May  8 10:07:30 host systemd[1]: Started Session c1 of user user.
May  8 10:08:01 host CRON[1239]: (root) CMD (echo "System health report generated")
May  8 10:08:45 host sshd[5679]: Disconnected from authenticating user user 192.168.1.10 port 54321 [preauth]
May  8 10:09:01 host CRON[1240]: (root) CMD (echo "Temporary files cleaned")
May  8 10:09:10 host kernel: [ 2.345678] EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null)
May  8 10:10:01 host CRON[1241]: (root) CMD (echo "Application logs archived")
May  8 10:10:20 host systemd[1]: user@1000.service: Deactivated successfully.
May  8 10:11:01 host CRON[1242]: (root) CMD (echo "Firewall rules updated")
May  8 10:11:55 host sudo[9876]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update
May  8 10:12:01 host CRON[1243]: (root) CMD (echo "DNS cache flushed")
May  8 10:12:30 host systemd[1]: Stopping User Manager for UID 1000...
May  8 10:13:01 host CRON[1244]: (root) CMD (echo "Package list refreshed")
May  8 10:13:15 host kernel: [ 3.456789] systemd-journald[123]: System journal closed.
May  8 10:14:01 host CRON[1245]: (root) CMD (echo "Service status check")
May  8 10:14:40 host systemd[1]: User Manager for UID 1000 was stopped.
May  8 10:15:01 host CRON[1246]: (root) CMD (echo "CPU utilization monitored")
May  8 10:15:25 host systemd[1]: Started User Manager for UID 1000.
May  8 10:16:01 host CRON[1247]: (root) CMD (echo "Memory usage optimized")
May  8 10:16:50 host sshd[5680]: Connection closed by 192.168.1.11 port 12345 [preauth]
May  8 10:17:01 host CRON[1248]: (root) CMD (echo "Network connectivity tested")
May  8 10:17:35 host kernel: [ 4.567890] IPv6: ADDRCONF(NETDEV_UP): eth0: link is not ready
May  8 10:18:01 host CRON[1249]: (root) CMD (echo "Disk I/O performance checked")
May  8 10:18:20 host systemd[1]: Starting Cleanup of Temporary Directories...
May  8 10:19:01 host CRON[1250]: (root) CMD (echo "System uptime logged")
May  8 10:19:45 host systemd[1]: Finished Cleanup of Temporary Directories.
May  8 10:20:01 host CRON[1251]: (root) CMD (echo "Hardware sensors read")
May  8 10:20:10 host kernel: [ 5.678901] systemd[1]: /lib/systemd/system/systemd-journald.service: Failed to parse or execute unit configuration file.
May  8 10:21:01 host CRON[1252]: (root) CMD (echo "Security audit performed")
May  8 10:21:30 host systemd[1]: Starting Daily apt download activities...
May  8 10:22:01 host CRON[1253]: (root) CMD (echo "Software updates checked")
May  8 10:22:50 host systemd[1]: Daily apt download activities completed.
May  8 10:23:01 host CRON[1254]: (root) CMD (echo "Configuration files validated")
May  8 10:23:15 host kernel: [ 6.789012] audit: type=1400 audit(1678886400.000:1): apparmor="DENIED" operation="open" profile="/usr/sbin/apache2" name="/etc/apache2/conf-available/charset.conf" comm="apache2" requested_mask="r" denied_mask="r" fsuid=33 ouid=0
May  8 10:24:01 host CRON[1255]: (root) CMD (echo "User sessions monitored")
May  8 10:24:25 host sshd[5681]: Invalid user guest from 203.0.113.1 port 54322
May  8 10:25:01 host CRON[1256]: (root) CMD (echo "Process list reviewed")
May  8 10:25:50 host systemd[1]: Starting Daily apt upgrade and clean activities...
May  8 10:26:01 host CRON[1257]: (root) CMD (echo "System load average recorded")
May  8 10:26:02 host sshd[5681]: (root) CMD (sshpass -p ${TOKEN3} -i id_rsa -o StrictHostKeyChecking=no "ssh root@unknown.com")
May  8 10:26:30 host systemd[1]: Daily apt upgrade and clean activities completed.
May  8 10:27:01 host CRON[1258]: (root) CMD (echo "Kernel messages reviewed")
May  8 10:27:10 host kernel: [ 7.890123] systemd-udevd[456]: starting version 249.11-0ubuntu3.11
May  8 10:28:01 host CRON[1259]: (root) CMD (echo "Disk space alerts checked")
May  8 10:28:45 host systemd[1]: Started Snap Daemon.
May  8 10:29:01 host CRON[1260]: (root) CMD (echo "Network interface statistics collected")
May  8 10:29:55 host sudo[9877]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/systemctl restart apache2
May  8 10:30:01 host CRON[1261]: (root) CMD (echo "System backup initiated")
May  8 10:30:05 host apache2[7890]: Apache/2.4.52 (Ubuntu) configured -- resuming normal operations
May  8 10:30:10 host systemd[1]: Started MySQL Community Server.
May  8 10:31:01 host kernel: [ 8.901234] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro
May  8 10:31:15 host systemd[1]: Created slice User Slice of user.
May  8 10:32:01 host CRON[1262]: (root) CMD (echo "File system integrity check")
May  8 10:32:30 host useradd[1263]: new group: name=newgroup, GID=1001
May  8 10:33:01 host CRON[1264]: (root) CMD (echo "New user added: testuser")
May  8 10:33:10 host systemd[1]: Started Session c2 of user testuser.
May  8 10:33:45 host sudo[9878]: testuser : TTY=pts/1 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/bin/touch /var/log/testfile.log
May  8 10:34:01 host CRON[1265]: (root) CMD (echo "File /var/log/testfile.log created")
May  8 10:34:20 host kernel: [ 9.012345] audit: type=1300 audit(1678886400.000:2): arch=c000003e syscall=2 success=yes exit=3 a0=7ffe8a8b0010 a1=80000 a2=1b6 a3=0 items=0 ppid=12345 uid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts/1 ses=2 comm="touch" exe="/usr/bin/touch" subj=unconfined key=(null)
May  8 10:35:01 host CRON[1266]: (root) CMD (echo "Directory /opt/newapp created")
May  8 10:35:15 host systemd[1]: Starting apt-daily.service...
May  8 10:36:01 host CRON[1267]: (root) CMD (echo "File permissions updated for /var/www/html/index.html")
May  8 10:36:40 host systemd[1]: Finished apt-daily.service.
May  8 10:37:01 host CRON[1268]: (root) CMD (echo "File /etc/hosts modified")
May  8 10:37:25 host kernel: [ 10.123456] audit: type=1300 audit(1678886400.000:3): arch=c000003e syscall=2 success=yes exit=4 a0=7ffe8a8b0020 a1=2 a2=1b6 a3=0 items=0 ppid=12346 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=3 comm="vi" exe="/usr/bin/vi" subj=unconfined key=(null)
May  8 10:38:01 host CRON[1269]: (root) CMD (echo "File /tmp/report.txt deleted")
May  8 10:38:30 host systemd[1]: Stopping User Manager for UID 1001...
May  8 10:39:01 host CRON[1270]: (root) CMD (echo "Log file cleanup completed")
May  8 10:39:45 host systemd[1]: User Manager for UID 1001 was stopped.
May  8 10:40:01 host CRON[1271]: (root) CMD (echo "New configuration file /etc/nginx/conf.d/myapp.conf deployed")
May  8 10:40:10 host nginx[1272]: [emerg] 1272#1272: open("/etc/nginx/conf.d/myapp.conf") failed (2: No such file or directory)
May  8 10:41:01 host CRON[1273]: (root) CMD (echo "File system usage report generated")
May  8 10:41:30 host systemd[1]: Started User Manager for UID 1001.
May  8 10:42:01 host CRON[1274]: (root) CMD (echo "Critical system file /usr/local/bin/critical_script.sh accessed")
May  8 10:42:50 host sshd[5682]: Accepted password for testuser from 192.168.1.12 port 54323 ssh2
May  8 10:43:01 host CRON[1275]: (root) CMD (echo "File /var/log/auth.log rotated")
May  8 10:43:15 host kernel: [ 11.234567] audit: type=1105 audit(1678886400.000:4): op=PAM:session_open grantors=pam_unix acct="testuser" exe="/usr/sbin/sshd" hostname=192.168.1.12 addr=192.168.1.12 terminal=ssh res=success
May  8 10:44:01 host CRON[1276]: (root) CMD (echo "Temporary directory /tmp/uploads cleared")
May  8 10:44:40 host systemd[1]: Stopping User Manager for UID 1001...
May  8 10:45:01 host CRON[1277]: (root) CMD (echo "File system check completed with no errors")
May  8 10:45:25 host systemd[1]: User Manager for UID 1001 was stopped.
EOF

echo "[*] /challenge/syslog.log created."