#!/bin/bash

set -eu
: "${TOKEN1:?TOKEN1 not set}"

TOKEN1=$TOKEN1

echo "root:x:0:0:root:/root:/bin/bash" > /app/etc/passwd
echo "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" >> /app/etc/passwd
echo "bin:x:2:2:bin:/bin:/usr/sbin/nologin" >> /app/etc/passwd
echo "sys:x:3:3:sys:/dev:/usr/sbin/nologin" >> /app/etc/passwd
echo "sync:x:4:65534:sync:/bin:/bin/sync" >> /app/etc/passwd
echo "games:x:5:60:games:/usr/games:/usr/sbin/nologin" >> /app/etc/passwd
echo "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin" >> /app/etc/passwd
echo "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin" >> /app/etc/passwd
echo "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin" >> /app/etc/passwd
echo "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin" >> /app/etc/passwd
echo "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin" >> /app/etc/passwd
echo "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin" >> /app/etc/passwd
echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" >> /app/etc/passwd
echo "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin" >> /app/etc/passwd
echo "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin" >> /app/etc/passwd
echo "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin" >> /app/etc/passwd
echo "gnats:x:41:41:Gnats Bug-Reporting System:/var/lib/gnats:/usr/sbin/nologin" >> /app/etc/passwd
echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" >> /app/etc/passwd
echo "systemd-network:x:100:101:systemd Network Management:/run/systemd:/usr/sbin/nologin" >> /app/etc/passwd
echo "systemd-resolve:x:101:102:systemd Resolver:/run/systemd/resolve:/usr/sbin/nologin" >> /app/etc/passwd
echo "systemd-timesync:x:102:103:systemd Time Synchronization:/run/systemd:/usr/sbin/nologin" >> /app/etc/passwd
echo "messagebus:x:103:104::/nonexistent:/usr/sbin/nologin" >> /app/etc/passwd
echo "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin" >> /app/etc/passwd
echo "TOKEN1::${TOKEN1}:0:0:root:/root:/bin/bash" >> /app/etc/passwd
