# President's Cup Cybersecurity Competition 2019 Challenges
#
# Copyright 2020 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
# FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
# OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
# MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# DM20-0347

#!/bin/bash

while fuser /var/{lib/{dpkg,apt/lists},cache/apt/archives}/lock >/dev/null 2>&1; do
  sleep 1
done
apt update &>/dev/null
apt -y install libc6-i386

useradd -m johny 
usermod --shell /bin/bash johny
echo johny:iloveowls | chpasswd 

tar xzf johny.tgz
cp johny/homedir/* /home/johny/
cp johny/flag.txt /root/flag.txt
chown johny /home/johny/cleanup.sh
chown johny /home/johny/johny-inventory
chown johny /home/johny/notes.txt
chown johny /home/johny/run-server.sh
chgrp johny /home/johny/cleanup.sh
chgrp johny /home/johny/johny-inventory
chgrp johny /home/johny/notes.txt
chgrp johny /home/johny/run-server.sh
chmod 777 /home/johny/cleanup.sh
chmod 775 /home/johny/johny-inventory
chmod 644 /home/johny/notes.txt
chmod 744 /home/johny/run-server.sh

# Disable ASLR now and through reboots.
echo 0 > /proc/sys/kernel/randomize_va_space
echo 'kernel.randomize_va_space = 0' > /etc/sysctl.d/01-disable-aslr.conf

echo "* * * * * /home/johny/run-server.sh" | crontab -u johny -

echo 'johny ALL=(ALL:ALL) /home/johny/cleanup.sh' > /root/johny.sudoers
visudo -cf /root/johny.sudoers &>/dev/null
if [ $? -eq 0 ];  then
  cp /root/johny.sudoers /etc/sudoers.d/johny
else
  echo 'Could not install challenge successfully. Are you on the right OS (Ubuntu 18.04 recommended)?'
fi
rm -f /root/johny.sudoers
