#!/bin/bash -e

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# Update System
apt-get -y -qq update
apt-get -y -qq full-upgrade

## Needed dependencies
apt-get install -y libmaxminddb0 zlib1g curl gpg default-jre make gcc g++ zlib1g-dev gcc-12-base libc-dev-bin libc6 libc6-dev libc6-i386 libpython3.10 libstdc++6 apt-transport-https bison \
  cmake cmake-data default-jdk default-jdk-headless dh-elpa-helper flex gcc-11-multilib gcc-multilib ghidra-data gir1.2-packagekitglib-1.0 gnupg2 gnutls-bin hdf5-helpers lib32asan6 lib32atomic1 \
  lib32gcc-11-dev lib32gomp1 lib32itm1 lib32quadmath0 lib32ubsan1 libaec-dev libappstream4 libbabeltrace1 libblkid-dev libboost-regex1.74.0 libc-ares-dev libc6-dbg libc6-dev-i386 libc6-dev-x32 \
  libc6-x32 libcurl4-openssl-dev libdbi1 libdbus-1-dev libdebuginfod-common libdebuginfod1 libfl-dev libfl2 libglib2.0-dev libglib2.0-dev-bin libgnutls-dane0 libhdf5-cpp-103-1 libhdf5-dev \
  libhdf5-fortran-102 libhdf5-hl-cpp-100 libhdf5-hl-fortran-100 libice-dev libipt2 libjpeg-dev libjpeg62-turbo-dev libjsoncpp25 libleveldb-dev libleveldb1d liblmdb-dev libmaxminddb-dev libmount-dev \
  libncurses5-dev libnetfilter-queue-dev libpackagekit-glib2-18 libpcap-dev libpcap0.8-dev libpcre16-3 libpcre2-32-0 libpcre2-dev libpcre2-posix3 libpcre3-dev libpcre32-3 libpcrecpp0v5 \
  libpthread-stubs0-dev librhash0 librrd8 libselinux1-dev libsepol-dev libsm-dev libsnappy-dev libsource-highlight-common libsource-highlight4v5 libssl-dev libstemmer0d libunbound8 libx11-dev \
  libx32asan6 libx32atomic1 libx32gcc-11-dev libx32gcc-s1 libx32gomp1 libx32itm1 libx32quadmath0 libx32stdc++6 libx32ubsan1 libxau-dev libxcb1-dev libxdmcp-dev libxmlb2 libxt-dev lmdb-doc m4 \
  mmdb-bin openjdk-11-jdk openjdk-11-jdk-headless packagekit packagekit-tools pkg-config python3-distro-info python3-lzo python3-software-properties sgml-base software-properties-common swig \
  swig4.0 unattended-upgrades uuid-dev x11proto-dev xml-core xorg-sgml-doctools xtrans-dev linux-headers-generic

## Import Microsoft GPG key to Kali Linux
mkdir VSCode && cd VSCode
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/

## Add APT repository for VS Code to Kali Linux
echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" | sudo tee /etc/apt/sources.list.d/vscode.list

## Install Visual Studio Code on Kali Linux
apt-get update -y
apt-get install code -y
cd ..

#################################################################################
## VSCODE EXTENSIONS

## Python
sudo -u user code --install-extension ms-python.python

## Pylance
sudo -u user code --install-extension ms-python.vscode-pylance

## C/C++ tools and extension pack
sudo -u user code --install-extension ms-vscode.cpptools
sudo -u user code --install-extension ms-vscode.cpptools-extension-pack

## CMAKE
sudo -u user code --install-extension twxs.cmake

## CMAKE Tools
sudo -u user code --install-extension ms-vscode.cmake-tools

## Excel Viewer
sudo -u user code --install-extension GrapeCity.gc-excelviewer

## Jupyter
sudo -u user code --install-extension ms-toolsai.jupyter

## C#
sudo -u user code --install-extension ms-dotnettools.csharp

## VSCODE PDF
sudo -u user code --install-extension tomoki1207.pdf

## ZIP File Explorer
sudo -u user code --install-extension slevesque.vscode-zipexplorer

## PowerShell
sudo -u user code --install-extension ms-vscode.PowerShell

## Rust
sudo -u user code --install-extension rust-lang.rust

## Docs-yaml
sudo -u user code --install-extension docsmsft.docs-yaml

## Docs-markdown
sudo -u user code --install-extension docsmsft.docs-markdown

## Remote - SSH
sudo -u user code --install-extension ms-vscode-remote.remote-ssh

## Remote - WSL
sudo -u user code --install-extension ms-vscode-remote.remote-wsl

## JAVA and Extension Pack for Java
sudo -u user code --install-extension vscjava.vscode-java-pack

## Hex Editor
sudo -u user code --install-extension ms-vscode.hexeditor

## .Net Extension Pack
sudo -u user code --install-extension ms-dotnettools.vscode-dotnet-pack

## Makefile Tools
sudo -u user code --install-extension ms-vscode.makefile-tools

## VIM keymap
## sudo -u user code --install-extension vscodevim.vim

## ATOM Keymap
## sudo -u user code --install-extension ms-vscode.atom-keybindings

## Notepad++ Keymap
## sudo -u user code --install-extension ms-vscode.notepadplusplus-keybindings

#################################################################################

## GDB
apt-get install gdb -y

## Python3 and packages
apt-get install -y python3 python-is-python3 python3-pip python3-impacket
pip install unicorn pwntools
pip install pycryptodome

## Rust(needed)
su user -c "curl https://sh.rustup.rs -sSf | sh -s -- -y"
source /home/user/.cargo/env

## HEXEDIT
apt-get install hexedit -y

## GEDIT
apt-get install gedit -y

## NTOPNG
apt-get install ntopng -y

## tcpflow
apt-get install tcpflow -y

## MALTEGO
apt-get install maltego -y

## GHIDRA
apt-get install ghidra -y

## RADARE2
apt-get install radare2 -y

## NFDUMP
apt-get install nfdump -y

## LibreOffice
apt-get install libreoffice -y

## OpenVas
apt-get install openvas -y
gvm-setup
sudo -E -u _gvm -g _gvm gvmd --user=admin --new-password=admin
gvm-stop

## Zaproxy
apt-get install zaproxy -y

## DockerExplorer
mkdir DockerExplorer && cd DockerExplorer
wget https://github.com/google/docker-explorer/archive/refs/tags/20220106.tar.gz && tar -xzvf 20220106.tar.gz && ln -s /home/user/DockerExplorer/docker-explorer-20220106/de.py /usr/bin/de.py
cd ..

## ZEEK Repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_Testing/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
apt-get update

## ZEEK Dependencies
apt-get install libbroker-dev liblockfile1 lockfile-progs python3-semantic-version sendmail-base sendmail-bin sendmail-cf zeek zeek-btest zeek-btest-data zeek-core zeek-core-dev zeek-libcaf-dev zeek-zkg zeekctl -y

## ZEEK install
apt-get install zeek -y
sed -i 's/PATH/#PATH/g' /etc/environment
echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/bin:/usr/local/games:/usr/games:/opt/zeek/bin" >> /etc/environment

## SiLK 3.19.2
mkdir silk-3.19.2 && cd silk-3.19.2
wget https://tools.netsa.cert.org/releases/silk-3.19.2.tar.gz
gzip -d -c silk-3.19.2.tar.gz | tar xf -
silk-3.19.2/configure \
--enable-data-rootdir=/data \
--prefix=/usr/local
make && make install
cd ..

## libfixbuf - YAF dependency
mkdir libfixbuf-2.4.1 && cd libfixbuf-2.4.1
wget https://tools.netsa.cert.org/releases/libfixbuf-2.4.1.tar.gz
gzip -d -c libfixbuf-2.4.1.tar.gz | tar xf -
libfixbuf-2.4.1/configure
make && make install
cd ..

## YAF
mkdir yaf-2.12.2 && cd yaf-2.12.2
wget https://tools.netsa.cert.org/releases/yaf-2.12.2.tar.gz
gzip -d -c yaf-2.12.2.tar.gz | tar xf -
yaf-2.12.2/configure
make && make install
cd ..
ldconfig

## OpenSSH
apt-get install ssh -y
service ssh start
systemctl enable ssh

## SSHPass
apt-get install sshpass -y

## Open-VM-tools
apt-get install open-vm-tools-desktop -y


## IDA and Dependencies
dpkg --add-architecture i386
apt-get update
apt-get install libc6-i686:i386 libexpat1:i386 libffi6:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libice6:i386 libpcre3:i386 libpng16-16:i386 libsm6:i386 libstdc++6:i386 libuuid1:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxrender1:i386 zlib1g:i386 libx11-xcb1:i386 libdbus-1-3:i386 libxi6:i386 libsm6:i386 libcurl3:i386 -y
apt-get install libgtk2.0-0:i386 gtk2-engines-murrine:i386 gtk2-engines-pixbuf:i386 libpango1.0-0:i386 -y
mkdir ida && cd ida
wget https://out7.hex-rays.com/files/idafree77_linux.run
chmod +x idafree77_linux.run
./idafree77_linux.run --mode unattended
ln -s /opt/idafree-7.7/ida64 /usr/bin/


## Startup Service
mv /usr/tmp/startup.service /etc/systemd/system/
chmod +x /usr/tmp/change_hostname.sh
systemctl enable startup.service
cd

## Background Symlink
mv /usr/tmp/PC2022-Kali-Background-4k.jpg /usr/share/backgrounds/kali-16x9/
unlink /usr/share/backgrounds/kali-16x9/default
ln -s /usr/share/backgrounds/kali-16x9/PC2022-Kali-Background-4k.jpg /usr/share/backgrounds/kali-16x9/default
cd

## Move Read Me to Desktop
mv /usr/tmp/tools_README.txt /home/user/Desktop/

## SSH Keys
cd /home/user/
mkdir .ssh
cd /home/user/.ssh/
touch authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDjVXoJbu3oG6dHnmYRX0sN9Ua23zmmU4JtPcv4KZaTPVx2uAmkqP2mg4VD+wztMwc6XD3uvNaGtrOlY6XB4wBhfTK6LoTti7lM+JzyFG/N27eM/4oGZuPA+zxVmWIy8jIAvjWyf5eg74NjyTJygcH+Gg+vfQvr1BVlUjLDVepmlEf9Dt3k2OJSz1jjuzp9rWuZiIoNvPUTgO86J7hl4upxluiOcglRjniHi0Mp5pJKskU208H5162cDpXc1SyiWErcZFDBwr9YPT48uFor4L7pc6RtUMzZdo57T0Dg+zPSqBaobzGxQg6MzBbtkXknMpkeLJPN+Zbg6X7gnfHCuDRrEkmcOVboK/cs65HW7aCENZ8QxlMkPx1O0UWPs2TDuZJcYH5VByuFVR8q0PnK8D2cT1xIKc8JPrDZoCoGpELlhs7MOlGJxDwvfFZlBraAi2rqwvLEheaR7jAuwR1vjdsdFNOo9EvUlJ9yH77MLE9N4SshqgurLLRlgv5GesWYLR8= user@challenge" >> /home/user/.ssh/authorized_keys


## Auto Login
echo "[Seat:*]\nautologin-user=user\nautologin-user-timeout=0" > /etc/lightdm/lightdm.conf

## Launch Firefox
# firefox &
# sleep 30s
# pkill -f firefox

## Add Cert
cp /usr/tmp/challenge-root-ca.pem /usr/local/share/ca-certificates/challenge-root-ca.crt
update-ca-certificates

## Add Cert to Firefox
python /usr/tmp/firefox_cert.py

# defaultFirefox=$(find ~/.mozilla/firefox -name "*.default")
# defaultESRFirefox=$(find ~/.mozilla/firefox -name "*.default-esr")
#
# sudo apt-get install libnss3-tools
# certutil -A -n "Challenge Cert" -t "TC,," -i /usr/tmp/challenge-root-ca.pem -d sql:$defaultFirefox
# certutil -A -n "Challenge Cert" -t "TC,," -i /usr/tmp/challenge-root-ca.pem -d sql:$defaultESRFirefox


## Remove SMBus Host Controller Error from Boot
echo "blacklist i2c-piix4" >> /etc/modprobe.d/blacklist.conf


#####################
##### Cleanup #######
#####################
apt-get autoremove -y
apt-get -y autoclean
apt-get -y clean
