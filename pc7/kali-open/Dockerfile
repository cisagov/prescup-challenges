FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install default Kali tools
RUN apt update && apt -y full-upgrade
RUN apt install -y kali-linux-default 

# Install desktop environment and tools
# Graphics/VNC, and dbus to keep xfce from spamming logs with "not found" errors
RUN apt update && apt install -y kali-desktop-xfce xfce4-goodies dbus-x11 tigervnc-standalone-server novnc websockify 
RUN apt install -y dbus-x11 dbus && dbus-uuidgen --ensure=/etc/machine-id

# Create a non-root user for VNC access
RUN useradd -m -s /bin/bash user && \
    echo 'user:password' | chpasswd && \
    adduser user sudo

ENV USER=user
# USER user # Now I start as root and drop privs instead
WORKDIR /home/user

RUN mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix

# Expose browser port
EXPOSE 6080

# ----- Tools -----

############################### 
### System / Administration 
###############################
RUN apt install -y sudo python3-pip unzip zbar-tools

# Disable the external management; venv is not practical or necessary for a temporary CTF box
RUN python3 -m pip config set global.break-system-packages true && \
    sudo -u user python3 -m pip config set global.break-system-packages true

############################### 
### Networking & Communication
###############################
RUN apt install -y firefox-esr inetutils-ping curl python3-pymodbus python3-rpyc
RUN pip install bacpypes pyasyncore requests --break-system-packages

RUN apt install -y mosquitto-clients

RUN apt install -y vsftpd
RUN pip install pyftpdlib --break-system-packages

RUN apt install -y ansible

RUN apt install -y chisel

############################### 
### Bin Exploit & Reversing 
############################### 
RUN apt install -y ghidra python3-pwntools checksec
RUN pip install ROPGadget --break-system-packages

# Install gdb-gef gdb-peda and gdb-pwndbg
# Note we start gdb-pwndbg to run the updater for it
# I wanted to give them all the main ones, but peda is too old and breaks with Python3, so just scrap it
RUN cd /opt && pip install six --break-system-packages && \
    git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef.git && \
    cd gdb-peda-pwndbg-gef && \
    HOME=/home/user ./install.sh && \
    cd /opt && rm -rf gdb-peda-pwndbg-gef && \
    rm -rf /home/user/peda /home/user/peda-arm /usr/bin/gdb-peda && \
    echo "alias gdb='gdb-gef'" >> /home/user/.bashrc && \
    chown user:user -R /home/user/.bashrc /home/user/.cache /home/user/pwndbg /home/user/gef && \
    echo "q" | sudo -u user gdb-pwndbg

############################### 
### Editors and Programming Languages 
###############################
# VSCode is complex, so it has its own block at the end
RUN apt install -y rustc cargo
RUN apt install -y gedit nano jq
RUN pip install pyyaml --break-system-packages

# Added a -q to stop overly verbose progress bars
RUN wget -q https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
RUN rm -f go1.25.1.linux-amd64.tar.gz
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go
USER user
RUN mkdir -p /home/user/tf-go-mod
WORKDIR /home/user/tf-go-mod
RUN go mod init tf-go
RUN go get github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema
RUN go get github.com/hashicorp/terraform-plugin-sdk/v2/plugin
USER root
WORKDIR /home/user

###############################
### Forensics & Stego
###############################
RUN pip install git-dumper --break-system-packages
RUN apt install -y hashalot
RUN apt install -y sleuthkit autopsy

RUN apt install -y foremost && pip install volatility3 --break-system-packages

RUN apt install -y mtools

## Autopsy v4
# Unsure if we can get this to work without JDK 17, which is no longer in Kali's packaging
# RUN apt install -y unzip curl \
#     && mkdir -p /opt/autopsy \
#     && curl -L -o /tmp/sleuthkit-java_4.14.0-1_amd64.deb https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-java_4.14.0-1_amd64.deb \
#     && curl -L -o /tmp/autopsy.zip https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.22.1/autopsy-4.22.1_v2.zip \
#     && unzip /tmp/autopsy.zip -d /opt/autopsy \
#     && apt install /tmp/sleuthkit-java_4.14.0-1_amd64.deb \
#     && rm -f /tmp/autopsy.zip /tmp/sleuthkit-java_4.14.0-1_amd64.deb \
#     && chmod +x /opt/autopsy/autopsy-4.22.1/linux_macos_install_scripts/install_application.sh \
#     && export JAVA_HOME="$(dirname $(dirname $(readlink -f $(which javac))))" \
#     && /opt/autopsy/autopsy-4.22.1/linux_macos_install_scripts/install_application.sh -i /opt/autopsy/autopsy-4.22.1 -j $JAVA_HOME \
#     && ln -sf /opt/autopsy/autopsy-4.22.1/bin/autopsy /usr/local/bin/autopsy4

RUN apt install -y steghide
RUN gem install zsteg

###############################
### VSCode
###############################
# Pretty complex and lots of extensions, so gets a block by itself
RUN apt-get update && apt-get install -y curl ca-certificates gnupg apt-transport-https \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor -o /etc/apt/keyrings/ms-vscode.gpg \
 && echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/ms-vscode.gpg] https://packages.microsoft.com/repos/code stable main" \
    > /etc/apt/sources.list.d/vscode.list \
 && apt-get update && apt-get install -y code
# Wrapper to make it work in Docker
RUN cat >/usr/local/bin/code <<'EOF' && chmod +x /usr/local/bin/code
#!/usr/bin/env bash
export DONT_PROMPT_WSL_INSTALL=1
exec /usr/bin/code --no-sandbox "$@"
EOF
# Create settings dir and apply VS Code settings
# Note the current settings just disable inline terminal suggestions,
#   a preview feature that appears to not be playing well in the Docker environment
RUN mkdir -p /home/user/.config/Code/User && \
    chown -R user:user /home/user/.config

COPY files/vscode-settings.json /home/user/.config/Code/User/settings.json
RUN chown user:user /home/user/.config/Code/User/settings.json

# VSCode extensions
RUN \
    \
    ############################### \
    ### Programming Languages + Compilers \
    ############################### \
    \
    #### Rust (compiler + cargo for local builds) \
    sudo -u user code --install-extension rust-lang.rust-analyzer && \
    sudo -u user code --install-extension tamasfe.even-better-toml && \
    \
    #### Go \
    sudo -u user code --install-extension golang.go && \
    \
    #### C / C++ \
    sudo -u user code --install-extension ms-vscode.cpptools && \
    sudo -u user code --install-extension ms-vscode.cpptools-extension-pack && \
    sudo -u user code --install-extension ms-vscode.cpptools-themes && \
    sudo -u user code --install-extension ms-vscode.cmake-tools && \
    sudo -u user code --install-extension twxs.cmake && \
    sudo -u user code --install-extension ms-vscode.makefile-tools && \
    \
    #### Python \
    sudo -u user code --install-extension ms-python.python && \
    sudo -u user code --install-extension ms-python.vscode-pylance && \
    \
    #### PHP \
    sudo -u user code --install-extension bmewburn.vscode-intelephense-client && \
    \
    #### Ruby \
    sudo -u user code --install-extension shopify.ruby-lsp && \
    \
    #### Perl \
    sudo -u user code --install-extension richterger.perl && \
    \
    ############################### \
    ### Markup / Data Languages \
    ############################### \
    \
    #### YAML / XML / JSON-adjacent \
    sudo -u user code --install-extension redhat.vscode-yaml && \
    sudo -u user code --install-extension redhat.vscode-xml && \
    \
    #### Markdown \
    sudo -u user code --install-extension yzhang.markdown-all-in-one && \
    \
    #### CSV / TSV \
    sudo -u user code --install-extension mechatroner.rainbow-csv && \
    \
    ############################### \
    ### Tools / Utilities \
    ############################### \
    \
    #### Hex editor \
    sudo -u user code --install-extension ms-vscode.hexeditor && \
    \
    #### Zip explorer \
    sudo -u user code --install-extension slevesque.vscode-zipexplorer && \
    \
    #### PDF viewer \
    sudo -u user code --install-extension tomoki1207.pdf && \
    \
    #### PowerShell (only works if PowerShell is installed!) \
    sudo -u user code --install-extension ms-vscode.powershell

# ----- End tools -----

# Copy over entrypoint script(s)
COPY files/entrypoint.sh files/start-gui.sh /
RUN chmod +x /start-gui.sh /entrypoint.sh

# Copy/set PCCC background for the good vibes! Hooray!
RUN mkdir -p /usr/share/backgrounds/kali-16x9/pccc/
COPY backgrounds/ /usr/share/backgrounds/kali-16x9/pccc/
RUN chmod +x /usr/share/backgrounds/kali-16x9/pccc/update.sh
# RUN ln -sfn /usr/share/backgrounds/kali-16x9/pccc/1.png /usr/share/backgrounds/kali-16x9/default # Now set at runtime, but can switch back if needed

# Self-signed cert for running on the prod site
RUN mkdir -p /etc/novnc
# WEB CERT REMOVED FOR LOCAL VERSION
# COPY ./websockify_novnc_self.pem /etc/novnc/websockify_novnc_self.pem
# RUN chown user:user /etc/novnc/websockify_novnc_self.pem \
#     && chmod 600 /etc/novnc/websockify_novnc_self.pem
# ENV WEB_SOCK_CERT="/etc/novnc/websockify_novnc_self.pem"

# Copy approved word list to home and Desktop directories
COPY --chown=user:user ./files/wordlist.txt /home/user/wordlist.txt
COPY --chown=user:user ./files/wordlist.txt /home/user/Desktop/wordlist.txt

ENTRYPOINT ["/entrypoint.sh"]

# Some thread limiting, added specifically for john
RUN echo 'export OMP_NUM_THREADS=16' >> /home/user/.profile \
 && echo 'export OMP_NUM_THREADS=16' >> /home/user/.bashrc \
 && chown user:user /home/user/.profile /home/user/.bashrc

# Defaults to no password for VNC
ENV DYNAMIC_VNC_PASS=
RUN apt install -y xfce4-genmon-plugin

# Allows the challenge name to show in Kali; not currently implemented
RUN echo " " > /opt/current_challenge.txt
RUN chmod +r /opt/current_challenge.txt

COPY files/challenge_panel.sh /opt/challenge_panel.sh
RUN chmod +rx /opt/challenge_panel.sh

# Fix for running wireshark from the whiskermenu
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
RUN getent group wireshark >/dev/null || groupadd wireshark
RUN usermod -aG wireshark user

# Copy over xfce4 and other GUI config files
COPY --chown=user:user user_home/ /home/user/
RUN chmod 700 /home/user \
 && find /home/user/.config /home/user/.local -type d -exec chmod 755 {} \; \
 && find /home/user/.config /home/user/.local -type f -exec chmod 644 {} \;

# Default timezone is UTC
ENV TZ="UTC"

# Overide all of the various shutdown options; provide the reset instructions
COPY ./files/kali_reset_instructions.sh /usr/local/bin/kali_reset_instructions
RUN chmod +x /usr/local/bin/kali_reset_instructions

RUN for cmd in shutdown poweroff reboot halt loginctl; do \
      ln -sf /usr/local/bin/kali_reset_instructions /usr/local/bin/$cmd; \
    done

# Busybox is a bit special; it really does kill, though, so might as well safeguard it
RUN mv /bin/busybox /bin/busybox.real \
 && cat <<'EOF' > /bin/busybox
#!/bin/sh
case "$1" in
  reboot|poweroff|halt)
    exec /usr/local/bin/kali_reset_instructions
    ;;
  *)
    exec /bin/busybox.real "$@"
    ;;
esac
EOF
RUN chmod +x /bin/busybox

# Remove these unusable apps for now
#   Long term, ettercap might work with ipv6 forwarding enabled, but short term is removal
#   ammass could be fixed by simply running it once to download the files it needs, but that adds nearly 2 gigs! For something that almost certainly won't be used 
#   recon-ng has no modules installed. Like amass, likely not gonna be used, just uninstall
RUN apt remove -y ettercap-graphical ettercap-text-only blueman amass recon-ng gophish

# Fix Chromium by redirecting to version with no sandbox
RUN cat >/usr/local/bin/chromium <<'EOF' && chmod +x /usr/local/bin/chromium
#!/usr/bin/env bash
export DONT_PROMPT_WSL_INSTALL=1
exec /usr/bin/chromium --no-sandbox "$@"
EOF

RUN updatedb

# Let's us run some applications like zenmap from the start menu seamlessly
RUN apt install -y ssh-askpass-gnome
