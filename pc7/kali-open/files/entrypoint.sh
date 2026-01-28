#!/bin/bash

#xfdesktop works, but slams the log full of messages, without dbus
mkdir -p /run/dbus
# start system bus 
/usr/bin/dbus-daemon --system --address=unix:path=/run/dbus/system_bus_socket --nofork --nopidfile &

# Update desktop background
/usr/share/backgrounds/kali-16x9/pccc/update.sh

# Create file with the VNC_PASS
#   If blank password, don't create the pass file
VNC_PASS_FILE=/opt/vnc.pass
if [ -n "$DYNAMIC_VNC_PASS" ]; then
    printf "%s\n" "$DYNAMIC_VNC_PASS" | vncpasswd -f > "$VNC_PASS_FILE"
    chmod +r "$VNC_PASS_FILE"
fi


# Drop privs and run gui
exec sudo -u user WEB_SOCK_CERT="$WEB_SOCK_CERT" TZ="$TZ" VNC_PASS_FILE="$VNC_PASS_FILE" /start-gui.sh
