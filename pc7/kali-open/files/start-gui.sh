#!/bin/bash

# clean up any stale sockets/locks
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1
mkdir -p /tmp/.X11-unix

export DISPLAY=:1

# Start TigerVNC X server (port 5901). noVNC will bridge it to 6080.
#   If a password file exists, start with auth. Else, don't.
if [ -f "$VNC_PASS_FILE" ]; then
  Xvnc :1 -geometry 1920x1080 -depth 24 -localhost -AlwaysShared \
    -SecurityTypes VncAuth -PasswordFile "$VNC_PASS_FILE" &
else
  Xvnc :1 -geometry 1920x1080 -depth 24 -localhost -AlwaysShared \
    -SecurityTypes None &
fi

# Wait for X socket to exist (race-free)
for i in {1..50}; do
  [ -S /tmp/.X11-unix/X1 ] && break
  sleep 0.1
done

# Start XFCE desktop (session bus)
eval "$(dbus-launch --sh-syntax)"

elogind --daemon

startxfce4 &

# wait (briefly, max ~5s) until the session is up
for i in {1..25}; do pgrep -xu "$USER" xfce4-session >/dev/null && break; sleep 0.2; done

# X server saver/DPMS off
xset s off -dpms 2>/dev/null || true

# We are so fast now! Need to slow down just a second so the desktop actually loads!
sleep 3

# Bridge VNC -> WebSocket on 6080 (bind all)
CMD="exec /usr/share/novnc/utils/novnc_proxy --vnc localhost:5901 --listen 0.0.0.0:6080"

if [ -n "$WEB_SOCK_CERT" ]; then
    CMD="$CMD --cert $WEB_SOCK_CERT"
fi

eval "$CMD"
