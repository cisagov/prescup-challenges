#!/bin/bash -e

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

export DISPLAY=:0.0
export XAUTHORITY=/home/user/.Xauthority
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
gsettings set org.gnome.desktop.background primary-color "#000000"
gsettings set org.gnome.desktop.background secondary-color "#000000"
gsettings set org.gnome.desktop.background color-shading-type "solid"
gsettings set org.gnome.desktop.background picture-uri "file:////usr/share/backgrounds/kali-16x9/PC2022-Kali-Background-4k.jpg"
gsettings set org.gnome.desktop.screensaver picture-uri "file:////usr/share/backgrounds/kali-16x9/PC2022-Kali-Background-4k.jpg"
gsettings set org.gnome.desktop.background picture-options scaled
xfconf-query -c xfce4-desktop --list | grep "/last-image" | xargs --replace="{}" xfconf-query --channel xfce4-desktop --property {}
xfconf-query -c xfce4-desktop --list | grep "/last-image" | xargs --replace="{}" xfconf-query --channel xfce4-desktop --property {} --set /usr/share/backgrounds/kali-16x9/PC2022-Kali-Background-4k.jpg
xfconf-query -c xfce4-desktop --list | grep "/last-image" | xargs --replace="{}" xfconf-query --channel xfce4-desktop --property {} --set /usr/share/backgrounds/kali-16x9/default
xfconf-query -c xfce4-desktop --list | grep "/last-image" | xargs --replace="{}" xfconf-query --channel xfce4-desktop --property {} --set /usr/share/backgrounds/kali-16x9/PC2022-Kali-Background-4k.jpg
