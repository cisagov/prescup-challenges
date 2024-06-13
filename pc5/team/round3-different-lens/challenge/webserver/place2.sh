#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


if [ "$#" -ne 1 ]; then
	echo "Usage: $0 \"Text to convert into the image\""
	exit 1
fi

TEXT="$1"
OUTPUT_DIR="/var/www/html/"
OUTPUT_FILENAME="security.txt"
OUTPUT_DESTINATION="${OUTPUT_DIR}${OUTPUT_FILENAME}"
FONT="Arial"
POINTSIZE=48
TEXT_COLOR="white"
BACKGROUND_COLOR="black"
IMAGE_SIZE="800x600"

convert -size $IMAGE_SIZE -gravity center -background $BACKGROUND_COLOR -fill $TEXT_COLOR -pointsize $POINTSIZE caption:"$TEXT" token4.png
xxd -p token4.png | rev > $OUTPUT_DESTINATION
