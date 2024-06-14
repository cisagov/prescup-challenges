#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


if [ "$#" -ne 2 ]; then
	echo "Usage: $0 text_to_write output_filename"
	exit 1
fi

TOKEN1="$1"
TEXT="When you look for happiness in mere objects, they are never enough. Look around. Look within. -Nick Vujicic"
OUTPUT_DIR="/var/www/html/quotes/"
OUTPUT_FILENAME="$2"
OUTPUT_DESTINATION="${OUTPUT_DIR}${OUTPUT_FILENAME}"
FONT="Arial"
POINTSIZE=48
TEXT_COLOR="white"
BACKGROUND_COLOR="black"
IMAGE_SIZE="800x600"

convert -size $IMAGE_SIZE -gravity center -background $BACKGROUND_COLOR -fill $TEXT_COLOR -pointsize $POINTSIZE caption:"$TEXT" /home/user/$2.png

convert /home/user/$2.png -gravity northeast -pointsize 20 -fill white -annotate +10+10 $TOKEN1 $OUTPUT_DESTINATION.png

convert $OUTPUT_DESTINATION.png $OUTPUT_DESTINATION.bmp

rm $OUTPUT_DESTINATION.png

printf '\x02\x02' | sudo dd of=$OUTPUT_DESTINATION.bmp bs=1 seek=22 count=2 conv=notrunc
