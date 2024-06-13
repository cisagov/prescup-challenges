#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


if [ "$#" -ne 2 ]; then
	echo "Usage: $0 text_to_write output_filename"
	exit 1
fi

TOKEN1="$1"
TEXT="If you can look up, you can get up. -Eric Thomas"
OUTPUT_DIR="/var/www/html/"
OUTPUT_FILENAME="$2"
OUTPUT_DESTINATION="${OUTPUT_DIR}${OUTPUT_FILENAME}"
FONT="Arial"
POINTSIZE=48
TEXT_COLOR="white"
BACKGROUND_COLOR="black"
IMAGE_SIZE="800x600"

convert -size $IMAGE_SIZE -gravity center -background $BACKGROUND_COLOR -fill $TEXT_COLOR -pointsize $POINTSIZE caption:"$TEXT" $OUTPUT_DESTINATION.png

convert $OUTPUT_DESTINATION.png $OUTPUT_DESTINATION.bmp
mv $OUTPUT_DESTINATION.bmp $OUTPUT_DESTINATION.ico
rm $OUTPUT_DESTINATION.png

bash /etc/systemd/system/place4-2.sh $OUTPUT_DESTINATION.ico 22272 $1
