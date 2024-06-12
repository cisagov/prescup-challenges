#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


input_file="$1"

file_size=$(wc -c < "$input_file")
chunk_size=$(( ( file_size + 2 ) / 3))

split -b "$chunk_size" "$input_file" chunk
mv chunkaa /usr/bin/.a1234
mv chunkab /var/lib/.b5ef6
mv chunkac /etc/cups/.c789e


