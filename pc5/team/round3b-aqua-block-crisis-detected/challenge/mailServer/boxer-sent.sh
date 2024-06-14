#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Define file paths
input_file="working.txt"
temp_file="current_email.txt"


# Iterate over the reformatted emails file
while IFS= read -r line; do

    # When we encounter the "From " field, extract the username
        if [[ $line == From\ *@dam.local* ]]; then
    	username="${line#From }"
        username="${username%@*}"
        username=$(echo "$username" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    fi

    #if [[ $line == From\ * ]] && ! [[ $line == From\ *@dam\.local ]]; then
    #    username=""
    #fi

    # Write the current line to a temporary email file
    echo "$line" >> "$temp_file"

    # When we encounter a blank line after the email body, append the temp email to the appropriate mailbox
    if [[ -z $line && -s $temp_file ]]; then
        cat "$temp_file" >> "/home/$username/.sent_archive"
        echo "Email appended to /home/$username/.sent_archive"
        rm "$temp_file"   # Clear the temporary file for the next email
    fi

done < "$input_file"

# Remove the temporary email file if it exists at the end of the script
rm -f "$temp_file"


