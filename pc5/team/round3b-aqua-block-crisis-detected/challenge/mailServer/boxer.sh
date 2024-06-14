#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Define file paths
input_file="working.txt"
temp_file="current_email.txt"

for a in /home/*/mbox; do cat /dev/null | sudo tee $b; done 

for b in /home/*/.sent*; do cat /dev/null | sudo tee $b; done 

for g in /home/*/.bash_history; do rm -rf $g; done

for i in /var/mail/*; do cat /dev/null | sudo tee $i; done 


# Iterate over the reformatted emails file
while IFS= read -r line; do

    # Correct the From field to include the day
    if [[ $line == From\ user@* ]]; then
        day=$(date -d "$(echo "$line" | cut -d' ' -f4-7)" +"%a")
        line=$(echo "$line" | sed "s/From user/From user@$day/")
    fi

    # When we encounter the "Delivered-To:" field, extract the username
    if [[ $line == Delivered-To:*@dam.local ]]; then
        username="${line#Delivered-To: }"
        username="${username%@*}"
        username=$(echo "$username" | tr '[:upper:]' '[:lower:]')  # Convert to lowercase
    fi

    if [[ $line == *Delivered-To:* ]] && ! [[ $line == *Delivered-To:*@dam.local ]]; then
        username=""
    fi

    # Write the current line to a temporary email file
    echo "$line" >> "$temp_file"

    # When we encounter a blank line after the email body, append the temp email to the appropriate mailbox
    if [[ -z $line && -s $temp_file ]]; then
        cat "$temp_file" >> "/var/mail/$username"
        echo "Email appended to /var/mail/$username"
        rm "$temp_file"   # Clear the temporary file for the next email
    fi

done < "$input_file"

# Remove the temporary email file if it exists at the end of the script
rm -f "$temp_file"


