#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Function to shift character by one in the alphabet
shift_char() {
    local char="$1"
    if [[ $char =~ [a-zA-Z] ]]; then
        # Handle uppercase and lowercase separately
        if [[ $char == [A-Z] ]]; then
            echo "$char" | tr 'A-Z' 'ZABCDEFGHIJKLMNOPQRSTUVWXY'
        else
            echo "$char" | tr 'a-z' 'zabcdefghijklmnopqrstuvwxy'
        fi
    else
        # Non-alphabetic characters remain unchanged
        echo "$char"
    fi
}

# Check for correct number of arguments
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <file_path> <starting_offset> <word>"
    exit 1
fi

file_path="$1"
offset="$2"
word="$3"

# Calculate the length of the word
word_length=${#word}

# Iterate over each character of the word in reverse order
for (( i=0; i<word_length; i++ )); do
    # Calculate the position to insert the character
    position=$((offset - i * 16))

    # Extract the character
    char="${word:i:1}"

    # Shift the character by one in the alphabet
    shifted_char=$(shift_char "$char")

    # Convert the shifted character to ASCII and write it to the file at the specified position
    printf "%b" "\\$(printf '%03o' "'$shifted_char'")" | dd of="$file_path" bs=1 seek="$position" count=1 conv=notrunc 2> /dev/null
done

echo "Word inserted in reverse and shifted order starting at offset $offset."
