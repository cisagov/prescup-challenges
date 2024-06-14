#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


WORDS=("SALE" "COUPON" "10FOR2" "HIT" "SAVINGS" "SAVE" "FREEDELIVERY")
NUM_WORDS=${#WORDS[@]}
COUPONS_FILE="coupons.txt"

# Function to generate a random coupon
generate_coupon() {
    # Randomly select a word
    word_index=$((RANDOM % NUM_WORDS))
    word="${WORDS[word_index]}"

    # Generate a random number between 1000 and 9999
    number=$((RANDOM % 9000 + 1000))

    # Generate additional random characters
    extra_chars=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 4)

    # Combine the word, number, and extra characters
    coupon="${word}${number}${extra_chars}"

    echo "$coupon"
}

# Generate 1000 random coupons and save to file
for ((i=0; i<1000; i++)); do
    coupon=$(generate_coupon)
    echo "$coupon" >> "$COUPONS_FILE"
done

echo "Coupons generated and saved to $COUPONS_FILE"

