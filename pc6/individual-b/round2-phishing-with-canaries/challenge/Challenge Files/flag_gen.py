#!/usr/bin/python3

import random
import os
import time

def random_hex_bytes(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def main():
    # Check if valid_emails.txt already exists
    if os.path.exists('valid_emails.txt'):
        print("Error: valid_emails.txt already exists. Exiting.")
        return

    # Wait for phish.txt to exist
    while not os.path.exists('phish.txt'):
        print("Waiting for phish.txt to be created...")
        time.sleep(5)

    # Define a list of words to use for user-agent strings
    words = ["TOKEN-1: 676f", "TOKEN-2: 7068", "TOKEN-3: 6973", "TOKEN-4: 6869", "TOKEN-5: ##phish##"]

    # Read the content of phish.txt
    with open('phish.txt', 'r') as file:
        phish_content = file.read().strip()

    # Replace ##phish## with the content of phish.txt
    words = [word.replace("##phish##", phish_content) for word in words]

    # Generate a list of user numbers and shuffle it
    user_numbers = list(range(1, 100))  # Start from 1 to exclude 0
    random.shuffle(user_numbers)

    # Generate 95 lines with the same provided string
    provided_string = "nope"
    common_lines = [f"user{str(user_numbers[i]).zfill(4)}@internal, {provided_string}/1.0 {str(user_numbers[i]).zfill(4)}@internal" for i in range(94)]

    # Add the fixed entry for user0000
    fixed_entry = "user0000@internal, clck/1.0 0000@internal"
    common_lines.insert(0, fixed_entry)

    # Generate 5 unique entries using the words
    unique_lines = [f"user{str(user_numbers[i + 94]).zfill(4)}@internal, {words[i % len(words)]}/1.0 {str(user_numbers[i + 94]).zfill(4)}@internal" for i in range(5)]

    # Sort the unique lines based on the user number
    unique_lines.sort(key=lambda x: int(x.split('@')[0][4:]))

    # Write the common lines to valid_emails.txt
    with open('valid_emails.txt', 'w') as f:
        for line in common_lines:
            f.write(line + '\n')

    # Append the unique lines to valid_emails.txt
    with open('valid_emails.txt', 'a') as f:
        for line in unique_lines:
            f.write(line + '\n')

if __name__ == "__main__":
    main()
