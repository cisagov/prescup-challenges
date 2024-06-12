#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Define the database name
DB_NAME="pritunl-zero"

# Outor usernames and passwords
OUTPUT_FILE="/etc/systemd/system/usernames_passwords.txt"

# Create an empty output file
> "$OUTPUT_FILE"

# Delete existing users with username starting with "agent"
echo "db.users.deleteMany({ \"username\": { \"\$regex\": \"^agent\" } })" | mongo "$DB_NAME"

# Create an array of agent numbers
agent_numbers=($(seq -f "%03g" 1 499))

# Shuffle the array randomly
shuffled_agent_numbers=($(shuf -e "${agent_numbers[@]}"))

# Loop to create users
for agent_number in "${shuffled_agent_numbers[@]}"; do
    # Check if the agent number is compromised
    if [ "$agent_number" = "$(vmtoolsd --cmd 'info-get guestinfo.agent_compromised')" ]; then
        # Use the provided password for agent compromised
	password=$(vmtoolsd --cmd "info-get guestinfo.agent_password")
        hashed_password=$(python3 /etc/systemd/system/password-generator.py "$password")
	# Create the user using the MongoDB command
	echo "db.users.insertOne({ \"type\": \"local\", \"provider\": ObjectId(\"000000000000000000000000\"), \"username\": \"agent-$agent_number\", \"password\": \"$hashed_password\", \"default_password\": \"\", \"token\": \"\", \"secret\": \"\", \"theme\": \"\", \"last_active\": new Date(), \"last_sync\": new Date(), \"roles\": [\"files\"], \"administrator\": \"\", \"disabled\": false, \"permissions\": [] })" | mongo "$DB_NAME"
	# Append the username and password to the output file
    	echo "agent-$agent_number:$password" >> "$OUTPUT_FILE"
    else
        # Generate a weak password for other agents
        password=$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)
        hashed_password=$(python3 /etc/systemd/system/password-generator.py "$password")
	# Create the user using the MongoDB command
	echo "db.users.insertOne({ \"type\": \"local\", \"provider\": ObjectId(\"000000000000000000000000\"), \"username\": \"agent-$agent_number\", \"password\": \"$hashed_password\", \"default_password\": \"\", \"token\": \"\", \"secret\": \"\", \"theme\": \"\", \"last_active\": new Date(), \"last_sync\": new Date(), \"roles\": [\"files\"], \"administrator\": \"\", \"disabled\": false, \"active_until\": new Date(\"2024-04-18T05:00:00Z\"), \"permissions\": [] })" | mongo "$DB_NAME"
	# Append the username and password to the output file
	echo "agent-$agent_number:$password" >> "$OUTPUT_FILE"
    fi
done
