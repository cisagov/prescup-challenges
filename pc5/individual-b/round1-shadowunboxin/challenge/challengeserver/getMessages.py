
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os

inbox_file_path = '/home/user/c36/inbox'
output_directory = '/home/user/c36/messages/'

# read the inbox file and find the ID of the last message
with open(inbox_file_path, 'r') as inbox_file:
    inbox_content = inbox_file.read()

# split inbox records
message_records = inbox_content.split("From customer@merch.codes")

# Remove empty records
if message_records[0].strip() == "":
    message_records = message_records[1:]
    
# save each message
for index, message_record in enumerate(message_records):
    message = "From customer@merch.codes" + message_record.strip()
    
    message_file_path = os.path.join(output_directory, f'message_{index+1}.txt')
    
    with open(message_file_path, 'w') as message_file:
        message_file.write(message_record.strip())
        
    print(f"Message {index+1} saved to: {message_file_path}")

