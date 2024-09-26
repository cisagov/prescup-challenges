
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import re

message_directory = '/home/user/c21/messages/'
output_directory = '/home/user/c21/output/'
status_file = '/home/user/c21/status.txt'

status = '0'

for filename in os.listdir(message_directory):
    if filename.endswith('.txt'):
        message_file_path = os.path.join(message_directory, filename)

        with open(message_file_path, 'r') as message_file:
            message_content = message_file.read()

        if 'To: user@merch.codes' not in message_content:
            status = max(status, '0')
            continue

        if 'Sender: it-admin@merch.codes' not in message_content:
            status = max(status, '1')
            continue
            
        target_link = 'http://yourfiles.zip'

        if target_link not in message_content:
            status = max(status, '2')
            continue

        output_file_path = os.path.join(output_directory, filename)
        os.rename(message_file_path, output_file_path)
        print(f"Matching message found: {filename} - Saved to: {output_file_path}")

	
file_list = os.listdir(output_directory)
if file_list:
   status = '3'

with open(status_file, 'w') as file:
    file.write(status)

if not file_list:
    exit()
