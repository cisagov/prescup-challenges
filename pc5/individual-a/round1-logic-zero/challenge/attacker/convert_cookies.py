
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/bin/python3

import sqlite3
import shutil

source_file = '/home/user/.mozilla/firefox/1e84sk97.default-esr/cookies.sqlite'
destination_file = '/home/user/cookies.sqlite'

shutil.copyfile(source_file, destination_file)

# Open and close Firefox to ensure cookies are written to db
import subprocess

bash_command_1 = 'firefox &'
bash_command_2 = 'sleep 10 && pkill firefox'

# Run the Bash command
result = subprocess.run(bash_command_1, shell=True)
result = subprocess.run(bash_command_2, shell=True)

# Open the cookies.sqlite file
conn = sqlite3.connect("/home/user/cookies.sqlite")
cursor = conn.cursor()

# Query the cookies table
cursor.execute("SELECT host, path, isSecure, expiry, name, value FROM moz_cookies")

# Write cookies to the cookie.txt file
with open("/home/user/cookies.txt", "w") as file:
    for row in cursor.fetchall():
        host, path, isSecure, expiry, name, value = row
        file.write(f"{host}\t{isSecure}\t{path}\t{isSecure}\t{expiry}\t{name}\t{value}\n")

# Close the database connection
conn.close()

