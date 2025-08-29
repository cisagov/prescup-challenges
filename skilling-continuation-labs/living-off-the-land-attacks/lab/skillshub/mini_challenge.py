#!/usr/bin/python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, base64, logging, subprocess

# Define Static Variables 
username = 'jarren' # Username to connect to remote system with 
password = 'renounce-overpass7-residue' # Password to connect to remote system with 
host = '10.2.2.151' # IP of server connecting to 

# Configure basic logging 
logging.basicConfig(
    filename='/var/log/mini_challenge.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s %(message)s'
)

# Get Transform Value
random_value = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.token3'", shell=True, capture_output=True).stdout

# Define the PowerShell command that echoes the random value
powershell_command = f'Write-Output "Secret Token: {random_value}"'

# Encode the PowerShell command in Base64 (UTF-16LE encoding required)
encoded_command = base64.b64encode(powershell_command.encode("utf-16le")).decode()

# Construct the full command to execute PowerShell with Base64 decoding
full_command = f"pwsh -EncodedCommand {encoded_command}"

try:       
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password, timeout=15) # Connect to remote system via username and password, timeout after 15 seconds
    logging.info(f"Connecting to host: {host}")

    # Execute the PowerShell command
    logging.info(f"Executing PowerShell command on {host}")
    stdin, stdout, stderr = ssh.exec_command(full_command)

    # Capture the output
    output = stdout.read().decode().strip()
    error_output = stderr.read().decode().strip()

    # Log output and errors
    if output:
        logging.info(f"PowerShell Command Output: {output}")
    if error_output:
        logging.error(f"PowerShell Command Error: {error_output}")

    # Close the SSH connection
    ssh.close()
    logging.info("SSH connection closed")


except Exception as e: 
    logging.error(f"Grading Check Error on {host}: Error Message is {e}")
