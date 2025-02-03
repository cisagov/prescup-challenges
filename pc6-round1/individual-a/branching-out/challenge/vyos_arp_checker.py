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


import paramiko, re, sys, time, subprocess, platform, logging

# -------------------- Configuration --------------------
HOST = "192.168.1.1"         # IP address of the VyOS router
PORT = 22                    # SSH port (default is 22)
USERNAME = "user"            # SSH username
PASSWORD = "tartans"         # SSH password
INTERFACE = "eth2"           # Interface to check ARP entries on
PING_COUNT = 2               # Number of ping packets to send
PING_TIMEOUT = 3             # Timeout in seconds for each ping
TARGET_IPS = ["192.168.2.11", "192.168.2.12"]  # The two IPs to look for
# -------------------------------------------------------

# Configure basic logging
logging.basicConfig(
    filename='/var/log/gradingCheck.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
    )

def ping_host(host, count=PING_COUNT, timeout=PING_TIMEOUT):
    """
    Pings the specified host to check its availability.

    :param host: IP address or hostname to ping
    :param count: Number of ping packets to send
    :param timeout: Timeout in seconds for each ping
    :return: True if host is reachable, False otherwise
    """
    try:
        # Determine the ping command based on the OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # For timeout option, different in Windows and Unix
        if platform.system().lower() == 'windows':
            timeout_param = '-w'
            timeout_ms = str(timeout * 1000)  # Windows expects timeout in milliseconds
            command = ['ping', param, str(count), timeout_param, timeout_ms, host]
        else:
            timeout_param = '-W'
            command = ['ping', param, str(count), timeout_param, str(timeout), host]

        logging.info(f"Pinging {host} with {count} packets...")
        # Execute the ping command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Check the return code
        if result.returncode == 0:
            logging.info(f"Ping to {host} successful.")
            return True
        else:
            logging.info(f"Ping to {host} failed.")
            return False
    except Exception as e:
        logging.error(f"Error during ping: {e}")
        return False

def get_arp_entries(host, port, username, password, interface):
    """
    Connects to the VyOS router via SSH and retrieves ARP entries for the specified interface.

    :param host: IP address or hostname of the VyOS router
    :param port: SSH port (usually 22)
    :param username: SSH username
    :param password: SSH password
    :param interface: Network interface to check ARP entries on (e.g., 'eth2')
    :return: List of unique IP addresses found in ARP entries or False on failure
    """
    try:
        # Initialize the SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logging.info(f"Connecting to {host}:{port} as {username}...")
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10)
        logging.info("Connection established.")

        # Open a shell
        shell = ssh.invoke_shell()
        time.sleep(5)  # Wait for the shell to be ready

        # Clear the buffer
        if shell.recv_ready():
            shell.recv(65535)

        # Send the command
        command = f"show arp interface {interface} | no-match '(incomplete)' | no-more\n"
        logging.info(f"Executing command: {command.strip()}")
        shell.send(command)
        time.sleep(5)  # Wait for the command to execute

        # Receive the output
        output = ""
        while shell.recv_ready():
            output += shell.recv(65535).decode('utf-8')
            time.sleep(5)

        ssh.close()
        logging.info("SSH connection closed.")

        # Parse the output for IP addresses
        ip_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
        ips = ip_pattern.findall(output)

        # Remove duplicates by converting to a set
        unique_ips = list(set(ips))
        logging.info(f"Found IP addresses: {unique_ips}")

        return unique_ips

    except paramiko.AuthenticationException:
        logging.error("Authentication failed, please verify your credentials.")
        return False
    except paramiko.SSHException as sshException:
        logging.error(f"Unable to establish SSH connection: {sshException}")
        return False
    except Exception as e:
        logging.error(f"Operation error: {e}")
        return False

def check_arp_entries(ips, target_ips=TARGET_IPS):
    """
    Checks if the specified IP addresses are found in the list.

    :param ips: List of IP addresses from the ARP table
    :param target_ips: List of target IPs to look for
    :return: True if both target IPs are found, False otherwise
    """
    if not isinstance(ips, list):
        logging.error("Invalid IP list provided.")
        return False

    # Check if both target IPs are in the ARP list
    missing_ips = [ip for ip in target_ips if ip not in ips]

    if not missing_ips:
        logging.info(f"SUCCESS: Both target IPs {target_ips} found in ARP entries.")
        return True
    else:
        logging.info(f"FAILURE: Missing IP addresses: {missing_ips}")
        return False

def check_vyos_arp():
    """
    Performs the ping test and ARP entry check.

    :return: True if all checks pass, False otherwise
    """
    # Step 1: Ping Test
    if not ping_host(HOST):
        logging.error("FAILURE: Unable to reach the VyOS router via ping.")
        return False

    # Step 2: Get ARP entries only if ping was successful
    ips = get_arp_entries(HOST, PORT, USERNAME, PASSWORD, INTERFACE)

    # If get_arp_entries returned False due to an error, treat it as failure
    if ips is False:
        logging.error("FAILURE: Error retrieving ARP entries.")
        return False

    # Step 3: Check the number of IPs
    return check_arp_entries(ips, target_ips=TARGET_IPS)

def main():
    success = check_vyos_arp()

    if success:
        sys.exit(0)  # Exit with code 0 for success
    else:
        sys.exit(1)  # Exit with code 1 for failure

if __name__ == "__main__":
    main()