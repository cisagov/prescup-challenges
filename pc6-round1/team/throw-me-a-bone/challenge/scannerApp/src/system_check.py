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

import paramiko, re, subprocess, logging

# Configure basic logging
logging.basicConfig(filename='/var/log/scannerApp.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Define Static Variables
username = 'scanuser' # Username to connect to remote system with
password = '2th3st@rs' # Password to connect to remote system with
user_list = ['lrobinson', 'eclark', 'awright', 'sscott', 'dgreen', 'hcarter'] # Define list of usernames to check if present on a given system


def validate_and_check_host(ip):
    '''
    This function takes a user provided input and verifies that it is a valid IPv4 address.
    It then checks if the IP address responds to ICMP in the environment.
    If both are true, the IP is passed to the check_system function. If false, returns an error.
    '''
    result = {"valid_ip": True, "online": True, "error": None}

    logging.info(f"User provided IP address is: {ip}")

    # Verify provided input is a valid IPv4 address
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip):
        result["valid_ip"] = False
        logging.warn(f"The entered IP address {ip} is not valid")
        return result

    # Use ping to verify host is online
    try:
        ping_result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ping_result.returncode != 0:
            result["online"] = False
            logging.warn(f"{ip} cannot be reached via ping")
    except Exception as e:
        result["error"] = str(e)
        logging.error(f"Ping failed to {ip}: {e}")
    return result


def check_system(ip):
    result = {"rootLogin": None, "users": {}, "homeDir": {}, "passwdPerm": None, "shdwPerm": None, "error": None}

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15) # Connect to remote system via username and password, timeout after 15 seconds
        logging.info(f"Conecting to host: {ip}")

        # Check if PermitRootLogin is still configured
        stdin, stdout, stderr = ssh.exec_command("(sudo egrep -q '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config && echo fail) || (sudo egrep -q '^\s*#\s*PermitRootLogin\s+' /etc/ssh/sshd_config && echo pass) || echo pass")
        root_output = stdout.read().decode().strip()
        logging.info(f"Output of PermitRootLogin check on {ip} is: {root_output}")
        if root_output == "pass":
            result["rootLogin"] = f"Pass - {ip} does not permit login as root"
        else:
            result["rootLogin"] = f"Fail - Login as root is permitted on {ip}"
            logging.info(f"Fail - Login as root is permitted on {ip}")

        # Check if users are present on system using exit code from id command
        # A successful exit code means the user is still present on the system
        for user in user_list:
            stdin, stdout, stderr = ssh.exec_command(f'id -u {user}')
            if stdout.channel.recv_exit_status() == 0:
                result["users"][user] = f"Fail - An inactive user still exists on {ip}"
                logging.info(f"Fail - User {user} is still present on {ip}")
            else:
                result["users"][user] = f"Pass - {user} has been removed from {ip}"

        # Check if a user's /home directory was moved to /archived_users
        for user in user_list:
            stdin, stdout, stderr = ssh.exec_command(f"(test -d '/home/{user}/' && echo 'fail') || (test -d '/home/archived_users/{user}/' && echo 'pass')")
            user_dir = stdout.read().decode().strip()
            if user_dir == "pass":
                result["homeDir"][user] = f"Pass - {user} home directory has been moved"
            else:
                result["homeDir"][user] = f"Fail - An inactive user home directory is not in /home/archived_users"
                logging.info(f"Fail - User {user}'s home directory has not been moved on {ip}")

        # Check the file permissions of etc/passwd
        stdin, stdout, stderr = ssh.exec_command("stat -c %a /etc/passwd")
        pass_perm = stdout.read().decode().strip()
        logging.info(f"Passwd file permission is currently set to: {pass_perm} Expecting 644")
        if pass_perm == "644":
            result["passwdPerm"] = f"Pass - passwd has the correct file permissions"
        else:
            result["passwdPerm"] = f"Fail - Check passwd file permissions"
            logging.info(f"Fail - /etc/passwd is currently set to {pass_perm}")

        # Check the file permissions of /etc/shadow
        stdin, stdout, stderr = ssh.exec_command("stat -c %a /etc/shadow")
        shdw_perm = stdout.read().decode().strip()
        logging.info(f"Shadow file permission is currently set to: {shdw_perm} Expecting 640")
        if shdw_perm == "640":
            result["shdwPerm"] = f"Pass - shadow has the correct file permissions"
        else:
            result["shdwPerm"] = f"Fail - Check shadow file permissions"
            logging.info(f"Fail - /etc/shadow is currently set to {shdw_perm}")

        ssh.close()
    except Exception as e:
        result["error"] = str(e)
        logging.error(f"Scanner App Error on {ip}: Error Message is {e}")

    return result