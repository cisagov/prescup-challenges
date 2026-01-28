#!/usr/local/bin/python

import logging
import os
import paramiko

HOST = "publicsite.pccc"
USER = "user"
PASSWORD = "password"
WORM_PATH = "/var/www/html/uploads/.htaccess"
WORM_TAG = "Z4MPK7WQLE"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode(), stderr.read().decode()

def check_worm_status():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOST, username=USER, password=PASSWORD, timeout=5)

        # 1. Check if the worm file exists
        out, err = run_command(client, f"echo password | sudo -S file {WORM_PATH}")
        logging.info(f"Output from file: {out}")
        logging.info(f"Stderr from file: {err}")
        worm_exists = "python" in out.lower()

        # 2. Check if worm is in ps
        out, err = run_command(client, "echo password | sudo -S ps -aux 2>/dev/null")
        logging.info(f"Output from ps: {out}")
        logging.info(f"Stderr from ps: {err}")
        in_ps = f"/usr/bin/python3 {WORM_PATH}" in out

        if worm_exists and in_ps:
            logging.info("Worm and process remain")
            print("publicRemoved: Failure - Worm artifacts remain on publicsite.pccc")
        elif not worm_exists and in_ps:
            logging.info("Process remains")
            print("publicRemoved: Failure - Worm script removed, but an artifact remains on publicsite.pccc")
        elif worm_exists and not in_ps:
            logging.info("Script remains")
            print("publicRemoved: Failure - Worm process removed, but an artifact remains on publicsite.pccc")
        else:
            logging.info("Success, granting token")
            print(f"publicRemoved: Success - Worm artifacts removed")
    except Exception as e:
        logging.warning(f"Error accessing publicsite.pccc with SSH - {e}")
        print("publicRemoved: Failure - Error accessing publicsite.pccc with SSH")
    finally:
        client.close()

if __name__ == "__main__":
    check_worm_status()
