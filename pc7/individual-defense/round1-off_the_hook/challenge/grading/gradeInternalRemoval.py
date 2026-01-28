#!/usr/local/bin/python

import logging
import os
import paramiko

HOST = "internalreports.pccc"
USER = "user"
PASSWORD = "password"
WORM_PATH = "/tmp/.6X9TQJ4P2M.py"
WORM_TAG = "6X9TQJ4P2M"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode(), stderr.read().decode()

def check_worm_status():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOST, username=USER, password=PASSWORD, timeout=5)

        # 1. Check if worm file exists
        out, err = run_command(client, f"echo password | (sudo -S test -f {WORM_PATH} && echo 'FOUND') || echo 'NOT FOUND'")
        logging.info(f"Output from test: {out}")
        logging.info(f"Stderr from test: {err}")
        worm_exists = out.strip() == "FOUND"

        # 2. Check if worm is in crontab
        out, err = run_command(client, "echo password | sudo -S crontab -l -u www-data")
        logging.info(f"Output from crontab: {out}")
        logging.info(f"Stderr from crontab: {err}")
        in_crontab = WORM_TAG in out

        if worm_exists and in_crontab:
            logging.info("Worm and crontab remain")
            print("reportsRemoved: Failure - Worm artifacts remain on internalreports.pccc")
        elif not worm_exists and in_crontab:
            logging.info("Crontab remains")
            print("reportsRemoved: Failure - Worm script removed, but an artifact remains on internalreports.pccc")
        elif worm_exists and not in_crontab:
            logging.info("Worm remains")
            print("reportsRemoved: Failure - Worm runner removed, but an artifact remains on internalreports.pccc")
        else:
            logging.info("Success, granting token")
            print(f"reportsRemoved: Success - Worm artifacts removed")
    except Exception as e:
        logging.warning(f"Error accessing internalreports.pccc with SSH - {e}")
        print("reportsRemoved: Failure - Error accessing internalreports.pccc with SSH")
    finally:
        client.close()

if __name__ == "__main__":
    check_worm_status()
