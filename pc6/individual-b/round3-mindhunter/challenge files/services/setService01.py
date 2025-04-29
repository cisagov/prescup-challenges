#!/usr/bin/env python3

import os
import subprocess
import threading
import time

binary = "c47_01_server"

def start_services():
    try:
        print("[+] Starting Breaking Fourth Wall service...")
        subprocess.run(f"python3 /home/user/Desktop/server/{binary}.py", shell=True, check=True)
        print("[+] Service started successfully!")
    except Exception as e:
        print(f"[x] Error starting service: {e}")

def create_systemd_service():
    try:
        print("[+] Creating systemd service...")
        service_content = f"""[Unit]
Description=Breaking Fourth Wall Challenge Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 /home/user/Desktop/server/{binary}.py
Restart=always
User=user
WorkingDirectory=/home/user/Desktop/server

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/bt4w.service", "w") as f:
            f.write(service_content)
            f.close()
        os.system(f"chmod +x /home/user/Desktop/server/{binary}.py")
        os.system("chmod 644 /etc/systemd/system/bt4w.service")
        os.system("systemctl daemon-reload")
        os.system("systemctl enable bt4w.service")
        os.system("systemctl restart bt4w.service")
        print("[+] Breaking Fourth Wall service has been enabled and started.")

    except Exception as e:
        print("[x] Error making service.")

def main():
    try:
        create_systemd_service()
        print("[+] Breaking Fourth Wall is now running as a persistent service!")
    except Exception as e:
        print("[x] Error running service.")

if __name__ == "__main__":
    main()


