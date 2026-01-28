import os
import random
from datetime import datetime, timedelta

# === CONFIGURATION ===
OUTPUT_DIR = "/var/log/"
NUM_FILES = 100
LINES_PER_FILE = 2000
CHALLENGE_LOGS = [
    # Injected lines: place across random files
    'Jun 12 14:22:01 purple sshd[1337]: Accepted password for sudouser from 172.19.0.5 port 2222 ssh2',
    'Jun 12 14:23:44 purple sudo: sudouser : TTY=pts/3 ; PWD=/home/sudouser ; USER=sudouser ; COMMAND=/usr/bin/nano /etc/passwd',
    'Jun 12 14:25:01 purple bash[1399]: suspicious activity detected: attacker created /tmp/.backdoor',
    'Jun 12 14:26:10 purple python3[1422]: attacker connected to C2 at evil.corp.com:4444',
    'Jun 12 14:28:00 purple bash[1429]: attacker escalated privileges using CVE-2021-4034',
    'TOKEN{log_analysis}'  # Hidden in plain sight
]

# === SAMPLE DATA ===
USERNAMES = ['alice', 'bob', 'charlie', 'dave', 'eve']
COMMANDS = ['ls', 'cat', 'nano', 'vi', 'top', 'wget', 'ssh', 'ftp', 'curl', 'whoami']
HOSTNAME = 'fileserver'
PROCESS = ['sshd', 'bash', 'systemd', 'cron', 'python3']
BASE_DATE = datetime(2025, 6, 12)

# === FUNCTIONS ===
def random_log_line():
    time = BASE_DATE + timedelta(seconds=random.randint(0, 86400))
    timestamp = time.strftime('%b %d %H:%M:%S')
    proc = random.choice(PROCESS)
    pid = random.randint(100, 9999)
    user = random.choice(USERNAMES)
    ip = f"172.19.{random.randint(0,255)}.{random.randint(1,254)}"
    cmd = random.choice(COMMANDS)
    return f"{timestamp} {HOSTNAME} {proc}[{pid}]: {user} executed `{cmd}` from {ip}"

def inject_challenge_logs(files):
    targets = random.sample(files, len(CHALLENGE_LOGS))
    for log, fname in zip(CHALLENGE_LOGS, targets):
        with open(fname, 'a') as f:
            f.write(log + '\n')

# === MAIN SCRIPT ===
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"[+] Generating {NUM_FILES} log files...")

    file_paths = []

    for i in range(1, NUM_FILES + 1):
        filename = os.path.join(OUTPUT_DIR, f"log_{i:02}.log")
        file_paths.append(filename)
        with open(filename, 'w') as f:
            for _ in range(LINES_PER_FILE):
                f.write(random_log_line() + '\n')

    print("[+] Injecting challenge log entries...")
    inject_challenge_logs(file_paths)

    print(f"[✓] Done. Logs saved in `{OUTPUT_DIR}/`")

if __name__ == '__main__':
    main()
