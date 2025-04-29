import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
import os
import re
import requests
import logging
import sys
import time

# Configuration
HOST = "0.0.0.0"
SMTP_PORT = 1025
STORAGE_DIR = "./emails"
VALID_EMAILS_FILE = "./valid_emails.txt"

# Load valid email addresses and their user-agents
def load_valid_emails(file_path):
    valid_emails = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                email_address, user_agent = map(str.strip, line.split(",", 1))
                valid_emails[email_address] = user_agent
        return valid_emails
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except ValueError:
        print(f"Error: Ensure each line in '{file_path}' has the format 'email,user-agent'.")
        return None

# Keep checking for the valid emails file until it is loaded successfully
VALID_EMAILS = None
while VALID_EMAILS is None:
    VALID_EMAILS = load_valid_emails(VALID_EMAILS_FILE)
    if VALID_EMAILS is None:
        print("Waiting for valid emails file...")
        time.sleep(5)  # Wait for 5 seconds before checking again

# Extract links from email content
def extract_links(email_content):
    return re.findall(r'(https?://\S+)', email_content)

# Email handler
class MyHandler:
    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content.decode('utf8', errors='replace')

        print(f"Received email from {mail_from} to {rcpt_tos}")

        # Ensure the storage directory exists
        if not os.path.exists(STORAGE_DIR):
            os.makedirs(STORAGE_DIR)

        # Save the email to a file if the recipient is valid
        for recipient in rcpt_tos:
            recipient = recipient.strip()
            if recipient in VALID_EMAILS:
                email_path = os.path.join(STORAGE_DIR, f"{recipient}.eml")
                with open(email_path, "w") as f:
                    f.write(data)
                print(f"Email saved to {email_path}")

                # Extract links
                links = extract_links(data)
                if links:
                    print(f"Extracted Links: {links}")
                    user_agent = VALID_EMAILS[recipient]
                    for link in links:
                        print(f"Attempting to click link: {link} with User-Agent: {user_agent}")
                        try:
                            requests.post(link, headers={"User-Agent": user_agent}, timeout=1)
                            print(f"Clicked link: {link}")
                        except requests.RequestException:
                            pass  # Suppress the error message
                else:
                    print("No links found in this email.")
        return '250 Message accepted for delivery'

# Start the SMTP server
async def start_server():
    handler = MyHandler()
    controller = Controller(handler, hostname=HOST, port=SMTP_PORT)
    controller.start()

    print(f"SMTP server running on {HOST}:{SMTP_PORT}...")
    try:
        while True:
            await asyncio.sleep(10)  # Keep the server running
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()

if __name__ == "__main__":
    asyncio.run(start_server())