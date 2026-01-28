#!/usr/bin/python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from playwright.sync_api import sync_playwright
import time, datetime

#### In case they put in a alert script, let's dismiss it.
def handle_dialog(dialog):
    [print(f"\n[!] Alert triggered with message: {dialog.message}\n")]
    dialog.dismiss()
    page.on("dialog", handle_dialog)

def browse(email, password):
    log_data = list()
    with sync_playwright() as p:
        #browser = p.firefox.launch(headless=True, args=["--no-sandbox"])
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            print(f"\n[+] Logging in as {email}\n")

            #first visit logout.php to kill any active session

            page.goto("http://marketdev.skills.hub/logout.php")
            
            # Log the user in
            
            page.goto("http://marketdev.skills.hub/login.php", timeout=4000)

            page.fill("input[name=email]", email)
            page.fill("input[name=password]", password)
            page.click("button[type=submit]")

            page.wait_for_timeout(2000)

            # visit the feedback 
            print("[+] Navigating to feedback...\n")
            page.goto('http://marketdev.skills.hub/feedback.php')
            print("[+] Done. Sleeping briefly before closing.\n")

            page.wait_for_timeout(3000)


        except Exception as e:
            print(f"[-] Error: {e}")
            with open('/home/user/Desktop/webBrowser/log.txt', 'a+') as f:
                f.write(f"{datetime.datetime.now()}\ncreds: {email}\nerror:\n{e}\n\n")
                f.write("\n".join(log_data))

        finally:
            browser.close()

if __name__ == '__main__':
    browse("xssvictim@skills.hub", "LkRP-u%AhTGME4y")
