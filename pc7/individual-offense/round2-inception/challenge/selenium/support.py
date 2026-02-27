from datetime import datetime, timedelta, timezone
import logging
import os
import random
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from pymongo import MongoClient, ASCENDING

BASE_URL = "http://pccc.pccc"
USERS = ["OTA-Kevin@pccc.pccc", "OTA-Alex@pccc.pccc", "OTA-Jake@pccc.pccc", "OTA-Malakai@pccc.pccc",]
ADMIN_PASS = "1!1M5nPV#*7TLReJ"  # They all share the same password

UNSEEN, SEEN, RESOLVED = 0, 1, 2

SEEN_MESSAGE = "Hello,\nWe are investigating now and will update you as soon as possible."
RESOLVED_MESSAGE = "Hello,\nI'm not sure why, but I can't focus now; everything seems really hazy. However, everything should be working now! Sorry for the confusion. Please let me know if you have any other issues or concerns."

# ---- Mongo connection (URI comes from Docker Compose env) ----
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client[os.getenv("MONGO_DB", "pccc")]
tickets = db.tickets

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def scroll_into_view_instant(driver, el):
    driver.execute_script("""
      const root = document.documentElement;
      const prev = root.style.scrollBehavior;
      root.style.scrollBehavior = 'auto';     // force instant scroll
      try { arguments[0].scrollIntoView({block:'center'}); }
      finally { root.style.scrollBehavior = prev; }
    """, el)

def dump_response(driver, filename):
    time.sleep(1)
    html = driver.page_source

    full_path = os.path.join("/app/logs", filename)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    with open(full_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"Saved response HTML to {full_path}")
    return html

def getDriver():
    logging.info("Initializing headless Chrome driver")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    service = Service(executable_path='/usr/bin/chromedriver') 
    driver = webdriver.Chrome(service=service, options=options)

    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})

    logging.info("Chrome driver initialized successfully")
    return driver

def login(driver, username, password):
    login_url = f"{BASE_URL}/login"
    logging.info(f"Navigating to login page: {login_url}")
    driver.get(login_url)
    dump_response(driver, f"{username}_login_response.html")

    try:
        wait = WebDriverWait(driver, 10)
        wait.until(lambda d: d.execute_script("return document.readyState") == "complete")

        # Ensure fields are interactable
        wait.until(EC.element_to_be_clickable((By.ID, "email")))
        wait.until(EC.element_to_be_clickable((By.ID, "password")))
        wait.until(EC.element_to_be_clickable((By.ID, "submit")))
        
    except Exception as e:
        logging.error("Login page did not load correctly")
        raise e

    time.sleep(0.3)
    driver.find_element(By.ID, "email").send_keys(username)
    time.sleep(0.3)
    driver.find_element(By.ID, "password").send_keys(password)
    time.sleep(0.3)
    scroll_into_view_instant(driver, driver.find_element(By.ID, "submit"))
    time.sleep(0.3)
    driver.find_element(By.ID, "submit").click()
    
    logging.info(f"Login attempt for user '{username}' completed")
    return dump_response(driver, f"{username}_login_post_response.html")

def comment(driver, id, comment):
    support_url = f"{BASE_URL}/support/{id}"
    logging.info(f"Navigating to support page: {support_url}")
    driver.get(support_url)
    dump_response(driver, f"support_{id}_response.html")

    try:
        wait = WebDriverWait(driver, 10)
        wait.until(lambda d: d.execute_script("return document.readyState") == "complete")

        # Ensure fields are interactable
        wait.until(EC.element_to_be_clickable((By.ID, "text")))
        wait.until(EC.element_to_be_clickable((By.ID, "submit")))
    except Exception as e:
        logging.error("Support page did not load correctly")
        raise e

    time.sleep(0.3)
    driver.find_element(By.ID, "text").send_keys(comment)
    time.sleep(0.3)
    scroll_into_view_instant(driver, driver.find_element(By.ID, "submit"))
    time.sleep(0.3)
    driver.find_element(By.ID, "submit").click()
    logging.info(f"Commented on '{id}'")
    dump_response(driver, f"{id}_login_post_response.html")

def getNextUnseenTicket():
    """Return the oldest unseen ticket (>=20s old) by key, or None."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=20)
    doc = tickets.find_one(
        {
            "createdAt": {"$lte": cutoff},
            "$or": [{"status": 0}, {"status": {"$exists": False}}],
        },
        sort=[("createdAt", ASCENDING)],
    )
    key = doc["key"] if doc else None
    if key:
        logging.info(f"Retrieved unseen ticket: {key}")
    return key

def setSeen(key):
    """Mark a ticket 0->1 (Unseen -> Seen)."""
    res = tickets.update_one(
        {"key": key, "$or": [{"status": UNSEEN}, {"status": {"$exists": False}}]},
        {"$set": {"status": SEEN}}
    )
    if res.matched_count:
        logging.info(f"Marked Seen: {key}")
    else:
        logging.info(f"No update (already seen/resolved or not found): {key}")

def getNextSeenTicket():
    """Return the oldest seen ticket (>=5m old) by key, or None."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    doc = tickets.find_one(
        {"status": 1, "createdAt": {"$lte": cutoff}},
        sort=[("createdAt", ASCENDING)],
    )
    key = doc["key"] if doc else None
    if key:
        logging.info(f"Retrieved seen ticket: {key}")
    return key

def setResolved(key):
    """Mark a ticket 1->2 (Seen -> Resolved)."""
    res = tickets.update_one(
        {"key": key, "status": SEEN},
        {"$set": {"status": RESOLVED}}
    )
    if res.matched_count:
        logging.info(f"Marked Resolved: {key}")
    else:
        logging.info(f"No update (not in 'Seen' state or not found): {key}")

if __name__ == "__main__":
    id = getNextUnseenTicket()
    if id is None:
        logging.info("No pending unseen tickets to process.")
    else:
        driver = getDriver()
        try:
            response = login(driver, random.choice(USERS), ADMIN_PASS)
            
            if "Invalid email or password" in response:  # Could maybe fix by storing sessions (depends on expiration), but I think this is fine (that's what would happen in real life, after all)
                logging.warning("Could not log in with the usual password. This is likely benign, as the competitor changes the password.")
            else:
                setSeen(id) # setSeen first, so we don't get stuck if they break the bot
                comment(driver, id, SEEN_MESSAGE)
        except Exception as e:
            logging.error(f"Error during Selenium workflow: {e}")
        finally:
            driver.quit()
    
    id2 = getNextSeenTicket()
    id = id2 if id2 != id else None
    if id is None:
        logging.info("No seen tickets to resolve.")
    else:
        driver = getDriver()
        try:
            response = login(driver, random.choice(USERS), ADMIN_PASS)
            
            if "Invalid email or password" in response:  # Could maybe fix by storing sessions (depends on expiration), but I think this is fine (that's what would happen in real life, after all)
                logging.warning("Could not log in with the usual password. This is likely benign, as the competitor changes the password.")
            else:
                setResolved(id) # setResolved first, so we don't get stuck if they break the bot
                comment(driver, id, RESOLVED_MESSAGE)
        except Exception as e:
            logging.error(f"Error during Selenium workflow: {e}")
        finally:
            driver.quit()


