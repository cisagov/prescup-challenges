import logging
import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from sqlalchemy import Boolean, Column, Integer, Text, ForeignKey, create_engine
from sqlalchemy.orm import relationship, Session, sessionmaker, declarative_base

PAWN_URL = "http://pawn.secondorder.pccc"
WAREHOUSE_URL = "http://warehouse.secondorder.pccc"
ADMIN_USER = "admin"
ADMIN_PASS = "12If7tqNM@2WP#Hw"

engine = create_engine(os.getenv("PAWN_DB_URL"), future=True, pool_pre_ping=True, pool_recycle=1800)
Session = sessionmaker(bind=engine)
Base = declarative_base()
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def dump_response(driver, filename):
    time.sleep(1)
    html = driver.page_source

    full_path = os.path.join("/app/logs", filename)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    with open(full_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"Saved response HTML to {full_path}")


class Cancellation(Base):
    __tablename__ = 'cancellations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    auction_id = Column(Integer)
    reason = Column(Text)
    approved = Column(Boolean)

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
    login_url = f"{PAWN_URL}/login"
    logging.info(f"Navigating to login page: {login_url}")
    driver.get(login_url)
    dump_response(driver, f"{username}_login_response.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "username"))
        )
    except Exception as e:
        logging.error("Login page did not load correctly")
        raise e

    time.sleep(0.3)
    driver.find_element(By.ID, "username").send_keys(username)
    time.sleep(0.3)
    driver.find_element(By.ID, "password").send_keys(password)
    time.sleep(0.2)
    driver.find_element(By.ID, "submit").click()
    logging.info(f"Login attempt for user '{username}' completed")
    dump_response(driver, f"{username}_login_post_response.html")

def getNextCancelID():
    with Session() as session:
        result = session.query(Cancellation.id)\
                        .filter(Cancellation.approved == None)\
                        .order_by(Cancellation.id.asc())\
                        .first()
        if result:
            logging.info(f"Next pending cancellation ID is {result[0]}")
            return result[0]
        else:
            return None

def denyRequest(driver, id):
    url = f"{PAWN_URL}/admin/cancellation/{id}"
    driver.get(url)
    dump_response(driver, f"admin_cancel_page_{id}.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "deny"))
        )
    except Exception as e:
        logging.error(f"Deny button not found on page for ID {id}")
        raise e

    time.sleep(1.5)
    driver.find_element(By.ID, "deny").click()
    logging.info(f"Clicked 'Deny' for cancellation ID {id}")
    dump_response(driver, f"admin_cancel_post_{id}.html")

def manualDeny(id):
    with Session() as session:
        cancellation = session.get(Cancellation, id)
        if cancellation is None:
            logging.warning(f"Cancellation ID {id} not found in database.")
            return

        if cancellation.approved is None:
            logging.warning(f"Cancellation ID {id} had null approval — setting to 0.")
            cancellation.approved = 0
            session.commit()
            logging.info(f"Cancellation ID {id} set to approved=0")
        elif cancellation.approved == 0:
            logging.info(f"Cancellation ID {id} was correctly denied (approved=0).")
        elif cancellation.approved == 1:
            logging.info(f"Cancellation ID {id} was approved — competitor succeeded.")

if __name__ == "__main__":
    id = getNextCancelID()
    if id is None:
        logging.info("No pending cancellations to process. Exiting.")
    else:
        driver = getDriver()
        try:
            login(driver, ADMIN_USER, ADMIN_PASS)
            denyRequest(driver, id)
        except Exception as e:
            logging.error(f"Error during Selenium workflow: {e}")
            cookies = driver.get_cookies()
            logging.info("Cookies after login:")
            for cookie in cookies:
                logging.info(f"  {cookie['name']} = {cookie['value']}")
        finally:
            driver.quit()

        manualDeny(id)

