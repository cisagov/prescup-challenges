import os
from admin import *
import xml.etree.ElementTree as ET
import re
from datetime import datetime, timedelta, timezone

SPY_USER = "NotAFed"
SPY_PASSWORD = "v7#Bn0YC7oKtsiz&"


SPY_TOKEN = os.getenv("tokenSpy")

if SPY_TOKEN is None:
    logging.error("The tokenSpy env variable has not been configured!")

def getRSS(driver):
    rss_url = f"{PAWN_URL}/rss"
    
    driver.get(rss_url)
    dump_response(driver, "spy_rss_response.html")
    time.sleep(1)  # Allow for dynamic JS / redirects if any

    xml_source = driver.execute_script("return document.documentElement.outerText")

    try:
        root = ET.fromstring(xml_source)
    except ET.ParseError as e:
        logging.error(f"Failed to parse RSS feed: {e}")
        return []

    urls = []
    for item in root.findall(".//item"):
        link = item.find("link")
        if link is not None and link.text:
            urls.append(link.text.strip())

    logging.info(f"Found {len(urls)} item(s) in RSS feed")
    for url in urls:
        logging.info(f"  RSS item: {url}")
    
    return urls

# The competitor can't change their auction after it's created, so only visit each URL once; if it doesn't work, it doesn't work
def filter_and_store_urls(urls, filename="checked_spy_urls.txt"):
    checked = set()

    if os.path.exists(filename):
        logging.info(f"Loading previously checked URLs from '{filename}'")
        with open(filename, "r") as f:
            checked = set(line.strip() for line in f if line.strip())
        logging.info(f"Loaded {len(checked)} previously checked URLs.")
    else:
        logging.info(f"No existing file '{filename}' found. Starting fresh.")

    new_urls = [url for url in urls if url not in checked]
    logging.info(f"Filtered {len(urls) - len(new_urls)} already-checked URLs. {len(new_urls)} new URLs to visit.")

    if new_urls:
        with open(filename, "a") as f:
            for url in new_urls:
                f.write(url + "\n")
        logging.info(f"Appended {len(new_urls)} new URLs to '{filename}'.")

    return new_urls

def visit_urls(driver, urls):
    def snapshot_cookies():
        return {c['name']: c['value'] for c in driver.get_cookies()}

    for url in urls:
        logging.info(f"Visiting {url}")

        before = snapshot_cookies()

        driver.get(url)
        dump_response(driver, f"spy_visit_{url.split('/')[-1]}.html")
        time.sleep(1.2)

        after = snapshot_cookies()

        added = {k: v for k, v in after.items() if k not in before}
        changed = {k: v for k, v in after.items() if k in before and before[k] != v}
        removed = {k: v for k, v in before.items() if k not in after}

        if added or changed or removed:
            logging.info(f"Cookie changes after visiting {url}:")
            for k, v in added.items():
                logging.info(f"  ADDED: {k} = {v}")
            for k, v in changed.items():
                logging.info(f"  CHANGED: {k} = {v} (was {before[k]})")
            for k, v in removed.items():
                logging.info(f"  REMOVED: {k} = {v}")
        else:
            logging.info(f"No cookie changes after visiting {url}")

def checkUser(driver, expected_username):
    url = f"{PAWN_URL}/dashboard"
    
    driver.get(url)
    dump_response(driver, "spy_dashboard_response.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "username-greeting"))
        )
        text = driver.find_element(By.ID, "username-greeting").text.strip()

        if not text.startswith("Welcome, ") or not text.endswith("!"):
            logging.warning(f"Unexpected format in greeting: {text}")
            return

        displayed_username = text[9:-1].strip()

        if displayed_username != expected_username:
            logging.warning(f"Username mismatch! Expected '{expected_username}', saw '{displayed_username}'")
            return False
        else:
            logging.info(f"Dashboard username is correct: {displayed_username}")
            return True

    except Exception as e:
        logging.error(f"Failed to verify username on dashboard: {e}")

def newItem(driver, name, description, file_path, file_description):
    url = f"{WAREHOUSE_URL}/items/new"
    
    driver.get(url)
    dump_response(driver, "spy_item_form_response.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "name"))
        )

        time.sleep(0.3)
        driver.find_element(By.NAME, "name").send_keys(name)

        time.sleep(0.3)
        driver.find_element(By.NAME, "description").send_keys(description)

        time.sleep(0.3)
        driver.find_element(By.NAME, "documents-0-documentDescription").send_keys(file_description)

        time.sleep(0.3)
        driver.find_element(By.NAME, "documents-0-file").send_keys(file_path)

        time.sleep(0.3)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        logging.info(f"Item submission attempted for: {name}")
        dump_response(driver, "spy_item_submit_response.html")

    except Exception as e:
        logging.error(f"Failed to submit new item: {e}")

def get_create_auction_link(driver):
    url = f"{PAWN_URL}/auctions/manage"
    logging.info(f"Visiting auction management page: {url}")
    
    driver.get(url)
    dump_response(driver, "spy_auction_manage_response.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "a"))
        )
        anchors = driver.find_elements(By.TAG_NAME, "a")

        max_item_id = -1
        best_href = None

        for a in anchors:
            href = a.get_attribute("href")
            if href and "/auctions/new/" in href:
                match = re.search(r"/auctions/new/(\d+)", href)
                if match:
                    item_id = int(match.group(1))
                    logging.debug(f"Found candidate item ID {item_id} with link {href}")
                    if item_id > max_item_id:
                        max_item_id = item_id
                        best_href = href

        if max_item_id != -1:
            logging.info(f"Selected item ID {max_item_id} with link {best_href}")
            return max_item_id, best_href

        logging.warning("No create-auction link found on page.")
        return None, None

    except Exception as e:
        logging.error(f"Failed to scan auction management page: {e}")
        return None, None

def create_auction(driver, create_url, starting_bid, future_datetime):
    logging.info(f"Visiting auction creation page: {create_url}")
    driver.get(create_url)
    dump_response(driver, "spy_create_auction_form.html")

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "starting_bid"))
        )

        driver.find_element(By.NAME, "starting_bid").send_keys(str(starting_bid))

        # Format as required: YYYY-MM-DDTHH:MM
        formatted_dt = future_datetime.strftime("%Y-%m-%dT%H:%M")
        driver.execute_script(f"document.getElementById('end_date').value = '{formatted_dt}';")

        # Select the radio option for cover image
        radios = driver.find_elements(By.NAME, "cover_image")
        if not radios:
            logging.error("No cover image options found.")
            return

        radios[0].click()  # Just select the first one
        logging.info(f"Selected cover image ID: {radios[0].get_attribute('value')}")

        driver.execute_script("document.getElementById('auction-form').submit();")
        time.sleep(1) 
        logging.info("Auction form submitted.")
        dump_response(driver, "spy_create_auction_submit.html")
    except Exception as e:
        logging.error(f"Failed to submit auction form: {e}")

if __name__ == "__main__":

    driver = getDriver()
    try:
        login(driver, SPY_USER, SPY_PASSWORD)
        urls = getRSS(driver)
        urls_to_check = filter_and_store_urls(urls)
        visit_urls(driver, urls_to_check)
        if checkUser(driver, SPY_USER):
            logging.warning("User session not hijacked, exiting")
        else:
            newItem(driver, "Old Laptop", f"An old laptop I have. Doesn't run Doom somehow. Token 4 (Spy Hijack): {SPY_TOKEN}", "/app/laptop.webp", "Image of the laptop")
            # Just realized there is no text in auction, so no place to put token. Can still make an auction for story reasons, but not really needed
            item_id, create_url = get_create_auction_link(driver)
            if item_id and create_url:
                create_auction(driver, create_url, 10000, datetime.now(timezone.utc) + timedelta(weeks=1))
    except Exception as e:
        # Log cookies for debug
        logging.error(f"Error during Selenium workflow: {e}")
        cookies = driver.get_cookies()
        logging.info("Cookies after login:")
        for cookie in cookies:
            logging.info(f"  {cookie['name']} = {cookie['value']}")
    finally:
        driver.quit()