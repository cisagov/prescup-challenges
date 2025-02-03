#!/usr/bin/python3
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


import requests, logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import connectAndExecute

# Variables
MAILCATCHER_URL = 'http://10.2.2.151:1080/messages'
EXPECTED_RECIPIENT = '<william@fakefish.co>' # The correct recipient's email address
EXPECTED_DOMAIN = "lure.fakefish.co" # Domain that should be in the href of the link. This is the dangling CNAME record

# Configure basic logging
logging.basicConfig(
    filename='/var/log/gradingCheck.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s')

def fetch_emails():
    # Fetch all emails
    response = requests.get(MAILCATCHER_URL)

    # Check if the request was successful
    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Failed to fetch emails: {response.status_code} - Check status of MailCatcher VM")
        return []


def fetch_email_body(email_id):
# This function fetches the body of the email in HTML or plain text
    response_plain = requests.get(f"{MAILCATCHER_URL}/{email_id}.plain")
    plain_text = response_plain.text if response_plain.status_code == 200 else None

    response_html = requests.get(f"{MAILCATCHER_URL}/{email_id}.html")
    html_text = response_html.text if response_html.status_code == 200 else None

    return plain_text, html_text


def extract_hyperlinks_from_html(html_text):
# This function extracts any hyperlinks from the body of an HTML message
    soup = BeautifulSoup(html_text, 'html.parser')

    links = []
    for a_tag in soup.find_all('a', href=True):
        link_text = a_tag.get_text(strip=True)
        link_href = a_tag['href']
        links.append((link_text, link_href))

    return links


def validate_recipient(email_recipients):
    return EXPECTED_RECIPIENT in email_recipients


def validate_domain(url):
    parsed_url = urlparse(url)
    return EXPECTED_DOMAIN in parsed_url.netloc


def print_most_recent_email(emails):
# This function will parse only the most recently received email
    if not emails:
        print("GradingCheck1: The target has not received any emails.")
        return

    most_recent_email = emails[-1]
    email_id = most_recent_email['id']
    logging.info("Details of the downloaded email message")
    logging.info(f"Email ID: {email_id}")
    logging.info(f"From: {most_recent_email['sender']}")
    logging.info(f"To: {most_recent_email['recipients']}")
    logging.info(f"Subject: {most_recent_email['subject']}")

    if validate_recipient(most_recent_email['recipients']):
        logging.info("The email was sent to the correct recipient")
    else:
        logging.info("This email was sent to the wrong recipient")
        print("GradingCheck1: Your email was sent to the wrong person. Take another look at the fakefish.co website.")
        return

    # Fetch content from both plain text and HTML messages
    plain_text, html_text = fetch_email_body(email_id)

    if html_text:
        logging.info("HTML Version of Body Text:")
        logging.info(html_text)

        links = extract_hyperlinks_from_html(html_text)
        if links:
            logging.info("Extracted Hyperlinks:")
            for link_text, link_href in links:
                logging.info(f"Link Text: {link_text}")
                logging.info(f"Link URL: {link_href}")

                if validate_domain(link_href):
                    logging.info("Phishing email met required criteria: Moving to execute payload.")
                    print(f"GradingCheck1: Success - William clicked on your link to {link_href}. Your file was downloaded and executed on their workstation.")
                    connectAndExecute.execute_payload_on_server(link_href)
                else:
                    logging.info("Masked URL was not lure.fakefish.co so email was deleted.")
                    print(f"GradingCheck1: The user examined the link you masked as: {link_text}. They did not recognize the destination URL ({link_href}), or it was an invalid URL link, so they deleted the email.")

        else:
            logging.info("There was no link in the body of the email.")
            print("GradingCheck1: There was no link in the email, so nothing was clicked.")

    elif plain_text:
        logging.info("Plain Text Version of Body Text:")
        logging.info(plain_text)
        logging.info("Email was in plain text. No interactive links to click on.")
        print("GradingCheck1: Your email was received as plain text. There were no interactive links for the user to click, so they didn't. The email was deleted.")
    else:
        logging.info("Email was received, but there was no text in the body of the email.")
        print("GradingCheck1: There was no text in the body of the email, so it was deleted.")


# Main flow
if __name__ == "__main__":
    emails = fetch_emails()
    if emails:
        print_most_recent_email(emails)
    else:
        print("GradingCheck1: The target has not received any emails.")

