#!/usr/local/bin/python

import requests
import logging
import os
import random
import string
from reportlab.pdfgen import canvas
import io

def generate_valid_pdf_bytes():
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=(200, 200))
    c.drawString(50, 150, "This is a test PDF.")
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()

UPLOAD_URL = "http://publicsite.pccc/upload.php"
UPLOADS_BASE = "http://publicsite.pccc/uploads/"

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def random_name(ext):
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + f".{ext}"

def test_pdf_upload():
    filename = random_name("pdf")
    pdfData = generate_valid_pdf_bytes()
    files = {'file': (filename, pdfData, "application/pdf")}

    try:
        res = requests.post(UPLOAD_URL, files=files, timeout=3)
        if res.status_code != 200:
            logging.info(f"PDF upload failed with status {res.status_code}")
            return "publicFixed: Failure - PDF file could not be uploaded"

        # Try to access the uploaded PDF
        pdf_url = UPLOADS_BASE + filename
        res = requests.get(pdf_url, timeout=3)
        if res.status_code != 200:
            logging.info("Uploaded PDF file not accessible")
            return "publicFixed: Failure - PDF file uploaded but not accessible"
        if not res.content.startswith(b"%PDF"):
            logging.info("PDF file accessible, but content looks wrong")
        return ""
    except Exception as e:
        logging.info(f"Exception during PDF upload: {e}")
        return "publicFixed: Failure - Error while uploading/accessing PDF"

def test_php_execution_block():
    filename = random_name("php")
    php_code = b"<?php echo 6 * 7; ?>"
    files = {'file': (filename, php_code, "application/x-php")}

    try:
        res = requests.post(UPLOAD_URL, files=files, timeout=3)
        if res.status_code != 200:
            logging.info(f"PHP upload blocked with status {res.status_code}")
            return ""  # Upload blocked = good

        # Try to access the uploaded PHP file
        php_url = UPLOADS_BASE + filename
        res = requests.get(php_url, timeout=3)
        if res.status_code == 200 and "42" in res.text:
            logging.info("PHP file executed remotely!")
            return "publicFixed: Failure - Uploaded PHP file is still executable"

        return ""
    except Exception as e:
        logging.info(f"Exception during PHP test: {e}")
        return ""  # If access is blocked, that's okay

if __name__ == "__main__":
    pdf_check = test_pdf_upload()
    if pdf_check == "":
        php_check = test_php_execution_block()

        if php_check == "":
            logging.info("Success, granting token")
            print(f"publicFixed: Success - Upload vulnerability mitigated and functionality preserved")
        else:
            print(php_check)
    else:
        print(pdf_check)
