FROM python:3.13.4-slim

# Install Chrome + dependencies
RUN apt-get update && apt-get install -y \
    wget unzip gnupg curl xvfb fonts-liberation \
    chromium chromium-driver wait-for-it

# Install Selenium
RUN pip install selenium pymongo werkzeug

COPY init.py /app/init.py
COPY support.py /app/support.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]