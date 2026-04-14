FROM python:3.13.4-slim

# Install Chrome + dependencies
RUN apt-get update && apt-get install -y \
    wget unzip gnupg curl xvfb fonts-liberation \
    chromium chromium-driver wait-for-it

# Install Selenium
RUN pip install selenium sqlalchemy mysql-connector-python 

COPY laptop.webp /app/laptop.webp
COPY admin.py /app/admin.py
COPY spy.py /app/spy.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]