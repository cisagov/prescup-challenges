FROM python:3.10-slim

# Install Chrome + dependencies
RUN apt-get update && apt-get install -y \
    wget unzip gnupg curl xvfb fonts-liberation \
    chromium chromium-driver

# Install Selenium
RUN pip install selenium

RUN apt install -y dnsutils tcpdump

RUN pip install dnspython

RUN apt-get install -y iproute2 iputils-ping net-tools

COPY app.py /app.py

CMD ["python", "/app.py"]