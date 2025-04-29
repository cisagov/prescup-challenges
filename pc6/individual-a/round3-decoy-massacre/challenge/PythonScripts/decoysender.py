import requests
import time
import logging
from random import randint

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# List of target IPs and ports
targets = [
    ('10.1.1.10', 80),
    ('10.2.2.10', 80),
    ('10.7.7.30', 80)
]

# Random delay between requests (in seconds)
delay_range = (4, 6)

def send_request(ip, port):
    try:
        # Add random delay
        time.sleep(randint(*delay_range))
        
        # Send GET request
        response = requests.get(f'http://{ip}:{port}', timeout=10)
        
        # Log the response status
        logging.info(f'Successful request to {ip}:{port} - Status Code: {response.status_code}')
    except requests.exceptions.RequestException as e:
        logging.error(f'Failed request to {ip}:{port} - Error: {str(e)}')

if __name__ == "__main__":
    logging.info("Starting the web traffic sender script.")
    
    while True:
        for ip, port in targets:
            send_request(ip, port)