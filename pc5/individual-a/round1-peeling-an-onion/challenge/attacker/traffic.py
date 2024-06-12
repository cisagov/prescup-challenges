
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import random
import time
import requests
import subprocess

# List of URLs to simulate user activity
urls = [
# Site 1
"http://marketing.merch.codes/",
"http://marketing.merch.codes/page1",
"http://marketing.merch.codes/page2",
"http://marketing.merch.codes/page3",
# Site 2
"http://sales.merch.codes",
"http://sales.merch.codes/page1",
"http://sales.merch.codes/page2",
"http://sales.merch.codes/page3",
# Site 3
"http://service.merch.codes",
"http://service.merch.codes/page1",
"http://service.merch.codes/page2",
"http://service.merch.codes/page3",
 #Site 4
"http://sites.merch.codes/?page=documentation",
"http://sites.merch.codes/?page=contact",
]

# List of user agents to simulate different devices
user_agents = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
"Mozilla/5.0 (Linux; Android 11; SM-G975U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Mobile Safari/537.36",
"Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
# Add more user agents as needed
]

# Simulate user activity
def simulate_user_activity():
    while True:
        # Select a random URL and user agent
        url = random.choice(urls)
        user_agent = random.choice(user_agents)

        # Send a GET request with random URL and user agent
        try:
            response = requests.get(url, headers={"User-Agent": user_agent})
            # Log the request or process the response as needed
            print(f"GET {url} | User-Agent: {user_agent} | Response: {response.status_code}")
        except requests.RequestException as e:
            # Handle request errors
            print(f"Error: {str(e)}")

        # Change the IP address of eth0 to a random number between 100 and 150
        new_ip_last_octet = random.randint(100, 150)
        change_ip_last_octet(new_ip_last_octet)
        
        # Pause for a random duration before the next request
        time.sleep(random.uniform(1, 5))

# Function to change the last octet of eth0's IP address
def change_ip_last_octet(new_octet):

    interface = "eth0"
    ip_address = f"10.2.2.{new_octet}"
    subprocess.run(f"ip address flush dev {interface}", shell=True)
    subprocess.run(f"ip address add {ip_address}/24 dev {interface}", shell=True)

        
# Run the simulation
simulate_user_activity()



