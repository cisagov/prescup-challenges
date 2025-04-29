import socket
import threading
import time
import random

# List of target server hostnames/IP addresses (use hostnames for legality)
targets = ['123.45.67.100', '10.1.1.10']

# Malicious-looking User-Agent string
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Linux; Android 10; botnet userAgent)',
    'CustomBot/1.0'
]

# Headers to include
headers = {
    'User-Agent': random.choice(user_agents),
    'Referer': 'http://malicious-site.com/',
    'Accept': '*/*',
    'Connection': 'Keep-Alive'
}

def generate_malicious_traffic():
    while True:
        for target in targets:
            try:
                # Create a socket object
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Connect to the target server on port 80
                s.connect((socket.gethostbyname(target), 80))
                
                # Send HTTP request with suspicious headers
                request = f"GET /?{random.randint(1, 1000)} HTTP/1.1\r\n"
                request += f"Host: {target}\r\n"
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"
                request += "\r\n"
                
                s.send(request.encode())
                
                # Receive response
                response = s.recv(1024)
                print(f"Response from {target}: {response.decode()}")
                
                # Close the connection
                s.close()
                
            except Exception as e:
                print(f"Connection to {target} failed: {e}")
            
            # Random delay between 3 to 7 seconds
            time.sleep(random.randint(3, 7))
            
        # Sleep for 5 seconds before next iteration
        time.sleep(5)

if __name__ == "__main__":
    print("Starting traffic generation...")
    generate_malicious_traffic()