#!/usr/bin/python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


'''
A Basic HTTP server to receive exfiltrated data.

Summary:
This script sets up a simple HTTP server that listens on port 8080 and accepts HTTP POST requests.
When a POST request is received, the script does the following:
1. Reads the 'Content-Length' header to determine the size of the incoming data.
2. Extracts and decodes the data from the request body.
3. Prints the received data to the console, simulating an exfiltration scenario.
4. Sends an HTTP 200 OK response to acknowledge receipt of the data.

Key Components:
- `BaseHTTPRequestHandler`: A built-in class that allows handling HTTP requests.
- `HTTPServer`: A basic HTTP server that listens for incoming connections.
- `do_POST()`: A method that processes POST requests and extracts the data.
- `httpd.serve_forever()`: Keeps the server running indefinitely to handle multiple requests.

Usage:
Run this script on a system where you want to receive exfiltrated data.
It will listen on all available network interfaces (`''`) on port `8080` and print any data received via a POST request.

'''

from http.server import BaseHTTPRequestHandler, HTTPServer

class ExfiltrationHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        print(f"Exfiltrated Data:\n{post_data}\n")
        self.send_response(200)
        self.end_headers()

server_address = ('', 8080)
httpd = HTTPServer(server_address, ExfiltrationHandler)
print("Listening for exfiltrated data on port 8080...")
httpd.serve_forever()
