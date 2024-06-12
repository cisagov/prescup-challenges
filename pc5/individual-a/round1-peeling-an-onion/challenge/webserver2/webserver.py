
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading

class MyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Customize the response based on the requested path
        if self.path == '/page1':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>This is page 1</h1>')
        elif self.path == '/page2':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>This is page 2</h1>')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Page not found</h1>')

def run_server(ip, port):
    server_address = (ip, port)
    httpd = HTTPServer(server_address, MyRequestHandler)
    print(f'Starting server on {ip}:{port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    # Define the IP addresses and ports for your simulated sites
    sites = [
        ('10.7.7.101', 80),  # Site 1
        ('10.7.7.102', 80),  # Site 2
        ('10.7.7.103', 80),  # Site 3
    ]

    # Create a thread for each site and start the servers
    threads = []
    for site in sites:
        ip, port = site
        thread = threading.Thread(target=run_server, args=(ip, port))
        thread.daemon = True  # Set the thread as a daemon to run in the background
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

