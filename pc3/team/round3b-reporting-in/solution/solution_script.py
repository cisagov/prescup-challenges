#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from http.server import HTTPServer, BaseHTTPRequestHandler

SPOOF_ADDR = "202.128.10.13"

class CustomHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(SPOOF_ADDR.encode())

httpd = HTTPServer(("0.0.0.0", 80), CustomHTTPRequestHandler)
httpd.serve_forever()
