#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
from io import BytesIO
import subprocess

number = "101"
missionnumber=number.stdout.strip()
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'Welcome to the internal rocketship mission identifier webserver. The rocketship mission identifier workstation is preconfigured to make post requests to identify the correct mission name and ID.')

        def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                self.send_response(200)
                self.end_headers()
                response = BytesIO()
                req = str(body.decode("utf-8"))
                if missionnumber in req:
                        response.write(b'This is the correct mission. ')
                        response.write(b'Received: ')
                        response.write(body)
                        self.wfile.write(response.getvalue())
                else:
                        response.write(b'This is an incorrect mission. ')
                        response.write(b'Received: ')
                        response.write(body)
                        self.wfile.write(response.getvalue())

httpd = HTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="./server.key", certfile="./server.cert", server_side=True)

httpd.serve_forever()
