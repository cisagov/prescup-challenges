#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from http.server import BaseHTTPRequestHandler, HTTPServer

class handler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.send_header('Access-Control-Allow-Origin','*')
		self.end_headers()
		message = "GET Good"
		self.wfile.write(bytes(message,"utf8"))
		
	def do_POST(self):
		#print(self.rfile.readline().decode('utf-8'))
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.send_header('Access-Control-Allow-Origin','*')
		self.end_headers()
		message = "POST Good"
		self.wfile.write(bytes(message,"utf8"))
		

if __name__ == '__main__':
	with HTTPServer(('', 28572),handler) as server:
		server.serve_forever()
