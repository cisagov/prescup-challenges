# Import necessary modules
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Send response headers
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # Send the response body
        self.wfile.write(b"The secret token is totally not here. s.VuGa:D-m7CLS6g39!8J")

if __name__ == "__main__":
    # Create an HTTP server object on port 80
    server_address = ('0.0.0.0', 80)
    http_server = HTTPServer(server_address, SimpleHandler)

    # Start the server
    print("Starting server on port 80...")
    http_server.serve_forever()