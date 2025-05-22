import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Create /app directory if it doesn't exist
        app_dir = '/app'
        if not os.path.exists(app_dir):
            os.makedirs(app_dir, exist_ok=True)
        
        # Save the received data to a file in /app
        current_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = os.path.join(app_dir, f'data_{self.client_address[0]}_{os.getpid()}_{current_date}.txt')
        with open(filename, 'wb') as f:
            f.write(post_data)
        
        # Send response
        self.send_response(200)
        self.wfile.write(b"Data received and saved successfully")

def run_server():
    server_address = ('', 80)  # Listen on all interfaces, port 80
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print("Starting server on port 80...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the server...")

if __name__ == "__main__":
    run_server()