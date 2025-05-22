import signal
import socket
import time
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

CR_LF = "\r\n"

ALLOWED_URLS = ["/", "/channel", "/token", "/maelstrom"]

HOST_ALIASES = ["channel.us", "channel.us:8080"]

MAX_BODY_SIZE = 1024

PROXY = ""

PROXY_PORT = 0

class ClientClosed(Exception):
    pass
class BadData(Exception):
    pass

class HTTPHandler:

    def __init__(self, socket, timeout=5, maxAttempts=5):
        self.data = ""
        self.socket = socket
        self.timeout = timeout
        self.maxAttempts = maxAttempts

    # Retrieves size bytes from the socket
    def getChunk(self, size):
        self.socket.settimeout(self.timeout)
        chunk = self.socket.recv(size).decode('utf-8')
        if not chunk:
            raise ClientClosed
        self.data += chunk

    # Returns the next line from the socket
    def linesGen(self):
        attempt = 0
        while attempt < self.maxAttempts:
            self.getChunk(128)

            # If buffer fills with no new line, throw exception
            if CR_LF not in self.data and len(self.data) >= 128:
                raise BadData

            # If no new line after getChunk, wait and try again
            if CR_LF not in self.data:
                attempt += 1
            else:
                attempt = 0 

            # Read out lines in buffer
            while CR_LF in self.data:
                line, self.data = self.data.split(CR_LF, 1)
                yield line
    
    def code2Message(self, code):
        if code == 200:
            return "OK"
        elif code == 400:
            return "Bad Request"
        elif code == 403:
            return "Forbidden"
        elif code == 404:
            return "Not Found"
        elif code == 405:
            return "Method Not Allowed"
        elif code == 413:
            return "Content Too Large"
        elif code == 501:
            return "Not Implemented"
        elif code == 505:
            return "HTTP Version Not Supported"
        return "Bad Request"

    # Creates a new HTTP Response
    def craftResponse(self, code, body, headers):
        # Line 1
        response = f"HTTP/1.1 {code} {self.code2Message(code)}{CR_LF}"
        # Add Headers
        for h in headers:
            response += h + f"{CR_LF}"
        # Add the body
        if isinstance(body, str) and body != "":
            response += f"Content-Length: {len(body) + len(CR_LF)}{CR_LF}"
            # Add content length and the body
            response += f"{CR_LF}{body}{CR_LF}"
        elif isinstance(body, list) and len(body) != 0:
            # Add transfer encoding and the body
            response += f"Transfer-Encoding: chunked{CR_LF}{CR_LF}"
            for b in body:
                response += f"{len(b)}{CR_LF}"
                response += f"{b}{CR_LF}"
            response += f"0{CR_LF}{CR_LF}"
        else:
            # No body (for my oooown oooohaaaaaaaa)
            response += f"{CR_LF}"
        return response

    # Returns the Method, Path, and Version
    def parseFirstLine(self, line):
        vals = line.split(" ")
        if len(vals) != 3:
            return (-1, -1, -1)

        return (vals[0], vals[1], vals[2])

    # Check method, path, and version are all valid
    def validateRequest(self, method, path, version):
        if method != "GET" and method != "POST":
            logging.info("Bad method, sending 501")
            return 501
        
        if path not in ALLOWED_URLS:
            logging.info("Unknown URL, sending 404")
            return 404
        
        if version != "HTTP/1.1":
            logging.info("Bad HTTP Version, sending 505")
            return 505

        return 200

    # Retrieve size bytes from data buffer.
    # If buffer isn't full enough, calls getChunk to fill it 
    def getData(self, size):
        if size > len(self.data):
            self.getChunk(size - len(self.data))
        ret = self.data[:size]
        self.data = self.data[size:]
        return ret
    
    # Crafts a HTTP request to send to out Proxy
    def craftRequest(self, method, path, body, headers):
        # Line 1
        request = f"{method} {path} HTTP/1.1{CR_LF}"
        # Host line should be our proxy 
        request += f"Host: {PROXY}:{PROXY_PORT}{CR_LF}"
        # Only one request to the proxy
        request += f"Connection: close{CR_LF}"  # Only want to make one request
        for h in headers:  # Custom headers
            request += h + f"{CR_LF}"
        if isinstance(body, str) and body != "":
            # Add content length and the body
            request += f"Content-Length: {len(body) + len(CR_LF)}{CR_LF}"
            request += f"{CR_LF}{body}{CR_LF}"
        elif isinstance(body, list) and len(body) != 0:
            # Add transfer encoding and the body
            request += f"Transfer-Encoding: chunked{CR_LF}{CR_LF}"
            for b in body:
                request += f"{len(b)}{CR_LF}"
                request += f"{b}{CR_LF}"
            request += f"0{CR_LF}{CR_LF}"
        else:
            # No body (for my oooown oooohaaaaaaaa)
            request += f"{CR_LF}"
        return request

    # Socket connection to the proxy
    def proxyPass(self, method, path, body, headers):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((PROXY, PROXY_PORT))
            s.settimeout(self.timeout)
            s.sendall(self.craftRequest(method, path, body, headers).encode('utf-8'))

            logging.info("Passed request to proxy")
            ret = b""
            try:
                data = s.recv(1024)
                while data != b"":
                    ret += data
                    data = s.recv(1024)
            except TimeoutError:
                pass
            logging.info(f"Received from proxy: {ret}")
            return ret 

    # The work horse of the server
    # Retrieves and handles the incoming HTTP requests
    def handleRequests(self):
        lines = self.linesGen()
        while True:
            
            request = []
            # Read the request line by line
            line = next(lines).strip()
            while line != "":
                request.append(line)
                line = next(lines).strip()

            if len(request) > 0:
                logging.info(f"Received request: {'~'.join(request)}")

            # Valid request must have Method Path Version and Host lines
            if len(request) < 2:
                logging.info("Malformed request -- Must be at least two lines")
                response = self.craftResponse(400, "", ["Connection: close"])
                self.socket.sendall(response.encode('utf-8'))
                return
            
            # Retrieve and validate first line
            method, path, version = self.parseFirstLine(request[0])
            code = self.validateRequest(method, path, version)

            if code != 200:
                response = self.craftResponse(code, "", ["Connection: close"])
                self.socket.sendall(response.encode('utf-8'))
                return

            # Retrieve and validate Host
            vals = request[1].split(": ", 1)
            if len(vals) != 2 or vals[0] != "Host" or vals[1] not in HOST_ALIASES:
                logging.info("Malformed request -- Must contain a valid Host")
                response = self.craftResponse(400, "", ["Connection: close"])
                self.socket.sendall(response.encode('utf-8'))
                return

            # Handle these headers:
            # Connection Content-Length Content-Type Transfer-Encoding
            body = None
            headers = []
            keep_alive = True
            for line in request[2:]:
                vals = line.split(": ", 1)
                if len(vals) != 2:
                    continue  # Just drop bad headers
                header = vals[0]
                val = vals[1]

                if header == "Connection":
                    # Check if this is the last request
                    if val != "keep-alive":
                        logging.info("Final request, connection set to close")
                        keep_alive = False
                    else:
                        logging.info("Connection will remain open")
                        keep_alive = True
                    headers.append(line) # Put it back for use in response
                elif header == "Content-Length":
                    try:
                        size = int(val)
                    except ValueError:
                        # Bad size
                        size = MAX_BODY_SIZE + 1 
                    if size > MAX_BODY_SIZE:
                        logging.info("Malformed request -- Content length was too long")
                        response = self.craftResponse(413, "", ["Connection: close"])
                        self.socket.sendall(response.encode('utf-8'))
                        return
                    else:
                        # Grab next size bytes as the data
                        body = self.getData(size)
                        # Need to escape for logging purposes
                        log = body.replace('\n', '\\n').replace('\r', '\\r')
                        logging.info(f"Packet body ({size}) - {log}")
                elif header == "Transfer-Encoding" and body is None:
                    if val != "chunked":  # Only supporting chunked at the moment
                        logging.info("Malformed request -- Bad transfer-encoding")
                        response = self.craftResponse(501, "", ["Connection: close"])
                        self.socket.sendall(response.encode('utf-8'))
                        return       
                    body = []
                    # Retrieve size of first chunk
                    line = next(lines).strip()
                    while line != "" and line != "0":
                        try:
                            # If size valid, grab next size bytes as data
                            body.append(self.getData(int(line, 16)))
                        except ValueError:
                            logging.info("Malformed request -- Bad data size for transfer encoding")
                            response = self.craftResponse(501, "", ["Connection: close"])
                            self.socket.sendall(response.encode('utf-8'))
                            return
                        next(lines)  # Consume the new line left over from above
                        line = next(lines).strip() # Retrieve size of next chunk
                    next(lines)  # Consume the final empty line following the "0"
                    # Need to escape for logging purposes
                    log = '~'.join(body).replace('\n', '\\n').replace('\r', '\\r')
                    logging.info(f"Packet chunks - {log}")
                else:
                    # Unknown header - just slap it on there I guess
                    logging.info(f"Extra header appended: {line}")
                    headers.append(line)
            
            if not any("Connection" in h for h in headers):
                headers.append("Connection: close")  # If none specified, we close
                logging.info("Added Connection close header")

            responseBody = ""
            # Retrieve the HTML if requested
            if path == "/token":
                with open("./token.html", "r") as f:
                    responseBody = f.read()
            elif path == "/" or path == "/channel":
                with open("./channel.html", "r") as f:
                    responseBody = f.read()
            
            if responseBody == "":
                #Proxy pass
                response = self.proxyPass(method, path, body, headers)
                self.socket.sendall(response)
            else:
                response = self.craftResponse(200, responseBody, headers)
                self.socket.sendall(response.encode('utf-8'))

            if not keep_alive:
                return

terminate = False

# Define the signal handler for SIGTERM
def handle_sigterm(signum, frame):
    global terminate
    logging.info("Received SIGTERM signal. Exiting...")
    terminate = True

def run_server(port):
    global terminate
    """Starts the HTTP server to handle requests"""
    host = '0' # Listen on all interfaces

    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    logging.info(f"Server running on {host}:{port}")
    try:
        while not terminate:
            # Accept client connections
            client_socket, client_address = server_socket.accept()
            logging.info(f"Connection established with {client_address}")
            
            try:
                # Handle client requests
                handle = HTTPHandler(client_socket)
                handle.handleRequests()
            except (ClientClosed, ConnectionResetError):
                logging.info("Client disconnected")
            except BadData:
                logging.info("Client sent malformed data")
            except (TimeoutError, socket.timeout):
                logging.info("Timeout")
            finally:
                # Close the client socket after finishing the requests
                logging.info("Closing connection")
                client_socket.close()
    except KeyboardInterrupt:
        logging.info("Server interrupted by user. Exiting...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sigterm)

    parser = argparse.ArgumentParser(description='HTTP (Hyperspace Tunnel Travel Protocol) Server')
    parser.add_argument('-X', '--proxyhost', nargs=1, help='Proxy hostname', required=True)
    parser.add_argument('-Y','--proxyport', nargs=1, help='Proxy port', default=["8080"])
    parser.add_argument('-H','--host', nargs='*', help='Server hostname', default = [])
    parser.add_argument('-P', '--port', nargs=1, help='Server port', default=["8080"])

    args = parser.parse_args()

    port = int(args.port[0], 10)

    for h in args.host:
        HOST_ALIASES.append(h)
        HOST_ALIASES.append(f"{h}:{port}")

    PROXY = args.proxyhost[0]
    PROXY_PORT = int(args.proxyport[0], 10)

    run_server(port)
