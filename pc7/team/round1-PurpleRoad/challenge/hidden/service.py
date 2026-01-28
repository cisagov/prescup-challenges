import socket
import threading
import os

HOST = '0.0.0.0'     # Expose to all interfaces
PORT = 8080          # Change to any unused port
UPLOAD_DIR = '/tmp/uploaded_scripts'  # Safe writable dir

os.makedirs(UPLOAD_DIR, exist_ok=True)

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    try:
        conn.sendall(b"Send your Python script (end with EOF line):\n")

        script_lines = []
        while True:
            line = conn.recv(1024)
            if not line:
                break
            if line.strip() == b'EOF':
                break
            script_lines.append(line.decode('utf-8'))

        script = ''.join(script_lines)
        filename = os.path.join(UPLOAD_DIR, f'script_{addr[1]}.py')

        with open(filename, 'w') as f:
            f.write(script)

        conn.sendall(b"Executing script...\n")

        # Insecure: executing uploaded code
        try:
            exec_globals = {}
            exec(script, exec_globals)
            conn.sendall(b"Execution complete.\n")
        except Exception as e:
            conn.sendall(f"Execution error: {e}\n".encode('utf-8'))

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed for {addr}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[+] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

if __name__ == '__main__':
    main()
