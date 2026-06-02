import socket

UDP_IP = "0.0.0.0"
UDP_PORT = 5683

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print("Inert CoAP simulator listening on 5683...")
while True:
    data, addr = sock.recvfrom(1024)
    print(f"Got CoAP-like payload from {addr}: {data[:50]}...")
    sock.sendto(b"STATIC-RESPONSE:SHN-A3-PLACEHOLDER", addr)
