import socket
import os
import platform
import subprocess
from ipaddress import ip_network

def ping_host(host):
    """
    Ping a host to check if it's alive.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        subprocess.run(["ping", param, "1", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def scan_ports(host, ports):
    """
    Scan specific ports on a host to see if they are open.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def scan_network(network_range):
    print(f"Scanning network: {network_range}")
    ports_to_scan = [22, 80, 443]  # Common ports
    live_hosts = []

    # Generate IP addresses for the network
    for ip in ip_network(network_range, strict=False).hosts():
        ip = str(ip)
        if ping_host(ip):
            print(f"Host {ip} is up.")
            open_ports = scan_ports(ip, ports_to_scan)
            print(f"  Open Ports: {open_ports}")
            live_hosts.append((ip, open_ports))
    print("\nScan complete.")
    return live_hosts

def connect_to_server(server_ip, server_port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        print("Connected to server")

        # Receive network scan instructions
        data = client_socket.recv(1024).decode()
        print(f"Server says: {data}")

        if "SCAN NETWORK" in data:
            network_range = data.split(":")[1].strip()
            scan_network(network_range)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    server_ip = "10.3.3.3"  # Change to server's IP if needed
    server_port = 9090
    connect_to_server(server_ip, server_port)
# ON Venenatis
