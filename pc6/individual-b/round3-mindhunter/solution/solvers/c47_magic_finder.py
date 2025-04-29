#!/usr/bin/env python3

import requests
import argparse
from bs4 import BeautifulSoup

def parse_headers(header_list):
    """Parses headers from command-line input into a dictionary."""
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers

def get_endpoints(base_url, headers):
    """Scrapes all endpoints listed in the /explorer page."""
    try:
        resp = requests.get(f"{base_url}/explorer", headers=headers, timeout=5)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = soup.find_all('a')
        endpoints = [link.get('href') for link in links if link.get('href') and link.get('href').startswith("/")]
        return list(set(endpoints))  # Deduplicate
    except Exception as e:
        print(f"[!] Error fetching endpoints: {e}")
        return []

def visit_endpoints(base_url, endpoints, headers, magic_indicator="perspective"):
    """Visits each endpoint and checks for the magic indicator in the response."""
    found_magic = []

    print(f"\n[+] Visiting {len(endpoints)} endpoints...\n")
    for endpoint in endpoints:
        try:
            url = f"{base_url}{endpoint}"
            resp = requests.get(url, headers=headers, timeout=3)
            if magic_indicator in resp.text:
                print(f"✅️ {endpoint} --> Magic Endpoint Found!")
                found_magic.append(endpoint)
            else:
                print(f"➖ {endpoint} --> Ordinary Endpoint")
        except Exception as e:
            print(f"[!] Error visiting {endpoint}: {e}")

    return found_magic

def main():
    parser = argparse.ArgumentParser(description="Universal Magic Endpoint Finder with Optional Headers")
    parser.add_argument("--host", required=True, help="Target server (IP or domain, no trailing slash)")
    parser.add_argument("--header", "-H", action="append", help="Optional headers in 'Key: Value' format (can specify multiple)", default=[])
    parser.add_argument("--port", type=int, default=5001, help="Port to connect to (default: 5001)")
    args = parser.parse_args()

    headers = parse_headers(args.header)
    base_url = f"http://{args.host}:{args.port}"

    print(f"[+] Scraping endpoints from {base_url}/explorer with headers: {headers}")

    endpoints = get_endpoints(base_url, headers)
    if not endpoints:
        print("[!] No endpoints found. Aborting.")
        return

    magic_endpoints = visit_endpoints(base_url, endpoints, headers)

    print("\n🎯 Summary: Magic Endpoints Found:")
    if magic_endpoints:
        for magic in magic_endpoints:
            print(f"  - {magic}")
    else:
        print("  - No magic endpoints detected.")

if __name__ == "__main__":
    main()