#!/usr/bin/env python3

import requests
import argparse
import time

def patch_timeout(host, headers):
    url = f"http://{host}/timeout"
    try:
        r = requests.patch(url, headers=headers)
        return r
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Peace /timeout solver (timing based)")
    parser.add_argument("--host", required=True, help="Target IP (e.g., 10.4.4.21:5004)")
    parser.add_argument("--token1", required=True, help="Token1 value")
    parser.add_argument("--token2", required=True, help="Token2 value")
    parser.add_argument("--token3", required=True, help="Token3 value")

    args = parser.parse_args()

    headers = {
        "X-Forwarded-Mind": args.token1,
        "X-Forwarded-Body": args.token2,
        "X-Forwarded-Soul": args.token3,
        "X-Perspective": "acceptance",
        "Content-Type": "application/json"
    }

    print("[*] Sending first PATCH to /timeout...")
    resp1 = patch_timeout(args.host, headers)

    if resp1:
        try:
            print(resp1.json())
        except:
            print(resp1.text)

    print("[*] Waiting 10 seconds exactly...")
    time.sleep(10)

    print("[*] Sending second PATCH to /timeout...")
    resp2 = patch_timeout(args.host, headers)

    if resp2:
        try:
            print(resp2.json())
        except:
            print(resp2.text)

if __name__ == "__main__":
    main()
