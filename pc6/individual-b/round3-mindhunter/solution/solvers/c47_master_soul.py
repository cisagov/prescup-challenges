#!/usr/bin/env python3

import requests
import argparse
import base64
import json

def send_payload(host, token1, token2, correct_word):
    url = f"http://{host}/encode"
    headers = {
        "X-Forwarded-Mind": token1,
        "X-Forwarded-Body": token2,
        "X-Perspective": "awakened",
        "Content-Type": "application/json"
    }

    # Encode the payload
    b64_payload = base64.b64encode(correct_word.encode()).decode()

    payload = {
        "task": {
            "payload": {
                "exec": {
                    "cmd": b64_payload
                }
            }
        }
    }

    print("[*] Sending payload...")
    r = requests.post(url, headers=headers, data=json.dumps(payload))

    if r.status_code == 200:
        print("[+] Success!")
        print(r.json())
    else:
        print(f"[-] Failed: {r.status_code}")
        try:
            print(r.json())
        except:
            print(r.text)

def main():
    parser = argparse.ArgumentParser(description="Mirror3 /encode solver")
    parser.add_argument("--host", required=True, help="Target IP address (e.g., 10.4.4.21:5003)")
    parser.add_argument("--token1", required=True, help="Token1 value")
    parser.add_argument("--token2", required=True, help="Token2 value")
    parser.add_argument("--word", default="soul", help="Word to base64 encode (default: 'soul')")

    args = parser.parse_args()

    send_payload(args.host, args.token1, args.token2, args.word)

if __name__ == "__main__":
    main()
