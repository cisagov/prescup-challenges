#!/usr/local/bin/python

import requests
import logging
import os

URL = "http://internalreports.pccc/reports.php"

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --- Payloads ---
safe_queries = [
    {"type": "clients", "query": "alice", "expected": ["Name", "Email", "2024-05-01", "alice"], "unexpected": ["2024-01-15", "bob"]},
    {"type": "quotes", "query": "Q1010", "expected": ["QuoteID", "ClientID", "13250", "Q1010"], "unexpected": ["2023-12-22", "Pending"]},
    {"type": "orders", "query": "cloud", "expected": ["OrderID", "ClientID", "C002", "Status", "Migration"], "unexpected": ["2024-01-10", "Hosting"]}
]
injection_attempts = [
    {"type": "clients", "query": "alice; whoami"},
    {"type": "clients", "query": "alice && whoami"},
    {"type": "clients", "query": "alice | whoami"},
    {"type": "clients", "query": "alice`whoami`"},
    {"type": "clients", "query": "alice$(whoami)"}
]

# Indicators that command injection occurred
suspicious_terms = ["root", "user", "www-data", "uid=", "whoami"]

def test_safe_queries():
    for q in safe_queries:
        try:
            res = requests.get(URL, params={"type": q["type"], "query": q["query"]}, timeout=3)
            if res.status_code != 200:
                logging.info(f"Safe query for type '{q['type']}' failed with status {res.status_code}")
                return "reportsFixed: Failure - Web service not responding correctly"
            if not all(field in res.text for field in q["expected"]):
                logging.info(f"Safe query for type '{q['type']}' did not contain expected fields")
                return f"reportsFixed: Failure - '{q['type']}' CSV output not present"
            if any(field in res.text for field in q["unexpected"]):
                logging.info(f"Safe query for type '{q['type']}' contained unexpected fields")
                return f"reportsFixed: Failure - '{q['type']}' CSV output contains unexpected fields"
        except Exception as e:
            logging.info(f"Exception on safe query for {q['type']}: {e}")
            return "reportsFixed: Failure - Web service error on safe query"
    return ""


def test_injections():
    for payload in injection_attempts:
        try:
            res = requests.get(URL, params=payload, timeout=3)
            content = res.text.lower()
            if any(term in content for term in suspicious_terms):
                logging.info(f"Injection leaked: {payload['query']}")
                return "reportsFixed: Failure - Injection vulnerability still present on internalreports.pccc"
        except Exception as e:
            logging.info(f"Injection attempt error: {e}")
            return "reportsFixed: Failure - Web service error on injection attempt"
    return ""


if __name__ == "__main__":
    safe = test_safe_queries()
    
    if safe == "":
        injected = test_injections()

        if injected == "":
            print(f"reportsFixed: Success - Injection mitigated and service intact")
        else:
            print(injected)
    else:
        print(safe)
    
