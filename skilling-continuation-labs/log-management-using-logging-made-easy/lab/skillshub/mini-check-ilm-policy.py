#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


#
# The purpose of this script is to use the ELastic API to querty if students
# have created the appropriate ILM policy and configured correct retentions.
#

import requests
import re
import urllib3

# ---------- Configuration ----------
ELASTIC_URL = "https://10.4.4.10:9200"
API_KEY = "ZlJkVFlwWUIzcWhFemdZY0tmcVc6dXNweHNYNlFUbEtJb3hzZkVJai1MQQ=="
POLICY_NAME = "mc-ilm" # Name of the ILM policy that should exist

# Disable warnings about insecure HTTPS (self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_ilm_policy(policy_name):
    url = f"{ELASTIC_URL}/_ilm/policy/{policy_name}"
    headers = {
        "Authorization": f"ApiKey {API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 404:
        print(f"Failure -- The ILM policy '{policy_name}' does not exist.")
        return None
    elif response.status_code != 200:
        print(f"ERROR -- Failed to retrieve ILM policy: {response.status_code} - {response.text}")
        return None

    return response.json().get(policy_name, {}).get("policy", {})

def parse_duration_to_days(duration_str):
    if not duration_str or not isinstance(duration_str, str):
        return 0

    match = re.match(r"(\d+)(ms|s|m|h|d)", duration_str)
    if not match:
        return 0

    value, unit = int(match.group(1)), match.group(2)
    conversion = {
        "ms": 1 / 1000 / 60 / 60 / 24,
        "s": 1 / 60 / 60 / 24,
        "m": 1 / 60 / 24,
        "h": 1 / 24,
        "d": 1
    }
    return value * conversion.get(unit, 0)

def validate_ilm_policy(policy):
    phases = policy.get("phases", {})
    warm_age = phases.get("warm", {}).get("min_age", "0d")
    delete_age = phases.get("delete", {}).get("min_age", "0d")

    warm_days = parse_duration_to_days(warm_age)
    delete_days = parse_duration_to_days(delete_age)

    if warm_days == 14 and delete_days == 120:
        print(f"Success -- The ILM policy is configured correctly.")
    else:
        print("Failure -- The ILM policy does not meet the required retention settings.")
        # print(f"Warm phase: {warm_days:.2f} days (expected = 30)")
        # print(f"Delete phase: {delete_days:.2f} days (expected = 90)")

def main():
    policy = get_ilm_policy(POLICY_NAME)
    if policy:
        validate_ilm_policy(policy)

if __name__ == "__main__":
    main()
