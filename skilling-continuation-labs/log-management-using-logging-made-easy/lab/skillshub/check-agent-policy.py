#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#
# The purpose of this script is to use the Kibana API to query if students
# have created the appropriate policy and added the correct integrations.
#

import requests
import urllib3

# ---------- Configuration ----------
KIBANA_URL = "https://10.4.4.10:5601"
API_KEY = "ZlJkVFlwWUIzcWhFemdZY0tmcVc6dXNweHNYNlFUbEtJb3hzZkVJai1MQQ=="
POLICY_NAME = "Webserver Policy" # Name of the agent policy that should exist
EXPECTED_INTEGRATIONS = {"system", "auditd", "apache"}  # Integrations that should be present in the policy

# Disable warnings about insecure self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Headers for using Kibana API
HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
    "Authorization": f"ApiKey {API_KEY}"
}

def get_agent_policies():
    url = f"{KIBANA_URL}/api/fleet/agent_policies"
    response = requests.get(url, headers=HEADERS, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def get_package_policies_for_policy(policy_id):
    url = f"{KIBANA_URL}/api/fleet/package_policies"
    params = {"kuery": f'ingest-package-policies.policy_id : "{policy_id}"'}
    response = requests.get(url, headers=HEADERS, params=params, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def main():
    try:
        policies = get_agent_policies()
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to connect to Kibana: {e}")
        return

    # Find the custom policy
    custom_policy = next((p for p in policies if p["name"] == POLICY_NAME), None)
    if not custom_policy:
        print(f"FAIL: Policy '{POLICY_NAME}' not found.")
        return

    print(f"SUCCESS: Found policy: {custom_policy['name']} (ID: {custom_policy['id']})")

    try:
        packages = get_package_policies_for_policy(custom_policy["id"])
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to retrieve integrations: {e}")
        return

    found_integrations = {pkg["package"]["name"] for pkg in packages if pkg.get("package")}

    print(f"INFO: Integrations found: {', '.join(found_integrations)}")

    if EXPECTED_INTEGRATIONS.issubset(found_integrations):
        print("SUCCESS: All expected integrations are present.")
    else:
        missing = EXPECTED_INTEGRATIONS - found_integrations
        print(f"FAIL: Missing expected integrations: {', '.join(missing)}")

if __name__ == "__main__":
    main()
