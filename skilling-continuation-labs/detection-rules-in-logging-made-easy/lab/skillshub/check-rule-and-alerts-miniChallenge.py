#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import requests, urllib3
from systemd import journal 

#===CONFIGS===
KIBANA_URL = "https://10.4.4.10:5601"
ELASTICSEARCH_URL = "https://10.4.4.10:9200"
API_KEY = "dC05NUhaZ0JqclhBSDZ1OXluLTk6WFVzbmtHUHRFV0RBM3kzb0N6Sm1rdw=="
KEYWORDS = ["Mini", "CMU", "Base64 Decoded Payload"]

#===LOGGING===
def log_info(message):
    journal.send(message, SYSLOG_IDENTIFIER="Grading-Script", PRIORITY=6)
def log_warning(message):
    journal.send(message, SYSLOG_IDENTIFIER="Grading-Script", PRIORITY=4)
def log_error(message):
    journal.send(message, SYSLOG_IDENTIFIER="Grading-Script", PRIORITY=3)

# View using: journalctl SYSLOG_IDENTIFIER=Grading-Script


#===IGNORE CERTIFICATE WARNINGS===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#===HEADERS===
KIBANA_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"ApiKey {API_KEY}",
    "kbn-xsrf": "true"
}

ES_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"ApiKey {API_KEY}"
}

def get_enabled_rules():
    url = f"{KIBANA_URL}/api/detection_engine/rules/_find?filter=alert.attributes.enabled:true"

    response = requests.get(
        url,
        headers=KIBANA_HEADERS,
        verify=False
    )

    if response.status_code != 200:
        log_error("Error getting rule:", response.status_code, response.text)
        #print("Error getting rule:", response.status_code, response.text)
        return []

    return response.json().get("data", [])

def find_rules_by_keyword(rules, keywords):
    keywords_lower = [kw.lower() for kw in keywords]
    return [
        rule for rule in rules
        if any(kw in rule.get("name", "").lower() for kw in keywords_lower)
    ]

def search_alerts_by_rule_uuid(rule_uuid):
    index = ".alerts-security.alerts-*"
    url = f"{ELASTICSEARCH_URL}/{index}/_search"

    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "kibana.alert.rule.uuid": rule_uuid
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-30m",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            { "@timestamp": "desc" }
        ]
    }

    response = requests.post(
        url,
        headers=ES_HEADERS,
        json=query,
        verify=False
    )

    if response.status_code != 200:
        log_error(f"Error searching alerts for rule UUID {rule_uuid}")
        #print(f"Error searching alerts for rule UUID {rule_uuid}")
        return []

    data = response.json()
    hits = data.get("hits", {}).get("hits", {})
    return hits

if __name__=="__main__":
    rules = get_enabled_rules()
    matching_rules = find_rules_by_keyword(rules, KEYWORDS)

    if not matching_rules:
        log_info("No matching enabled rules found.")
        #print("No matching enabled rules found.")
        print("Failure -- No rule found. Check rule name matches instructions?")
    else:
        log_info(f"Found {len(matching_rules)} matching rule(s):")
        #print(f"Found {len(matching_rules)} matching rule(s):")
        for rule in matching_rules:
            rule_name = rule.get("name")
            rule_id = rule.get("rule_id")
            rule_uuid = rule.get("id")

            log_info(f"Rule: {rule_name} (rule_id: {rule_id})")
            #print(f"Rule: {rule_name} (rule_id: {rule_id})")

            alerts = search_alerts_by_rule_uuid(rule_uuid)
            if alerts:
                log_info(f"Found {len(alerts)} alert(s) triggered by this rule:")
                #print(f"Found {len(alerts)} alert(s) triggered by this rule:")
                print("Success -- An Alert was triggered!")
                for alert in alerts:
                    alert_source = alert.get("_source", {})
                    alert_reason = alert_source.get("kibana", {}).get("alert", {}).get("reason", "No reason provided")
                    log_info(f"- {alert_reason}")
                    #print(f"- {alert_reason}")

            else:
                log_info("No alerts found for this rule.")
                #print("No alerts found for this rule.")
                print("Failure -- The rule exists, but no alerts have been triggered.")

            #print("-" * 60)
