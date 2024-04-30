#!/usr/bin/python3

import requests, base64, json

def run_auth():
    auth_dict = dict()
    try:
        get_resp = requests.get("http://10.3.3.53:5000/auth_request_string/", timeout=3)
    except Exception as e:
        print("Unable to reach repo. Please give time for it to boot.")
    auth_dict['auth_string'] = get_resp.text.strip("\n")
    tmp_auth_str = auth_dict['auth_string']
    ip_split = "**IP address of Kali VM**".split('.')
    for ind,octet in zip([1,5,9,13],ip_split):
        tmp_auth_str = tmp_auth_str[0:ind]+octet+tmp_auth_str[ind:]
    auth_dict['host_auth'] = base64.b64encode(tmp_auth_str.encode()).decode()
    auth_dict['get']='true'
    auth_dict['post']='true'
    post_resp = requests.post("http://10.3.3.53:5000/verify_auth_request/", json=json.dumps(auth_dict), timeout=5)
    print(post_resp.text)

    
if __name__ == "__main__":
    run_auth()