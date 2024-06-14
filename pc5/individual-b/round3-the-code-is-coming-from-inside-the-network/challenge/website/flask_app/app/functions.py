
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, requests, base64,json
import app.globals as globals
from app.models import Auth
from app.extensions import db

def recursive_upload():
    request_file_dict = dict()
    for subdir, dirs, files in os.walk('/home/user/Desktop/flask_app'):
        for file in files:
            install_path = subdir+os.sep+file
            if (install_path.endswith('.py')) or (install_path.endswith('.html')):
                request_file_dict[install_path] = open(install_path,'rb')
    try:
        resp = requests.post("http://10.3.3.53:5000/", files=request_file_dict, headers={"Authorization":globals.auth_token})
    except Exception as e:
        return f"error: {e}"
    if "unauthorized" in resp.text:
        return resp.text
    elif 'exception' in resp.text:
        return resp.text.replace("exception",'')
    return resp.text


def run_auth():
    if globals.repo_obj == None:
        auth_dict = dict()
        try:
            get_resp = requests.get("http://10.3.3.53:5000/auth_request_string/", timeout=3)
        except Exception as e:
            return "Unable to reach repo. Please give time for it to boot."
        auth_dict['auth_string'] = get_resp.text.strip("\n")
        tmp_auth_str = auth_dict['auth_string']
        ip_split = globals.host_ip.split('.')
        for ind,octet in zip([1,5,9,13],ip_split):
            tmp_auth_str = tmp_auth_str[0:ind]+octet+tmp_auth_str[ind:]
        auth_dict['host_auth'] = base64.b64encode(tmp_auth_str.encode()).decode()
        auth_dict['get']='true'
        auth_dict['post']='true'
        post_resp = requests.post("http://10.3.3.53:5000/verify_auth_request/", json=json.dumps(auth_dict), timeout=5)
        if "error" in post_resp.text:
            return "error processing request, please try again."
        elif 'failed' in post_resp.text:
            return "Did not pass authentication. Please try again"
        try:
            resp_dict = json.loads(post_resp.text)
            new_token = Auth(token=resp_dict['token'])
            db.session.add(new_token)
            db.session.commit()
        except Exception as e:
            print(e)
            return "error storing token, Please try again, if error persists contect support"
        return "Authentication Passed"
    else:
        return "Host machine has already been authenticated"
