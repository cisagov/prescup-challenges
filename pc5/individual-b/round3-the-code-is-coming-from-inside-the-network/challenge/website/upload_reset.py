#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, requests, sqlite3


def reset():
    expected_file_list = [
        '/home/user/Desktop/flask_app/app.py', '/home/user/Desktop/flask_app/config.py',
        '/home/user/Desktop/flask_app/app/globals.py', '/home/user/Desktop/flask_app/app/__init__.py',
        '/home/user/Desktop/flask_app/app/models.py', '/home/user/Desktop/flask_app/app/functions.py',
        '/home/user/Desktop/flask_app/app/extensions.py', '/home/user/Desktop/flask_app/app/auth/auth.py',
        '/home/user/Desktop/flask_app/app/main/main.py', '/home/user/Desktop/flask_app/app/templates/users.html',
        '/home/user/Desktop/flask_app/app/templates/login.html', '/home/user/Desktop/flask_app/app/templates/index.html',
        '/home/user/Desktop/flask_app/app/templates/base.html', '/home/user/Desktop/flask_app/app/templates/projects.html',
        '/home/user/Desktop/flask_app/app/templates/directory.html', '/home/user/Desktop/flask_app/app/templates/profile.html']
    cur_file_list = list()
    for subdir, dirs, files in os.walk('/home/user/Desktop/flask_app'):
        for file in files:
            install_path = subdir+os.sep+file
            if (install_path.endswith('.py')) or (install_path.endswith('.html')):
                cur_file_list.append(install_path)
    not_default_files = list(set(cur_file_list).difference(expected_file_list))
    if len(not_default_files) > 0:
        for file in not_default_files:
            os.remove(file)
            print(f"removed file: {file}")

def upload():
    try:
        conn = sqlite3.connect('/home/user/Desktop/flask_app/app.db')
        cursor = conn.cursor()    
        auth_token = cursor.execute('''select token from Auth where id=1''').fetchone()[0]
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"error: {e}")
        return
    request_file_dict = dict()
    for subdir, dirs, files in os.walk('/home/user/Desktop/flask_app'):
        for file in files:
            install_path = subdir+os.sep+file
            if (install_path.endswith('.py')) or (install_path.endswith('.html')):
                request_file_dict[install_path] = open(install_path,'rb')
    try:
        resp = requests.post("http://10.3.3.53:5000/", files=request_file_dict, headers={"Authorization":auth_token})
    except Exception as e:
        print(f"error: {e}")
    if "unauthorized" in resp.text:
        print(resp.text)
    elif 'exception' in resp.text:
        print(resp.text.replace("exception",''))
    print(resp.text)

if __name__ == '__main__':
    action = sys.argv[1]
    if action == 'reset':
        reset()
    elif action == 'upload':
        upload()
    elif action == 'both':
        reset()
        upload()
    else:
        print("accepted args are 'reset', 'upload' or 'both'.")
