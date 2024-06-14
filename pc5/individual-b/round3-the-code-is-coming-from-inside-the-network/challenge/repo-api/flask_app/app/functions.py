
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, zipfile, subprocess, datetime, base64, random
from sqlalchemy.orm.exc import *
from app.models import Last_update, Auth, Backup, Source
from app.extensions import db
from pathlib import Path
import app.globals as globals


def download_all(files):
    cur_zip = Path("/home/user/Desktop/flask_app/app/main/static/website.zip")
    if cur_zip.is_file():
        os.remove(cur_zip)
    zip_folder = zipfile.ZipFile("/home/user/Desktop/flask_app/app/main/static/website.zip",'w', compression=zipfile.ZIP_STORED)
    for file in files:
        tmp_str = file.blob
        zip_folder.writestr(file.name, tmp_str)
    zip_folder.close()
    return 

def update_website(action, files):
    update_tracker = Last_update.query.filter_by(id=1).first()
    resp = """"""
    if update_tracker == None:
        update_tracker = Last_update(last_push=datetime.datetime(2023,1,1,1,1).strftime('%m-%d-%Y, %H:%M'))
    try:
        subprocess.run(f"ssh user@10.7.7.7 'sudo systemctl stop website.service'",shell=True)
        if action == 'reset':
            try:
                res = db.session.execute("SELECT id,name from Source WHERE name NOT IN (SELECT name FROM Backup)")
                res_list = res.fetchall()
                for tuple in res_list:
                    cur_file = Source.query.filter_by(id=tuple[0]).one()
                    db.session.delete(cur_file)
                    db.session.commit()
            except Exception as e:
                print(str(e))
                return "Error attempting to clean up DB. Please try again, if issue persists please contact support."
            resp = """
            Website files being reset. 
            Please give it a moment to update before attempting connection.
            """
            for file in files:
                subprocess.run(f"ssh user@10.7.7.7 'cat > {file.remote_path}'",input=file.blob,shell=True)
                matching_source = Source.query.filter_by(name=file.name).one()
                matching_source.name = file.name
                matching_source.remote_path = file.remote_path
                matching_source.blob = file.blob
                matching_source.last_update = file.last_update
                db.session.commit()
            subprocess.run(f"ssh user@10.7.7.7 'python3 /home/user/Desktop/upload_reset.py reset'",shell=True)
        else:
            resp = """
            Website files being updated. 
            Please give it a moment to update before attempting connection.
            """
            for file in files:
                if file.last_update > update_tracker.last_push:
                    subprocess.run(f"ssh user@10.7.7.7 'cat > {file.remote_path}'",input=file.blob,shell=True)
        subprocess.run(f"ssh user@10.7.7.7 'sudo systemctl start website.service'",shell=True)
        push_time = datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')
        update_tracker.last_push = push_time
        db.session.commit()
    except Exception as e:
        print(f"error:\t{e}")
        subprocess.run(f"ssh user@10.7.7.7 'sudo systemctl start website.service'",shell=True)
        return "Unable to complete request, please try again. If issue persists please contact support."
    return resp

def check_auth(method, req_ip, headers):
    if (req_ip == "127.0.0.1") or  (req_ip == "10.3.3.53"):
        return True
    try:
        ip_record = Auth.query.filter_by(ip=req_ip).one()
        if getattr(ip_record,method) == 'true':
            if method == 'post':
                try:
                    if 'Authorization' in list(headers.keys()):
                        if headers['Authorization'] == ip_record.token:
                            return True
                        return "Authentication failed. Passed key does not match key on file."
                    return "Authentication failed. Authorization header containing authentication key missing."
                except Exception as e:
                    print(str(e))
                    return f"exception {str(e)}"
                else:
                    return False
            return True
    except NoResultFound as n:
        print(str(n))
        return None
    except Exception as e:
        print(e)
        return f"exception {str(e)}"
    else:
        return False

def verify_auth_new_host(req_ip, req_json):
    decoded_host_auth_str = base64.b64decode(req_json['host_auth']).decode("utf-8")
    req_ip_split = reversed(req_ip.strip('\n').split('.'))
    ip_chk = list()
    for ind,octet in zip([13,9,5,1],req_ip_split):
        tmp_len = ind + len(octet)
        cur_oct = decoded_host_auth_str[ind:tmp_len]
        if cur_oct == octet:
            ip_chk.insert(0,cur_oct)

    if '.'.join(ip_chk) == req_ip:
        return True
    return False

def rotate_auth_token():
    globals.auth_string = ''.join(random.choice(globals.auth_chars) for _ in range(12))
