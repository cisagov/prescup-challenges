#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, traceback, secrets, json, hashlib, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, jsonify, flash
from extensions import db
from models import ID, Create_ID
from cryptography.fernet import Fernet



######## Funcs to create app and other checks
def create_app():
    app = Flask(__name__) 
    app.config['SECRET_KEY'] = 'NOT_A_TOKEN' 
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'id.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    db.init_app(app) 
    with app.app_context():
        db.create_all()
    return app

def check_existing(un,update=False):
    try:
        chk = ID.query.filter_by(username=un).one()
        if update == True:
            return chk
        return True
    except:
        return False

######## func to handle sending ID to user
def send_mail(un,recp):
    sender = "canello.temporary@merch.codes"
    sent_mail_chk = 0
    files = [f"/home/user/Desktop/identification/storage/{un}.cred.ini"]
    for file in files:
        message = MIMEMultipart()
        message["From"] = sender
        message['To'] = recp
        message['Subject'] = "New digital Identification"
        
        attachment = open(file,'rb')
        fn = file.rsplit('/',1)[1]
        obj = MIMEBase('application','octet-stream')
        obj.set_payload((attachment).read())
        encoders.encode_base64(obj)
        obj.add_header("content-disposition","attachment; filename= "+fn)
        message.attach(obj)
        my_message = message.as_string()
        with smtplib.SMTP('mail.merch.codes', 25) as smtp:
            try:
                smtp.sendmail(sender,recp,my_message)
            except:
                flash(jsonify({"error":f"Unable to send {file}"}))
                print(f"ERROR: Issue when sending file:\t{file}.")
            else:
                sent_mail_chk += 1
                print(f"{fn} sent")
    return sent_mail_chk == len(files)


######## funcs to handle creating ID 
def create_new_id(id_info):
    if check_existing(id_info['un']):
        flash("ID already exists for this user")
        return False
    creds = Create_ID()
    creds.username = id_info['un']
    creds.email = id_info['email']
    creds.role = id_info['role']
    creds.unlock_code = id_info['key']
    resp = creds.create()
    if resp == True:
        file_hash = create_hash(id_info['un'])
        new_id = ID(username=id_info['un'],email=id_info['email'],role=id_info['role'],key=id_info['key'], hash=file_hash)
        try:
            db.session.add(new_id)
            db.session.commit()
        except Exception as e:
            print(f"Error adding new ID.\t{str(e)}")
            flash(jsonify({"error":"Unable to add new ID to Database"}))
            return False
        else:
            return True
    flash("Error creating new ID file.")
    return False


######## func to create hash of file
def create_hash(un):
    fn = f"/home/user/Desktop/identification/storage/{un}.cred.ini"
    with open(fn,'rb') as f:
        data = f.read()
    md5hash = hashlib.md5(data).hexdigest()
    return md5hash


######## funcs to handle updating ID 
def update_record(id_info):
    id_to_update = check_existing(id_info['old_un'], update=True)
    if id_to_update == False:
        flash("No ID found with this username")
        return False
    os.remove(f"/home/user/Desktop/identification/storage/{id_to_update.username}.cred.ini")
    os.remove(f"/home/user/Desktop/identification/storage/{id_to_update.username}.key")
    creds = Create_ID()
    creds.username = id_info['new_un']
    creds.email = id_info['email']
    creds.role = id_info['role']
    creds.unlock_code = id_info['key']
    resp = creds.create()
    if resp == True:
        file_hash = create_hash(id_info['new_un'])
        id_to_update.username = id_info['new_un']
        id_to_update.email = id_info['email']
        id_to_update.role = id_info['role']
        id_to_update.key = id_info['key']
        id_to_update.hash = file_hash
        try:
            db.session.commit()
        except Exception as e:
            print(f"Error adding new ID.\t{str(e)}")
            flash(jsonify({"error":"Unable to add new ID to Database"}))
            return False
        else:
            return True
    flash("Error creating new ID file.")
    return False


######## Function used to decrypt ID files
def decrypt_id(un):
    if not check_existing(un):
        return "ID does not exist for this user"
    filename = f"/home/user/Desktop/identification/storage/{un}.cred.ini"
    keyfile = f"/home/user/Desktop/identification/storage/{un}.key"

    with open(keyfile,'r') as f:
        cipher_key = f.read().encode()

    decryptor = Fernet(cipher_key)

    with open(filename) as f:
        lines = f.readlines()
    data_dict = dict()
    for line in lines:
        tmp_list = line.rstrip('\n').split('=',1)
        if (len(tmp_list) == 2):
            if 'code' not in tmp_list[0]:
                data_dict[tmp_list[0]] = decryptor.decrypt(tmp_list[1].encode()).decode()
            else:
                data_dict[tmp_list[0]] = tmp_list[1]
