#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys
from flask import jsonify,flash
from cryptography.fernet import Fernet
from extensions import db


class ID(db.Model):
    __tablename__ = 'ID'
    username = db.Column(db.String, primary_key=True, nullable=False)
    email = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    key = db.Column(db.String, nullable=False)
    hash = db.Column(db.String, nullable=False)

class AdminCodes(db.Model):
    __table__name = "AdminCodes"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String,nullable=False)
    code = db.Column(db.String, nullable=False)



class Create_ID():
    def __init__(self):
        self.__username = ""
        self.__email = ""
        self.__role = ""
        self.__unlock_code = ""
        self.__cipher_lock = ""
        self.__key_file = ".key"

    @property
    def username(self):
        return self.__username
    
    @username.setter
    def username(self,username):
        self.__username = username

    @property
    def email(self):
        return self.__email
    
    @email.setter
    def email(self,email):
        self.__email = email

    @property
    def role(self):
        return self.__role
    
    @role.setter
    def role(self,role):
        self.__role = role

    @property
    def unlock_code(self):
        return self.__unlock_code
    
    @unlock_code.setter
    def unlock_code(self,unlock_code):
        self.__cipher_lock  = Fernet.generate_key()
        f = Fernet(self.__cipher_lock )
        self.__unlock_code = f.encrypt(unlock_code.encode()).decode()
        del f
        #self.__key = key

    def create(self):
        basedir = "/home/user/Desktop/identification/storage/"
        cred_filename = f"{self.__username}.cred.ini"
        #id_filename = str(self.__username+".ini")
        f = Fernet(self.__cipher_lock)
        try:
            ini_file = basedir + cred_filename
            with open(ini_file,'w+') as file_in:
                file_in.write("#Credential File:\nUsername={}\nEmail={}\nrole={}\ncode={}\n".format(f.encrypt(self.__username.encode()).decode(),f.encrypt(self.__email.encode()).decode(),f.encrypt(self.__role.encode()).decode(),self.__unlock_code))
                file_in.write("++"*20)
        except Exception as e:
            flash(jsonify({"error":str(e)}))
            os.remove(cred_filename)
            return False

        self.__key_file = self.__username + self.__key_file

        try:
            key_file = basedir + self.__key_file
            with open(key_file,'w') as key_in:
                key_in.write(self.__cipher_lock.decode())

        except Exception as e:
            os.remove(cred_filename)
            os.remove(self.__key_file)
            flash(jsonify({"error":str(e)}))
            return False
            #sys.exit()

        self.__username = ""
        self.__email = ""
        self.__role = ""
        self.__unlock_code = ""
        self.__cipher_lock  = ""
        self.__key_file
        return True
