#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask_login import UserMixin, AnonymousUserMixin
from flask import current_app
from sqlalchemy import JSON
from sqlalchemy.ext.mutable import MutableDict
from app.extensions import db_conn1, loc_db
from apscheduler.job import Job


class Anonymous(AnonymousUserMixin):
    @property
    def is_authenticated(self):
        return False
    
    @property
    def is_active(self):
        return False  
    
    @property
    def is_anonymous(self):
        return True  
    
    def get_id(self):
        return None


class RcUser(UserMixin):
    __tablename__ = 'RC User'
    def __init__(self, user):
        user_fields = ['id', 'createat', 'updateat', 'deleteat', 'username', 'password', 'authdata', 'authservice', 'email', 'emailverified', 'nickname', 'firstname', 'lastname', 'roles', 'allowmarketing', 'props', 'notifyprops', 'lastpasswordupdate', 'lastpictureupdate', 'failedattempts', 'locale', 'mfaactive', 'mfasecret', 'position', 'timezone', 'remoteid']
        for key, value in user.items():
            if key in user_fields:
                setattr(self,key,value)

    def get(id):
        sql_cmd = f"select * from public.users where id='{id}'"
        mm_db = db_conn1.cursor()
        mm_db.execute(sql_cmd)
        user=mm_db.fetchone()
        mm_db.close()
        if user == None:
            return None
        desc = [row.name for row in mm_db.description]
        user_dict = dict(zip(desc,user))
        return RcUser(user_dict)

    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True  
    
    @property
    def is_anonymous(self):
        return False


class LocalUser(loc_db.Model):
    __tablename__ = 'local_user'
    __mapper_args__ = {
        'confirm_deleted_rows': False
    }
    un_id = loc_db.Column(loc_db.String ,primary_key=True)
    client_ip = loc_db.Column(loc_db.String)
    valid_session = loc_db.Column(loc_db.Boolean)
    endtime = loc_db.Column(loc_db.String)
    time_left = loc_db.Column(loc_db.String)
    passed = loc_db.Column(MutableDict.as_mutable(JSON))

