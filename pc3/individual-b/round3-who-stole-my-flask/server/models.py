
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask_login import UserMixin, AnonymousUserMixin
from flask import Flask, jsonify, make_response
import pandas as pd
import json
#from __init__ import db


RECORDS = './static/records.csv'


class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.role='guest'

class User(UserMixin):
    def __init__(self, userID):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        self.id = userID
        self.username = records[userID]['username']
        self.password = records[userID]['password']
        self.name = records[userID]['name']
        self.email = records[userID]['email']
        self.note = records[userID]['note']
        self.role = records[userID]['role']


    @staticmethod
    def chkUsers(em):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        for u in records:
            if (em == records[u]['email']):
                return True
        return False

    @staticmethod
    def authUser(e, pwd):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        curUser=int
        for u in records:
            if records[u]['email'] == e:
                curUser = u
                break
        if records[curUser]['password'] == pwd:
            return curUser
        return False

    @staticmethod
    def addUser(un, e, name, pwd, note='', role='user'):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        curIndexs = list()
        for k,v in records.items():
            curIndexs.append(k)
        if (len(curIndexs) == 0):
            newID = 1
        else:
            newID = str(int(curIndexs[-1]) + 1)
        records[newID] = {'name': str(name), 'username' : str(un), 'email': str(e), 'password': str(pwd),'note': note, 'role': role}
        pd.DataFrame.from_dict(records, orient='index').to_csv(RECORDS, index_label='id', sep=',')

    @staticmethod
    def userSearch(searchRole, username='', email='', name='', password='', note='', role=''):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        ans=list()
        userList=list()
        for u in range(1, len(records)+1):
            curUser = User(u)
            userList.append(curUser)
        for user in userList:
            if username==email==name==password==note==role=='':
                if (searchRole == 'admin'):
                    ans.append(user)
                else:
                    user.password=user.role=None
                    ans.append(user)
            else:
                if username != '':
                    if user.username != username:
                        continue
                if email != '':
                    if user.email != email:
                        continue
                if name != '':
                    if user.name != name:
                        continue
                if password != None:
                    if user.password != password:
                        continue
                if note != '':
                    if user.note != note:
                        continue
                if role != None:
                    if user.role != role:
                        continue
                if (searchRole == 'admin'):
                        ans.append(user)
                else:
                    user.password=user.role=None
                    ans.append(user)
        if (len(ans) == 0):
            return 0
        return ans

    @staticmethod
    def updateUser(curID,curRole,username,email,name,password,note,newRole):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        curRec = records[int(curID)]
        if curRole == 'admin':
            if (newRole != '') and (newRole != None):
                curRec['role']=newRole
        if (username != '') and (username != None):
            curRec['username']=username
        if (email != '') and (email != None):
            curRec['email']=email
        if (name != '') and (name != None):
            curRec['name']=name
        if (password != '') and (password != None):
            curRec['password']=password
        if (note != '') and (note != None):
            curRec['note']=note

        records[int(curID)]={'name': str(curRec['name']), 'username' : str(curRec['username']), 'email': str(curRec['email']), 'password': str(curRec['password']),'note': curRec['note'], 'role': curRec['role']}
        pd.DataFrame.from_dict(records, orient='index').to_csv(RECORDS, index_label='id', sep=',')

    @staticmethod
    def delUser(uid):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        try:
            del records[uid]
            pd.DataFrame.from_dict(records, orient='index').to_csv(RECORDS, index_label='id', sep=',')
            return 0
        except Exception:
            return 1

    @staticmethod
    def getAdmins():
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        res = list()
        for u in records:
            if records[u]['role'] == 'admin':
                curUser = User(u)
                res.append(curUser)
        return res

    @staticmethod
    def getID(email):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        for k,v in records.items():
            if (email == records[k]['email']):
                return k
        return 'No ID found for that email'

    @staticmethod
    def listUsers():
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        res = list()
        for u in records:
            if records[u]['role'] == 'user':
                curUser = User(u)
                res.append(curUser)
        return res

    @staticmethod
    def writeUpdate(current_user):
        records = pd.read_csv(RECORDS, keep_default_na=False, sep=',').set_index('id').to_dict('index')
        records[current_user.id]['name']=current_user.name
        records[current_user.id]['username']=current_user.username
        records[current_user.id]['email']=current_user.email
        records[current_user.id]['password']=current_user.password
        records[current_user.id]['note']=current_user.note
        records[current_user.id]['role']=current_user.role
        pd.DataFrame.from_dict(records, orient='index').to_csv(RECORDS, index_label='id', sep=',')

