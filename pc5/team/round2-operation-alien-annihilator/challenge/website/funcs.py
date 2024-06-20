#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, requests, json

def add_user_to_team(team_id, user_id):
    login_out = check_login('admin','T@rt@ns@@1!')
    header_dict = dict(login_out.headers)
    token = header_dict['Token']
    add_team = {
        "team_id": team_id,
        "user_id": user_id
    }
    url = f"https://chat.merch.codes/api/v4/teams/{team_id}/members"
    try:
        team_out = requests.post(url,headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"})
    except Exception as e:
        return "Unable to contact mattermost. Please give time to boot. If issue persists, contact support."
    return True
    

def create_user(email, pwd):
    un = email.split('@',1)[0]
    new_user = {
        "email":email,
        "username":un,
        "password":pwd,
    }
    url = "https://chat.merch.codes/api/v4/users"
    try:
        create_resp = requests.post(url,json=new_user,headers={"Content-Type":"application/json"})
    except Exception as e:
        return "Unable to contact mattermost. Please give time to boot. If issue persists, contact support."
    
    new_user_dict = json.loads(create_resp.text)
    user_id = new_user_dict['id']
    team_id = "me8f41oh3381jq6sst731hkoga"
    return create_resp  #, team_add_status

def check_login(email, pwd):
    creds = {
        "login_id":email,
        "password":pwd,
    }
    url = "https://chat.merch.codes/api/v4/users/login"
    try:
        out = requests.post(url,json=creds,headers={"Content-Type":"application/json"})
    except Exception as e:
        return "Unable to contact mattermost. Please give time to boot. If issue persists, contact support."
    return out

def search(param):      
    login_out = check_login('admin','T@rt@ns@@1!')
    try:
        header_dict = dict(login_out.headers)
        token = header_dict['Token']
    except Exception as e:
        return "Unable to contact mattermost. Please give time to boot. If issue persists, contact support."
    search = {
        "term": param
    }
    url = "https://chat.merch.codes/api/v4/users/search"
    try:
        out = requests.post(url,json=search,headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"})
    except Exception as e:
        return "Unable to contact mattermost. Please give time to boot. If issue persists, contact support."
    return out

