#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys,requests, json, time

def get_users(url):
    tkretts_key = "eih7t4qbypg5uqkuijnnudhhpa"
    
    try:
        out = requests.get(url,headers={"Requester":"tkretts@merch.codes", "Authorization":f"Bearer {tkretts_key}","Content-Type":"application/json"})
    except Exception as e:
        print(f"Error making Request:\n{e}")
        return "Unable to contact mattermost."
    else:
        return f"Request to {url} successful."
        #return True
    
    #users = json.loads(out.text)
    #return users


if __name__ == '__main__':
    while True:
        urls = ["https://chat.merch.codes/api/v4/users", "http://chat.merch.codes/api/v4/users", "https://chat.merch.codes/api/v4/users"]
        for u in urls:
            print(get_users(u))
            time.sleep(10)
            ## Print Response
            #resp = get_users(u)
            #print(json.dumps(resp, indent=2))
