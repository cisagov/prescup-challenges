
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from app.models import Auth

def init():
    global repo_obj
    repo_obj = Auth.query.filter_by(id=1).one()
    global auth_token
    auth_token = repo_obj.token


    global host_ip
    host_ip = '10.7.7.7'
