
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io, datetime, random, string
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from app.extensions import db
from app.functions import *
from app.models import Source, Backup, Token, Last_update

main = Blueprint("main",__name__, template_folder='templates', static_folder='static')     # add path to templates/static if error

@main.route("/", methods=["GET", "POST"])
def index():
    auth = check_auth(request.method.lower(),request.remote_addr.strip('\n'), request.headers)
    if auth != True:
        if auth == False:
            return f"{request.remote_addr} does not have permissions to make {request.method.upper()} requests.\n"
        elif auth == None:
            return f"{request.remote_addr} has not been authenticated.\nPlease authenticate your machine and try again."
        return auth
    if request.method == "GET":
        if len(dict(request.args)) == 0:        # .get() if this doesnt work
            home = """
                        Welcome to our local website repo API.
                        If you want to download a file, you can do it by passing `filename` in the URL.
                        If you want all files, you can download them in a zip by passing `filename=*`.
                        If you want to upload and update a file, pass the file in a POST request.
                        If you want to PUSH updates or RESET the website back to default, please visit http://10.3.3.53:5000/action/.
                """
            resp = make_response(home)
            token1 = Token.query.filter_by(name='t1').first()
            resp.headers['token1'] = token1.hex
            return resp
        args = request.args.to_dict()
        if 'filename' not in list(args.keys()):
            return "`Filename` argument not present in request."
        if args['filename'] == '*':
            files = Source.query.all()
            download_all(files)
            resp = make_response(send_file(f"{current_app.config['STATIC_FOLDER']}/website.zip",mimetype='zip',as_attachment=True))
            token1 = Token.query.filter_by(name='t1').first()
            resp.headers['token1'] = token1.hex
            return resp
        try:
            fn = args['filename'].strip('\n')
            cur_file = Source.query.filter_by(name=fn).first()
            str_stream = io.BytesIO(cur_file.blob)
            resp = make_response(send_file(str_stream,download_name=cur_file.name,as_attachment=True))
            token1 = Token.query.filter_by(name='t1').first()
            resp.headers['token1'] = token1.hex
            return resp
        except Exception as e:
            return "No file found with that name. Please refine request and try again"
        
    else:
        files = request.files.to_dict()
        updated = datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')
        log = ""
        for k,v in files.items():
            fn = v.filename
            content = v.stream.read()
            try:
                cur_file = Source.query.filter_by(name=fn).one()
            except Exception as e:
                try:
                    cur_file = Source(name=fn,remote_path=k,blob=content,last_update=updated)
                    db.session.add(cur_file)
                    db.session.commit()
                except Exception as e:
                    print(e)
                    log += f"\tUnable to add file {fn}.error -- {e}\n"
                    continue
                else:
                    log += f"\t{fn} file successfully added.\n"
                    continue
            else:
                try:
                    cur_file.blob = content
                    cur_file.remote_path = k
                    cur_file.last_update = updated
                    db.session.commit()
                    log += f"\t{fn} file successfully updated.\n"
                except Exception as e:
                    print(e)
                    log += f"\tUnable to update file {fn}.error -- {e}\n"
        
        print(f"{updated} ---- Output from POST request:\n{log}")
        token2 = Token.query.filter_by(name='t2').first()
        resp = f"\nFiles updated.\nPlease visit the URL `10.3.3.53:5000/action/` in order to access the `push` function to upload updated files to the website.\n\nToken 2:\t{token2.hex}"
        return resp


@main.route("/action", methods=["GET", "POST"])
@main.route("/action/", methods=["GET", "POST"])
def reset():
    if len(dict(request.args)) == 0:
        return """
        If you wish to reset the website to default, please visit the following URL:
                http://10.3.3.53:5000/action/?action=reset
        If you wish to push the updated code to the website, please visit the following URL:
                http://10.3.3.53:5000/action/?action=update
                """
    else:
        status = request.args.get('action').strip('\n')
        resp = ''
        if status.lower() == 'reset':
            backup_files = Backup.query.all()
            resp = update_website('reset',backup_files)
        elif status.lower() == 'update':
            source_files = Source.query.all()
            resp = update_website('update',source_files)
        else:
            resp = "Unrecognized arguments passed. Please ensure request is correct and try again."
        return resp


@main.route("/auth_request_string", methods=['GET'])
@main.route("/auth_request_string/", methods=['GET'])
def ret_auth_string():
    return globals.auth_string


@main.route("/verify_auth_request", methods=['POST'])
@main.route("/verify_auth_request/", methods=['POST'])
def verify_request():
    try:
        req_json = json.loads(request.json)
        if req_json['auth_string'] != globals.auth_string:
            return f"Auth string refreshes every {globals.auth_rotate_time} seconds to deter any malicious attempts for access.\nPlease try again."
    except Exception as e:
        return "Request JSON data missing or incorrect.\nPlease verify input and try again."
    output = verify_auth_new_host(request.remote_addr, req_json)
    if output == True:
        while True:
            token = ''.join(random.choice(string.digits) for _ in range(8))
            try:
                new_auth = Auth(ip=request.remote_addr,get=req_json['get'],post=req_json['post'],token=token)
                db.session.add(new_auth)
                db.session.commit()
            except exc.IntegrityError as s:
                db.session.rollback()
                if "UNIQUE constraint failed: Auth.ip" in str(s):
                    cur_host = Auth.query.filter_by(ip=request.remote_addr).one()
                    try:
                        cur_host.get = req_json['get']
                        cur_host.post = req_json['post']
                        db.session.commit()
                    except Exception as e:
                        return f"Host has been previously authenticated.\nUnable to update GET and POST permissions.\n"
                    else:
                        return f"Host has been previously authenticated.\nGET and POST permissions have been updated.\nYour authentication token is {cur_host.token}."
                continue
            except Exception as e:
                print(e)
                return "error has occured, Please try again. If issue persists please contact support."
            else:
                resp  = """
%s Authenticated.
your host authentication token is:     %s
**PLEASE NOTE**
The authentication token is REQUIRED and must be passed when making POST requests as part of your authentication.
It MUST be sent in the request HEADER as the following:
    {"Authorization":"%s"} 
                """ % (request.remote_addr, token, token)
                return resp
            
    return "Authentication request failed. Please check your request and try again."
