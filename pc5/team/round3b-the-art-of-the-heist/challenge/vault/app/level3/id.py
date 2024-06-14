
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, redirect, url_for, make_response
from flask_login import current_user
from app.functions import *
import app.globals as globals
from functools import wraps


level3 = Blueprint("level3",__name__,static_folder=f"{globals.basedir}/level3/static/",template_folder=f"{globals.basedir}/level3/templates/")   

def login_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("level1.login"))
        level_check = check_local_user(current_user.username)
        if level_check.passed['level2'] != True:  
            return redirect(url_for("level2.submit_pin"))
        elif level_check.passed['level3'] == True:
            return redirect(url_for("final.success"))
        elif globals.attempts > 4:
            flash("More than 5 incorrect attempts made, logging out.")
            logout()
            return redirect(url_for("level1.login"))
        if callable(getattr(current_app, "ensure_sync",None)):
            return current_app.ensure_sync(view_func)(*args,**kwargs)
        return view_func(*args,**kwargs)
    return decorated_view


@level3.context_processor
@login_required
def inject_data():
    data = check_local_user(current_user.username)
    if data != False:
        return {
            "t1":globals.t1,
            "time_left":data.time_left
        }
    else:
        return {
            "t1":globals.t1
        }
    

@level3.route("/",methods=['GET','POST'])
@login_required
def submit_id():
    if request.method == 'GET':
        return render_template("id.html")
    else:
        if 'id_upload' not in request.files:
            flash("No file part in request")
            return redirect(url_for("level3.submit_id"))
        file_upload = request.files['id_upload']
        if file_upload.filename == "":
            flash("Filename missing.")
        file_data = verify_file(file_upload)
        if file_data == False:
            return redirect(url_for("level3.submit_id"))
        file_hash = get_hash(file_data[0])
        url = "http://canello.merch.codes/verify_id/"
        form_data = {
            "username":file_data[1],
            "hash":file_hash
        }
        try:
            resp = requests.post(url,data=form_data)
        except Exception as e:
            flash(f"Error during request. Please ensure `canello.merch.codes` can be reached and try again.")
            os.remove(file_data[0])
            return redirect(url_for("level3.submit_id"))
        
        if "Success" not in resp.text:
            flash("Hash did not match. Please ensure file has not been tampered with since its creation.")
            os.remove(file_data[0])
            return redirect(url_for('level3.submit_id'))
        
        passed_level("level3")
        os.remove(file_data[0])
        return redirect(url_for('final.success'))
        
