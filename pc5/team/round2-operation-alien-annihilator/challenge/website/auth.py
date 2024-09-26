#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from io import StringIO
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, g, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, File
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db
from sqlalchemy.sql import text
import funcs, globals, datetime, io, json, subprocess, random, hashlib

auth = Blueprint('auth', __name__) 

@auth.route('/login/', methods=['GET', 'POST']) 
def login(): 
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        email = request.form.get('email')
        password = request.form.get('password')
        resp = funcs.check_login(email,password)
        if type(resp) == str:
            flash(resp)
            return redirect(url_for('auth.signup')) 
        if resp.status_code != 200:
            flash('Incorrect email and/or password. Please try again')
            return redirect(url_for('auth.login'))
        out = json.loads(resp.text)
        user = User(out['email'], out['username'], out['roles'])
        login_user(user, remember=False)
        return redirect(url_for('auth.files'))

@auth.route('/signup/', methods=['GET', 'POST'])
def signup(): 
    if request.method=='GET': 
        return render_template('signup.html')
    else: 
        email = request.form.get('email').strip('\n')
        plaintext_pwd = email+str(random.randint(0,9))
        tmp_password = hashlib.sha1(plaintext_pwd.encode())                        #= generate_password_hash(plaintext_pwd, method='sha1')
        password = tmp_password.hexdigest()                                                 #tmp_password.split('$',1)[1]
        resp = funcs.search(email)
        if type(resp) == str:
            flash(resp)
            return redirect(url_for('auth.signup')) 
        email_chk = resp.text
        if 'email' in email_chk:
            flash('Email address already exists.')
            return redirect(url_for('auth.login'))
        resp2 = funcs.create_user(email,password)        # , team_add_status
        if type(resp2) == str:
            flash(resp2)
            return redirect(url_for('auth.signup')) 
        if resp2.status_code == 201:            
            return render_template("created.html",temp=password, email=email)
        flash("Account Creation Failed")
        return redirect(url_for('auth.signup')) 


@auth.route('/files/', methods=['GET','POST'])
@login_required
def files():
    if request.method == 'GET':
        return render_template('files.html')
    elif request.form.get('value') == 'list':
        fileList = File.query.all()
        return render_template('files.html',list=True, fileList=fileList)
    elif request.form.get('value') == 'up':
        return render_template('files.html',choice='up')
    elif request.form.get('value') == 'del':
        fileList = File.query.all()
        return render_template('files.html',choice='del', fileList=fileList)
    elif request.form.get('value') == 'down':
        fileList = File.query.all()
        return render_template('files.html',choice='down', fileList=fileList)
    else:
        if request.form.get('up') == 'Submit':  # add user
            f = request.files['up']
            tmpBlob = f.stream.read()
            f.close()
            uploaded = datetime.datetime.today().strftime('%m-%d-%Y, %H:%M')   
            new_File = File(name=f.filename,user_id=current_user.id,user_username=current_user.username,role=current_user.role,blob=tmpBlob,uploaded=uploaded)
            try:
                db.session.add(new_File)
                db.session.commit()
            except Exception as e:
                print(f'ERROR:\n{e}')
                flash("Unable to upload selected file.")
                return redirect(url_for('auth.files'))
            flash('New file uploaded!')
            return redirect(url_for('auth.files'))
        elif request.form.get('down') == 'Submit': 
            fileName = request.form.get('download')
            if fileName == 'None':
                flash("File not selected")
                return redirect(url_for('auth.files'))
            f = File.query.filter_by(name=fileName).first()
            if ((current_user.id == f.user_id) or ((current_user.role == 'system_admin' ) and (f.role != 'system_admin'))):
                strStream = io.BytesIO(f.blob)
                return send_file(strStream, download_name=f.name, as_attachment=True)
            else:
                flash("Do not have permission to view that file")
                return redirect(url_for('auth.files'))
        elif request.form.get('del') == 'Submit':  
            fileName = request.form.get('delete')
            if fileName == 'None':
                flash("File not selected")
                return redirect(url_for('auth.files'))
            f = File.query.filter_by(name=fileName).first()
            if ((current_user.id == f.user_id) or ((current_user.role == 'system_admin' ) and (f.role != 'system_admin'))):
                try:
                    db.session.delete(f)
                    db.session.commit()
                except Exception as e:
                    print(f'ERROR:\n{e}')
                    flash("Unable to delete selected file.")
                    return redirect(url_for('auth.files'))
                flash('File Deleted!')
                return redirect(url_for('auth.files'))
            else:
                flash("User does not have permission to delete that file")
                return redirect(url_for('auth.files'))


@auth.route('/logout/') # define logout path
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
