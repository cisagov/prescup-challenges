
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, render_template_string, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from jinja2 import Environment, Template, UndefinedError
import json
import html
#from __init__ import db

auth = Blueprint('auth', __name__) # create a Blueprint object that we name 'auth'

@auth.route('/login', methods=['GET', 'POST']) # define login page path
def login(): # define login page fucntion
    if current_user.is_authenticated:
        return redirect(url_for('auth.getProfile'))
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else: # if the request is POST the we check if the user exist and with te right password
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        # check if the user actually exists
        exist = User.chkUsers(email)
        if exist == False:
            flash('No account found registered with that email.\nSign up today!')
            return redirect(url_for('auth.signup'))
        # check username against pwd if account exists
        authChk = User.authUser(email, password)
        if authChk == False:
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page
        # if the above check passes, then we know the user has the right credentials
        authUser = User(authChk)
        login_user(authUser, remember=remember)
        return redirect(url_for('auth.getProfile'))

@auth.route('/signup', methods=['GET', 'POST'])# we define the sign up path
def signup(): # define the sign up function
    if request.method=='GET': # If the request is GET we return the sign up page and forms
        return render_template('signup.html')
    else: # if the request is POST, then we check if the email doesn't exist and then we save data
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        exist = User.chkUsers(email)
        if exist == True:
            flash('Email address already being used')
            return redirect(url_for('auth.login'))
        # add the new user to the database
        User.addUser(username, email, name, password)
        flash('New account created!')
        return redirect(url_for('auth.login'))

@auth.route('/profile', methods=['GET','POST'])
@login_required
def getProfile():
    if request.method=='GET':
        if request.args.get('userrole') == 'admin':         # okay for now, need to edit when live as it is vuln
            if len(request.args) != 0:
                current_user.name = request.args.get('name') if request.args.get('name') else current_user.name
                current_user.username = request.args.get('username') if request.args.get('username') else current_user.username
                current_user.email = request.args.get('email') if request.args.get('email') else current_user.email
                current_user.password = request.args.get('password') if request.args.get('password') else current_user.password
                current_user.note = render_template_string(request.args.get('note')) if request.args.get('note') else current_user.note
                current_user.role = request.args.get('role') if request.args.get('role') and request.args.get('role') != 'dev' else current_user.role
                User.writeUpdate(current_user)
                flash("Account Successfully Updated!")
                return redirect(url_for('auth.getProfile'))
        env = Environment()
        note = Template(current_user.note).render()        # allows for math based jinja injection, nothing else
        return render_template('profile.html',note=html.unescape(note))
    else:
        current_user.name = request.form.get('name') if request.form.get('name') else current_user.name
        current_user.email = request.form.get('email') if request.form.get('email') else current_user.email
        current_user.username = request.form.get('username') if request.form.get('username') else current_user.username
        current_user.note = Template(request.form.get('note')).render() if request.form.get('note') else current_user.note
        current_user.role = request.form.get('role') if current_user.role=='admin' else current_user.role
        if (request.form.get('password') != request.form.get('password2')):
            flash("Passwords entered do not match!\nPlease try again.")
            return redirect(url_for('auth.getProfile'))
        current_user.password = request.form.get('password') if request.form.get('password') else current_user.password
        User.writeUpdate(current_user)
        #User.updateUser(current_user.id,current_user.role,username,email,name,password,note,role)
        flash("Account Successfully Updated!")
        return redirect(url_for('auth.getProfile'))

@auth.route('/admin', methods=['GET','POST'])
@login_required
def admin():
    if request.method=='GET':
        if ((current_user.role == 'admin') or (current_user.role == 'dev')):
            return render_template('admin.html')
        flash("You do not have Admin permissions to view this page")
        return redirect(url_for('auth.getProfile'))
    elif request.form.get('value') == 'f1':
        return render_template('admin.html', choice='formVal1')
    elif request.form.get('value') == 'f2':
        return render_template('admin.html', choice='formVal2')
    elif request.form.get('value') == 'f3':
        return render_template('admin.html', choice='formVal3')
    elif request.form.get('value') == 'f4':
        res = User.getAdmins()
        return render_template('admin.html', choice='formVal4', res=res)
    elif request.form.get('value') == 'f5':
        return render_template('admin.html', choice='formVal5')
    elif request.form.get('value') == 'f6':
        res = User.listUsers()
        return render_template('admin.html', choice='formVal6', res=res)
    else:
        if request.form.get('formVal1') == 'Submit':  # del user
            status = User.delUser(request.form.get('deluser'))
            if status == 0:
                flash("User deleted.")
                return render_template('admin.html', choice='formVal1')
            elif status == 1:
                flash("User not found.")
                return render_template('admin.html', choice='formVal1')
        elif request.form.get('formVal2') == 'Submit':  # add user
            name = request.form.get('addname')
            username = request.form.get('addusername')
            email = request.form.get('addemail')
            password = request.form.get('addpassword')
            note = ''
            try:
                role = request.form.get('addrole')
            except Exception:
                role = 'user'
            exist = User.chkUsers(email)
            if exist == True:
                flash('Email address already being used')
                return render_template('admin.html', choice='formVal2')
            # add the new user to the database
            User.addUser(username, email, name, password, note, role)
            flash('New account created!')
            return render_template('admin.html', choice='formVal2')
        elif request.form.get('formVal3') == 'Submit':  # update user
            userId = request.form.get('upid')
            name = request.form.get('upname')
            username = request.form.get('upusername')
            email = request.form.get('upemail')
            password = request.form.get('uppassword')
            note = request.form.get('upnote')
            role = request.form.get('uprole')
            upUser=User(int(userId)) # user object for account to be updated
            if role == 'dev':   # if update will change account to dev
                if upUser.role != 'admin':
                    flash("Only Admin accounts may be assigned the 'dev' role")
                    return render_template('admin.html', choice='formVal3')
            User.updateUser(userId,current_user.role,username,email,name,password,note,role)
            flash("Account Successfully Updated!")
            return render_template('admin.html', choice='formVal3')
        elif request.form.get('formVal5') == 'Submit':  # Get User ID
            res=list()
            uid = request.form.get('getID')
            try:
                tmp = User(int(uid))
                res.append(tmp)
                flash("Account Found!")
                return render_template('admin.html', res=res)
            except Exception:
                flash("Invalid ID entered. Please try again.")
                return render_template('admin.html', choice='formVal5')

@auth.route("/directory", methods=['GET','POST'])
@login_required
def directory():
    if request.method=='GET': # If the request is GET we return the sign up page and forms
        return render_template('directory.html')
    else:
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        note = ''
        pwd = ''
        role = ''
        if (current_user.role == 'admin'):
            note = request.form.get('note')
            pwd = request.form.get('pwd')
            role = request.form.get('role')
        #seach = f"Search Entered:\nName: {name}.\nUsername: {username}.\nEmail: "+str(render_template_string(email))   # possible spot for vuln
        res = User.userSearch(current_user.role,username,email,name,pwd,note,role)
        if res == 0:
            return render_template('directory.html', res=res)
        return render_template('directory.html', res=res)

@auth.route('/logout') # define logout path
@login_required
def logout(): #define the logout function
    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/dev', methods=['GET'])
@login_required
def dev(): #define the logout function
    if current_user.role == 'dev':
        if len(request.args) != 0:
            content = request.args.get('cmd')
            block = ["."]
            for b in block:
                if b in content:
                    content = content.replace(b,"")
                    content = content.strip('{')
                    content = content.strip('}')
                    return render_template_string(f"Unauthorized characters entered, the following command failed:<br><br>{content}<br><br>Please try again")
            try:
                return render_template_string(content)
            except Exception as e:
                content = content.strip('{')
                content = content.strip('}')
                return render_template_string(f"Unable to render:&nbsp&nbsp{content}<br><br>due to:&nbsp&nbsp{e}")
        else:
            # Update for open-source
            # token = '#replaceme'
            token = "Success!"
            return render_template_string("Token2: "+str(token)+"<br><br>Devs,<br>Use 'cmd' as your variable when troubleshooting via URL requests.")
    else:
        flash("You do not have Permissions to view this page.")
        return redirect(url_for('auth.getProfile'))

'''
extra/backup code:
old profile arg handling:
    userrole = request.args.get('userrole')
    name = request.args.get('name')
    username = request.args.get('username')
    email = request.args.get('email')
    password = request.args.get('password')
    note = request.args.get('note')
    role = request.args.get('role')

    if (password != password2):
        flash("Passwords entered do not match!\nPlease try again.")
        return render_template('profile.html')
    if (current_user.role == 'admin'):
        role = request.args.get('role')
    User.updateUser(current_user.id,userrole,username,email,name,password,note,role)
    flash("Account Successfully Updated!")
    return redirect(url_for('auth.getProfile', note=note))

olf vuln note box reader:
    note = render_template_string(current_user.note)
'''

