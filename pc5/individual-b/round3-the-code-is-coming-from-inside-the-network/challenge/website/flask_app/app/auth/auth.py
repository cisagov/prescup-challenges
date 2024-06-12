
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import datetime
from flask import Blueprint, render_template_string, render_template, request, current_app, redirect, url_for, flash
from flask_login import logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from app.extensions import db
from app.functions import *
from app.models import User, Projects

auth = Blueprint("auth",__name__,static_folder="/home/user/Desktop/flask_app/app/static/",template_folder="/home/user/Desktop/flask_app/app/templates/")     # add path to templates/static if error

@auth.route("/profile/", methods=["GET","POST"],defaults={'uid':''})
@auth.route("/profile/<path:uid>", methods=["GET","POST"])
@login_required
def get_profile(uid):
    if request.method == 'GET':
        if (uid == '') or (int(uid) == int(current_user.id)):
            user = current_user
        else:
            if current_user.role != 'admin':
                flash("Must be admin to view other profiles.")
                return render_template("profile.html", user = current_user)
            try:
                user = User.query.filter_by(id=int(uid)).first()
            except Exception as e:
                flash("User profile page not found")
        if user == None:
            flash("User profile does not exist")
            return render_template("profile.html", user = current_user)
        return render_template("profile.html", user = user)
    else:
        name = request.form.get('name')        
        un = request.form.get('username') 
        email = request.form.get('email') 
        pwd = generate_password_hash(request.form.get('password')) 
        try:
            user = User.query.filter_by(id=int(uid)).first()
            user.name = name if name != '' else user.name
            user.username = un if un != '' else user.username
            user.email = email if email != '' else user.email
            user.pwd = pwd if request.form.get('password') != '' else user.password
            db.session.commit()
        except Exception as e:
            print(e)
            flash("Cannot update account")
            return redirect(url_for('auth.get_profile',uid=current_user.id))
        flash("Account updated")
        return redirect(url_for('auth.get_profile',uid=current_user.id))
    

@auth.route("/directory", methods=["GET","POST"])
@auth.route("/directory/", methods=["GET","POST"])
@login_required
def user_directory():
    if request.method == 'GET':
        return render_template('directory.html')
    else:
        param = request.form.get('param')
        search_str = request.form.get('searchStr')
        try:
            serach_dict = {
                str(param):str(search_str)
            }
            user = User.query.filter_by(**serach_dict).all()       
        except Exception as e:
            print(e)
            flash("Unable to process search. Please refine search and try again.")
            return redirect(url_for('auth.user_directory'))
        if len(user) == 0:
            return render_template('directory.html',empty='true')
        return render_template('directory.html',users=user)


@auth.route("/projects", methods=["GET","POST"])
@auth.route("/projects/", methods=["GET","POST"])
@login_required
def projects():
    if request.method == 'GET':
        return render_template('projects.html')
    elif request.form.get('value') == 'old':
        try:
            projects = Projects.Past.query.all()
        except:
            projects = None
        return render_template('projects.html',choice='old', projects=projects)
    elif request.form.get('value') == 'current':
        try:
            projects = Projects.Current.query.all()
        except:
            projects = None
        return render_template('projects.html',choice='current', projects=projects)
    elif request.form.get('value') == 'future':
        try:
            projects = Projects.Future.query.all()
        except:
            projects = None
        return render_template('projects.html',choice='future',projects=projects)
    else:
        try:
            projects = Projects.query.all()
        except Exception as e:
            projects = None
        return render_template('projects.html', choice='all', projects=projects)


@auth.route("/user_management", methods=["GET","POST"])
@auth.route("/user_management/", methods=["GET","POST"])
@login_required
def admin():
    if request.method == 'GET':
        return render_template('users.html')
    elif request.form.get('value') == 'create':
        return render_template('users.html',choice='create')
    elif request.form.get('value') == 'up':
        users = User.query.all()
        return render_template('users.html',choice='up', users=users)
    elif request.form.get('value') == 'del':
        users = User.query.all()
        return render_template('users.html',choice='del',users=users)
    else:
        if request.form.get('create') == 'Submit': 
            name = request.form.get("create_name")
            un = request.form.get("create_un")
            email = request.form.get("create_email")
            pwd = request.form.get("create_pwd")
            role = request.form.get("create_role")
            if role.lower() in current_app.config['ROLES']:
                role = role.lower()
            else:
                flash("Invalid role entered. Please try again.")
                return redirect(url_for('auth.admin'))
            created = datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')
            new_user = User(name=name,username=un,email=email,password=generate_password_hash(pwd), role=role, created=created)
            try:
                db.session.add(new_user)
                db.session.commit()
            except Exception as e:
                print(f'ERROR:\n{e}')
                flash("Unable to create user.")
                return redirect(url_for('auth.admin'))
            flash('New user created!')
            return redirect(url_for('auth.admin'))
        elif request.form.get('up') == 'Submit': 
            user_to_update = request.form.get('up_user')
            if user_to_update != None:
                try:
                    user = User.query.filter_by(name=user_to_update).first()
                except Exception as e:
                    flash("Error searching for user. Please try again, if issues persists please contact support.")
                    return redirect(url_for('auth.admin'))
                return render_template('users.html',choice='up', user=user)
            user_id = request.form.get('up_id')
            user = User.query.filter_by(id=int(user_id)).first()
            name = request.form.get('up_name')
            un = request.form.get('up_un')
            email = request.form.get('up_email')
            pwd = request.form.get('up_pwd')
            role = request.form.get('up_role')
            try:
                user.name = name
                user.username = un
                user.email = email
                if pwd != "":
                    user.password = pwd
                user.role = role if role in current_app.config['ROLES'] else user.role
                db.session.commit()
            except Exception as e:
                flash("Error updating user. Please try again, if issues persists please contact support.")
                return redirect(url_for('auth.admin'))
            flash("User updated!")
            return redirect(url_for('auth.admin'))
        elif request.form.get('del') == 'Submit':
            user_name = request.form.get('delete')
            user = User.query.filter_by(name=user_name).one()
            try:
                db.session.delete(user)
                db.session.commit()
            except:
                flash("Unable to delete user. Please try again, if issue persists please contact support")
                return redirect(url_for('auth.admin'))
            flash("User deleted!")
            return redirect(url_for('auth.admin'))
        

@auth.route("/upload", methods=["GET"])
@auth.route("/upload/", methods=["GET"])
@login_required
def upload():
    tmp_resp = recursive_upload()
    template='''
    {% extends 'base.html' %}
    {% block content %}
    <div><center "font-size: 20px;"><br>
    {% if 'Files updated' not in resp %}
        <h2>Request Failed</h3>
        <h3>{{resp}}</h3>
    {% else %}
        <h2>Request Completed</h3>
        <h3>{{resp}}</h3>
    {% endif %}
    </center></div.
    {% endblock %}
    '''
    return render_template_string(template,resp=tmp_resp)

@auth.route("/repo_authentication",methods=['GET'])
@auth.route("/repo_authentication/",methods=['GET'])
def repo_auth():
    out = run_auth()
    template='''
    {% extends "base.html" %}
    {% block content %}
    <div><center "font-size: 20px;"><br>
        <h3 style="font-size:22px">{{ output }}</h3>
    </center></div.
    {% endblock %}
    '''
    return render_template_string(template, output=out)
    

    
@auth.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
