#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, json, traceback
from flask import request, Blueprint, current_app, render_template, jsonify, flash, redirect, url_for, render_template_string
from models import ID, AdminCodes
from extensions import db
from funcs import create_new_id, send_mail, update_record
#from funcs import *

main = Blueprint('main',__name__)

@main.route('/', methods=['GET'])
def index():
    success_chk = request.args.get('success')
    if success_chk != None:
        return render_template("home.html",success=success_chk)
    return render_template("home.html")


@main.route("/create_id",methods=['GET','POST'])
@main.route("/create_id/",methods=['GET','POST'])
def create_id():
    if request.method == 'GET':
        return render_template("create.html")
    else:
        code = request.form.get("code")
        try:
            admin_code = AdminCodes.query.filter_by(code=code).one()
        except:
            flash("Admin Approval Code Invalid")
            return redirect(url_for("main.create_id"))
        id_info = dict()
        id_info['un'] = request.form.get('username').strip('\n')
        id_info['email'] = request.form.get('email').strip('\n')
        id_info['role'] = request.form.get('role').strip('\n')
        id_info['key'] = request.form.get('key').strip('\n')
        resp = create_new_id(id_info)
        if resp == False:
            return redirect(url_for("main.create_id"))
        mail_chk = send_mail(id_info['un'],id_info['email'])
        if mail_chk == 1:
            return redirect(url_for("main.index", success=id_info['email']))   # f"Identification file sent to {id_info['email']}
        return redirect(url_for("main.create_id"))
            


@main.route("/verify_id", methods=['GET','POST'])
@main.route("/verify_id/", methods=['GET','POST'])
def verify_id():
    if request.method == 'GET':
        return render_template("verify.html")
    else:
        id_username = request.form.get('username').strip('\n')
        id_hash = request.form.get('hash').strip('\n')
        try:
            cur_id = ID.query.filter_by(username=id_username).one()
        except Exception as e:
            flash("No Identification found with that username.")
            return redirect(url_for("main.verify_id"))
        if cur_id.hash == id_hash:
            template ="""
            {% extends "base.html" %}
            {% block header %}
            <meta http-equiv="refresh" content="3;url={{url_for('main.verify_id')}}">
            {% endblock %}
            {% block content %}
                <br><span name='resp' id='resp' style="font-size: 25px;">Success</span>
            {% endblock %}
            """
            return render_template_string(template)
        flash("Submitted hash does not match")
        return redirect(url_for("main.verify_id"))
    

@main.route("/update_id",methods=['GET','POST'])
@main.route("/update_id/",methods=['GET','POST'])
def update_id():
    if request.method == 'GET':
        return render_template("update.html")
    else:
        try:
            override = request.form.get('override').strip('\n')
        except:
            override = 'no'
        if override != 'yes':
            code = request.form.get("code")
            try:
                admin_code = AdminCodes.query.filter_by(code=code).one()
            except:
                flash("Admin Approval Code Invalid")
                return redirect(url_for("main.update_id"))
        id_info = dict()
        id_info['old_un'] = request.form.get('old_username').strip('\n')
        id_info['new_un'] = request.form.get('new_username').strip('\n')
        id_info['email'] = request.form.get('email').strip('\n')
        id_info['role'] = request.form.get('role').strip('\n')
        id_info['key'] = request.form.get('key').strip('\n')
        resp = update_record(id_info)
        if resp == False:
            return redirect(url_for("main.update_id"))
        mail_chk = send_mail(id_info['new_un'],id_info['email'])
        if mail_chk:
            return redirect(url_for("main.index", success=id_info['email']))    # success=f"Update successful. Updated ID file sent to {id_info['email']}
        flash("Not all mail sent")
        return redirect(url_for("main.update_id"))
