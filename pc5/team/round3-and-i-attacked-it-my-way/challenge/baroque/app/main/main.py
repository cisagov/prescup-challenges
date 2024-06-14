
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io, datetime, requests, json, urllib3
from flask import Blueprint, render_template_string, render_template, request, current_app, send_file, make_response, flash, url_for, redirect, session, jsonify,Response
from flask_login import login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.functions import *
import app.globals as globals
from app.models import *
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

main = Blueprint("main",__name__,static_folder="static",template_folder=f"{globals.basedir}/main/templates/")    

@main.route("/", methods=["GET","POST"])
def home():
    return render_template("home.html")


@main.route("/login", methods=["GET","POST"])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        
        login_data = request.form
        user = User.query.filter_by(email=login_data['email']).first()
        session.clear()
        login_user(user)
        return redirect(url_for("social.my_profile"))


@main.route("/signup",methods=["GET","POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    else:
        signup_data = request.form      
        check_existing = User.query.filter_by(email=signup_data['email']).first() is not None
        if check_existing:
            msg = f"Account already exists. Try <a href='{url_for('main.login')}'>Logging In!</a>"
            flash(msg)
            return redirect(url_for('main.login')) 
        
        created = datetime.datetime.now().strftime('%d-%m-%Y, %H:%M')
        un = signup_data['username']
        if un == '':
            if len(signup_data['lname']) < 4:
                un = f"{signup_data['fname'][0].lower()}{signup_data['lname'].lower()}"
            else:
                un = f"{signup_data['fname'][0].lower()}{signup_data['lname'][:4].lower()}"
        un = un.rstrip()
        new_user = User(fname=signup_data['fname'],lname=signup_data['lname'],username=un,email=signup_data['email'],password=generate_password_hash(signup_data['password']),role="user",created=created)
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(f"Error occurred during Signup\n{str(e)}")
            flash("Account Creation Failed")
            return redirect(url_for('main.signup'))
        else:
            flash("Account Created Successfully, please sign in") 
            return redirect(url_for('main.login'))
    

@main.route("/search",methods=["GET","POST"],defaults={"search_type":None})
@main.route("/search/<path:search_type>",methods=["GET","POST"])
def search(search_type):
    if search_type == None:
        ## Show page with no results
        return render_template("search.html")
    else:
        if search_type not in ['user','shop']:
            flash("Unknown search type specified.")
            return redirect(url_for("main.search"))
        elif (search_type == "user") and (not current_user.is_authenticated):
            flash("Must be logged in to search & view other users.")
            return redirect(url_for("main.search"))
        
        query = request.args.get("query")
        results = search_query(search_type, query)
        categories_dict = Categories.get_dict()
            
        return render_template("search.html",type=search_type,results=results,categories=categories_dict)


@main.route("/FAQ",methods=["GET","POST"])
def faq():
    return render_template('faq.html')


@main.route("/Support",methods=["GET","POST"])
def support():
    return render_template('support.html')


@main.route("/report_bug",methods=["GET","POST"])
def bug():
    if request.method == "GET":
        return render_template('bug.html')
    else:
        data = request.form
        try:
            req = requests.post("https://10.1.1.74/report",json=data, headers={"accept":"text/plain","Content-Type":"application/json"}, verify=False)
        except Exception as e:
            print("Unable to submit ticket")
        else:
            flash("Report Submitted, thank you!")
        return redirect(url_for("main.home"))
    

@main.route("/feed", methods=["GET"])
def feed():
    return render_template("feed.html")

@main.route("/feed_data",methods=['GET'])
def get_feed():
    if request.referrer != 'https://baroque.merch.codes/feed':
        return jsonify({"Error":"Unauthorized Access Attempted"})
    expr = text("select * from Purchase_receipts")
    all_pr = db.session.execute(expr).fetchall()
    results = [dict(row) for row in all_pr]
    return jsonify(results)

@main.route("/fetch_js",methods=['GET','POST'])
def fetch_js():
    if request.referrer == None:
        return jsonify({"Info":"This endpoint is used for pulling and using javascript files hosted on the server https://10.1.1.74"})
    if 'https://baroque.merch.codes' not in request.referrer:
        return jsonify({"Error":"Unauthorized Access Attempted"})
    js_script = request.args.get('js')
    if (js_script == '') or (js_script == None):
        return Response(f"Error: No JS file referenced. View JS server at https://10.1.1.74 for accepted filenames.",status=500)
    try:
        url = f"https://10.1.1.74/{js_script}"
        resp = requests.get(url, verify=False)
        return Response(resp.content,mimetype="application/javascript")
    except Exception as e:
        return Response(f"Error fetching js {js_script}",status=500)

@main.route("/authenticate",methods=['GET','POST'])
def authenticate():
    
    if 'https://baroque.merch.codes' not in request.referrer:
        return jsonify({"Error":"Unauthorized Access Attempted"})
    login_data = request.form
    user = User.query.filter_by(email=login_data['email']).first()
    if user == None:
        msg = f"Account not found. Feel free to <a href='{url_for('main.signup')}'>Signup Here!</a>"
        flash(msg)
        return 'false' #redirect(url_for('main.login'))

    if check_password_hash(user.password, login_data['password']):
        return 'true'
    
    flash("Incorrect credentials entered. Please try again")
    return 'false'
