
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Flask, request, render_template, url_for, redirect, session, jsonify, json, make_response
from flask_pymongo import PyMongo
from bson.json_util import dumps
import subprocess
import os
import requests

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/userDB"
mongo = PyMongo(app)
app.secret_key = "SUPERSECRETKEY"

@app.route("/", methods=['POST', 'GET'])
def index():
	if "user" in session:
		return redirect(url_for("site"))
	if request.method == "POST":
		username = request.form.get("username")
		password1 = request.form.get("password1")
		password2 = request.form.get("password2")
		group = 'user'
		user_found = mongo.db.user.find_one({"username": username})
		if user_found:
			message = 'There is a user already registered with that name'
			return render_template('index.html', message=message)
		if password1 != password2:
			message = 'Entered passwords do not match'
			return render_template('index.html', message=message)
		else:
			user_input = {'username': username, 'group': group, 'password': password2}
			mongo.db.user.insert_one(user_input)
			session['username'] = username
			session['group'] = group
			return render_template('site.html', username=username, group=group)
	return render_template("index.html")

@app.route("/login", methods=['POST', 'GET'])
def login():
	if "username" in session:
		return redirect(url_for("site"))
	if request.method == "POST":
		username = request.form.get("username")
		password = request.form.get("password")

		username_found = mongo.db.user.find_one({"username": username})
		if username_found:
			uval = username_found['username']
			pval = username_found['password']
			
			if password == pval:
				session["username"] = uval
				session["group"] = username_found["group"]
				return redirect(url_for('site'))
			else:
				message = "Wrong password"
				return render_template('login.html', message=message)
	return render_template('login.html')

@app.route("/logout", methods=['POST', 'GET'])
def logout():
	if "username"  in session:
		session.pop("username", None)
		session.pop("group", None)
		return redirect(url_for('login'))
	else:
		return redirect(url_for('login'))

@app.route("/site")
def site():
	if "username" in session:
		username = session["username"]
		group = session["group"]
		ipaddr = request.remote_addr
		# ping = requests.get('http://secret-server.us/ping.php').json()
		return render_template('site.html', username=username, ipaddr=ipaddr, group=group)

@app.route("/backdoor", methods=['POST', 'GET'])
def backdoor():
	good_str = 'ls'
	bad_str = ['$(', '&']
	ipaddr = request.remote_addr
	os.chdir('/var/www/html/')
	cmd = request.form['cmd']
	for bad in bad_str:
		if (cmd.find(bad) > -1):
			message = 'Malicious activity! Reported to the authorities'
			return message, 200
	if (cmd.find(good_str) == -1):
		message = 'Only ls command allowed'
		return message, 200
	else:
		output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
		username = session["username"]
		group = session["group"]
		print(output)
		return output.decode("utf-8"), 200
	

@app.route("/users", methods=["POST"])
def users():
	if request.method == 'POST':
		found_user = mongo.db.user.find_one(request.json, {'_id': False})
	if found_user:
		return jsonify({"message": "Username taken"})
	else:
		return jsonify({"message": "Username available"})


if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80, debug=True)

