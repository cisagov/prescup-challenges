
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from  flask import Flask
from flask import session
from flask import request
from flask import redirect
from flask import url_for
from flask import render_template
from flaskext.mysql import MySQL
import re

app = Flask( __name__ )
app.secret_key = b'I am a teapot lol.'

app.config['SESSION_COOKIE_HTTPONLY'] = False

mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'prescup'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'prescup'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
#app.config['MYSQL_DATABASE_PORT'] = 5555

mysql.init_app( app )

@app.route( "/" )
def index():
	adminToken = ''
	if session.get('username') == 'admin':
		adminToken = '047fb07e' # this ensures the participant actually logged in as admin and didn't just use SQL injection to read the code from the database. though there are two ways to admin: blind sql injection to get admin password, or regular sql injection to confuse login logic

	return render_template( 'home.html', username=session.get('username'), adminToken=adminToken )
#	if 'username' in session:
#		return 'Logged in as ' + session['username'] + '.'
#	else:
#		return 'You are not logged in.'

@app.route( '/browse' )
def browse():
	if 'username' not in session:
		return redirect( url_for( 'login' ) )
	
	conn = mysql.connect()
	cursor = conn.cursor()
	cursor.execute( "SELECT id, title, body, author FROM listing" )
	result = cursor.fetchall()
	print( result )
	return render_template( 'browse.html', listings=result )

@app.route( '/login', methods = [ 'GET', 'POST' ] )
def login():
	if 'username' in session:
		return redirect( url_for( 'index' ) )
	if request.method == 'POST':
		if len( request.form['password'].strip() ) == 0:
			return "bad username or password"
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute( "SELECT username, password FROM user WHERE username = '" + request.form['username'] + "' and password = '" + request.form['password'] + "'"  )
		data = cursor.fetchone()
		if data == None:
			return 'bad username or password'

		print( data )
		session['username'] = data[0]
		return redirect( url_for( 'index' ) )
	else:
		return render_template( 'login.html' )

@app.route( '/listing' )
def listing():
	if request.args.get('id') is not None:
		conn = mysql.connect()
		cursor = conn.cursor()
		cursor.execute( "SELECT id, title, body, author FROM listing WHERE id = " + request.args.get('id') )
		data = cursor.fetchone()
		if data == None:
			return 'listing not found'
		#return '<h1>' + data[1] + '</h1><p>' + data[2] + '</p><p>posted by ' + data[3] + '</p>'
		return render_template( 'listing.html', listing=data )
	return 'no id'

def escapeScript( text ):
	pattern = re.compile( 'script', re.IGNORECASE )
	text = pattern.sub( '&#115;&#99;&#114&#105;&#112;&#116;', text )
	return text

@app.route( '/post', methods = [ 'GET', 'POST' ] )
def postListing():
	if 'username' not in session:
		return 'you must log in first. <a href="/login">log in</a>'

	if request.method == 'POST':
		body = escapeScript( request.form['body'] )
		conn = mysql.connect()
		cursor = conn.cursor()
		#cursor.execute( "INSERT INTO listing ( title, body, author ) VALUES ( '" + request.form['title'] + "', '" + request.form['body'] + "', '" + session['username'] + "')" )
		cursor.execute( "INSERT INTO listing ( title, body, author ) VALUES ( %s, %s, %s )", [ request.form['title'], body, session['username'] ] )
		conn.commit()
		return 'message posted'
	else:
		return render_template( 'post.html' )
		#return '''
		#	<form method="post">
		#		<p><input type=text name=title>
		#		<p><input type=text name=body>
		#		<p><input type=submit value=Post>
		#	</form>
		#	
		#'''

@app.route( '/logout' )
def logout():
	if 'username' in session:
		session.pop( 'username', None )
	else:
		print( 'logging out a user who had a valid cookie from before this run of the server' )
	return redirect( url_for( 'index' ) )

@app.route( '/demo' )
def demo():
	conn = mysql.connect()
	cursor = conn.cursor()
	cursor.execute( "SELECT username, password FROM user" )
	data = cursor.fetchone()
	print( data )
	return "<p>Dark Web Market</p>" + ' '.join( data )

