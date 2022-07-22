
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
#from mysql.connector import IntegrityError
import pymysql

app = Flask( __name__ )
app.secret_key = b'I am a teapot lol.'

app.config['SESSION_COOKIE_HTTPONLY'] = False

mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'awfulbb'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'awfulbb'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
#app.config['MYSQL_DATABASE_PORT'] = 5557

mysql.init_app( app )

@app.route( "/" )
def index():

        return render_template( 'home.html', username=session.get('username') )

@app.route( '/threads' )
def browse():
        if 'username' not in session:
                return redirect( url_for( 'login' ) )
        
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute( 'SELECT t.id, t.title, u.username, t.posted as date FROM thread t INNER JOIN user u ON t.author = u.id' )
        result = cursor.fetchall()
        print( result )
        return render_template( 'threads.html', threads=result )

@app.route( '/login', methods = [ 'GET', 'POST' ] )
def login( message = '' ):
        if 'username' in session:
                return redirect( url_for( 'index' ) )
        if request.method == 'POST':
                conn = mysql.connect()
                cursor = conn.cursor()
                cursor.execute( "SELECT id, username, password FROM user WHERE username = '" + request.form['username'] + "' and password = '" + request.form['password'] + "'"  )
                data = cursor.fetchone()
                if data == None:
                        return render_template( 'login.html', message = "Bad username or password." )

                print( data )
                session['username'] = data[1]
                session['userId'] = data[0]
                return redirect( url_for( 'index' ) )
        else:
                return render_template( 'login.html', message = message )

@app.route( '/thread/<threadId>' )
def thread( threadId = 1 ):
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute( "SELECT id, title, author, posted as date FROM thread WHERE id = " + str( threadId ) )
        data = cursor.fetchone()
        if data == None:
                return 'thread not found'
        cursor.execute( "SELECT p.body, u.username as author, p.posted as date FROM post p INNER JOIN user u ON p.author = u.id WHERE thread = " + str( threadId ) + " ORDER BY date ASC" )
        posts = cursor.fetchall()
        return render_template( 'thread.html', thread=data, posts=posts )

@app.route( '/delete/<threadId>' )
def deleteThread( threadId = 1 ):
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute( "SELECT id, title, author, posted as date FROM thread WHERE id = " + str( threadId ) )
        data = cursor.fetchone()
        if data == None:
                return 'thread not found'
        if data[2] == session['userId']:
                cursor.execute( 'DELETE FROM post WHERE thread = ' + str( threadId ) )
                cursor.execute( 'DELETE FROM thread WHERE id = ' + str( threadId ) )
                conn.commit()
                return "deleted successfully"
        return "you can only delete your own threads"

@app.route( '/post', methods = [ 'GET', 'POST' ] )
def postThread():
        if 'username' not in session:
                return redirect( url_for( 'login' ) )

        if request.method == 'POST':
                conn = mysql.connect()
                cursor = conn.cursor()
                cursor.execute( "INSERT INTO thread ( title, author ) VALUES ( %s, %s )", [ request.form['title'], session['userId'] ] )
                conn.commit()
                #threadId = conn.insert_id()
                threadId = cursor.lastrowid
                print( "thread id is: " + str( threadId ) )
                cursor = conn.cursor()
                cursor.execute( "INSERT INTO post ( body, author, thread ) VALUES ( %s, %s, %s )", [ request.form['body'], session['userId'], threadId ] )
                conn.commit()
                #return 'thread created'
                return redirect( url_for( 'thread', threadId=threadId ) )
        else:
                return render_template( 'post.html' )
                #return '''
                #       <form method="post">
                #               <p><input type=text name=title>
                #               <p><input type=text name=body>
                #               <p><input type=submit value=Post>
                #       </form>
                #       
                #'''

@app.route( '/reply', methods = [ 'POST' ] )
def replyToThread():
        if 'username' not in session:
                return 'you must log in first'

        if request.method == 'POST':
                conn = mysql.connect()
                cursor = conn.cursor()
                cursor.execute( 'INSERT INTO post ( body, author, thread ) VALUES ( %s, %s, %s )', [ request.form['body'], session['userId'], request.form['threadId'] ] )
                conn.commit()
                postId = cursor.lastrowid
                print( 'post id: ' + str( postId ) )
                return redirect( url_for( 'thread', threadId=request.form['threadId'] ) )
        else:
                return 'only POST allowed'

@app.route( '/logout' )
def logout():
        if 'username' in session:
                session.pop( 'username', None )
        else:
                print( 'logging out a user who had a valid cookie from before this run of the server' )
        return redirect( url_for( 'index' ) )

@app.route( '/register', methods = [ 'GET', 'POST' ] )
def register():
        if 'username' in session:
                return render_template( 'register.html', message="You are already logged in. Log out to register a new account." )

        if request.method == 'POST':
                try:
                        conn = mysql.connect()
                        cursor = conn.cursor()
                        cursor.execute( "INSERT INTO user ( username, password ) VALUES ( %s, %s )", [ request.form['username'], request.form['password'] ] )
                        conn.commit()
                        return redirect( url_for( 'login', message = "You have successfully registered. Please log in." ) )
                        #return render_template( 'login.html', message="You have successfully registered. Please log in." )
                except pymysql.err.IntegrityError as e:
                        return render_template( 'register.html', message="Username " + request.form['username'] + " is not available. Please choose a different name." )
        else:
                return render_template( 'register.html' )


