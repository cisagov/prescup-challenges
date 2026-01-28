import hashlib
import pymysql
from flask import Flask, request, redirect, url_for,  render_template, make_response
from tinydb import TinyDB, Query
import os
import logging

app = Flask(__name__)

def get_db_connection():
    return pymysql.connect(
        host='database',          
        user='user',
        password='password',
        database='trustfall',
        cursorclass=pymysql.cursors.DictCursor
    )

# TOKEN: _TOKEN_

db = TinyDB('/tmp/session_store.json')
session_table = db.table('sessions')
meta_table = db.table('meta')

# Initialize counter if not present
if not meta_table.contains(Query().key == 'counter'):
    meta_table.insert({'key': 'counter', 'value': 0})

def get_next_session_id():
    entry = meta_table.get(Query().key == 'counter')
    count = entry['value'] + 1
    session_id = hashlib.md5(str(count).encode()).hexdigest()
    meta_table.update({'value': count}, Query().key == 'counter')
    logging.info(f"Next id: {session_id}")
    return session_id, count

def get_logged_in_user():
    session_id = request.cookies.get('session_id')
    Session = Query()
    result = session_table.get(Session.sid == session_id)
    if not result:
        return None
 
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE id = {result['uid']}")
        user = cursor.fetchone()
    conn.close()
    
    logging.info(f"User login: {result['uid']} ({session_id})")
    
    return user

import hashlib

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.sha1(password.encode()).hexdigest()

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute(query)
                user = cursor.fetchone()
            conn.close()
        except Exception as e:
            logging.warning(f"Potentially acceptable database error: {e}")
            return render_template('500.html', query=query, error=str(e)), 500

        if user:
            session_id, _ = get_next_session_id()
            session_table.insert({'sid': session_id, 'uid': user['id']})

            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_id', session_id)
            return resp

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        Session = Query()
        session_table.remove(Session.sid == session_id)
        logging.info(f"Session logout: {session_id}")

    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session_id', '', expires=0)
    return resp

@app.route('/dashboard')
def dashboard():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)


@app.route('/')
def index():
    user = get_logged_in_user()
    
    return render_template('index.html', user=user)

if __name__ == '__main__':
    app.run()