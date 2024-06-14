
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.



import sys, os, flask_bcrypt, datetime, secrets, requests, json
from flask import render_template, redirect, url_for, current_app, session, copy_current_request_context, flash, request
from flask_login import current_user, logout_user, login_required
from app.extensions import db_conn1, loc_db
from app.models import LocalUser
from app.globals import scheduler, request_auth
from apscheduler.events import EVENT_ALL_JOBS_REMOVED, EVENT_JOB_ERROR, EVENT_JOB_REMOVED, EVENT_SCHEDULER_PAUSED, EVENT_SCHEDULER_SHUTDOWN, EVENT_JOB_MODIFIED
import hashlib

def home():
    return render_template('home.html')

def logout(server_exit=False):
    if current_user.is_authenticated:
        chk = check_local_user(current_user.username)
        if chk != False:
            if chk.time_left == "00:00":
                flash("Session timed out. Please try again.")
            elif chk.valid_session == False:
                flash("Unauthorized client detected. Session ended.")
            loc_db.session.delete(chk)
            loc_db.session.commit()
        try:
            scheduler.remove_job(chk.un_id)
        except Exception as e:
            print(f"Error removing job for user {current_user.username}.\nException:\t{str(e)}")
        logout_user()
    if server_exit == False:
        return redirect(url_for('level1.login'))

def get_session_info():
    if (request.remote_addr != '10.7.7.7') and ((request.referrer == None) or ("vault.merch.codes" not in request.referrer)):
        return "Unauthorized"
    un = request.args['un']
    with current_app.app_context():
        try:
            loc_user = LocalUser.query.filter_by(un_id=un).first()
            if loc_user == None:
                return ''
        except Exception as e:
            print(str(e))
            return ''
        info = {
            "time_left":loc_user.time_left,
            "valid_session":loc_user.valid_session
        }
        return json.dumps(info)

def check_local_user(un):
    try:
        chk_user = LocalUser.query.filter_by(un_id=un).first()
        if chk_user == None:
            return False
    except Exception as e:
        print(f"{un} not found in local DB")
        return False
    return chk_user

def passed_level(level_name):
    local_user = check_local_user(current_user.username)
    try:
        local_user.passed[level_name] = True#level_token
        loc_db.session.commit()
    except Exception as e:
        print(f"error updating passed levels.\nError:\t {e}")



def create_and_start():
    chk = check_local_user(current_user.username)
    if chk != False:
        loc_db.session.delete(chk)
        loc_db.session.commit()
    tmp_endtime = datetime.datetime.now() + current_app.config['SESSION_TIMER']
    hours = current_app.config['SESSION_TIMER'].seconds // 60
    seconds = current_app.config['SESSION_TIMER'].seconds % 60
    local_user = LocalUser(
        un_id=current_user.username,
        client_ip = request.remote_addr,
        valid_session = True,
        endtime = tmp_endtime.strftime("%Y-%m-%d %H:%M:%S"),
        time_left = f"{hours:02}:{seconds:02}",
        passed = {
            "level1":False,
            "level2":False,
            "level3":False
        }
    )
    try:
        loc_db.session.add(local_user)
        loc_db.session.commit()
    except Exception as e:
        print(f"DB local_user commit error:\n{e}")
        flash("Error during login process.")
        return redirect(url_for("level1.login"))
    
    user_job = {
    "id": current_user.username,
    "name": str(request.remote_addr),
    "func": "app.functions:timer", 
    "args": [current_user.username],
    "trigger": "interval",
    "seconds": 0.5,
    "replace_existing": True
    }
    resp = requests.post('http://vault.merch.codes/scheduler/jobs', json=user_job, auth=request_auth)


def my_listener(event):
    with scheduler.app.app_context():
        try:
            if event.code in [EVENT_ALL_JOBS_REMOVED, EVENT_JOB_REMOVED]:       # EVENT_JOB_ERROR,  EVENT_SCHEDULER_PAUSED, EVENT_SCHEDULER_SHUTDOWN]:
                print(f"--- Job {event.job_id} removed.")
                if event.job_id == "restart_timer":
                    scheduler.add_job(id="restart_timer",func=restart_timer,trigger="interval",seconds=15)
                    print(f"--- Job {event.job_id} restarted.") # \t\tcode:\t{event.code}
            elif event.code == EVENT_JOB_MODIFIED:
                print(f"--- Job {event.job_id} modified (likely paused or resumed).")
                if event.job_id == "restart_timer":
                    try:
                        scheduler.resume_job(id="restart_timer")  
                        print(f"--- Job {event.job_id} resumed.")
                        return
                    except:
                        ...
            elif event.code == EVENT_SCHEDULER_PAUSED:
                print("--- scheduler paused")
                scheduler.resume()
                print("--- scheduler resumed")
                try:
                    scheduler.add_job(id="restart_timer",func=restart_timer,trigger="interval",seconds=15)
                    print(f"--- Job restart_timer started.")
                except:
                    ...
            elif event.code == EVENT_SCHEDULER_SHUTDOWN:
                print("--- scheduler has been shutdown")
                scheduler.start()
                print("--- scheduler restarted")
                try:
                    scheduler.add_job(id="restart_timer",func=restart_timer,trigger="interval",seconds=15)
                    print(f"--- Job restart_timer started.")
                except:
                    ...
            elif event.code == EVENT_JOB_ERROR:
                print(f"--- Job {event}\t\tfailed:\t{event.exception}")
            elif hasattr(event,'exception'):
                print(f"--- Exception Occured:\t{event.exception}")
            return
        except Exception as e:
            print(f"--- Listener event {event} had exception.\t\t{str(e)}")
            

def restart_timer():
    with scheduler.app.app_context():
        try:
            users = LocalUser.query.all()
            if users == None:
                print("No sessions found")
                return
        except Exception as e:
            print("No sessions found")
            return
    
        try:
            resp = requests.get(f"http://vault.merch.codes/scheduler/jobs", auth=request_auth)
            jobs = json.loads(resp.text)
        except Exception as e:
            print(resp.text)
            print("Error getting jobs")
            return

        if len(jobs) == 0:
            return
        
        job_tracker = dict()
        for index,job in enumerate(jobs):
            job_tracker[job['id']] = index

        for user in users:
            if user.un_id in list(job_tracker.keys()):
                if jobs[job_tracker[job['id']]]['next_run_time'] == None:
                    try:
                        scheduler.resume_job(user.un_id)
                        print(f"--- job {job['id']} resumed")
                    except:
                        ...
                continue
            else:
                user_job = {
                    "id": user.un_id,
                    "name": str(user.client_ip),
                    "func": "app.functions:timer",    
                    "args": [user.un_id],
                    "trigger": "interval",
                    "seconds": 0.5,
                    "replace_existing": True
                    }
                try:
                    resp = requests.post('http://vault.merch.codes/scheduler/jobs', json=user_job, auth=request_auth)
                except Exception as e:
                    print(f"--- error attempting to add job for {user.un_id}")
                else:
                    print(f"--- Job {user.un_id} added.")

def timer(un):
    ## get the mm_db entry for the current user
    with scheduler.app.app_context():
        try:
            loc_user = LocalUser.query.filter_by(un_id=un).first()
            #print(loc_user)
        except Exception as e:
            print(f"Cannot find entry with un_id:\t{un}\nError:\n{e}")
            return
        ## Update timer
        try:
            user_endtime = datetime.datetime.strptime(loc_user.endtime, "%Y-%m-%d %H:%M:%S")
        except:
            try:
                scheduler.remove_job(un)
            except Exception as e:
                ...
            return
        session_timer = user_endtime - datetime.datetime.now()
        if session_timer <= datetime.timedelta(minutes=0,seconds=0):
            try:
                loc_user.time_left = "00:00"
                #loc_user.valid_session = False
                loc_db.session.commit()
            except Exception as e:
                print(f"DB loc_user update error:\n{e}")
        else:
            try:
                hours = session_timer.seconds // 60
                seconds = session_timer.seconds % 60
                loc_user.time_left  = f"{hours:02}:{seconds:02}"
                loc_db.session.commit()
            except Exception as e:
                print(f"DB loc_user update error:\n{e}")


def unauthorized_clients(*argv):
    with scheduler.app.app_context():
        for user in argv:
            try:
                loc_user = LocalUser.query.filter_by(un_id=user).one()
                #print(loc_user)
            except Exception as e:
                print(f"Cannot find entry with un_id:\t{user}\nError:\n{e}")
                continue
            try:
                loc_user.valid_session = False
                loc_db.session.commit()
            except Exception as e:
                print(str(e))
                continue

            #scheduler.remove_job(user)
            #print(f"{user} job removed")
        


def check_user(email,pwd):
    try:
        sql_cmd = f"select * from public.users where email='{email}'"
        mm_db = db_conn1.cursor()
        mm_db.execute(sql_cmd)
    except:
        flash("Unable to process request. Please verify network connectivity and try again")
        return "error"
    user=mm_db.fetchone()
    mm_db.close()
    if user == None:
        return None
    desc = [row.name for row in mm_db.description]
    user = dict(zip(desc,user))

    password_check = flask_bcrypt.check_password_hash(user['password'],pwd)
    if password_check:
        return user
    else:
        return False

def scheduler_auth(username, pwd):
    try:
        sql_cmd = f"select * from public.users where username='{username}'"
        mm_db = db_conn1.cursor()
        mm_db.execute(sql_cmd)
    except:
        print("Error attempting to run scheduler authentication.")
        return
    user=mm_db.fetchone()
    mm_db.close()
    if user == None:
        return None
    desc = [row.name for row in mm_db.description]
    user = dict(zip(desc,user))

    password_check = flask_bcrypt.check_password_hash(user['password'],pwd)
    if password_check and ('system_admin' in user['roles']):
        return True
    else:
        return False
    

def check_filename(filename):
    username,extension = filename.split('.',1)
    if current_user.username != username:
        flash("Credential file name doesnt match current user logged in")
        return False
    elif extension != "cred.ini":
        flash("Credential file extension doesnt follow accepted `.cred.ini` format.")
        return False
    return username


def verify_file(file):
    chk_username = check_filename(file.filename)
    if chk_username == False:
        return False
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'],file.filename)
    file.save(full_path)
    return [full_path, chk_username]
    
def get_hash(filepath):
    with open(filepath,'rb') as f:
        data = f.read()
    md5hash = hashlib.md5(data).hexdigest()
    return md5hash
