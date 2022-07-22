#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import pandas as pd
import json, os, binascii, random
from models import User
from threading import Thread
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
import multiprocessing as mp
import queue



'''
def ul(rec, u):
    if rec['role'] == 'user':
        curUser = User(u)
        return curUser


records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=',').set_index('id').to_dict('index')
#poolv = Pool(mp.cpu_count())
pool = ThreadPool(5)
res = []
for u in records:
    result = pool.apply_async(ul, [(records[u])])
    if result != 0:
        #print(result.get())
        res.append(result.get())
pool.close()
pool.join()
#print(res)

records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=',').set_index('id').to_dict('index')
poolv = Pool(mp.cpu_count())
res = []
for u in records:
    result = poolv.starmap_async(ul,[(records[u],u)])
    if result != [None]:
        #res.append(result[0])
        res.append(result.get())
        #print(result.get())

poolv.close()
poolv.join()
print(len(res))

q=queue.Queue()
res = []
def worker():
    while True:
        item = q.get()
        #print(f"working on {item}")
        q.task_done()

Thread(target=worker, daemon=True).start()

for u in records:
    res = q.put(u)
    print(res)

#print(f"all tasks sent")
q.join()
print("completed")

# Give admin role to 56 random accounts
adminList = random.sample(range(0, 500), 56)
records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=',').set_index('id').to_dict('index')
for x in adminList:
    records[x]['role']='admin'

pd.DataFrame.from_dict(records, orient='index').to_csv('/home/user/Desktop/site/static/records.csv', index_label='id', sep=',')


# code to add 500 fake users 
records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=',').set_index('id').to_dict('index')
curIndexs = list()
for k,v in records.items():
    curIndexs.append(k)
nextID = 1
nd = dict()
und = dict()
ed = dict()
with open('un.txt', 'r') as f1:
    lines1 = f1.read()
    und = json.loads(lines1)
with open('n.txt', 'r') as f2:
    lines2 = f2.read()
    nd = json.loads(lines2)
with open('e.txt', 'r') as f3:
    lines3 = f3.read()
    ed = json.loads(lines3)

for x in range(len(nd)):
    records[nextID] = {'name': str(nd[x]['Name']), 'username' : str(und[x]['Username']), 'email': str(ed[x]['Username']+'@jmori.com'), 'password': str(binascii.b2a_hex(os.urandom(8)).decode()),'note': '', 'role': 'user'}
    nextID += 1

pd.DataFrame.from_dict(records, orient='index').to_csv('/home/user/Desktop/site/static/records1.csv', index_label='id', sep=',')


userList=list()
for u in range(1, len(records)+1):
    curUser = User(u)
    userList.append(curUser)

for l in userList:
    print(l.name, l.username)


#records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=';').to_dict('index')
#records = pd.read_csv(r'/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=';').set_index('id').to_dict('index')
#print(records[1])

#un=e=name=pwd=note=role=''

#if un==e==name==pwd==note==role=='':
#    print('hi')

<a href="/admin?choice=formVal5" class="navbar-item">Get User ID</a>
<a href="/admin?choice=formVal1" class="navbar-item">Delete User</a>
<a href="/admin?choice=formVal2" class="navbar-item">Add User</a>
<a href="/admin?choice=formVal3" class="navbar-item">Update User</a>
<a href="/admin?choice=formVal4&res={{getAdmins}}" class="navbar-item">See Current Admins</a>

<input type="hidden" name="extra_submit_param" value="extra_submit_value">


if len(request.args) != 0:
    env = Environment()
    env.filters['getAdmins']=User.getAdmins
    print(request.args.get('res'))
    res= Template(request.args.get('res')).render()
    print(res)
    choice = request.args.get('choice')
    return render_template('admin.html', choice=choice,res=res)


def updateUser(curID,curRole,username,email,name,password,note,newRole):
    records = pd.read_csv('/home/user/Desktop/site/static/records.csv', keep_default_na=False, sep=',').set_index('id').to_dict('index')
    curRec = records[curID]
    if curRole == 'admin':
        if newRole != '':
            curRec['role']=newRole
    if username != '':
        curRec['username']=username
    if email != '':
        curRec['email']=email
    if name != '':
        curRec['name']=name
    if password != '':
        curRec['password']=password
    if note != '':
        curRec['note']=note
    
    records[curID]={'name': str(curRec['name']), 'username' : str(curRec['username']), 'email': str(curRec['email']), 'password': str(curRec['password']),'note': curRec['note'], 'role': curRec['role']}
    #for k,v in records.items():
    #    print(f"{k}, value:{v}")
    pd.DataFrame.from_dict(records, orient='index').to_csv('/home/user/Desktop/site/static/records.csv', index_label='id', sep=',')

updateUser(1,'user','','','','','pizza','')

backup code for profile page:
{% if current_user.role == 'admin' %}
<label for='updateRole'>Update Role:</label>
<input class="input is-large" type="role" name="role" placeholder="New Role"><br><br>
{%endif%}

'''
