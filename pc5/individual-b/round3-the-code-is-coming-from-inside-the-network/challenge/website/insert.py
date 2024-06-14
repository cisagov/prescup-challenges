#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import random, sys, sqlite3
from sqlite3 import *


def insert_project(project):
    try:
        conn = sqlite3.connect('/home/user/Desktop/flask_app/app.db')
        cursor = conn.cursor()
        for k,tuple_list in projects.items():
            for tuple in tuple_list:
                if k == 'Past':
                    cmd = f'''insert into {k}(customer_name,start_date,date_completed,price,details) values (?, ?, ?, ?, ?)'''
                elif k == 'Current':
                    cmd = f'''insert into {k}(customer_name,start_date,projected_end_date,projected_price,details) values (?, ?, ?, ?, ?)'''
                else:
                    cmd = f'''insert into {k}(customer_name,projected_start_date,projected_price,details) values (?, ?, ?, ?)'''
                data_tuple = tuple
                cursor.execute(cmd, data_tuple)
                conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"error: {e}")
    else:
        print('Projects uploaded')




if __name__ == '__main__':
    projects = {
        "Current": [
            ("Mashle Macabre", "August 2, 2023","August 3, 2024", "$" + str(random.randint(100000, 900000)) + "." + str(random.randint(0, 99)), f"Token 3: {sys.argv[1]}")
    ]}
    insert_project(projects)
