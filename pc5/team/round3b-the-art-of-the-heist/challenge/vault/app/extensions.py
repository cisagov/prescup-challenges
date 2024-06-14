
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask_sqlalchemy import SQLAlchemy
import psycopg2

#sqlite3 mm_db
global loc_db
loc_db = SQLAlchemy()

## connect to `mattermost_db` table on `db.merch.codes`
db_conn1 = psycopg2.connect(
    host="10.3.3.10",
    port="30432",
    dbname="mattermost_db",
    user="root",
    password="tartans"
)

