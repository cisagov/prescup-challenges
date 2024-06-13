
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask_sqlalchemy import SQLAlchemy
import psycopg2

global db
db = SQLAlchemy()
