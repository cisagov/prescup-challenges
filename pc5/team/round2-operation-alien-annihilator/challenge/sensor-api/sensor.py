#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, AnonymousUserMixin, user_logged_out
from __init__ import create_app
from flask import current_app
import globals


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0',port=5000,debug=True)
