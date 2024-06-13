
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, threading
from flask import Flask, redirect, url_for, request
from flask_login import LoginManager, current_user
from config import Config
from app.extensions import db
import app.globals as globals
from app.functions import *


def create_app(config_class=Config):
    app = Flask(__name__, static_folder=f"{globals.basedir}/static/",template_folder=f"{globals.basedir}/templates/")
    app.config.from_object(config_class) 
    from app.models import Anonymous, User
    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .main.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    from .auth.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        @app.errorhandler(404)
        def page_not_found(e):
            if current_user.is_authenticated:
                return redirect(url_for("auth.success"))
            return redirect(url_for("main.login"))
        
        @app.before_request
        def check_failsafe():
            if globals.failsafe == True:
                if (request.endpoint != 'static') and (request.endpoint not in ['main.failsafe','main.download','/queue_status']):
                    return redirect(url_for("main.failsafe"))

    app.add_url_rule("/queue_status",view_func=queue_status, endpoint="/queue_status")
    app.add_url_rule("/login/queue/status",view_func=get_queue_info, endpoint="/login/queue/status")
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"templates"))
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"static"))

    return app
