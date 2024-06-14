
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask
from flask_login import LoginManager
from config import Config
from flask_sqlalchemy import SQLAlchemy
from app.extensions import db
import app.globals as globals
#Path = /home/user/Desktop/flask_app/app/__init__.py

def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=False,static_folder="/home/user/Desktop/flask_app/app/static/",template_folder="/home/user/Desktop/flask_app/app/templates/")
    app.config.from_object(config_class) 

    from app.models import Anonymous, User
    login_manager = LoginManager()
    login_manager.login_view = "main.index"
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
        globals.init()

    return app


