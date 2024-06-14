
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from app.extensions import db
from app.models import Source, Backup, Token
import app.globals as globals

def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_class) 

    from .main.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        globals.init()

    return app

