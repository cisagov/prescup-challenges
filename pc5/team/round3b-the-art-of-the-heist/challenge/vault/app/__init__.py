
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os
from flask import Flask, redirect, url_for
from flask_login import LoginManager, current_user, logout_user
#from flask_session import Session
from config import Config
from app.functions import home, logout, get_session_info, check_local_user
from app.extensions import loc_db


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=False,static_folder="static",template_folder="templates")
    app.config.from_object(config_class) 
    from .level1.login import level1 as level1_blueprint
    app.register_blueprint(level1_blueprint,url_prefix='/level1')
    
    from .level2.pin import level2 as level2_blueprint
    app.register_blueprint(level2_blueprint,url_prefix='/level2')

    from .level3.id import level3 as level3_blueprint
    app.register_blueprint(level3_blueprint,url_prefix='/level3')

    from .final.final import final as final_blueprint
    app.register_blueprint(final_blueprint,url_prefix='/final')

    loc_db.init_app(app)
    with app.app_context():     
        from app.models import Anonymous, RcUser, LocalUser
        login_manager = LoginManager()
        login_manager.blueprint_login_views = {
            "level1_blueprint": "level1.login",
            "level2_blueprint": "level2.submit_pin",
            "level3_blueprint": "level3.submit_id"
        }
        login_manager.anonymous_user = Anonymous
        login_manager.init_app(app)
        
        loc_db.create_all()

        @login_manager.user_loader
        def load_user(id):
            user = RcUser.get(id)
            if user == None:
                return Anonymous
            return user
    
        @app.before_request
        def check_user():
            if hasattr(current_user,'username'):
                if not check_local_user(current_user.username):
                    logout()
                    return redirect(url_for("level1.login"))


    app.add_url_rule("/",view_func=home, endpoint="home")
    app.add_url_rule("/logout",view_func=logout, endpoint="logout")
    app.add_url_rule("/session_info",view_func=get_session_info, endpoint="session_info")
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"templates"))
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"static"))

    return app
