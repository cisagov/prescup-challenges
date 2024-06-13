
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os
from sqlalchemy.exc import OperationalError
from flask import Flask, redirect, url_for, session, jsonify
from flask_login import LoginManager, current_user
from config import Config
from app.functions import logout        
from app.extensions import db
import app.globals as globals


def create_app(config_class=Config):
    app = Flask(__name__)      
    
    app.config.from_object(config_class) 

    from app.models import Anonymous, User
    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    from app.main.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from app.social.social import social as social_blueprint
    app.register_blueprint(social_blueprint)
    
    from app.shop.shop import shop as shop_blueprint
    app.register_blueprint(shop_blueprint)

    db.init_app(app)
    with app.app_context():
        db.create_all()

        @app.errorhandler(404)
        def page_not_found(e):
            if current_user.is_authenticated:
                return redirect(url_for("social.my_profile"))
            return redirect(url_for("main.login"))
    
        @app.errorhandler(OperationalError)
        def handle_exception(error):
            error_info = str(error.orig) + " - " + str(error.statement)
            app.logger.error(error_info)
            return jsonify({"Error":"A database error has occurred","details": str(error.orig),"query entered":str(error.statement)})
        

        @app.before_request
        def initialize_cart():
            if 'cart' not in session:
                session['cart'] = {}

    app.add_url_rule("/logout",view_func=logout,endpoint="/logout")
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"templates"))
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"static"))
    
    return app

