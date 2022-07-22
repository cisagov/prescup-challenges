
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, AnonymousUserMixin, user_logged_out


# init SQLAlchemy so we can use it later in our models
#db = SQLAlchemy()
def create_app():
    app = Flask(__name__) # creates the Flask instance, __name__ is the name of the current Python module
    app.config['SECRET_KEY'] = 'flagFLAG' # it is used by Flask and extensions to keep data safe
    #app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite' #it is the path where the SQLite database file will be saved
    #app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # deactivate Flask-SQLAlchemy track modifications
    #db.init_app(app) # Initialiaze sqlite database
    # The login manager contains the code that lets your application and Flask-Login work together
    from models import User, Anonymous
    login_manager = LoginManager() # Create a Login Manager instance
    login_manager.login_view = 'main.index' # define the redirection path when login required and we attempt to access without bnager.init_app(app) # configin
    login_manager.session_protection = 'strong'
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)
    from models import User
    @login_manager.user_loader
    def load_user(user_id): #reload user object from the user ID stored in the session
        # since the user_id is just the primary key of our user table, use it in the query for the user
        curUser = User(int(user_id))
        return curUser
    # blueprint for auth routes in our app
    # blueprint allow you to orgnize your flask app
    from auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    # blueprint for non-auth parts of app
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    return app

'''
extra code:

#if user_id == None:
    #    curUser = AnonymousUserMixin
    #    curUser.role='user'
    #else:
    #    curUser = User(int(user_id))
    try:
        curUser=
    #except Exception:
        #curUser = AnonymousUserMixin
        #curUser.is_anonymous = True
        #curUser.user_logged_out = True
        #curUser.is_authenticated = False
'''
