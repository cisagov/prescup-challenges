
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, signal
from flask import Flask, redirect, url_for, session, jsonify
from flask_login import LoginManager, current_user
from config import Config
from app.extensions import db, scheduler
from app.models import Config_Logs
import app.globals as globals

def create_app(config_class=Config):
    app = Flask(__name__)
    
    app.config.from_object(config_class) 

    from app.main.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    db.init_app(app)
    with app.app_context():
        db.create_all()

        @app.errorhandler(404)
        def page_not_found(e):
            return redirect(url_for("main.index"))
        
        @app.errorhandler(415)
        def unsupported_media(error):
            return jsonify({"Error":"Could not read data because the request Content-Type was not 'application/json'"})
        
        @app.errorhandler(400)
        def unsupported_media(error):
            return jsonify({"Error":"Data missing or not sent in JSON format"})
        
        def signal_handler(sig, frame):
            app.logger.info(f"------ Signal Received -- Shutting down device API")
            scheduler.shutdown()
            os._exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"templates"))
    app.jinja_loader.searchpath.append(os.path.join(os.path.dirname(__file__),"static"))
    
    return app
