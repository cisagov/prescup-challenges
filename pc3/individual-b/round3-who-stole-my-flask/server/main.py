#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import uuid
from flask import Flask, request, make_response, session, render_template, url_for, redirect, render_template_string, current_app, flash, Blueprint
from flask_login import LoginManager, login_required, current_user
from __init__ import create_app

#app = Flask(__name__)
main = Blueprint('main', __name__)
@main.route('/')
def index():
    return render_template('index.html')

@main.route('/about')
def about():
    return render_template('about.html')

@main.errorhandler(404)
def page_not_found(e):
    template='''
        {%% block body %%}
        <div class="center-content error">
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
        </div>
        {%% endblock %%}
    '''%(request.url)
    return render_template_string(template),404

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0',port=5000,debug=False)
