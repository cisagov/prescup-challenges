#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, request, make_response, session, render_template, url_for, redirect, render_template_string, current_app, flash, Blueprint
import globals, sqlalchemy, json


main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.errorhandler(404)
def page_not_found(e):
    template=globals.pageNotFound%(request.url)
    return render_template_string(template),404
